// Package threatdata manages Spamhaus's DROP/DROPv6/ASN-DROP and ipapi.is's network/ASN lists.
// Each has an embedded copy and may have a downloaded copy beside the default config. Each
// source is replaced atomically as one bundle: spamhaus.jsonl or ipapi.json.
//
// Load selects the newer copy per list, preferring downloaded data on equal dates. An invalid
// downloaded bundle falls back entirely to embedded data with a warning. Validation rejects
// malformed metadata, control characters, duplicates and counts below 90% of the stated total.
//
// A source is stale only when both its oldest active list and its last successful update check
// are over 30 days old. Update fetches through egress, applies shared acceptance rules and
// saves per-source contact/check times.
package threatdata

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/sanitize"
	"github.com/rafaelh/nyx/internal/spamhaus"
)

// The hosts an update contacts. Nothing else in nyx sends them anything as a threat-data source.
const (
	SpamhausHost = "www.spamhaus.org"
	IpapiHost    = "ipapi.is"
)

// The two sources, as the update's output and envelope name them.
const (
	Spamhaus = "spamhaus"
	Ipapi    = "ipapi.is"
)

// The names of ipapi.is's two lists. Spamhaus's are spamhaus.ListV4, ListV6 and ListASN.
const (
	ListNetworks = "networks"
	ListASNs     = "asns"
)

// BuiltIn supplies embedded-list replacements for tests with fixed dates. Nil uses the binary's
// data.
type BuiltIn struct {
	Spamhaus spamhaus.Lists
	Ipapi    abusive.Snapshot
}

// List describes one of the five lists in use.
type List struct {
	Source     string // Spamhaus or Ipapi
	Name       string // drop_v4, drop_v6, asndrop, networks or asns
	Updated    string // the list's date: RFC 3339 UTC to the second (Spamhaus), or YYYY-MM-DD (ipapi.is)
	Entries    int
	Downloaded bool // the copy in use is the downloaded one, not the built-in one
}

// Notice carries a sanitised source warning/staleness message without a display prefix.
type Notice struct {
	Source string
	Text   string
}

// Set contains active matchers, list metadata and command notices.
type Set struct {
	Drop    spamhaus.Lists
	Abusive *abusive.Snapshot // loaded, ready to match

	// Lists describes the five lists, in the order drop_v4, drop_v6, asndrop, networks, asns.
	Lists []List

	// Copyright and Terms use sanitised active drop_v4 credit, falling back to built-in
	// metadata.
	Copyright, Terms string

	// Warnings has one notice for each source whose downloaded copy is unreadable.
	Warnings []Notice
	// Stale contains one dated update notice per stale source.
	Stale []Notice
}

// Dir places threat-data beside the default config under XDG_CONFIG_HOME or ~/.config. It
// returns "" when neither base directory is known.
func Dir(env config.Env) string {
	path := config.DefaultConfigPath(env)
	if path == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(path), "threat-data")
}

// Load selects active downloaded/built-in copies and uses now for staleness. Nil b uses
// embedded data. An empty dir uses only built-ins and suppresses warnings and stale notices.
func (b *BuiltIn) Load(dir string, now time.Time) Set {
	builtSH := b.spamhausLists()
	builtIP, loadedIP := b.ipapiSnapshot()
	var downSH *spamhaus.Lists
	var downIP *abusive.Snapshot
	var set Set
	if dir != "" {
		var warn *Notice
		if downSH, warn = readSpamhaus(dir); warn != nil {
			set.Warnings = append(set.Warnings, *warn)
		}
		if downIP, warn = readIpapi(dir); warn != nil {
			set.Warnings = append(set.Warnings, *warn)
		}
	}
	useSH, fromSH := spamhausInUse(builtSH, downSH)
	useIP, fromIP := ipapiInUse(builtIP, downIP)
	set.Drop = useSH
	set.Abusive = loadedIP
	if fromIP != [2]bool{} || loadedIP == nil {
		set.Abusive = abusive.Load(useIP)
	}
	spViews, ipViews := spamhausViews(useSH, fromSH), ipapiViews(useIP, fromIP)
	for _, v := range append(spViews, ipViews...) {
		set.Lists = append(set.Lists, v.List)
	}
	set.Copyright, set.Terms = credit(useSH, builtSH)
	if dir != "" {
		if n, ok := staleNotice(Spamhaus, spViews, readState(dir, stemSpamhaus), now); ok {
			set.Stale = append(set.Stale, n)
		}
		if n, ok := staleNotice(Ipapi, ipViews, readState(dir, stemIpapi), now); ok {
			set.Stale = append(set.Stale, n)
		}
	}
	return set
}

// Source files share a stem: data, state JSON, lock and temporary update files.
const (
	stemSpamhaus = "spamhaus"
	stemIpapi    = "ipapi"

	fileSpamhaus = "spamhaus.jsonl"
	fileIpapi    = "ipapi.json"
)

// staleAfter requires both old list data and an old successful check before warning.
const staleAfter = 30 * 24 * time.Hour

// spamhausLists is the built-in Spamhaus copy: b's, or the embedded one.
func (b *BuiltIn) spamhausLists() spamhaus.Lists {
	if b != nil {
		return b.Spamhaus
	}
	return *spamhaus.Default()
}

// ipapiSnapshot selects b's copy or the embedded one. The embedded snapshot is pre-indexed for
// matching and must be treated as read-only.
func (b *BuiltIn) ipapiSnapshot() (abusive.Snapshot, *abusive.Snapshot) {
	if b != nil {
		return b.Ipapi, nil
	}
	d := abusive.Default()
	return *d, d
}

// state stores last HTTP response and last successful update/check times. Unknown times encode
// as null.
type state struct {
	LastResponse *time.Time `json:"last_response"`
	LastChecked  *time.Time `json:"last_checked"`
}

// readState defaults missing or unreadable state to zero values.
func readState(dir, stem string) state {
	var st state
	if b, err := os.ReadFile(filepath.Join(dir, stem+".state.json")); err == nil {
		if json.Unmarshal(b, &st) != nil {
			return state{}
		}
	}
	return st
}

// readSpamhaus distinguishes absent downloads from unreadable ones, returning a notice only for
// the latter.
func readSpamhaus(dir string) (*spamhaus.Lists, *Notice) {
	l, err := parseSpamhausFile(filepath.Join(dir, fileSpamhaus))
	if err != nil {
		return nil, unreadable(Spamhaus, dir, err)
	}
	return l, nil
}

// parseSpamhausFile validates downloaded bundles, accepting missing files as nil.
func parseSpamhausFile(path string) (*spamhaus.Lists, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil //nolint:nilnil // nothing downloaded
	}
	if err != nil {
		return nil, err
	}
	l, err := spamhaus.ParseBundle(b)
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// readIpapi reads the downloaded ipapi.is copy, as readSpamhaus does.
func readIpapi(dir string) (*abusive.Snapshot, *Notice) {
	s, err := parseIpapiFile(filepath.Join(dir, fileIpapi))
	if err != nil {
		return nil, unreadable(Ipapi, dir, err)
	}
	return s, nil
}

// parseIpapiFile validates snapshots while tolerating unknown future fields; missing files
// return nil.
func parseIpapiFile(path string) (*abusive.Snapshot, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil //nolint:nilnil // nothing downloaded
	}
	if err != nil {
		return nil, err
	}
	s, err := abusive.ParseLenient(b)
	if err != nil {
		return nil, err
	}
	if err := abusive.Validate(s); err != nil {
		return nil, err
	}
	if err := abusive.ValidateCounts(s); err != nil {
		return nil, err
	}
	return &s, nil
}

// unreadable is the warning for a downloaded source that can't be used.
func unreadable(source, dir string, err error) *Notice {
	return &Notice{Source: source, Text: sanitize.Line(fmt.Sprintf(
		"the downloaded %s data in %s is unreadable (%v), so nyx uses its built-in copy; run nyx setup --update-threat-data to replace it",
		source, dir, err))}
}

// spamhausInUse selects downloaded lists at least as new as built-ins and reports the selection
// per list. down may be nil.
func spamhausInUse(built spamhaus.Lists, down *spamhaus.Lists) (spamhaus.Lists, [3]bool) {
	use := built
	var from [3]bool
	if down == nil {
		return use, from
	}
	if !down.V4.Meta.Timestamp.Before(built.V4.Meta.Timestamp) {
		use.V4, from[0] = down.V4, true
	}
	if !down.V6.Meta.Timestamp.Before(built.V6.Meta.Timestamp) {
		use.V6, from[1] = down.V6, true
	}
	if !down.ASNs.Meta.Timestamp.Before(built.ASNs.Meta.Timestamp) {
		use.ASNs, from[2] = down.ASNs, true
	}
	return use, from
}

// ipapiInUse is spamhausInUse for ipapi.is's two lists.
func ipapiInUse(built abusive.Snapshot, down *abusive.Snapshot) (abusive.Snapshot, [2]bool) {
	use := built
	var from [2]bool
	if down == nil {
		return use, from
	}
	if !ipapiDate(down.Nets.Updated).Before(ipapiDate(built.Nets.Updated)) {
		use.Nets, from[0] = down.Nets, true
	}
	if !ipapiDate(down.ASNs.Updated).Before(ipapiDate(built.ASNs.Updated)) {
		use.ASNs, from[1] = down.ASNs, true
	}
	return use, from
}

// ipapiDate converts a source day to midnight UTC or zero when missing.
func ipapiDate(day string) time.Time {
	t, _ := time.Parse(time.DateOnly, day)
	return t
}

// credit sanitises active drop_v4 credit and fills missing fields from built-in metadata.
func credit(use, built spamhaus.Lists) (copyright, terms string) {
	copyright, terms = use.V4.Meta.Copyright, use.V4.Meta.Terms
	if copyright == "" {
		copyright = built.V4.Meta.Copyright
	}
	if terms == "" {
		terms = built.V4.Meta.Terms
	}
	return sanitize.Line(copyright), sanitize.Line(terms)
}

// view exposes active dates and entry identities for update comparisons.
type view struct {
	List
	date time.Time
	keys func() map[string]struct{}
}

// keySet is the set of the keys.
func keySet[E any](entries []E, key func(E) string) func() map[string]struct{} {
	return func() map[string]struct{} {
		set := make(map[string]struct{}, len(entries))
		for _, e := range entries {
			set[key(e)] = struct{}{}
		}
		return set
	}
}

func netView(name string, l spamhaus.NetworkList, downloaded bool) view {
	return view{
		Source: Spamhaus, Name: name, Updated: l.Meta.Updated(), Entries: len(l.Entries), Downloaded: downloaded,
		date: l.Meta.Timestamp,
		keys: keySet(l.Entries, func(e spamhaus.NetworkEntry) string { return e.CIDR.String() + " " + e.SBLID }),
	}
}

func asnView(l spamhaus.ASNList, downloaded bool) view {
	return view{
		Source: Spamhaus, Name: spamhaus.ListASN, Updated: l.Meta.Updated(), Entries: len(l.Entries), Downloaded: downloaded,
		date: l.Meta.Timestamp,
		keys: keySet(l.Entries, func(e spamhaus.ASNEntry) string { return strconv.Itoa(e.ASN) }),
	}
}

// spamhausViews describes the three Spamhaus lists, in the order drop_v4, drop_v6, asndrop.
func spamhausViews(l spamhaus.Lists, from [3]bool) []view {
	return []view{netView(spamhaus.ListV4, l.V4, from[0]), netView(spamhaus.ListV6, l.V6, from[1]), asnView(l.ASNs, from[2])}
}

// ipapiViews describes the two ipapi.is lists, in the order networks, asns.
func ipapiViews(s abusive.Snapshot, from [2]bool) []view {
	return []view{
		{
			Source: Ipapi, Name: ListNetworks, Updated: s.Nets.Updated, Entries: len(s.Nets.Entries), Downloaded: from[0],
			date: ipapiDate(s.Nets.Updated),
			keys: keySet(s.Nets.Entries, func(e abusive.NetworkEntry) string { return e.Start.String() + "-" + e.End.String() }),
		},
		{
			Source: Ipapi, Name: ListASNs, Updated: s.ASNs.Updated, Entries: len(s.ASNs.Entries), Downloaded: from[1],
			date: ipapiDate(s.ASNs.Updated),
			keys: keySet(s.ASNs.Entries, func(e abusive.ASNEntry) string { return strconv.Itoa(e.ASN) }),
		},
	}
}

// staleNotice explains when both active data and successful checks exceed 30 days.
func staleNotice(source string, views []view, st state, now time.Time) (Notice, bool) {
	oldest := views[0].date
	for _, v := range views[1:] {
		if v.date.Before(oldest) {
			oldest = v.date
		}
	}
	if now.Sub(oldest) <= staleAfter {
		return Notice{}, false
	}
	// Future check times cannot suppress stale notices before an update clamps them to now.
	if st.LastChecked != nil && !st.LastChecked.After(now) && now.Sub(*st.LastChecked) <= staleAfter {
		return Notice{}, false
	}
	name := "Spamhaus DROP"
	if source == Ipapi {
		name = "ipapi.is abuse"
	}
	return Notice{Source: source, Text: fmt.Sprintf("%s data is from %s; run nyx setup --update-threat-data", name, oldest.UTC().Format(time.DateOnly))}, true
}
