// Package threatdata holds the threat data nyx checks addresses against: Spamhaus's three DROP
// lists and ipapi.is's two abuse lists, five lists in all. Each list has a built-in copy, embedded
// in the binary, and may have a downloaded copy, which an update keeps in the threat-data directory
// beside the default config file.
//
// # Terms
//
// A source is one provider of lists: Spamhaus (drop_v4, drop_v6 and asndrop) or ipapi.is
// (networks and asns). A source's downloaded copy is replaced as a whole or not at all, so it is
// one file: spamhaus.jsonl (a bundle, as internal/spamhaus reads it) or ipapi.json (a snapshot file,
// as internal/abusive reads it).
//
// The copy in use of a list is whichever of its built-in and downloaded copies is dated later, the
// downloaded one when both have the same date. A downloaded source that is unreadable (it fails to
// parse, holds a control character, lists an entry twice, lacks its metadata, or holds fewer than
// 90% of the entries it states) is not used at all: the whole source falls back to its built-in
// copy, with a warning.
//
// A source is stale when more than 30 days have passed both since the oldest date among its lists
// in use and since its last successful check: an update that found it updated or already current.
//
// Load reads the lists in use. Update downloads the five lists through egress's third-party client
// (this package does file I/O but never network I/O itself), checks each against the acceptance
// rules in accept.go, and keeps a per-source state file of when the source last answered and was
// last checked.
package threatdata

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
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

// BuiltIn is the built-in copy of each list. A nil *BuiltIn means the copies embedded in the
// binary; a test gives its own, so that its dates don't move with each refresh of the embedded data.
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

// Notice is a warning or a stale notice about one source. Text is the whole line, without a
// "hint: " or "warning: " prefix.
type Notice struct {
	Source string
	Text   string
}

// Set is the five lists in use, ready to match, with what a command reading them reports.
type Set struct {
	Drop    spamhaus.Lists
	Abusive *abusive.Snapshot // loaded, ready to match

	// Lists describes the five lists, in the order drop_v4, drop_v6, asndrop, networks, asns.
	Lists []List

	// Copyright and Terms are Spamhaus's credit, from the metadata of the drop_v4 list in use,
	// sanitised, or the built-in copy's when that list has none.
	Copyright, Terms string

	// Warnings has one notice for each source whose downloaded copy is unreadable.
	Warnings []Notice
	// Stale has one notice for each stale source, as "Spamhaus DROP data is from <date>; run nyx
	// setup --update-threat-data" or "ipapi.is abuse data is from <date>; ...".
	Stale []Notice
}

// Dir is the threat-data directory: threat-data beside the default config file, under
// $XDG_CONFIG_HOME/nyx or else ~/.config/nyx. It is "" when neither XDG_CONFIG_HOME nor HOME is
// set.
func Dir(env config.Env) string {
	path := config.DefaultConfigPath(env)
	if path == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(path), "threat-data")
}

// Load reads the lists in use from dir and the embedded built-in copies. now decides staleness.
// With dir "" it uses the built-in copies, with no warning and no stale notice.
func Load(dir string, now time.Time) Set { return (*BuiltIn)(nil).Load(dir, now) }

// Load is the package's Load with b's built-in copies, or the embedded ones when b is nil.
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

// The files in the threat-data directory. Each source's names start with its stem: the data file,
// <stem>.state.json, <stem>.lock and the temporary files .<stem>-*.tmp.
const (
	stemSpamhaus = "spamhaus"
	stemIpapi    = "ipapi"

	fileSpamhaus = "spamhaus.jsonl"
	fileIpapi    = "ipapi.json"
)

// staleAfter is how long a source's data, and its last successful check, may be old before a
// command says so.
const staleAfter = 30 * 24 * time.Hour

var (
	embeddedOnce sync.Once
	embeddedSH   spamhaus.Lists
)

// spamhausLists is the built-in Spamhaus copy: b's, or the embedded one.
func (b *BuiltIn) spamhausLists() spamhaus.Lists {
	if b != nil {
		return b.Spamhaus
	}
	embeddedOnce.Do(func() {
		l, err := spamhaus.ParseBundle(spamhaus.Builtin())
		if err != nil {
			panic("threatdata: the embedded Spamhaus data is unreadable: " + err.Error())
		}
		embeddedSH = l
	})
	return embeddedSH
}

// ipapiSnapshot is the built-in ipapi.is copy: b's, or the embedded one. For the embedded copy it
// also returns the snapshot already prepared for matching, which must not be changed.
func (b *BuiltIn) ipapiSnapshot() (abusive.Snapshot, *abusive.Snapshot) {
	if b != nil {
		return b.Ipapi, nil
	}
	d := abusive.Default()
	return *d, d
}

// state is a source's state file: when it last sent a response, and when an update last found it
// updated or already current. A nil time is null.
type state struct {
	LastResponse *time.Time `json:"last_response"`
	LastChecked  *time.Time `json:"last_checked"`
}

// readState reads a source's state file, which is the zero state when it is absent or unreadable.
func readState(dir, stem string) state {
	var st state
	if b, err := os.ReadFile(filepath.Join(dir, stem+".state.json")); err == nil {
		if json.Unmarshal(b, &st) != nil {
			return state{}
		}
	}
	return st
}

// readSpamhaus reads the downloaded Spamhaus copy. It returns nil and no notice when there is none,
// and nil and a notice when it is unreadable.
func readSpamhaus(dir string) (*spamhaus.Lists, *Notice) {
	l, err := parseSpamhausFile(filepath.Join(dir, fileSpamhaus))
	if err != nil {
		return nil, unreadable(Spamhaus, dir, err)
	}
	return l, nil
}

// parseSpamhausFile reads and checks a bundle file. A missing file gives nil and no error.
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

// parseIpapiFile reads and checks a snapshot file, ignoring fields it does not know. A missing file
// gives nil and no error.
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

// spamhausInUse picks, for each of the three lists, the downloaded one when it is dated no earlier
// than the built-in one, and says which it picked. down may be nil.
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

// ipapiDate is an ipapi.is list's date as 00:00 UTC of its day, or the zero time when it has none.
func ipapiDate(day string) time.Time {
	t, _ := time.Parse(time.DateOnly, day)
	return t
}

// credit is Spamhaus's copyright line and terms link from the drop_v4 list in use, sanitised, with
// the built-in copy's for either that the list lacks.
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

// view is a list in use with what an update compares: its date, and its entries' identities.
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

// staleNotice is the notice for a source whose lists in use, and last successful check, are all
// more than 30 days old.
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
	// A check recorded in the future is no check: until an update rewrites it as now, it must not
	// hide the notice.
	if st.LastChecked != nil && !st.LastChecked.After(now) && now.Sub(*st.LastChecked) <= staleAfter {
		return Notice{}, false
	}
	name := "Spamhaus DROP"
	if source == Ipapi {
		name = "ipapi.is abuse"
	}
	return Notice{Source: source, Text: fmt.Sprintf("%s data is from %s; run nyx setup --update-threat-data", name, oldest.UTC().Format(time.DateOnly))}, true
}
