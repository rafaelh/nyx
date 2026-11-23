package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// The names of the files the tool reads from -dir, as `make threat-data` fetches them.
const (
	fetchedV4       = "drop_v4.json"
	fetchedV6       = "drop_v6.json"
	fetchedASN      = "asndrop.json"
	fetchedNetworks = "networks.html"
	fetchedASNs     = "asns.html"
)

// options are what one refresh reads and writes. now is the clock, in UTC.
type options struct {
	dir         string // the fetched files
	spamhaus    string // the bundle to replace
	ipapi       string // the snapshot file to replace
	allowShrink bool   // lift the shrink rule, and no other
	now         time.Time
}

// run is one refresh: args are the command's arguments (-dir, -spamhaus, -ipapi and
// -allow-shrink), what changed goes to stdout, and failures to stderr. now is the clock, which the
// future-date rule reads. It returns the exit code: 0 when every source was written or left as it
// is, 1 when a source failed (after writing the other), and 2 for a usage error.
func run(args []string, stdout, stderr io.Writer, now time.Time) int {
	o := options{now: now.UTC()}
	fs := flag.NewFlagSet("refresh", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&o.dir, "dir", "", "the directory of the fetched files")
	fs.StringVar(&o.spamhaus, "spamhaus", "", "the Spamhaus bundle to replace")
	fs.StringVar(&o.ipapi, "ipapi", "", "the ipapi.is snapshot file to replace")
	fs.BoolVar(&o.allowShrink, "allow-shrink", false, "let through a list with fewer than half the entries of the built-in copy")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if o.dir == "" || o.spamhaus == "" || o.ipapi == "" || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: refresh -dir <fetched files> -spamhaus <bundle> -ipapi <snapshot> [-allow-shrink]")
		return 2
	}
	code := 0
	for _, src := range []struct {
		name    string
		refresh func(options, io.Writer) error
	}{{threatdata.Spamhaus, refreshSpamhaus}, {threatdata.Ipapi, refreshIpapi}} {
		if err := src.refresh(o, stdout); err != nil {
			fmt.Fprintf(stderr, "%s: refresh failed, and its built-in copy is unchanged: %v\n", src.name, err)
			code = 1
		}
	}
	return code
}

// readFetched reads one of the fetched files.
func readFetched(o options, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(o.dir, name))
	if err != nil {
		return nil, fmt.Errorf("reading the fetched file: %w", err)
	}
	return b, nil
}

// writeAtomic writes data to a temporary file beside path and renames it into place, so the file
// is the old one or the new one and never half of either.
func writeAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".refresh-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(f.Name())
		}
	}()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Chmod(f.Name(), 0o644); err != nil { //nolint:gosec // the built-in copies are source, read by everyone
		return err
	}
	return os.Rename(f.Name(), path)
}

// accept applies the rules a list that is newer than the built-in copy must pass beside its
// format: it has entries, and (unless the maintainer allows it) not under half the copy's. A
// first refresh has no copy to compare with.
func accept(o options, list string, entries, inUse int, hasCopy bool) error {
	if err := threatdata.CheckEmpty(list, entries); err != nil {
		return err
	}
	if hasCopy && !o.allowShrink {
		return threatdata.CheckShrink(list, entries, inUse)
	}
	return nil
}

// ---- Spamhaus ----

// refreshSpamhaus checks the three fetched lists against the built-in bundle, prints what changed
// and replaces the bundle as a whole, unless no list is newer.
func refreshSpamhaus(o options, out io.Writer) error {
	var files [3][]byte
	for i, name := range []string{fetchedV4, fetchedV6, fetchedASN} {
		b, err := readFetched(o, name)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		files[i] = b
	}
	prev, hasPrev, err := readBundle(o.spamhaus)
	if err != nil {
		return err
	}
	var down spamhaus.Lists
	if down.V4, err = spamhaus.ParseDrop(files[0], false); err != nil {
		return fmt.Errorf("%s: %w", spamhaus.ListV4, err)
	}
	if down.V6, err = spamhaus.ParseDrop(files[1], true); err != nil {
		return fmt.Errorf("%s: %w", spamhaus.ListV6, err)
	}
	if down.ASNs, err = spamhaus.ParseASNDrop(files[2]); err != nil {
		return fmt.Errorf("%s: %w", spamhaus.ListASN, err)
	}
	// Every list is checked, newer or not (the date here, the format above); one that is not
	// newer is then left as it is, and the empty and shrink rules apply to one that replaces the
	// copy.
	next := prev
	var report strings.Builder
	newer := false
	// replaces says whether the download of a list replaces the built-in copy, and reports a list
	// that does not.
	replaces := func(name string, date, inUse time.Time, entries, was int) (bool, error) {
		if err := threatdata.CheckDate(name, date, o.now); err != nil {
			return false, err
		}
		if hasPrev && !threatdata.Newer(date, inUse) {
			fmt.Fprintf(&report, "%s (%s): not newer than the built-in copy (%s), left as it is\n", name, date.UTC().Format(time.RFC3339), inUse.UTC().Format(time.RFC3339))
			return false, nil
		}
		return true, accept(o, name, entries, was, hasPrev)
	}
	// was is a list's date in the built-in copy, "" when there is none.
	was := func(t time.Time) string {
		if !hasPrev {
			return ""
		}
		return t.UTC().Format(time.RFC3339)
	}
	for _, n := range []struct {
		name string
		down *spamhaus.NetworkList
		prev *spamhaus.NetworkList
		next *spamhaus.NetworkList
	}{{spamhaus.ListV4, &down.V4, &prev.V4, &next.V4}, {spamhaus.ListV6, &down.V6, &prev.V6, &next.V6}} {
		ok, err := replaces(n.name, n.down.Meta.Timestamp, n.prev.Meta.Timestamp, len(n.down.Entries), len(n.prev.Entries))
		if err != nil {
			return err
		}
		if ok {
			newer = true
			*n.next = *n.down
			writeList(&report, n.name, was(n.prev.Meta.Timestamp), n.down.Meta.Updated(), networkEntries(n.prev), networkEntries(n.down), networkFields)
		}
	}
	ok, err := replaces(spamhaus.ListASN, down.ASNs.Meta.Timestamp, prev.ASNs.Meta.Timestamp, len(down.ASNs.Entries), len(prev.ASNs.Entries))
	if err != nil {
		return err
	}
	if ok {
		newer = true
		next.ASNs = down.ASNs
		writeList(&report, spamhaus.ListASN, was(prev.ASNs.Meta.Timestamp), down.ASNs.Meta.Updated(), asnDropEntries(&prev.ASNs), asnDropEntries(&down.ASNs), asnDropFields)
	}
	if newer {
		fmt.Fprintf(&report, "Update docs/abusive-networks.md to give the new Spamhaus dates: %s %s, %s %s, %s %s.\n",
			spamhaus.ListV4, next.V4.Meta.Updated(), spamhaus.ListV6, next.V6.Meta.Updated(), spamhaus.ListASN, next.ASNs.Meta.Updated())
	}
	// The report is printed before the file is replaced, so that every error this returns, a
	// failed print included, leaves the bundle as it was.
	if _, err := io.WriteString(out, report.String()); err != nil {
		return err
	}
	if !newer {
		return nil
	}
	return writeAtomic(o.spamhaus, spamhaus.Bundle(next.V4.Raw, next.V6.Raw, next.ASNs.Raw))
}

// readBundle is the built-in bundle, and whether there is one. A missing file is no copy yet. A
// file that cannot be read is an error, so that a refresh never replaces what it could not
// understand.
func readBundle(path string) (spamhaus.Lists, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return spamhaus.Lists{}, false, nil
	}
	if err != nil {
		return spamhaus.Lists{}, false, fmt.Errorf("reading the built-in bundle: %w", err)
	}
	l, err := spamhaus.ParseBundle(b)
	if err != nil {
		return spamhaus.Lists{}, false, fmt.Errorf("the built-in bundle %s cannot be read: %w", path, err)
	}
	return l, true, nil
}

var (
	networkFields = []string{"rir"}
	asnDropFields = []string{"as_name", "country", "domain", "rir"}
)

// orNone is a field's text, or "none" for a field the list leaves null.
func orNone(s string) string { return cmp.Or(s, "none") }

func networkEntries(l *spamhaus.NetworkList) []entry {
	out := make([]entry, len(l.Entries))
	for i, e := range l.Entries {
		id := e.CIDR.String() + " " + e.SBLID
		out[i] = entry{id: id, fields: []string{orNone(e.RIR)}, line: id + " (" + orNone(e.RIR) + ")"}
	}
	return out
}

func asnDropEntries(l *spamhaus.ASNList) []entry {
	out := make([]entry, len(l.Entries))
	for i, e := range l.Entries {
		id := "AS" + strconv.Itoa(e.ASN)
		f := []string{orNone(e.ASName), orNone(e.Country), orNone(e.Domain), orNone(e.RIR)}
		out[i] = entry{id: id, fields: f, line: fmt.Sprintf("%s %s (%s, %s, %s)", id, f[0], f[1], f[2], f[3])}
	}
	return out
}

// ---- ipapi.is ----

// refreshIpapi checks the two fetched pages against the built-in snapshot, prints what changed and
// replaces the snapshot as a whole, unless no list is newer.
func refreshIpapi(o options, out io.Writer) error {
	netPage, err := readFetched(o, fetchedNetworks)
	if err != nil {
		return fmt.Errorf("%s: %w", fetchedNetworks, err)
	}
	asnPage, err := readFetched(o, fetchedASNs)
	if err != nil {
		return fmt.Errorf("%s: %w", fetchedASNs, err)
	}
	prev, hasPrev, err := readSnapshot(o.ipapi)
	if err != nil {
		return err
	}
	nets, err := abusive.ParseNetworksPage(netPage, o.now)
	if err != nil {
		return fmt.Errorf("networks page: %w", err)
	}
	asns, err := abusive.ParseASNsPage(asnPage, o.now)
	if err != nil {
		return fmt.Errorf("ASNs page: %w", err)
	}
	// ParseNetworksPage and ParseASNsPage apply the future-date rule themselves.
	next := prev
	var report strings.Builder
	newer := false
	for _, l := range []struct {
		name, date, inUse string
		entries, was      int
	}{
		{threatdata.ListNetworks, nets.Updated, prev.Nets.Updated, len(nets.Entries), len(prev.Nets.Entries)},
		{threatdata.ListASNs, asns.Updated, prev.ASNs.Updated, len(asns.Entries), len(prev.ASNs.Entries)},
	} {
		if hasPrev && !dayNewer(l.date, l.inUse) {
			fmt.Fprintf(&report, "%s (%s): not newer than the built-in copy (%s), left as it is\n", l.name, l.date, l.inUse)
			continue
		}
		if err := accept(o, l.name, l.entries, l.was, hasPrev); err != nil {
			return err
		}
		newer = true
		if l.name == threatdata.ListNetworks {
			next.Nets = nets
			writeList(&report, l.name, prev.Nets.Updated, nets.Updated, ipapiNetworks(prev), ipapiNetworks(next), ipapiFields)
		} else {
			next.ASNs = asns
			writeList(&report, l.name, prev.ASNs.Updated, asns.Updated, ipapiASNs(prev), ipapiASNs(next), ipapiFields)
		}
	}
	if !newer {
		_, err := io.WriteString(out, report.String())
		return err
	}
	if err := abusive.Validate(next); err != nil {
		return err
	}
	fmt.Fprintf(&report, "Update docs/abusive-networks.md to give the new ipapi.is dates: networks %s, ASNs %s.\n", next.Nets.Updated, next.ASNs.Updated)
	// The report is printed before the file is replaced, so that every error this returns, a
	// failed print included, leaves the snapshot as it was.
	if _, err := io.WriteString(out, report.String()); err != nil {
		return err
	}
	return writeAtomic(o.ipapi, abusive.Marshal(next))
}

// dayNewer reports whether the list dated date (YYYY-MM-DD) replaces the one dated inUse, which
// is "" when the snapshot has none.
func dayNewer(date, inUse string) bool {
	if inUse == "" {
		return true
	}
	d, err1 := time.Parse(time.DateOnly, date)
	u, err2 := time.Parse(time.DateOnly, inUse)
	return err1 != nil || err2 != nil || threatdata.Newer(d, u)
}

// readSnapshot is the built-in snapshot, and whether there is one. A missing file is no copy yet.
// A file that cannot be read is an error, so that a refresh never replaces what it could not
// understand.
func readSnapshot(path string) (abusive.Snapshot, bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return abusive.Snapshot{}, false, nil
	}
	if err != nil {
		return abusive.Snapshot{}, false, fmt.Errorf("reading the built-in snapshot: %w", err)
	}
	s, err := abusive.Parse(b)
	if err != nil {
		return abusive.Snapshot{}, false, fmt.Errorf("the built-in snapshot %s cannot be read: %w", path, err)
	}
	return s, true, nil
}

// ipapiFields name the fields a change of an ipapi.is entry is reported in. The rank is left out,
// so a rank that alone moved is no change.
var ipapiFields = []string{"score_tag", "abuse_score", "org", "org_type"}

func ipapiNetworks(s abusive.Snapshot) []entry {
	out := make([]entry, len(s.Nets.Entries))
	for i, e := range s.Nets.Entries {
		out[i] = ipapiEntry(input.RangeText(e.Start, e.End), e.ScoreTag, e.AbuseScore, e.Org, e.OrgType)
	}
	return out
}

func ipapiASNs(s abusive.Snapshot) []entry {
	out := make([]entry, len(s.ASNs.Entries))
	for i, e := range s.ASNs.Entries {
		out[i] = ipapiEntry("AS"+strconv.Itoa(e.ASN), e.ScoreTag, e.AbuseScore, e.Org, e.OrgType)
	}
	return out
}

func ipapiEntry(id, tag string, score float64, org, typ string) entry {
	s := abusive.ScoreText(score)
	return entry{id: id, fields: []string{tag, s, org, typ}, line: fmt.Sprintf("%s: %s %s%% %s (%s)", id, tag, s, org, typ)}
}

// ---- the summary ----

// entry is one entry of a list as the summary compares and prints it: the key that identifies
// it, the fields a change is reported in, and the line to print when it is added or removed.
type entry struct {
	id     string
	fields []string
	line   string
}

// diff lists what was added, removed and changed, each as the line the summary prints, in the
// order of the lists. names name the fields of an entry.
func diff(before, after []entry, names []string) (added, removed, changed []string) {
	byID := func(es []entry) map[string]entry {
		m := make(map[string]entry, len(es))
		for _, e := range es {
			m[e.id] = e
		}
		return m
	}
	prev, cur := byID(before), byID(after)
	for _, e := range after {
		p, ok := prev[e.id]
		switch {
		case !ok:
			added = append(added, e.line)
		case !slices.Equal(p.fields, e.fields):
			var parts []string
			for i, name := range names {
				if p.fields[i] != e.fields[i] {
					parts = append(parts, fmt.Sprintf("%s: %s -> %s", name, p.fields[i], e.fields[i]))
				}
			}
			changed = append(changed, e.id+": "+strings.Join(parts, "; "))
		}
	}
	for _, e := range before {
		if _, ok := cur[e.id]; !ok {
			removed = append(removed, e.line)
		}
	}
	return added, removed, changed
}

// writeList prints what changed in one list under a heading that names its dates.
func writeList(b *strings.Builder, name, was, now string, before, after []entry, fields []string) {
	added, removed, changed := diff(before, after, fields)
	dates := now
	if was != now {
		dates = cmp.Or(was, "none") + " -> " + now
	}
	if len(added)+len(removed)+len(changed) == 0 {
		fmt.Fprintf(b, "%s (%s): no entries changed\n", name, dates)
		return
	}
	fmt.Fprintf(b, "%s (%s): %d added, %d removed, %d changed\n", name, dates, len(added), len(removed), len(changed))
	for _, g := range []struct {
		what  string
		lines []string
	}{{"added", added}, {"removed", removed}, {"changed", changed}} {
		for _, l := range g.lines {
			fmt.Fprintf(b, "  %s: %s\n", g.what, l)
		}
	}
}
