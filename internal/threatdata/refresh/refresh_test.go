package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
)

// Fix time at 2026-11-21 noon UTC to match HTML fixtures and keep tests independent of real
// time or embedded refreshes.
var now = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

var (
	// oldTS/newTS anchor original and newer-download timestamps.
	oldTS = time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	newTS = time.Date(2026, 11, 20, 9, 56, 44, 0, time.UTC)
	// endOfTomorrow is 00:00 UTC two days from now: a Spamhaus list dated at it or later is in the
	// future.
	endOfTomorrow = time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
)

// The names of the files the tool reads from -dir, as make threat-data fetches them.
const (
	fileV4       = "drop_v4.json"
	fileV6       = "drop_v6.json"
	fileASN      = "asndrop.json"
	fileNetworks = "networks.html"
	fileASNs     = "asns.html"
)

// ---- Spamhaus files ----

// metaLine is a Spamhaus metadata line: the list's date, its record count and the credit, plus
// extra fields (`,"k":"v"`) when given.
func metaLine(ts time.Time, records, size int, extra string) string {
	return fmt.Sprintf(`{"type":"metadata","timestamp":%d,"size":%d,"records":%d,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"%s}`,
		ts.Unix(), size, records, extra)
}

// spamhausFile writes one source row per line followed by metadata.
func spamhausFile(rows []string, ts time.Time, records int) []byte {
	return spamhausFileMeta(rows, func(size int) string { return metaLine(ts, records, size, "") })
}

func spamhausFileMeta(rows []string, meta func(size int) string) []byte {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	size := b.Len()
	b.WriteString(meta(size) + "\n")
	return []byte(b.String())
}

// list is a list whose metadata counts its rows.
func list(rows []string, ts time.Time) []byte { return spamhausFile(rows, ts, len(rows)) }

// v4Rows are n DROP rows, numbered from base, so that two calls with different bases list
// different entries.
func v4Rows(n, base int) []string {
	out := make([]string, n)
	for i := range n {
		k := base + i
		out[i] = fmt.Sprintf(`{"cidr":"10.%d.%d.0/24","sblid":"SBL%d","rir":"ripencc"}`, k/256, k%256, 1000+k)
	}
	return out
}

func v6Rows(n, base int) []string {
	out := make([]string, n)
	for i := range n {
		k := base + i
		out[i] = fmt.Sprintf(`{"cidr":"2001:db8:%x::/48","sblid":"SBL%d","rir":"apnic"}`, k, 2000+k)
	}
	return out
}

func asnRows(n, base int) []string {
	out := make([]string, n)
	for i := range n {
		k := base + i
		out[i] = fmt.Sprintf(`{"asn":%d,"rir":"arin","domain":"d%d.example","cc":"US","asname":"AS-NAME-%d"}`, 64500+k, k, k)
	}
	return out
}

// bundle preserves fixed marker order and source bytes.
func bundle(v4, v6, asn []byte) []byte {
	var b bytes.Buffer
	for _, l := range []struct {
		name string
		body []byte
	}{{"drop_v4", v4}, {"drop_v6", v6}, {"asndrop", asn}} {
		fmt.Fprintf(&b, "{\"list\":%q}\n", l.name)
		b.Write(l.body)
		if len(l.body) > 0 && l.body[len(l.body)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

// withRow is rows with row i replaced.
func withRow(rows []string, i int, row string) []string {
	out := slices.Clone(rows)
	out[i] = row
	return out
}

// ---- ipapi.is pages and snapshots ----

// page reads one of the ipapi.is test pages, which the abusive package's tests share.
func page(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "abusive", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// replaceOnce changes the first occurrence of old in s, and fails the test when there is none.
func replaceOnce(t *testing.T, s []byte, old, repl string) []byte {
	t.Helper()
	if !bytes.Contains(s, []byte(old)) {
		t.Fatalf("the page has no %q", old)
	}
	return bytes.Replace(s, []byte(old), []byte(repl), 1)
}

// headerOrg selects the source's organisation-column spelling.
const headerOrg = "Organization" //nolint:misspell // the page's own spelling

// generated is a networks page that states stated entries and lists rows of them.
func generated(date string, stated, rows int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><span>Data last updated on <strong>%s</strong></span><p>The table lists the <strong>%d</strong> most abusive networks on the Internet.</p>`, formatDate(date), stated)
	b.WriteString(`<table><thead><tr><th>Rank</th><th>Network</th><th>Num Hosts</th><th>Score Tag</th><th>Abuse Score</th><th>` + headerOrg + `</th><th>Type</th></tr></thead><tbody>`)
	for i := range rows {
		fmt.Fprintf(&b, `<tr><td>%d</td><td><a>10.%d.%d.0 - 10.%d.%d.255</a></td><td>256</td><td><span>High</span></td><td>50%%</td><td>Org %d</td><td><span>isp</span></td></tr>`,
			i+1, i/200, i%200, i/200, i%200, i)
	}
	b.WriteString(`</tbody></table></body></html>`)
	return []byte(b.String())
}

func generatedASNs(date string, stated, rows int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><span>Data last updated on <strong>%s</strong></span><p>The table lists the <strong>%d</strong> most abusive ASNs.</p>`, formatDate(date), stated)
	b.WriteString(`<table><thead><tr><th>Rank</th><th>ASN</th><th>Num IPs and Routes</th><th>Score Tag</th><th>Abuse Score</th><th>` + headerOrg + `</th><th>Org Type</th></tr></thead><tbody>`)
	for i := range rows {
		fmt.Fprintf(&b, `<tr><td>%d</td><td><a>as%d</a></td><td>1</td><td><span>High</span></td><td>50%%</td><td>Org %d</td><td><span>isp</span></td></tr>`, i+1, 64000+i, i)
	}
	b.WriteString(`</tbody></table></body></html>`)
	return []byte(b.String())
}

func formatDate(d string) string {
	t, _ := time.Parse(time.DateOnly, d)
	return t.Format("January 2, 2006")
}

// snapshot is a valid built-in ipapi.is snapshot with nets network entries and asns ASN entries,
// none of them on the testdata pages.
func snapshot(netsDate, asnsDate string, nets, asns int) abusive.Snapshot {
	s := abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: netsDate, Stated: nets, Entries: []abusive.NetworkEntry{}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: asnsDate, Stated: asns, Entries: []abusive.ASNEntry{}},
	}
	for i := range nets {
		s.Nets.Entries = append(s.Nets.Entries, abusive.NetworkEntry{Rank: i + 1,
			Start: netip.MustParseAddr(fmt.Sprintf("172.16.%d.0", i)), End: netip.MustParseAddr(fmt.Sprintf("172.16.%d.255", i)),
			ScoreTag: "High", AbuseScore: 50, Org: fmt.Sprintf("Old Org %d", i), OrgType: "isp"})
	}
	slices.SortFunc(s.Nets.Entries, abusive.CompareNetworks)
	for i := range asns {
		s.ASNs.Entries = append(s.ASNs.Entries, abusive.ASNEntry{Rank: i + 1, ASN: 65000 + i, ScoreTag: "High", AbuseScore: 50,
			Org: fmt.Sprintf("Old AS %d", i), OrgType: "isp"})
	}
	return s
}

// ---- the world ----

// world is one refresh: a directory of fetched files, and a repository directory with the two
// built-in copies the tool replaces.
type world struct {
	t         *testing.T
	dir, repo string
	fetched   map[string][]byte // by file name; a name that is not here is not written
	// spamhaus/ipapi retain current file bytes across runs; nil represents an absent file.
	spamhaus, ipapi []byte
	allowShrink     bool

	// inUseV4, inUseV6 and inUseASN are the Spamhaus lists the built-in bundle was made of.
	inUseV4, inUseV6, inUseASN []byte
}

// newWorld supplies older built-ins and newer shifted downloads for all lists, including
// source-page fixtures for ipapi.is.
func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, dir: t.TempDir(), repo: t.TempDir()}
	w.inUseV4, w.inUseV6, w.inUseASN = list(v4Rows(40, 0), oldTS), list(v6Rows(20, 0), oldTS), list(asnRows(30, 0), oldTS)
	w.spamhaus = bundle(w.inUseV4, w.inUseV6, w.inUseASN)
	w.ipapi = abusive.Marshal(snapshot("2026-11-19", "2026-11-19", 16, 4))
	w.fetched = map[string][]byte{
		fileV4:       list(v4Rows(40, 5), newTS),
		fileV6:       list(v6Rows(20, 5), newTS),
		fileASN:      list(asnRows(30, 5), newTS),
		fileNetworks: page(t, "networks.html"),
		fileASNs:     page(t, "asns.html"),
	}
	return w
}

func (w *world) spamhausPath() string { return filepath.Join(w.repo, "builtin.jsonl") }
func (w *world) ipapiPath() string    { return filepath.Join(w.repo, "snapshot.json") }

// fetchedBundle is the bundle of the three fetched Spamhaus files.
func (w *world) fetchedBundle() []byte {
	return bundle(w.fetched[fileV4], w.fetched[fileV6], w.fetched[fileASN])
}

type result struct {
	code           int
	stdout, stderr string
}

func (w *world) args() []string {
	args := []string{"-dir", w.dir, "-spamhaus", w.spamhausPath(), "-ipapi", w.ipapiPath()}
	if w.allowShrink {
		args = append(args, "-allow-shrink")
	}
	return args
}

// run writes the fetched files and the built-in copies and refreshes. Afterwards spamhaus and
// ipapi hold what the files hold.
func (w *world) run() result {
	w.t.Helper()
	return w.runArgs(w.args())
}

func (w *world) runArgs(args []string) result {
	w.t.Helper()
	for _, name := range []string{fileV4, fileV6, fileASN, fileNetworks, fileASNs} {
		path := filepath.Join(w.dir, name)
		body, ok := w.fetched[name]
		if !ok {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				w.t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			w.t.Fatal(err)
		}
	}
	for path, body := range map[string][]byte{w.spamhausPath(): w.spamhaus, w.ipapiPath(): w.ipapi} {
		if body == nil {
			continue
		}
		if err := os.WriteFile(path, body, 0o644); err != nil { //nolint:gosec // the built-in copies are source, read by everyone
			w.t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr, now)
	w.spamhaus, w.ipapi = w.read(w.spamhausPath()), w.read(w.ipapiPath())
	w.noTemporaryFiles()
	return result{code, stdout.String(), stderr.String()}
}

func (w *world) read(path string) []byte {
	w.t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

// noTemporaryFiles allows only the two completed source files in the fixture repository.
func (w *world) noTemporaryFiles() {
	w.t.Helper()
	es, err := os.ReadDir(w.repo)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, e := range es {
		if e.Name() != "builtin.jsonl" && e.Name() != "snapshot.json" {
			w.t.Errorf("the directory of the built-in copies holds %s after the refresh", e.Name())
		}
	}
}

// mode is the permission bits of the file at path.
func (w *world) mode(path string) os.FileMode {
	w.t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		w.t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// parsedIpapi is the ipapi.is snapshot the file now holds, which must be valid.
func (w *world) parsedIpapi() abusive.Snapshot {
	w.t.Helper()
	if w.ipapi == nil {
		w.t.Fatal("there is no ipapi.is snapshot file")
	}
	s, err := abusive.Parse(w.ipapi)
	if err != nil {
		w.t.Fatalf("the ipapi.is snapshot written does not parse: %v", err)
	}
	if err := abusive.Validate(s); err != nil {
		w.t.Fatalf("the ipapi.is snapshot written is not valid: %v", err)
	}
	return s
}

// wantPagesWritten checks unchanged source-page dates and actual/stated counts.
func (w *world) wantPagesWritten() {
	w.t.Helper()
	s := w.parsedIpapi()
	if s.Nets.Updated != "2026-11-21" || s.ASNs.Updated != "2026-11-21" {
		w.t.Errorf("the ipapi.is snapshot is dated %q and %q, want both 2026-11-21 (the pages')", s.Nets.Updated, s.ASNs.Updated)
	}
	if len(s.Nets.Entries) != 10 || len(s.ASNs.Entries) != 4 {
		w.t.Errorf("the ipapi.is snapshot has %d network and %d ASN entries, want the pages' 10 and 4", len(s.Nets.Entries), len(s.ASNs.Entries))
	}
	if s.Nets.Stated != 10 || s.ASNs.Stated != 4 {
		w.t.Errorf("the ipapi.is snapshot states %d and %d entries, want the pages' 10 and 4", s.Nets.Stated, s.ASNs.Stated)
	}
}

// wantSpamhausWritten checks that the bundle is want, byte for byte.
func (w *world) wantSpamhausWritten(want []byte) {
	w.t.Helper()
	if !bytes.Equal(w.spamhaus, want) {
		w.t.Errorf("the Spamhaus bundle written is not the one expected:\n got %.300q\nwant %.300q", w.spamhaus, want)
	}
}

// ---- the tests ----

// Newer downloads replace both source copies while preserving Spamhaus source bytes exactly.
func TestRefresh_WritesBothSources(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	r := w.run()
	if r.code != 0 {
		t.Fatalf("exit %d, want 0; stderr:\n%s", r.code, r.stderr)
	}
	w.wantSpamhausWritten(w.fetchedBundle())
	w.wantPagesWritten()
}

// The first refresh, with no built-in copy yet, writes both, as the tool always has.
func TestRefresh_WritesBothSourcesWhenThereIsNoCopyYet(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.spamhaus, w.ipapi = nil, nil
	r := w.run()
	if r.code != 0 {
		t.Fatalf("exit %d, want 0; stderr:\n%s", r.code, r.stderr)
	}
	w.wantSpamhausWritten(w.fetchedBundle())
	w.wantPagesWritten()
}

// refusal is a download the shared acceptance rules refuse, failing its source.
type refusal struct {
	name   string
	source string // the source that fails: "spamhaus" or "ipapi.is"
	mod    func(w *world)
	// shrink is true for a list refused only for holding fewer than half the entries of the
	// built-in copy, which -allow-shrink lets through.
	shrink bool
	words  []string // whole words the error gives, besides the source's name
}

func refusals() []refusal {
	return []refusal{
		{name: "a row that is not JSON", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV4] = list(withRow(v4Rows(40, 5), 3, `{"cidr":"10.9.9.0/24","sblid":`), newTS)
		}},
		{name: "a row with no cidr", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV4] = list(withRow(v4Rows(40, 5), 3, `{"sblid":"SBL9999","rir":"apnic"}`), newTS)
		}},
		{name: "a row with no sblid", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV6] = list(withRow(v6Rows(20, 5), 2, `{"cidr":"2001:db8:ffff::/48","rir":"apnic"}`), newTS)
		}},
		{name: "a row with no asn", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileASN] = list(withRow(asnRows(30, 5), 1, `{"rir":"arin","domain":"x.example","cc":"US","asname":"X"}`), newTS)
		}},
		{name: "a CIDR that is not canonical", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV4] = list(withRow(v4Rows(40, 5), 0, `{"cidr":"10.200.0.1/24","sblid":"SBL9999","rir":"apnic"}`), newTS)
		}},
		{name: "an IPv6 CIDR in DROP", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV4] = list(withRow(v4Rows(40, 5), 0, `{"cidr":"2001:db8:ffff::/48","sblid":"SBL9999","rir":"apnic"}`), newTS)
		}},
		{name: "an IPv4 CIDR in DROPv6", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV6] = list(withRow(v6Rows(20, 5), 0, `{"cidr":"10.200.0.0/24","sblid":"SBL9999","rir":"apnic"}`), newTS)
		}},
		{name: "a control character in a row", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileASN] = list(withRow(asnRows(30, 5), 0, `{"asn":64999,"rir":"arin","domain":"x.example","cc":"US","asname":"BAD\u0007AS"}`), newTS)
		}},
		{name: "a control character in the metadata", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV4] = spamhausFileMeta(v4Rows(40, 5), func(size int) string {
				return fmt.Sprintf(`{"type":"metadata","timestamp":%d,"size":%d,"records":40,"copyright":"(c) 2026 The Spamhaus\u001b[31m Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}`, newTS.Unix(), size)
			})
		}},
		{name: "an identical pair twice", source: "spamhaus", mod: func(w *world) {
			rows := v4Rows(40, 5)
			w.fetched[fileV4] = list(append(rows, rows[7]), newTS)
		}},
		{name: "an ASN twice", source: "spamhaus", mod: func(w *world) {
			rows := asnRows(30, 5)
			w.fetched[fileASN] = list(append(rows, rows[4]), newTS)
		}},
		{name: "no metadata line", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV6] = []byte(strings.Join(v6Rows(20, 5), "\n") + "\n")
		}},
		{name: "89% of the records", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV4] = spamhausFile(v4Rows(89, 5), newTS, 100)
		}},
		{name: "no entries", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV4] = spamhausFile(nil, newTS, 0)
		}},
		{name: "fewer than half the built-in copy's entries", source: "spamhaus", shrink: true, words: []string{"19", "40"},
			mod: func(w *world) { w.fetched[fileV4] = list(v4Rows(19, 5), newTS) }},
		{name: "dated at the end of tomorrow", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileASN] = list(asnRows(30, 5), endOfTomorrow)
		}},
		{name: "a malformed list that is not newer", source: "spamhaus", mod: func(w *world) {
			w.fetched[fileV6] = list(withRow(v6Rows(20, 5), 2, `{"sblid":"SBL9999","rir":"apnic"}`), oldTS.Add(-time.Hour))
		}},
		{name: "a fetched file that is missing", source: "spamhaus", mod: func(w *world) {
			delete(w.fetched, fileV6)
		}},
		{name: "a built-in copy that cannot be read", source: "spamhaus", mod: func(w *world) {
			w.spamhaus = []byte("not a bundle\n")
		}},

		{name: "a page that does not parse", source: "ipapi.is", mod: func(w *world) {
			w.fetched[fileNetworks] = replaceOnce(w.t, w.fetched[fileNetworks], "<th>Network</th>", "<th>Net</th>")
		}},
		{name: "89% of the stated count", source: "ipapi.is", mod: func(w *world) {
			w.fetched[fileNetworks] = generated("2026-11-21", 100, 89)
		}},
		{name: "a page with no rows", source: "ipapi.is", mod: func(w *world) {
			w.fetched[fileASNs] = generatedASNs("2026-11-21", 4, 0)
		}},
		{name: "a page with fewer than half the built-in copy's entries", source: "ipapi.is", shrink: true, words: []string{"7", "16"},
			mod: func(w *world) { w.fetched[fileNetworks] = generated("2026-11-21", 7, 7) }},
		{name: "a control character in a page", source: "ipapi.is", mod: func(w *world) {
			w.fetched[fileNetworks] = replaceOnce(w.t, w.fetched[fileNetworks], "Proton66 OOO", "Proton\x0166 OOO")
		}},
		{name: "a network twice", source: "ipapi.is", mod: func(w *world) {
			w.fetched[fileNetworks] = replaceOnce(w.t, w.fetched[fileNetworks], "37.77.150.0 - 37.77.150.255", "34.68.34.64 - 34.68.34.95")
		}},
		{name: "an ASN twice on its page", source: "ipapi.is", mod: func(w *world) {
			w.fetched[fileASNs] = replaceOnce(w.t, w.fetched[fileASNs], ">as152194<", ">as64050<")
		}},
		{name: "a page dated the day after tomorrow", source: "ipapi.is", mod: func(w *world) {
			w.fetched[fileNetworks] = replaceOnce(w.t, w.fetched[fileNetworks], "November 21, 2026", "November 23, 2026")
		}},
		{name: "a fetched page that is missing", source: "ipapi.is", mod: func(w *world) {
			delete(w.fetched, fileASNs)
		}},
		{name: "a built-in snapshot that cannot be read", source: "ipapi.is", mod: func(w *world) {
			w.ipapi = []byte("not json")
		}},
	}
}

// Refresh shares runtime rejection rules and preserves failed sources while updating others.
// allow-shrink bypasses only size rejection.
func TestRefresh_Refusals(t *testing.T) { // mutation target
	t.Parallel()
	for _, tc := range refusals() {
		for _, allow := range []bool{false, true} {
			name := tc.name
			if allow {
				name += " with -allow-shrink"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				checkRefusal(t, tc, allow)
			})
		}
	}
}

// checkRefusal runs one refusal, with or without -allow-shrink.
func checkRefusal(t *testing.T, tc refusal, allow bool) {
	t.Helper()
	w := newWorld(t)
	w.allowShrink = allow
	tc.mod(w)
	failedPath := w.spamhausPath()
	if tc.source == "ipapi.is" {
		failedPath = w.ipapiPath()
	}
	before := w.spamhaus
	if tc.source == "ipapi.is" {
		before = w.ipapi
	}
	wantSpamhaus := w.fetchedBundle()
	r := w.run()
	if allow && tc.shrink {
		if r.code != 0 {
			t.Fatalf("exit %d, want 0: -allow-shrink lets a shrunken list through; stderr:\n%s", r.code, r.stderr)
		}
		if after := w.read(failedPath); bytes.Equal(after, before) {
			t.Errorf("the %s copy was not replaced", tc.source)
		}
		if tc.source == "spamhaus" {
			w.wantSpamhausWritten(wantSpamhaus)
		} else {
			if s := w.parsedIpapi(); len(s.Nets.Entries) != 7 {
				t.Errorf("the snapshot has %d network entries, want the page's 7", len(s.Nets.Entries))
			}
		}
		return
	}
	if r.code != 1 {
		t.Fatalf("exit %d, want 1; stdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
	}
	lower := strings.ToLower(r.stderr)
	if !strings.Contains(lower, tc.source) {
		t.Errorf("stderr does not name the failed source %s:\n%s", tc.source, r.stderr)
	}
	for _, word := range tc.words {
		if !regexp.MustCompile(`\b` + regexp.QuoteMeta(word) + `\b`).MatchString(r.stderr) {
			t.Errorf("the error does not give the count %s:\n%s", word, r.stderr)
		}
	}
	if after := w.read(failedPath); !bytes.Equal(after, before) {
		t.Errorf("the %s copy changed:\n got %.200q\nwant %.200q", tc.source, after, before)
	}
	if m := w.mode(failedPath); m != 0o644 {
		t.Errorf("the %s copy's mode is %v, want it unchanged (0644)", tc.source, m)
	}
	if tc.source == "spamhaus" {
		w.wantPagesWritten()
	} else {
		w.wantSpamhausWritten(wantSpamhaus)
	}
}

// Exercise valid boundaries and tolerated variations: unknown fields, distinct SBL IDs, 90%
// completeness, half-size lists, missing RIR and tomorrow's dates.
func TestRefresh_Accepts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		mod  func(w *world)
	}{
		{"an unknown field in a row and in the metadata", func(w *world) {
			rows := v4Rows(40, 5)
			rows[0] = strings.TrimSuffix(rows[0], "}") + `,"extra":"x"}`
			w.fetched[fileV4] = spamhausFileMeta(rows, func(size int) string { return metaLine(newTS, 40, size, `,"note":"x"`) })
		}},
		{"one CIDR under two SBL IDs", func(w *world) {
			w.fetched[fileV4] = list(append(v4Rows(40, 5),
				`{"cidr":"62.60.226.0/24","sblid":"SBL697779","rir":"ripencc"}`,
				`{"cidr":"62.60.226.0/24","sblid":"SBL671779","rir":"ripencc"}`), newTS)
		}},
		{"90% of the records", func(w *world) { w.fetched[fileV4] = spamhausFile(v4Rows(90, 5), newTS, 100) }},
		{"exactly half the built-in copy's entries", func(w *world) { w.fetched[fileV4] = list(v4Rows(20, 5), newTS) }},
		{"a null RIR", func(w *world) {
			w.fetched[fileV4] = list(withRow(v4Rows(40, 5), 0, `{"cidr":"10.0.5.0/24","sblid":"SBL1005","rir":null}`), newTS)
		}},
		{"a list dated just before the end of tomorrow", func(w *world) {
			w.fetched[fileASN] = list(asnRows(30, 5), endOfTomorrow.Add(-time.Second))
		}},
		{"a page dated tomorrow", func(w *world) {
			w.fetched[fileNetworks] = replaceOnce(w.t, w.fetched[fileNetworks], "November 21, 2026", "November 22, 2026")
		}},
		{"a page with exactly half the built-in copy's entries", func(w *world) {
			w.fetched[fileNetworks] = generated("2026-11-21", 8, 8)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			tc.mod(w)
			beforeIpapi := w.ipapi
			want := w.fetchedBundle()
			r := w.run()
			if r.code != 0 {
				t.Fatalf("exit %d, want 0; stderr:\n%s", r.code, r.stderr)
			}
			w.wantSpamhausWritten(want)
			w.parsedIpapi()
			if bytes.Equal(w.ipapi, beforeIpapi) {
				t.Error("the ipapi.is snapshot was not replaced")
			}
		})
	}
}

// Leave older/equal lists unchanged, including within partially updated bundles. Shrink
// comparisons apply only to replacements.
func TestRefresh_LeavesAListThatIsNotNewer(t *testing.T) {
	t.Parallel()
	t.Run("no Spamhaus list is newer", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		w.fetched[fileV4] = w.inUseV4                                     // the same file
		w.fetched[fileV6] = list(v6Rows(20, 9), oldTS)                    // the same date, other entries
		w.fetched[fileASN] = list(asnRows(3, 9), oldTS.Add(-time.Second)) // older, and fewer than half
		before := w.spamhaus
		r := w.run()
		if r.code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", r.code, r.stderr)
		}
		if !bytes.Equal(w.spamhaus, before) {
			t.Error("the Spamhaus bundle changed, though no list was newer")
		}
		if strings.Contains(r.stdout, "2001:db8:1c::") {
			t.Errorf("the output lists an entry of a list that was left as it is:\n%s", r.stdout)
		}
		w.wantPagesWritten()
	})
	t.Run("one Spamhaus list of three is newer", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		w.fetched[fileV6] = list(v6Rows(20, 9), oldTS)
		w.fetched[fileASN] = list(asnRows(3, 9), oldTS.Add(-time.Hour))
		r := w.run()
		if r.code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", r.code, r.stderr)
		}
		w.wantSpamhausWritten(bundle(w.fetched[fileV4], w.inUseV6, w.inUseASN))
		for _, entry := range []string{"2001:db8:1c::", "AS-NAME-11"} {
			if strings.Contains(r.stdout, entry) {
				t.Errorf("the output lists %s, of a list that was left as it is:\n%s", entry, r.stdout)
			}
		}
		w.wantPagesWritten()
	})
	t.Run("no ipapi.is list is newer", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		w.ipapi = abusive.Marshal(snapshot("2026-11-21", "2026-11-21", 16, 4)) // the pages' date
		before := w.ipapi
		r := w.run()
		if r.code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", r.code, r.stderr)
		}
		if !bytes.Equal(w.ipapi, before) {
			t.Error("the ipapi.is snapshot changed, though no list was newer")
		}
		w.wantSpamhausWritten(w.fetchedBundle())
	})
	t.Run("one ipapi.is list of two is newer", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		// The ASNs list built in is dated after the page, and would be refused for shrinking.
		old := snapshot("2026-11-20", "2026-11-22", 16, 9)
		w.ipapi = abusive.Marshal(old)
		r := w.run()
		if r.code != 0 {
			t.Fatalf("exit %d, want 0; stderr:\n%s", r.code, r.stderr)
		}
		s := w.parsedIpapi()
		if s.Nets.Updated != "2026-11-21" || len(s.Nets.Entries) != 10 {
			t.Errorf("networks = %s with %d entries, want the page's 2026-11-21 and 10", s.Nets.Updated, len(s.Nets.Entries))
		}
		if s.ASNs.Updated != old.ASNs.Updated || !slices.Equal(s.ASNs.Entries, old.ASNs.Entries) {
			t.Errorf("ASNs = %s with %d entries, want the built-in list kept as it was (%s, %d entries)",
				s.ASNs.Updated, len(s.ASNs.Entries), old.ASNs.Updated, len(old.ASNs.Entries))
		}
		w.wantSpamhausWritten(w.fetchedBundle())
	})
}

// A second refresh of the same downloads finds nothing newer and changes neither file.
func TestRefresh_Idempotent(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	if r := w.run(); r.code != 0 {
		t.Fatalf("the first refresh: exit %d; stderr:\n%s", r.code, r.stderr)
	}
	w.wantSpamhausWritten(w.fetchedBundle())
	w.wantPagesWritten()
	spamhaus, ipapi := w.spamhaus, w.ipapi
	if r := w.run(); r.code != 0 {
		t.Fatalf("the second refresh: exit %d; stderr:\n%s", r.code, r.stderr)
	}
	if !bytes.Equal(w.spamhaus, spamhaus) || !bytes.Equal(w.ipapi, ipapi) {
		t.Error("the second refresh changed a file")
	}
}

// kindOf finds one entry's added/removed/changed category and rejects duplicate appearances.
func kindOf(t *testing.T, out, id string) (kind, line string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	found := -1
	for i, l := range lines {
		if strings.Contains(l, id) {
			if found >= 0 {
				t.Errorf("the output names %s more than once:\n%s", id, out)
			}
			found = i
		}
	}
	if found < 0 {
		return "", ""
	}
	last := func(s string) string {
		best, at := "", -1
		for _, w := range []string{"added", "removed", "changed"} {
			if i := strings.LastIndex(strings.ToLower(s), w); i > at {
				best, at = w, i
			}
		}
		return best
	}
	l := lines[found]
	if before, _, _ := strings.Cut(l, id); last(before) != "" {
		return last(before), l
	}
	for i := found - 1; i >= 0; i-- {
		if k := last(lines[i]); k != "" {
			return k, l
		}
	}
	return "", l
}

// Change reports compare DROP by CIDR/SBL and RIR, ASN-DROP by ASN and metadata, omitting
// unchanged/older lists.
func TestRefresh_SpamhausSummary(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.inUseV4 = list([]string{
		`{"cidr":"10.0.0.0/24","sblid":"SBL1","rir":"ripencc"}`,
		`{"cidr":"10.0.1.0/24","sblid":"SBL2","rir":"apnic"}`,
		`{"cidr":"10.0.2.0/24","sblid":"SBL3","rir":"arin"}`,
		`{"cidr":"62.60.226.0/24","sblid":"SBL697779","rir":"ripencc"}`,
		`{"cidr":"10.0.4.0/24","sblid":"SBL5","rir":null}`,
	}, oldTS)
	w.inUseASN = list([]string{
		`{"asn":64500,"rir":"ripencc","domain":"bad.example","cc":"RU","asname":"BAD-AS"}`,
		`{"asn":64501,"rir":"arin","domain":"other.example","cc":"US","asname":"OTHER-AS"}`,
		`{"asn":64502,"rir":"ripencc","domain":"gone.example","cc":"NL","asname":"GONE-AS"}`,
		`{"asn":64504,"rir":"ripencc","domain":"same.example","cc":"DE","asname":"SAME-AS"}`,
	}, oldTS)
	w.spamhaus = bundle(w.inUseV4, w.inUseV6, w.inUseASN)
	w.ipapi = abusive.Marshal(snapshot("2026-11-21", "2026-11-21", 16, 4)) // not newer, so not listed
	w.fetched[fileV4] = list([]string{
		`{"cidr":"10.0.0.0/24","sblid":"SBL1","rir":"ripencc"}`,
		`{"cidr":"10.0.1.0/24","sblid":"SBL2","rir":"arin"}`,
		`{"cidr":"62.60.226.0/24","sblid":"SBL697779","rir":"ripencc"}`,
		`{"cidr":"62.60.226.0/24","sblid":"SBL671779","rir":"ripencc"}`,
		`{"cidr":"10.0.3.0/24","sblid":"SBL3","rir":"arin"}`,
		`{"cidr":"10.0.4.0/24","sblid":"SBL5","rir":"lacnic"}`,
	}, newTS)
	w.fetched[fileV6] = w.inUseV6 // not newer
	w.fetched[fileASN] = list([]string{
		`{"asn":64500,"rir":"ripencc","domain":"bad.example","cc":"RU","asname":"WORSE-AS"}`,
		`{"asn":64501,"rir":"arin","domain":"moved.example","cc":"US","asname":"OTHER-AS"}`,
		`{"asn":64503,"rir":"lacnic","domain":"new.example","cc":"BR","asname":"NEW-AS"}`,
		`{"asn":64504,"rir":"ripencc","domain":"same.example","cc":"DE","asname":"SAME-AS"}`,
	}, newTS)
	r := w.run()
	if r.code != 0 {
		t.Fatalf("exit %d, want 0; stderr:\n%s", r.code, r.stderr)
	}
	w.wantSpamhausWritten(w.fetchedBundle())
	out := r.stdout
	for _, tc := range []struct {
		id, kind string
		also     []string // on the entry's line
	}{
		{"62.60.226.0/24 SBL671779", "added", nil}, // one CIDR under a second SBL ID is a new entry
		{"10.0.3.0/24", "added", []string{"SBL3"}},
		{"10.0.2.0/24", "removed", []string{"SBL3"}},
		{"10.0.1.0/24", "changed", []string{"SBL2", "apnic", "arin"}},
		{"10.0.4.0/24", "changed", []string{"SBL5", "lacnic"}},
		{"64500", "changed", []string{"BAD-AS", "WORSE-AS"}},
		{"64501", "changed", []string{"other.example", "moved.example"}},
		{"64503", "added", nil},
		{"64502", "removed", nil},
	} {
		id := tc.id
		if strings.Contains(id, " ") {
			// The CIDR and the SBL ID may be written apart: find the line that has both.
			cidr, sbl, _ := strings.Cut(id, " ")
			found := false
			for l := range strings.SplitSeq(out, "\n") {
				if strings.Contains(l, cidr) && strings.Contains(l, sbl) {
					found = true
					if k, _ := kindOf(t, l, sbl); k != tc.kind {
						t.Errorf("%s is %q, want %s:\n%s", id, k, tc.kind, out)
					}
				}
			}
			if !found {
				t.Errorf("the output does not list %s:\n%s", id, out)
			}
			continue
		}
		kind, line := kindOf(t, out, id)
		if kind != tc.kind {
			t.Errorf("%s is %q, want %s:\n%s", id, kind, tc.kind, out)
			continue
		}
		for _, a := range tc.also {
			if !strings.Contains(line, a) {
				t.Errorf("the line for %s lacks %q: %s", id, a, line)
			}
		}
	}
	for _, unchanged := range []string{"10.0.0.0/24", "SBL697779", "64504", "SAME-AS", "2001:db8:"} {
		if strings.Contains(out, unchanged) {
			t.Errorf("the output lists %s, which did not change:\n%s", unchanged, out)
		}
	}
}

// ipapi reports substantive entry changes while ignoring rank-only movement.
func TestRefresh_IpapiSummary(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.ipapi = nil
	// The first refresh writes the pages dated the day before, as the built-in copy.
	pages := map[string][]byte{fileNetworks: w.fetched[fileNetworks], fileASNs: w.fetched[fileASNs]}
	for name, p := range pages {
		w.fetched[name] = replaceOnce(t, p, "November 21, 2026", "November 20, 2026")
	}
	if r := w.run(); r.code != 0 {
		t.Fatalf("the first refresh: exit %d; stderr:\n%s", r.code, r.stderr)
	}
	if s := w.parsedIpapi(); s.Nets.Updated != "2026-11-20" {
		t.Fatalf("the first refresh wrote networks dated %q, want 2026-11-20", s.Nets.Updated)
	}
	// Mix additions/removals and each changed field, plus rank-only movement that should
	// not be reported.
	n := pages[fileNetworks]
	i := bytes.LastIndex(n, []byte("</tbody>"))
	n = append(append(slices.Clone(n[:i]),
		[]byte(`<tr><td>11</td><td><a>1.1.1.0 - 1.1.1.255</a></td><td>256</td><td><span>Elevated</span></td><td>12%</td><td>New Org</td><td><span>isp</span></td></tr>`)...), n[i:]...)
	n = removeRow(t, n, "100.64.0.0 - 100.64.0.255")
	n = replaceOnce(t, n, `<td data-order="100"><span class="tag is-danger">Very High</span></td>
      <td class="is-numeric" data-order="100">100%</td>
      <td><a href="https://proton66.ru">`, `<td data-order="100"><span class="tag is-danger">Critical</span></td>
      <td class="is-numeric" data-order="100">100%</td>
      <td><a href="https://proton66.ru">`)
	n = replaceOnce(t, n, ">60%<", ">61.5%<")
	n = replaceOnce(t, n, "Some University", "Some College")
	n = replaceOnce(t, n, ">banking<", ">government<")
	n = replaceOnce(t, n, `<td class="is-numeric">4</td>`, `<td class="is-numeric">44</td>`)
	w.fetched[fileNetworks] = n
	w.fetched[fileASNs] = replaceOnce(t, pages[fileASNs], "Plain Net Ltd", "Renamed Net Ltd")
	r := w.run()
	if r.code != 0 {
		t.Fatalf("exit %d, want 0; stderr:\n%s", r.code, r.stderr)
	}
	out := r.stdout
	for _, tc := range []struct {
		id, kind string
		also     []string
	}{
		{"1.1.1.0/24", "added", nil},
		{"100.64.0.0/24", "removed", nil},
		{"37.77.150.0/24", "changed", []string{"Very High", "Critical"}},
		{"203.0.113.0/24", "changed", []string{"60", "61.5"}},
		{"198.51.100.0/24", "changed", []string{"Some University", "Some College"}},
		{"192.0.2.0/24", "changed", []string{"banking", "government"}},
		{"AS64501", "changed", []string{"Plain Net Ltd", "Renamed Net Ltd"}},
	} {
		kind, line := kindOf(t, out, tc.id)
		if kind != tc.kind {
			t.Errorf("%s is %q, want %s:\n%s", tc.id, kind, tc.kind, out)
			continue
		}
		for _, a := range tc.also {
			if !strings.Contains(line, a) {
				t.Errorf("the line for %s lacks %q: %s", tc.id, a, line)
			}
		}
	}
	if strings.Contains(out, "10.0.0.0-10.0.0.2") {
		t.Errorf("a rank that alone moved is listed:\n%s", out)
	}
	if got := w.parsedIpapi().Nets.Entries; !slices.ContainsFunc(got, func(e abusive.NetworkEntry) bool { return e.Rank == 44 }) {
		t.Error("the moved rank was not written")
	}
}

// removeRow drops the table row whose network cell holds text.
func removeRow(t *testing.T, p []byte, text string) []byte {
	t.Helper()
	s := string(p)
	i := strings.Index(s, text)
	if i < 0 {
		t.Fatalf("no row for %q", text)
	}
	start := strings.LastIndex(s[:i], "<tr>")
	end := strings.Index(s[i:], "</tr>")
	if start < 0 || end < 0 {
		t.Fatalf("no row around %q", text)
	}
	return []byte(s[:start] + s[i+end+len("</tr>"):])
}

// When both sources fail, exit 1 names both and neither file changes.
func TestRefresh_BothSourcesFail(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	delete(w.fetched, fileV4)
	w.fetched[fileNetworks] = generated("2026-11-21", 100, 50)
	spamhaus, ipapi := w.spamhaus, w.ipapi
	r := w.run()
	if r.code != 1 {
		t.Fatalf("exit %d, want 1; stderr:\n%s", r.code, r.stderr)
	}
	for _, source := range []string{"spamhaus", "ipapi.is"} {
		if !strings.Contains(strings.ToLower(r.stderr), source) {
			t.Errorf("stderr does not name %s:\n%s", source, r.stderr)
		}
	}
	if !bytes.Equal(w.spamhaus, spamhaus) || !bytes.Equal(w.ipapi, ipapi) {
		t.Error("a file changed, though both sources failed")
	}
}

// A missing or unknown flag is a usage error, exit 2, that writes nothing.
func TestRefresh_Usage(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args func(w *world) []string
	}{
		{"no -dir", func(w *world) []string { return []string{"-spamhaus", w.spamhausPath(), "-ipapi", w.ipapiPath()} }},
		{"no -spamhaus", func(w *world) []string { return []string{"-dir", w.dir, "-ipapi", w.ipapiPath()} }},
		{"no -ipapi", func(w *world) []string { return []string{"-dir", w.dir, "-spamhaus", w.spamhausPath()} }},
		{"the old -snapshot flag", func(w *world) []string { return append(w.args(), "-snapshot", w.ipapiPath()) }},
		{"an argument", func(w *world) []string { return append(w.args(), "extra") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			spamhaus, ipapi := w.spamhaus, w.ipapi
			r := w.runArgs(tc.args(w))
			if r.code != 2 {
				t.Errorf("exit %d, want 2", r.code)
			}
			if r.stderr == "" {
				t.Error("stderr is empty, want the usage")
			}
			if !bytes.Equal(w.spamhaus, spamhaus) || !bytes.Equal(w.ipapi, ipapi) {
				t.Error("a usage error changed a file")
			}
		})
	}
}
