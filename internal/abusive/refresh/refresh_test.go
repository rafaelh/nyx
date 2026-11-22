package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
)

// The clock of every test: 2026-11-21 12:00 UTC. The pages in testdata are dated that day.
var now = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func page(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// world is a directory with the two fetched pages and, perhaps, the current snapshot.
type world struct {
	t              *testing.T
	dir            string
	networks, asns string // the pages' text
	snapshot       []byte // the current snapshot file; nil for none
}

func newWorld(t *testing.T) *world {
	t.Helper()
	return &world{t: t, dir: t.TempDir(), networks: page(t, "networks.html"), asns: page(t, "asns.html")}
}

func (w *world) snapPath() string { return filepath.Join(w.dir, "snapshot.json") }

// run writes the files and refreshes, returning what it printed and its error.
func (w *world) run() (string, error) {
	w.t.Helper()
	for name, body := range map[string]string{"networks.html": w.networks, "asns.html": w.asns} {
		if err := os.WriteFile(filepath.Join(w.dir, name), []byte(body), 0o600); err != nil {
			w.t.Fatal(err)
		}
	}
	if w.snapshot != nil {
		if err := os.WriteFile(w.snapPath(), w.snapshot, 0o644); err != nil {
			w.t.Fatal(err)
		}
	}
	var out bytes.Buffer
	err := refresh(options{networks: filepath.Join(w.dir, "networks.html"), asns: filepath.Join(w.dir, "asns.html"), snapshot: w.snapPath(), now: now}, &out)
	return out.String(), err
}

// ok runs and fails the test on an error; it keeps what was written as the next run's current snapshot.
func (w *world) ok() string {
	w.t.Helper()
	out, err := w.run()
	if err != nil {
		w.t.Fatalf("refresh failed: %v", err)
	}
	b, rerr := os.ReadFile(w.snapPath())
	if rerr != nil {
		w.t.Fatal(rerr)
	}
	w.snapshot = b
	return out
}

func (w *world) written() abusive.Snapshot {
	w.t.Helper()
	b, err := os.ReadFile(w.snapPath())
	if err != nil {
		w.t.Fatal(err)
	}
	s, err := abusive.Parse(b)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

// files are the names in the directory, sorted.
func (w *world) files() []string {
	es, err := os.ReadDir(w.dir)
	if err != nil {
		w.t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// replaceOnce changes the first occurrence of old in s, and fails the test when there is none.
func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("the page has no %q", old)
	}
	return strings.Replace(s, old, new, 1)
}

// The refresh turns the two pages into the snapshot: every row, in order, both dates, text decoded.
func TestRefresh_WritesTheSnapshotFromThePages(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.ok()
	s := w.written()
	if err := abusive.Validate(s); err != nil {
		t.Fatalf("the snapshot written is not valid: %v", err)
	}
	if s.Nets.Updated != "2026-11-21" || s.ASNs.Updated != "2026-11-21" {
		t.Errorf("dates = %q, %q", s.Nets.Updated, s.ASNs.Updated)
	}
	if len(s.Nets.Entries) != 10 || len(s.ASNs.Entries) != 4 {
		t.Fatalf("%d network and %d ASN entries, want 10 and 4", len(s.Nets.Entries), len(s.ASNs.Entries))
	}
	byRank := map[int]abusive.NetworkEntry{}
	for _, e := range s.Nets.Entries {
		byRank[e.Rank] = e
	}
	want := map[int]abusive.NetworkEntry{
		1: {Rank: 1, Start: a("34.68.34.64"), End: a("34.68.34.95"), ScoreTag: "Very High", AbuseScore: 100, Org: "Mandiant, Inc.", OrgType: "business"},
		3: {Rank: 3, Start: a("45.135.193.0"), End: a("45.135.193.255"), ScoreTag: "High", AbuseScore: 99.5, Org: "Plain Org & Sons Pty Ltd", OrgType: "hosting"},
		6: {Rank: 6, Start: a("2001:db8::"), End: a("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), ScoreTag: "High", AbuseScore: 10.16, Org: "Ünïcode Örg – Ltd", OrgType: "isp"},
		7: {Rank: 7, Start: a("203.0.113.0"), End: a("203.0.113.255"), ScoreTag: "High", AbuseScore: 60, Org: "Dept & Agency", OrgType: "government"},
	}
	for rank, e := range want {
		if byRank[rank] != e {
			t.Errorf("rank %d = %+v, want %+v", rank, byRank[rank], e)
		}
	}
	last := s.ASNs.Entries[len(s.ASNs.Entries)-1]
	if last.ASN != 4200000000 || last.Org != "Big AS Number Co" || last.OrgType != "hosting" {
		t.Errorf("the last ASN entry = %+v", last)
	}
	if e := s.ASNs.Entries[0]; e.ASN != 64050 || e.OrgType != "Spamhaus ASN-DROP" || e.Rank != 1 {
		t.Errorf("the first ASN entry = %+v", e)
	}
	// The file is the marshalled snapshot, and nothing else is left in the directory.
	b, _ := os.ReadFile(w.snapPath())
	if !bytes.Equal(b, abusive.Marshal(s)) {
		t.Error("the file is not the marshalled snapshot")
	}
	if got := w.files(); !slices.Equal(got, []string{"asns.html", "networks.html", "snapshot.json"}) {
		t.Errorf("files = %v: a temporary file was left", got)
	}
}

func a(s string) netip.Addr { return netip.MustParseAddr(s) }

// A refresh changes neither list nor date when it fails, and a later refresh with good pages works.
func TestRefresh_FailsSafely(t *testing.T) {
	t.Parallel()
	const rank1 = `<td class="is-numeric">1</td>`
	for _, tc := range []struct {
		name string
		mod  func(t *testing.T, w *world)
		want string // part of the error
	}{
		{"no date", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "Data last updated on", "Data refreshed on")
		}, "date"},
		{"no date on the ASN page", func(t *testing.T, w *world) {
			w.asns = replaceOnce(t, w.asns, "Data last updated on", "Updated")
		}, "date"},
		{"a date that is not one", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "November 21, 2026", "Smarch 40, 2026")
		}, "date"},
		{"a date older than the snapshot's", func(t *testing.T, w *world) {
			w.snapshot = snapshotDated(t, "2026-11-22", "2026-11-21")
		}, "older"},
		{"an ASN date older than the snapshot's", func(t *testing.T, w *world) {
			w.snapshot = snapshotDated(t, "2026-11-21", "2026-11-22")
		}, "older"},
		{"a date the day after tomorrow", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "November 21, 2026", "November 23, 2026")
		}, "future"},
		{"an ASN date the day after tomorrow", func(t *testing.T, w *world) {
			w.asns = replaceOnce(t, w.asns, "November 21, 2026", "November 23, 2026")
		}, "future"},
		{"a rank that is not a number", func(t *testing.T, w *world) { w.networks = replaceOnce(t, w.networks, rank1, `<td>one</td>`) }, "rank"},
		{"a rank of 0", func(t *testing.T, w *world) { w.networks = replaceOnce(t, w.networks, rank1, `<td>0</td>`) }, "rank"},
		{"an ASN rank of -1", func(t *testing.T, w *world) { w.asns = replaceOnce(t, w.asns, rank1, `<td>-1</td>`) }, "rank"},
		{"a network that is one address", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "34.68.34.64 - 34.68.34.95", "34.68.34.64")
		}, "network"},
		{"a network that is not addresses", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "34.68.34.64 - 34.68.34.95", "somewhere - else")
		}, "network"},
		{"a range of two families", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "34.68.34.64 - 34.68.34.95", "34.68.34.64 - 2001:db8::1")
		}, "family"},
		{"a range whose start is after its end", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "34.68.34.64 - 34.68.34.95", "34.68.34.95 - 34.68.34.64")
		}, "order"},
		{"an ASN that is not one", func(t *testing.T, w *world) { w.asns = replaceOnce(t, w.asns, ">as64050<", ">asx<") }, "ASN"},
		{"AS0", func(t *testing.T, w *world) { w.asns = replaceOnce(t, w.asns, ">as64050<", ">as0<") }, "ASN"},
		{"an ASN over 32 bits", func(t *testing.T, w *world) { w.asns = replaceOnce(t, w.asns, ">as64050<", ">as4294967296<") }, "ASN"},
		{"an ASN with no prefix", func(t *testing.T, w *world) { w.asns = replaceOnce(t, w.asns, ">as64050<", ">64050<") }, "ASN"},
		{"a score that is not a number", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, ">99.5%<", ">lots%<")
		}, "score"},
		{"a score over 100", func(t *testing.T, w *world) { w.networks = replaceOnce(t, w.networks, ">99.5%<", ">100.5%<") }, "score"},
		{"a negative score", func(t *testing.T, w *world) { w.asns = replaceOnce(t, w.asns, ">33.3%<", ">-1%<") }, "score"},
		{"a score of NaN", func(t *testing.T, w *world) { w.asns = replaceOnce(t, w.asns, ">33.3%<", ">NaN%<") }, "score"},
		{"a score with no percent sign", func(t *testing.T, w *world) { w.networks = replaceOnce(t, w.networks, ">99.5%<", ">99.5<") }, "score"},
		{"no score tag", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, `<span class="tag is-warning">High</span></td>
      <td class="is-numeric" data-order="99.5">`, `<span class="tag is-warning"></span></td>
      <td class="is-numeric" data-order="99.5">`)
		}, "score tag"},
		{"a C0 character in an organisation", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "Proton66 OOO", "Proton\x0166 OOO")
		}, "control"},
		{"a C0 character as an entity", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "Proton66 OOO", "Proton&#x1b;[31m66")
		}, "control"},
		{"a C1 character", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "Proton66 OOO", "Proton\u008566 OOO")
		}, "control"},
		{"a C1 character as an entity", func(t *testing.T, w *world) {
			w.asns = replaceOnce(t, w.asns, "Plain Net Ltd", "Plain&#x81; Net Ltd")
		}, "control"},
		{"a C1 character as a hex entity that Windows-1252 maps", func(t *testing.T, w *world) {
			w.asns = replaceOnce(t, w.asns, "Plain Net Ltd", "Plain&#X85; Net Ltd")
		}, "control"},
		{"a C1 character as a decimal entity that Windows-1252 maps", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "Proton66 OOO", "Proton&#155;66 OOO")
		}, "control"},
		{"a C1 character as an entity with no semicolon", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "Proton66 OOO", "Proton&#x0096 OOO")
		}, "control"},
		{"a C1 character at the edge of a cell", func(t *testing.T, w *world) {
			w.asns = replaceOnce(t, w.asns, "Plain Net Ltd", "Plain Net Ltd\u0085")
		}, "control"},
		{"a control character in a cell the snapshot does not keep", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, `data-order="32">32<`, "data-order=\"32\">3\x072<")
		}, "control"},
		{"a control character in the type", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, ">isp<", ">i\x07sp<")
		}, "control"},
		{"a duplicate network", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "37.77.150.0 - 37.77.150.255", "34.68.34.64 - 34.68.34.95")
		}, "twice"},
		{"a duplicate ASN", func(t *testing.T, w *world) { w.asns = replaceOnce(t, w.asns, ">as152194<", ">as64050<") }, "twice"},
		{"no stated count", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "lists the <strong>10</strong> most", "lists most")
		}, "count"},
		{"no stated count on the ASN page", func(t *testing.T, w *world) {
			w.asns = replaceOnce(t, w.asns, "lists the <strong>4</strong> most", "lists the most")
		}, "count"},
		{"too few rows", func(t *testing.T, w *world) { w.networks = generated("2026-11-21", 100, 89) }, "rows"},
		{"no rows", func(t *testing.T, w *world) { w.asns = generatedASNs("2026-11-21", 4, 0) }, "rows"},
		{"a missing header", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, "<th>Network</th>", "<th>Net</th>")
		}, "Network"},
		{"a missing ASN header", func(t *testing.T, w *world) { w.asns = replaceOnce(t, w.asns, "Org Type", "Kind") }, "Type"},
		{"a row with too few cells", func(t *testing.T, w *world) {
			w.networks = replaceOnce(t, w.networks, `<td><a href="https://last.example">Last Net</a></td>
      <td><span class="tag is-info">business</span></td>`, "")
		}, "cells"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.snapshot = abusive.Marshal(w.goodSnapshot())
			tc.mod(t, w)
			before := slices.Clone(w.snapshot)
			_, err := w.run()
			if err == nil {
				t.Fatal("the refresh succeeded")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if got, _ := os.ReadFile(w.snapPath()); !bytes.Equal(got, before) {
				t.Error("the snapshot file changed")
			}
			if got := w.files(); !slices.Equal(got, []string{"asns.html", "networks.html", "snapshot.json"}) {
				t.Errorf("files = %v: a temporary file was left", got)
			}
			// Good pages after the failure succeed.
			w.networks, w.asns = page(t, "networks.html"), page(t, "asns.html")
			w.snapshot = nil
			if err := os.Remove(w.snapPath()); err != nil {
				t.Fatal(err)
			}
			if _, err := w.run(); err != nil {
				t.Errorf("a refresh with good pages after the failure: %v", err)
			}
		})
	}
}

// goodSnapshot is the snapshot the unmodified pages give, from an earlier refresh.
func (w *world) goodSnapshot() abusive.Snapshot {
	w.t.Helper()
	g := newWorld(w.t)
	g.ok()
	return g.written()
}

// snapshotDated is a valid snapshot file with the dates, with one entry in each list.
func snapshotDated(t *testing.T, networks, asns string) []byte {
	t.Helper()
	s := abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: networks, Entries: []abusive.NetworkEntry{{Rank: 1, Start: a("10.0.0.0"), End: a("10.0.0.255"), ScoreTag: "High", AbuseScore: 50, Org: "O", OrgType: "isp"}}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: asns, Entries: []abusive.ASNEntry{{Rank: 1, ASN: 64500, ScoreTag: "High", AbuseScore: 50, Org: "O", OrgType: "isp"}}},
	}
	return abusive.Marshal(s)
}

// generated is a networks page that states stated entries and lists rows of them.
func generated(date string, stated, rows int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><span>Data last updated on <strong>%s</strong></span><p>The table lists the <strong>%d</strong> most abusive networks on the Internet.</p>`, formatDate(date), stated)
	b.WriteString(`<table><thead><tr><th>Rank</th><th>Network</th><th>Num Hosts</th><th>Score Tag</th><th>Abuse Score</th><th>` + headerOrg + `</th><th>Type</th></tr></thead><tbody>`)
	for i := range rows {
		fmt.Fprintf(&b, `<tr><td>%d</td><td><a>10.%d.%d.0 - 10.%d.%d.255</a></td><td>256</td><td><span>High</span></td><td>50%%</td><td>Org %d</td><td><span>isp</span></td></tr>`,
			i+1, i/200, i%200, i/200, i%200, i)
	}
	b.WriteString(`</tbody></table></body></html>`)
	return b.String()
}

func generatedASNs(date string, stated, rows int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><span>Data last updated on <strong>%s</strong></span><p>The table lists the <strong>%d</strong> most abusive ASNs.</p>`, formatDate(date), stated)
	b.WriteString(`<table><thead><tr><th>Rank</th><th>ASN</th><th>Num IPs and Routes</th><th>Score Tag</th><th>Abuse Score</th><th>` + headerOrg + `</th><th>Org Type</th></tr></thead><tbody>`)
	for i := range rows {
		fmt.Fprintf(&b, `<tr><td>%d</td><td><a>as%d</a></td><td>1</td><td><span>High</span></td><td>50%%</td><td>Org %d</td><td><span>isp</span></td></tr>`, i+1, 64000+i, i)
	}
	b.WriteString(`</tbody></table></body></html>`)
	return b.String()
}

func formatDate(d string) string {
	t, _ := time.Parse(time.DateOnly, d)
	return t.Format("January 2, 2006")
}

// A page that lists 90% of what it states passes, and one with one fewer entry fails. More rows than
// stated pass too.
func TestRefresh_TheSizeCheckIsNinetyPercent(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		stated, rows int
		ok           bool
	}{{100, 90, true}, {100, 89, false}, {100, 100, true}, {100, 120, true}, {10, 9, true}, {10, 8, false}} {
		w := newWorld(t)
		w.networks = generated("2026-11-21", tc.stated, tc.rows)
		_, err := w.run()
		if (err == nil) != tc.ok {
			t.Errorf("stated %d, %d rows: err = %v, want ok=%v", tc.stated, tc.rows, err, tc.ok)
		}
	}
}

// A date of tomorrow (UTC) passes, and today's passes; the day after fails.
func TestRefresh_DateWindow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		date string
		ok   bool
	}{{"November 21, 2026", true}, {"November 22, 2026", true}, {"November 23, 2026", false}, {"November 20, 2026", true}} {
		w := newWorld(t)
		w.networks = strings.Replace(w.networks, "November 21, 2026", tc.date, 1)
		_, err := w.run()
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.date, err, tc.ok)
		}
	}
	// The same date as the snapshot's passes: only an older one fails.
	w := newWorld(t)
	w.snapshot = snapshotDated(t, "2026-11-21", "2026-11-21")
	if _, err := w.run(); err != nil {
		t.Errorf("a date equal to the snapshot's: %v", err)
	}
}

// An input file that cannot be read fails like a failed fetch, and the snapshot stays.
func TestRefresh_UnreadableInput(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.ok()
	before := slices.Clone(w.snapshot)
	var out bytes.Buffer
	err := refresh(options{networks: filepath.Join(w.dir, "missing.html"), asns: filepath.Join(w.dir, "asns.html"), snapshot: w.snapPath(), now: now}, &out)
	if err == nil {
		t.Fatal("a missing page was accepted")
	}
	if got, _ := os.ReadFile(w.snapPath()); !bytes.Equal(got, before) {
		t.Error("the snapshot changed")
	}
	// An unreadable current snapshot is an error too, not a first run that overwrites it.
	w.snapshot = []byte("not json")
	if _, err := w.run(); err == nil {
		t.Error("a snapshot that is not JSON was replaced")
	}
	if got, _ := os.ReadFile(w.snapPath()); string(got) != "not json" {
		t.Error("the unreadable snapshot was overwritten")
	}
}

// Running the refresh twice on the same pages gives the same file, and the second says nothing changed.
func TestRefresh_Idempotent(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	first := w.ok()
	if !strings.Contains(first, "added") {
		t.Errorf("the first refresh summary has no additions:\n%s", first)
	}
	b1 := slices.Clone(w.snapshot)
	second := w.ok()
	if !bytes.Equal(b1, w.snapshot) {
		t.Error("the file changed on the second refresh")
	}
	if strings.Count(second, "no entries changed") != 2 {
		t.Errorf("the second summary should say nothing changed in each list:\n%s", second)
	}
	for _, bad := range []string{"added:", "removed:", "changed:"} {
		if strings.Contains(second, bad) {
			t.Errorf("the second summary lists %q:\n%s", bad, second)
		}
	}
}

// The summary lists additions, removals and a change of each of the four fields, not a rank that
// moved alone, and ends with the reminder to update the README.
func TestRefresh_Summary(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.ok()
	// Networks: add one, remove one (rank 10), change the tag of rank 2, the score of rank 7, the
	// organisation of rank 8 and the type of rank 9; move the rank of rank 4 alone.
	n := w.networks
	i := strings.LastIndex(n, "</tbody>")
	n = n[:i] + `<tr><td>11</td><td><a>1.1.1.0 - 1.1.1.255</a></td><td>256</td><td><span>Elevated</span></td><td>12%</td><td>New Org</td><td><span>isp</span></td></tr>` + n[i:]
	w.networks = removeRow(t, n, "100.64.0.0 - 100.64.0.255")
	w.networks = replaceOnce(t, w.networks, `<td data-order="100"><span class="tag is-danger">Very High</span></td>
      <td class="is-numeric" data-order="100">100%</td>
      <td><a href="https://proton66.ru">`, `<td data-order="100"><span class="tag is-danger">Critical</span></td>
      <td class="is-numeric" data-order="100">100%</td>
      <td><a href="https://proton66.ru">`)
	w.networks = replaceOnce(t, w.networks, ">60%<", ">61.5%<")
	w.networks = replaceOnce(t, w.networks, "Some University", "Some College")
	w.networks = replaceOnce(t, w.networks, ">banking<", ">government<")
	w.networks = replaceOnce(t, w.networks, `<td class="is-numeric">4</td>`, `<td class="is-numeric">44</td>`)
	// ASNs: the organisation of AS64501 changes.
	w.asns = replaceOnce(t, w.asns, "Plain Net Ltd", "Renamed Net Ltd")
	out := w.ok()
	for _, want := range []string{
		"added: 1.1.1.0/24",
		"removed: 100.64.0.0/24",
		"37.77.150.0/24", "score_tag: Very High -> Critical",
		"203.0.113.0/24", "abuse_score: 60 -> 61.5",
		"198.51.100.0/24", "org: Some University -> Some College",
		"192.0.2.0/24", "org_type: banking -> government",
		"AS64501", "org: Plain Net Ltd -> Renamed Net Ltd",
		"README.md", "2026-11-21",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "10.0.0.0-10.0.0.2") {
		t.Errorf("a rank that alone moved is listed:\n%s", out)
	}
	if got := w.written().Nets.Entries; !slices.ContainsFunc(got, func(e abusive.NetworkEntry) bool { return e.Rank == 44 }) {
		t.Error("the moved rank was not written")
	}
}

// removeRow drops the table row whose network cell holds text.
func removeRow(t *testing.T, page, text string) string {
	t.Helper()
	i := strings.Index(page, text)
	if i < 0 {
		t.Fatalf("no row for %q", text)
	}
	start := strings.LastIndex(page[:i], "<tr>")
	end := strings.Index(page[i:], "</tr>")
	if start < 0 || end < 0 {
		t.Fatalf("no row around %q", text)
	}
	return page[:start] + page[i+end+len("</tr>"):]
}

// The summary of a changed list names its dates.
func TestRefresh_SummaryNamesTheDates(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.snapshot = snapshotDated(t, "2026-11-19", "2026-11-20")
	out := w.ok()
	for _, want := range []string{"2026-11-19 -> 2026-11-21", "2026-11-20 -> 2026-11-21"} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary lacks %q:\n%s", want, out)
		}
	}
}
