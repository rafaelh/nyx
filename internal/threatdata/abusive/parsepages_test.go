package abusive_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/threatdata/abusive"
)

// pagesNow is the clock of the page tests: 2026-11-21 12:00 UTC. The pages in testdata are dated
// that day.
var pagesNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

// headerOrg selects the source's organisation-column spelling.
const headerOrg = "Organization" //nolint:misspell // the page's own spelling

func page(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// replaceOnce changes the first occurrence of old in s, and fails the test when there is none.
func replaceOnce(t *testing.T, s, old, new string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("the page has no %q", old)
	}
	return strings.Replace(s, old, new, 1)
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

// pages are the two pages a test parses, the fixtures until it changes them.
type pages struct{ networks, asns string }

func fixtures(t *testing.T) *pages {
	t.Helper()
	return &pages{networks: page(t, "networks.html"), asns: page(t, "asns.html")}
}

func (p *pages) parse(now time.Time) (abusive.Snapshot, error) {
	return abusive.ParsePages([]byte(p.networks), []byte(p.asns), now)
}

// ParsePages turns the two pages into a snapshot: every row, sorted, both dates and stated counts,
// and the text decoded.
func TestParsePages_ReadsBothPages(t *testing.T) {
	t.Parallel()
	s, err := fixtures(t).parse(pagesNow)
	if err != nil {
		t.Fatalf("ParsePages: %v", err)
	}
	if err := abusive.Validate(s); err != nil {
		t.Errorf("the snapshot is not valid: %v", err)
	}
	if err := abusive.ValidateCounts(s); err != nil {
		t.Errorf("the snapshot fails the count rule: %v", err)
	}
	if s.Nets.Updated != "2026-11-21" || s.ASNs.Updated != "2026-11-21" {
		t.Errorf("dates = %q, %q, want 2026-11-21 for both", s.Nets.Updated, s.ASNs.Updated)
	}
	if s.Nets.Stated != 10 || s.ASNs.Stated != 4 {
		t.Errorf("stated counts = %d, %d, want 10 and 4", s.Nets.Stated, s.ASNs.Stated)
	}
	if len(s.Nets.Entries) != 10 || len(s.ASNs.Entries) != 4 {
		t.Fatalf("%d network and %d ASN entries, want 10 and 4", len(s.Nets.Entries), len(s.ASNs.Entries))
	}
	byRank := map[int]abusive.NetworkEntry{}
	for _, e := range s.Nets.Entries {
		byRank[e.Rank] = e
	}
	want := map[int]abusive.NetworkEntry{
		1: {Rank: 1, Start: addr("34.68.34.64"), End: addr("34.68.34.95"), ScoreTag: "Very High", AbuseScore: 100, Org: "Mandiant, Inc.", OrgType: "business"},
		3: {Rank: 3, Start: addr("45.135.193.0"), End: addr("45.135.193.255"), ScoreTag: "High", AbuseScore: 99.5, Org: "Plain Org & Sons Pty Ltd", OrgType: "hosting"},
		6: {Rank: 6, Start: addr("2001:db8::"), End: addr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), ScoreTag: "High", AbuseScore: 10.16, Org: "Ünïcode Örg – Ltd", OrgType: "isp"},
		7: {Rank: 7, Start: addr("203.0.113.0"), End: addr("203.0.113.255"), ScoreTag: "High", AbuseScore: 60, Org: "Dept & Agency", OrgType: "government"},
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
}

// Each page can be read on its own, as it arrives, and gives the list ParsePages gives for it.
func TestParsePages_EachPageOnItsOwn(t *testing.T) {
	t.Parallel()
	p := fixtures(t)
	both, err := p.parse(pagesNow)
	if err != nil {
		t.Fatalf("ParsePages: %v", err)
	}
	nets, err := abusive.ParseNetworksPage([]byte(p.networks), pagesNow)
	if err != nil {
		t.Fatalf("ParseNetworksPage: %v", err)
	}
	asns, err := abusive.ParseASNsPage([]byte(p.asns), pagesNow)
	if err != nil {
		t.Fatalf("ParseASNsPage: %v", err)
	}
	if nets.Updated != both.Nets.Updated || nets.Stated != both.Nets.Stated || !slices.Equal(nets.Entries, both.Nets.Entries) || len(nets.Entries) != 10 {
		t.Errorf("the networks page alone = %+v\nwant %+v", nets, both.Nets)
	}
	if asns.Updated != both.ASNs.Updated || asns.Stated != both.ASNs.Stated || !slices.Equal(asns.Entries, both.ASNs.Entries) || len(asns.Entries) != 4 {
		t.Errorf("the ASNs page alone = %+v\nwant %+v", asns, both.ASNs)
	}
	// A page read alone is held to its list's rules: a repeat is refused there, not later.
	dupNet := replaceOnce(t, p.networks, "37.77.150.0 - 37.77.150.255", "34.68.34.64 - 34.68.34.95")
	if _, err := abusive.ParseNetworksPage([]byte(dupNet), pagesNow); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a repeated network read alone: err = %v, want one that says twice", err)
	}
	dupASN := replaceOnce(t, p.asns, ">as152194<", ">as64050<")
	if _, err := abusive.ParseASNsPage([]byte(dupASN), pagesNow); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("a repeated ASN read alone: err = %v, want one that says twice", err)
	}
	// And to the count rule.
	if _, err := abusive.ParseNetworksPage([]byte(generated("2026-11-21", 100, 89)), pagesNow); err == nil {
		t.Error("a networks page with 89 of 100 rows read alone was accepted")
	}
	if _, err := abusive.ParseASNsPage([]byte(generatedASNs("2026-11-21", 4, 0)), pagesNow); err == nil {
		t.Error("an ASNs page with no rows read alone was accepted")
	}
}

// A page that breaks a rule is refused, with an error that says which.
func TestParsePages_Refuses(t *testing.T) {
	t.Parallel()
	const rank1 = `<td class="is-numeric">1</td>`
	for _, tc := range []struct {
		name string
		mod  func(t *testing.T, p *pages)
		want string // part of the error
	}{
		{"no date", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "Data last updated on", "Data refreshed on")
		}, "date"},
		{"no date on the ASN page", func(t *testing.T, p *pages) {
			p.asns = replaceOnce(t, p.asns, "Data last updated on", "Updated")
		}, "date"},
		{"a date that is not one", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "November 21, 2026", "Smarch 40, 2026")
		}, "date"},
		{"a date the day after tomorrow", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "November 21, 2026", "November 23, 2026")
		}, "future"},
		{"an ASN date the day after tomorrow", func(t *testing.T, p *pages) {
			p.asns = replaceOnce(t, p.asns, "November 21, 2026", "November 23, 2026")
		}, "future"},
		{"a rank that is not a number", func(t *testing.T, p *pages) { p.networks = replaceOnce(t, p.networks, rank1, `<td>one</td>`) }, "rank"},
		{"a rank of 0", func(t *testing.T, p *pages) { p.networks = replaceOnce(t, p.networks, rank1, `<td>0</td>`) }, "rank"},
		{"an ASN rank of -1", func(t *testing.T, p *pages) { p.asns = replaceOnce(t, p.asns, rank1, `<td>-1</td>`) }, "rank"},
		{"a network that is one address", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "34.68.34.64 - 34.68.34.95", "34.68.34.64")
		}, "network"},
		{"a network that is not addresses", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "34.68.34.64 - 34.68.34.95", "somewhere - else")
		}, "network"},
		{"a range of two families", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "34.68.34.64 - 34.68.34.95", "34.68.34.64 - 2001:db8::1")
		}, "family"},
		{"a range whose start is after its end", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "34.68.34.64 - 34.68.34.95", "34.68.34.95 - 34.68.34.64")
		}, "order"},
		{"an ASN that is not one", func(t *testing.T, p *pages) { p.asns = replaceOnce(t, p.asns, ">as64050<", ">asx<") }, "ASN"},
		{"AS0", func(t *testing.T, p *pages) { p.asns = replaceOnce(t, p.asns, ">as64050<", ">as0<") }, "ASN"},
		{"an ASN over 32 bits", func(t *testing.T, p *pages) { p.asns = replaceOnce(t, p.asns, ">as64050<", ">as4294967296<") }, "ASN"},
		{"an ASN with no prefix", func(t *testing.T, p *pages) { p.asns = replaceOnce(t, p.asns, ">as64050<", ">64050<") }, "ASN"},
		{"a score that is not a number", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, ">99.5%<", ">lots%<")
		}, "score"},
		{"a score over 100", func(t *testing.T, p *pages) { p.networks = replaceOnce(t, p.networks, ">99.5%<", ">100.5%<") }, "score"},
		{"a negative score", func(t *testing.T, p *pages) { p.asns = replaceOnce(t, p.asns, ">33.3%<", ">-1%<") }, "score"},
		{"a score of NaN", func(t *testing.T, p *pages) { p.asns = replaceOnce(t, p.asns, ">33.3%<", ">NaN%<") }, "score"},
		{"a score with no percent sign", func(t *testing.T, p *pages) { p.networks = replaceOnce(t, p.networks, ">99.5%<", ">99.5<") }, "score"},
		{"no score tag", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, `<span class="tag is-warning">High</span></td>
      <td class="is-numeric" data-order="99.5">`, `<span class="tag is-warning"></span></td>
      <td class="is-numeric" data-order="99.5">`)
		}, "score tag"},
		{"a C0 character in an organisation", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "Proton66 OOO", "Proton\x0166 OOO")
		}, "control"},
		{"a C0 character as an entity", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "Proton66 OOO", "Proton&#x1b;[31m66")
		}, "control"},
		{"a C1 character", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "Proton66 OOO", "Proton\u008566 OOO")
		}, "control"},
		{"a C1 character as an entity", func(t *testing.T, p *pages) {
			p.asns = replaceOnce(t, p.asns, "Plain Net Ltd", "Plain&#x81; Net Ltd")
		}, "control"},
		{"a C1 character as a hex entity that Windows-1252 maps", func(t *testing.T, p *pages) {
			p.asns = replaceOnce(t, p.asns, "Plain Net Ltd", "Plain&#X85; Net Ltd")
		}, "control"},
		{"a C1 character as a decimal entity that Windows-1252 maps", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "Proton66 OOO", "Proton&#155;66 OOO")
		}, "control"},
		{"a C1 character as an entity with no semicolon", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "Proton66 OOO", "Proton&#x0096 OOO")
		}, "control"},
		{"a C1 character at the edge of a cell", func(t *testing.T, p *pages) {
			p.asns = replaceOnce(t, p.asns, "Plain Net Ltd", "Plain Net Ltd\u0085")
		}, "control"},
		{"a control character in a cell the snapshot does not keep", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, `data-order="32">32<`, "data-order=\"32\">3\x072<")
		}, "control"},
		{"a control character in the type", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, ">isp<", ">i\x07sp<")
		}, "control"},
		{"a duplicate network", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "37.77.150.0 - 37.77.150.255", "34.68.34.64 - 34.68.34.95")
		}, "twice"},
		{"a duplicate ASN", func(t *testing.T, p *pages) { p.asns = replaceOnce(t, p.asns, ">as152194<", ">as64050<") }, "twice"},
		{"no stated count", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "lists the <strong>10</strong> most", "lists most")
		}, "count"},
		{"no stated count on the ASN page", func(t *testing.T, p *pages) {
			p.asns = replaceOnce(t, p.asns, "lists the <strong>4</strong> most", "lists the most")
		}, "count"},
		{"too few rows", func(t *testing.T, p *pages) { p.networks = generated("2026-11-21", 100, 89) }, "rows"},
		{"no rows", func(t *testing.T, p *pages) { p.asns = generatedASNs("2026-11-21", 4, 0) }, "rows"},
		{"a missing header", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, "<th>Network</th>", "<th>Net</th>")
		}, "Network"},
		{"a missing ASN header", func(t *testing.T, p *pages) { p.asns = replaceOnce(t, p.asns, "Org Type", "Kind") }, "Type"},
		{"a row with too few cells", func(t *testing.T, p *pages) {
			p.networks = replaceOnce(t, p.networks, `<td><a href="https://last.example">Last Net</a></td>
      <td><span class="tag is-info">business</span></td>`, "")
		}, "cells"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := fixtures(t)
			tc.mod(t, p)
			_, err := p.parse(pagesNow)
			if err == nil {
				t.Fatal("ParsePages accepted the pages")
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// The 90% completeness threshold is inclusive; extra source rows are allowed.
func TestParsePages_TheSizeCheckIsNinetyPercent(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		stated, rows int
		ok           bool
	}{{100, 90, true}, {100, 89, false}, {100, 100, true}, {100, 120, true}, {10, 9, true}, {10, 8, false}} {
		p := fixtures(t)
		p.networks = generated("2026-11-21", tc.stated, tc.rows)
		s, err := p.parse(pagesNow)
		if (err == nil) != tc.ok {
			t.Errorf("stated %d, %d rows: err = %v, want ok=%v", tc.stated, tc.rows, err, tc.ok)
		}
		if tc.ok && (s.Nets.Stated != tc.stated || len(s.Nets.Entries) != tc.rows) {
			t.Errorf("stated %d, %d rows: the list states %d and holds %d", tc.stated, tc.rows, s.Nets.Stated, len(s.Nets.Entries))
		}
	}
}

// Allow tomorrow UTC for source time zones, reject later dates, and leave age comparisons to
// callers.
func TestParsePages_DateWindow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		date string
		ok   bool
	}{
		{"November 21, 2026", true}, {"November 22, 2026", true}, {"November 23, 2026", false},
		{"November 20, 2026", true}, {"January 3, 2025", true},
	} {
		p := fixtures(t)
		p.networks = strings.Replace(p.networks, "November 21, 2026", tc.date, 1)
		_, err := p.parse(pagesNow)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.date, err, tc.ok)
		}
	}
	// Use UTC for tomorrow even when the supplied clock is already on the next local day.
	east := time.Date(2026, 11, 22, 8, 0, 0, 0, time.FixedZone("AEST", 10*60*60))
	p := fixtures(t)
	p.networks = replaceOnce(t, p.networks, "November 21, 2026", "November 23, 2026")
	if _, err := p.parse(east); err == nil {
		t.Error("a date the day after tomorrow in UTC passed with the clock in UTC+10")
	}
	p = fixtures(t)
	p.networks = replaceOnce(t, p.networks, "November 21, 2026", "November 22, 2026")
	if _, err := p.parse(east); err != nil {
		t.Errorf("tomorrow in UTC with the clock in UTC+10: %v", err)
	}
}

// Consume the whole numeric reference so a valid character such as &#x8F66; is not mistaken for
// a C1 control prefix.
func TestParsePages_ReferencesBeyondC1(t *testing.T) {
	t.Parallel()
	p := fixtures(t)
	p.asns = replaceOnce(t, p.asns, "Plain Net Ltd", "Plain &#x8F66;&#1488;&#12900;&#x9A6C Net Ltd")
	s, err := p.parse(pagesNow)
	if err != nil {
		t.Fatalf("ParsePages: %v", err)
	}
	want := "Plain 车א㉤马 Net Ltd"
	if !slices.ContainsFunc(s.ASNs.Entries, func(e abusive.ASNEntry) bool { return e.Org == want }) {
		t.Errorf("no ASN entry has the organisation %q: %+v", want, s.ASNs.Entries)
	}
}
