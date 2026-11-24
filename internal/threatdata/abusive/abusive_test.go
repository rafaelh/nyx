package abusive_test

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/threatdata/abusive"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func net4(rank int, start, end, tag string, score float64, org, typ string) abusive.NetworkEntry {
	return abusive.NetworkEntry{Rank: rank, Start: addr(start), End: addr(end), ScoreTag: tag, AbuseScore: score, Org: org, OrgType: typ}
}

func asnEntry(rank, asn int, tag string, score float64, org, typ string) abusive.ASNEntry {
	return abusive.ASNEntry{Rank: rank, ASN: asn, ScoreTag: tag, AbuseScore: score, Org: org, OrgType: typ}
}

// snap is a valid snapshot: nested and CIDR-shaped and start-end ranges, an IPv6 range and two ASNs.
func snap() abusive.Snapshot {
	return abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: "2026-11-21", Entries: []abusive.NetworkEntry{
			net4(2, "10.0.0.0", "10.0.255.255", "High", 80.5, "Outer Org", "isp"),
			net4(1, "10.0.0.0", "10.0.0.255", "Very High", 100, "Inner Org", "hosting"),
			net4(3, "10.0.0.16", "10.0.0.18", "High", 50, "Odd Org", "business"),
			net4(4, "10.0.0.32", "10.0.0.47", "High", 60, "Tie B", "business"),
			net4(5, "192.0.2.0", "192.0.2.15", "Elevated", 12.25, "Tie A", "banking"),
			net4(6, "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "Very High", 99, "V6 Org", "hosting"),
		}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: "2026-11-20", Entries: []abusive.ASNEntry{
			asnEntry(1, 64050, "Very High", 100, "BGP Network Limited", "Spamhaus ASN-DROP"),
			asnEntry(2, 64501, "Elevated", 33.3, "Other Net", "unknown"),
		}},
	}
}

func sorted(s abusive.Snapshot) abusive.Snapshot {
	slices.SortFunc(s.Nets.Entries, abusive.CompareNetworks)
	return s
}

// The embedded snapshot is valid, and parses to the lists it carries.
func TestDefault_EmbeddedSnapshotIsValid(t *testing.T) {
	t.Parallel()
	d := abusive.Default()
	if err := abusive.Validate(*d); err != nil {
		t.Fatalf("the embedded snapshot is not valid: %v", err)
	}
	if d.Nets.Updated == "" || d.ASNs.Updated == "" {
		t.Errorf("dates %q and %q, want both", d.Nets.Updated, d.ASNs.Updated)
	}
	if abusive.Default() != d {
		t.Error("Default parses the embedded file more than once")
	}
}

// Embedded lists must meet the same 90% completeness threshold as downloads.
func TestDefault_EmbeddedSnapshotStatesItsCounts(t *testing.T) {
	t.Parallel()
	d := abusive.Default()
	if d.Nets.Stated < 1 || d.ASNs.Stated < 1 {
		t.Errorf("stated counts %d and %d, want both at least 1", d.Nets.Stated, d.ASNs.Stated)
	}
	if err := abusive.ValidateCounts(*d); err != nil {
		t.Errorf("the embedded snapshot fails the count rule: %v", err)
	}
}

// counted is snap, sorted, with each list stating exactly the entries it holds.
func counted() abusive.Snapshot {
	s := sorted(snap())
	s.Nets.Stated, s.ASNs.Stated = len(s.Nets.Entries), len(s.ASNs.Entries)
	return s
}

// nASNs is a snapshot whose ASN list holds n entries and states stated, and whose networks list is
// counted.
func nASNs(stated, n int) abusive.Snapshot {
	s := counted()
	s.ASNs.Entries = nil
	for i := range n {
		s.ASNs.Entries = append(s.ASNs.Entries, asnEntry(i+1, 64000+i, "High", 50, "Org", "isp"))
	}
	s.ASNs.Stated = stated
	return s
}

// A list must state its count, and hold at least 90% of it; more than it states is fine. Both lists
// are checked.
func TestValidateCounts(t *testing.T) {
	t.Parallel()
	if err := abusive.ValidateCounts(counted()); err != nil {
		t.Fatalf("lists that hold what they state: %v", err)
	}
	for _, tc := range []struct {
		name string
		s    abusive.Snapshot
		ok   bool
	}{
		{"90 of 100", nASNs(100, 90), true},
		{"89 of 100", nASNs(100, 89), false},
		{"9 of 10", nASNs(10, 9), true},
		{"8 of 10", nASNs(10, 8), false},
		{"120 of 100", nASNs(100, 120), true},
		{"none of 4", nASNs(4, 0), false},
		{"no stated count", nASNs(0, 4), false},
		{"a negative stated count", nASNs(-1, 4), false},
		{"networks short", func() abusive.Snapshot { s := counted(); s.Nets.Stated = 100; return s }(), false},
		{"networks with no stated count", func() abusive.Snapshot { s := counted(); s.Nets.Stated = 0; return s }(), false},
	} {
		if err := abusive.ValidateCounts(tc.s); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// The stated counts survive Marshal and Parse.
func TestMarshal_KeepsTheStatedCounts(t *testing.T) {
	t.Parallel()
	s := counted()
	s.Nets.Stated, s.ASNs.Stated = 7, 3
	back, err := abusive.Parse(abusive.Marshal(s))
	if err != nil {
		t.Fatal(err)
	}
	if back.Nets.Stated != 7 || back.ASNs.Stated != 3 {
		t.Errorf("stated counts after a round trip = %d and %d, want 7 and 3", back.Nets.Stated, back.ASNs.Stated)
	}
}

// withUnknownFields simulates a newer snapshot format with extra fields at every level.
func withUnknownFields(t *testing.T, s abusive.Snapshot) []byte {
	t.Helper()
	b := string(abusive.Marshal(s))
	for _, r := range []struct{ old, new string }{
		{"{\n", "{\n \"source\": \"ipapi.is\",\n"},
		{`"networks": {`, `"networks": {"url": "https://ipapi.is/most-abusive-networks.html",`},
		{`"asns": {`, `"asns": {"url": "https://ipapi.is/most-abusive-asn.html",`},
		{`{"rank":`, `{"hosts":256,"rank":`},
		{`{"rank":1,"asn"`, `{"cc":"AU","rank":1,"asn"`},
	} {
		if !strings.Contains(b, r.old) {
			t.Fatalf("the marshalled snapshot has no %q:\n%s", r.old, b)
		}
		b = strings.Replace(b, r.old, r.new, 1)
	}
	if !json.Valid([]byte(b)) {
		t.Fatalf("not JSON:\n%s", b)
	}
	return []byte(b)
}

// Downloads tolerate future fields; embedded data still uses strict parsing.
func TestParseLenient_IgnoresUnknownFields(t *testing.T) {
	t.Parallel()
	s := counted()
	b := withUnknownFields(t, s)
	if _, err := abusive.Parse(b); err == nil {
		t.Error("Parse accepted a file with unknown fields")
	}
	got, err := abusive.ParseLenient(b)
	if err != nil {
		t.Fatalf("ParseLenient: %v", err)
	}
	if !slices.Equal(got.Nets.Entries, s.Nets.Entries) || !slices.Equal(got.ASNs.Entries, s.ASNs.Entries) {
		t.Errorf("entries = %+v\nwant %+v", got, s)
	}
	if got.Nets.Updated != s.Nets.Updated || got.ASNs.Updated != s.ASNs.Updated || got.Nets.Stated != s.Nets.Stated || got.ASNs.Stated != s.ASNs.Stated {
		t.Errorf("dates and counts = %s %d, %s %d; want %s %d, %s %d", got.Nets.Updated, got.Nets.Stated, got.ASNs.Updated, got.ASNs.Stated,
			s.Nets.Updated, s.Nets.Stated, s.ASNs.Updated, s.ASNs.Stated)
	}
	// A file that matches without unknown fields reads the same either way.
	plain := abusive.Marshal(s)
	strict, err1 := abusive.Parse(plain)
	lenient, err2 := abusive.ParseLenient(plain)
	if err1 != nil || err2 != nil {
		t.Fatalf("Parse: %v; ParseLenient: %v", err1, err2)
	}
	if !bytes.Equal(abusive.Marshal(strict), abusive.Marshal(lenient)) {
		t.Error("ParseLenient reads a plain file differently from Parse")
	}
}

// ParseLenient still refuses what is not a snapshot.
func TestParseLenient_RefusesWhatIsNotJSON(t *testing.T) {
	t.Parallel()
	for _, b := range []string{"", "not json", `{"networks": {"updated": 5}}`, `{"networks": {"entries": [{"rank": "one"}]}}`} {
		if _, err := abusive.ParseLenient([]byte(b)); err == nil {
			t.Errorf("ParseLenient(%q) succeeded", b)
		}
	}
}

// Validate rejects what a hand edit or a bad refresh could leave in the file.
func TestValidate(t *testing.T) {
	t.Parallel()
	if err := abusive.Validate(sorted(snap())); err != nil {
		t.Fatalf("a good snapshot: %v", err)
	}
	for _, tc := range []struct {
		name string
		mod  func(*abusive.Snapshot)
	}{
		{"unsorted networks", func(s *abusive.Snapshot) { *s = snap() }}, // snap's entries are deliberately out of order
		{"unsorted asns", func(s *abusive.Snapshot) { slices.Reverse(s.ASNs.Entries) }},
		{"duplicate network", func(s *abusive.Snapshot) {
			s.Nets.Entries = append(s.Nets.Entries, s.Nets.Entries[0])
		}},
		{"duplicate asn", func(s *abusive.Snapshot) { s.ASNs.Entries[1].ASN = s.ASNs.Entries[0].ASN }},
		{"start after end", func(s *abusive.Snapshot) {
			s.Nets.Entries[0].Start, s.Nets.Entries[0].End = s.Nets.Entries[0].End, s.Nets.Entries[0].Start
		}},
		{"two families", func(s *abusive.Snapshot) { s.Nets.Entries[0].End = addr("2001:db8::1") }},
		{"invalid end", func(s *abusive.Snapshot) { s.Nets.Entries[0].End = netip.Addr{} }},
		{"asn 0", func(s *abusive.Snapshot) { s.ASNs.Entries[0].ASN = 0 }},
		{"asn over 32 bits", func(s *abusive.Snapshot) { s.ASNs.Entries[1].ASN = 4294967296 }},
		{"rank 0", func(s *abusive.Snapshot) { s.Nets.Entries[0].Rank = 0 }},
		{"asn rank 0", func(s *abusive.Snapshot) { s.ASNs.Entries[0].Rank = 0 }},
		{"score over 100", func(s *abusive.Snapshot) { s.Nets.Entries[0].AbuseScore = 100.5 }},
		{"score below 0", func(s *abusive.Snapshot) { s.ASNs.Entries[0].AbuseScore = -1 }},
		{"bad date", func(s *abusive.Snapshot) { s.Nets.Updated = "21 Nov 2026" }},
		{"no date", func(s *abusive.Snapshot) { s.ASNs.Updated = "" }},
		{"C0 in org", func(s *abusive.Snapshot) { s.Nets.Entries[0].Org = "Evil\x1b[31m" }},
		{"C1 in tag", func(s *abusive.Snapshot) { s.Nets.Entries[0].ScoreTag = "High\u0085" }},
		{"C0 in type", func(s *abusive.Snapshot) { s.ASNs.Entries[0].OrgType = "a\tb" }},
	} {
		s := sorted(snap())
		tc.mod(&s)
		if err := abusive.Validate(s); err == nil {
			t.Errorf("%s: Validate passed", tc.name)
		}
	}
}

// Range endpoints are inclusive, and matches retain entry metadata and the list date.
func TestNetworks_InsideOutsideAndTheEdges(t *testing.T) {
	t.Parallel()
	s := abusive.Load(sorted(snap()))
	for _, tc := range []struct {
		addr string
		want []string // entry text of each match, in order
	}{
		{"192.0.2.0", []string{"192.0.2.0/28"}},
		{"192.0.2.15", []string{"192.0.2.0/28"}},
		{"192.0.2.16", nil},
		{"192.0.1.255", nil},
		{"10.0.0.16", []string{"10.0.0.16-10.0.0.18", "10.0.0.0/24", "10.0.0.0/16"}},
		{"10.0.0.18", []string{"10.0.0.16-10.0.0.18", "10.0.0.0/24", "10.0.0.0/16"}},
		{"10.0.0.19", []string{"10.0.0.0/24", "10.0.0.0/16"}},
		{"10.0.1.1", []string{"10.0.0.0/16"}},
		{"203.0.113.9", nil},
	} {
		var got []string
		for _, m := range s.Networks(addr(tc.addr)) {
			got = append(got, m.Network)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("Networks(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

// The match carries the list, the entry's rank, tag, score, organisation and type, and the list's date.
func TestNetworks_MatchCarriesTheEntry(t *testing.T) {
	t.Parallel()
	s := abusive.Load(sorted(snap()))
	got := s.Networks(addr("192.0.2.5"))
	want := []abusive.NetworkMatch{{Network: "192.0.2.0/28", Rank: 5, ScoreTag: "Elevated", AbuseScore: 12.25, Org: "Tie A", OrgType: "banking", Updated: "2026-11-21"}}
	if !slices.Equal(got, want) {
		t.Errorf("match = %+v, want %+v", got, want)
	}
	a := s.ASN(64050)
	wantASN := []abusive.ASNMatch{{ASN: 64050, Rank: 1, ScoreTag: "Very High", AbuseScore: 100, Org: "BGP Network Limited", OrgType: "Spamhaus ASN-DROP", Updated: "2026-11-20"}}
	if !slices.Equal(a, wantASN) {
		t.Errorf("ASN match = %+v, want %+v", a, wantASN)
	}
	if got := s.ASN(64502); len(got) != 0 || got == nil {
		t.Errorf("an unlisted ASN = %#v, want []", got)
	}
	if got := s.ASN(0); len(got) != 0 {
		t.Errorf("ASN 0 = %#v", got)
	}
}

// Of ranges the same size, the lower rank comes first.
func TestNetworks_TiesBreakByRank(t *testing.T) {
	t.Parallel()
	s := sorted(abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: "2026-11-21", Entries: []abusive.NetworkEntry{
			net4(9, "10.1.0.0", "10.1.0.255", "High", 70, "Nine", "isp"),
			net4(4, "10.1.0.0", "10.1.0.255", "High", 71, "Four", "isp"), // duplicate range used only to test ordering
		}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: "2026-11-21"},
	})
	got := abusive.Load(s).Networks(addr("10.1.0.7"))
	if len(got) != 2 || got[0].Rank != 4 || got[1].Rank != 9 {
		t.Errorf("matches = %+v, want rank 4 then 9", got)
	}
	// Two different ranges of equal size that both hold the address cannot be told apart by size.
	s = sorted(abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: "2026-11-21", Entries: []abusive.NetworkEntry{
			net4(8, "10.2.0.0", "10.2.0.9", "High", 70, "Eight", "isp"),
			net4(3, "10.2.0.5", "10.2.0.14", "High", 71, "Three", "isp"),
		}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: "2026-11-21"},
	})
	got = abusive.Load(s).Networks(addr("10.2.0.7"))
	if len(got) != 2 || got[0].Rank != 3 || got[1].Rank != 8 {
		t.Errorf("matches = %+v, want rank 3 then 8", got)
	}
}

// Exact CIDR ranges use prefix notation; other ranges use endpoints.
func TestNetworks_EntryIsWrittenAsRdapNetblockIs(t *testing.T) {
	t.Parallel()
	s := abusive.Load(sorted(snap()))
	for _, tc := range []struct{ start, end string }{
		{"10.0.0.0", "10.0.255.255"}, {"10.0.0.16", "10.0.0.18"}, {"10.0.0.32", "10.0.0.47"},
		{"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
	} {
		ms := s.Networks(addr(tc.start))
		want := input.RangeText(addr(tc.start), addr(tc.end))
		if !slices.ContainsFunc(ms, func(m abusive.NetworkMatch) bool { return m.Network == want }) {
			t.Errorf("%s-%s: no match is written as rdap_netblock writes it (%q): %+v", tc.start, tc.end, want, ms)
		}
	}
}

// An IPv6 address matches only an IPv6 range, and an IPv4-mapped address is the IPv4 address.
func TestNetworks_IPv6AndMapped(t *testing.T) {
	t.Parallel()
	v4only := abusive.Load(sorted(abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: "2026-11-21", Entries: []abusive.NetworkEntry{
			net4(1, "0.0.0.0", "255.255.255.255", "High", 70, "Everything", "isp"),
		}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: "2026-11-21"},
	}))
	if got := v4only.Networks(addr("2001:db8::1")); len(got) != 0 {
		t.Errorf("an IPv6 address matched an IPv4 range: %+v", got)
	}
	if got := v4only.Networks(addr("::ffff:10.0.0.1")); len(got) != 1 {
		t.Errorf("an IPv4-mapped address matches %d, want 1", len(got))
	}
	s := abusive.Load(sorted(snap()))
	if got := s.Networks(addr("2001:db8:1::1")); len(got) != 1 || got[0].Network != "2001:db8::/32" {
		t.Errorf("an IPv6 address in an IPv6 range = %+v", got)
	}
	if got := s.Networks(addr("2001:db9::1")); len(got) != 0 {
		t.Errorf("an IPv6 address outside = %+v", got)
	}
}

// Text from the snapshot is sanitised when it is loaded, whatever put it there.
func TestLoad_SanitisesText(t *testing.T) {
	t.Parallel()
	s := sorted(snap())
	s.Nets.Entries[4].Org = "Bad\x1b[31m Org\u202e"
	s.Nets.Entries[4].ScoreTag = "Hi\x07gh"
	s.Nets.Entries[4].OrgType = "is\np"
	s.ASNs.Entries[0].Org = "A\x1b]0;title\x07SN"
	l := abusive.Load(s)
	for _, m := range l.Networks(addr("192.0.2.1")) {
		for _, v := range []string{m.Org, m.ScoreTag, m.OrgType} {
			if strings.ContainsAny(v, "\x1b\x07\n\u202e") {
				t.Errorf("unsanitised text %q in %+v", v, m)
			}
		}
	}
	for _, m := range l.ASN(64050) {
		if strings.ContainsAny(m.Org, "\x1b\x07") {
			t.Errorf("unsanitised ASN org %q", m.Org)
		}
	}
}

// Match JSON preserves the record field order and numeric/string types.
func TestMatches_JSONTypes(t *testing.T) {
	t.Parallel()
	s := abusive.Load(sorted(snap()))
	b, err := json.Marshal(s.Networks(addr("192.0.2.5"))[0])
	if err != nil {
		t.Fatal(err)
	}
	want := `{"network":"192.0.2.0/28","rank":5,"score_tag":"Elevated","abuse_score":12.25,"org":"Tie A","org_type":"banking","updated":"2026-11-21"}`
	if string(b) != want {
		t.Errorf("network match = %s\nwant %s", b, want)
	}
	b, _ = json.Marshal(s.ASN(64050)[0])
	want = `{"asn":64050,"rank":1,"score_tag":"Very High","abuse_score":100,"org":"BGP Network Limited","org_type":"Spamhaus ASN-DROP","updated":"2026-11-20"}`
	if string(b) != want {
		t.Errorf("asn match = %s\nwant %s", b, want)
	}
}

// Marshal writes one entry to a line, so a refresh diffs as the entries that changed, and Parse
// reads back what it wrote.
func TestMarshal_OneEntryPerLineAndRoundTrips(t *testing.T) {
	t.Parallel()
	s := sorted(snap())
	s.Nets.Entries[4].Org = "A & B <Ltd>"
	b := abusive.Marshal(s)
	if !json.Valid(b) {
		t.Fatalf("not JSON:\n%s", b)
	}
	if !bytes.Contains(b, []byte("A & B <Ltd>")) {
		t.Errorf("the organisation was escaped:\n%s", b)
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	entries := 0
	for _, l := range lines {
		if bytes.HasPrefix(bytes.TrimSpace(l), []byte(`{"rank"`)) {
			entries++
		}
	}
	if want := len(s.Nets.Entries) + len(s.ASNs.Entries); entries != want {
		t.Errorf("%d entry lines, want %d:\n%s", entries, want, b)
	}
	back, err := abusive.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(back.Nets.Entries, s.Nets.Entries) || !slices.Equal(back.ASNs.Entries, s.ASNs.Entries) || back.Nets.Updated != s.Nets.Updated {
		t.Errorf("round trip changed the snapshot:\n%+v\n%+v", back, s)
	}
	if !bytes.Equal(abusive.Marshal(back), b) {
		t.Error("marshalling twice gives different bytes")
	}
}

// A snapshot is read by many lookups at once.
func TestSnapshot_ConcurrentUse(t *testing.T) {
	t.Parallel()
	s := abusive.Load(sorted(snap()))
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				_ = s.Networks(addr("10.0.0.17"))
				_ = s.ASN(64050)
			}
		})
	}
	wg.Wait()
}

// Compare the index with an independent full scan across overlapping, nested and boundary
// ranges in both address families.
func TestNetworks_AgreesWithAScanOfEveryEntry(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2))
	at := func(v6 bool, n uint32) netip.Addr {
		if v6 {
			var b [16]byte
			b[0], b[1] = 0x20, 0x01
			binary.BigEndian.PutUint32(b[12:], n)
			return netip.AddrFrom16(b)
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		return netip.AddrFrom4(b)
	}
	type span struct {
		v6     bool
		lo, hi uint32
		rank   int
	}
	const space = 1 << 12
	var spans []span
	for i := range 400 {
		lo := rng.Uint32N(space)
		sp := span{v6: i%3 == 0, lo: lo, hi: min(lo+rng.Uint32N(space/(1+rng.Uint32N(64))), space), rank: 1 + rng.IntN(20)}
		spans = append(spans, sp)
		if i%25 == 0 {
			spans = append(spans, sp) // a repeated entry
		}
	}
	entries := make([]abusive.NetworkEntry, len(spans))
	single := make([]abusive.NetworkMatch, len(spans)) // each entry's match on its own
	for i, sp := range spans {
		entries[i] = abusive.NetworkEntry{Rank: sp.rank, Start: at(sp.v6, sp.lo), End: at(sp.v6, sp.hi), ScoreTag: "High", Org: fmt.Sprint("org", i), OrgType: "isp"}
		one := abusive.Load(abusive.Snapshot{Nets: abusive.List[abusive.NetworkEntry]{Updated: "2026-11-21", Entries: entries[i : i+1]}})
		single[i] = one.Networks(entries[i].Start)[0]
	}
	s := abusive.Load(abusive.Snapshot{Nets: abusive.List[abusive.NetworkEntry]{Updated: "2026-11-21", Entries: entries}})
	for n := range uint32(space + 2) {
		for _, v6 := range []bool{false, true} {
			var held []int
			for i, sp := range spans {
				if sp.v6 == v6 && sp.lo <= n && n <= sp.hi {
					held = append(held, i)
				}
			}
			// The smallest range first, then by rank, then by start, then in list order.
			slices.SortStableFunc(held, func(x, y int) int {
				a, b := spans[x], spans[y]
				return cmp.Or(cmp.Compare(a.hi-a.lo, b.hi-b.lo), cmp.Compare(a.rank, b.rank), cmp.Compare(a.lo, b.lo))
			})
			want := []abusive.NetworkMatch{}
			for _, i := range held {
				want = append(want, single[i])
			}
			if got := s.Networks(at(v6, n)); !slices.Equal(got, want) {
				t.Fatalf("Networks(%s) = %v, want %v", at(v6, n), got, want)
			}
		}
	}
}

// ParseLenient refuses a file with anything after the snapshot, rather than reading the first value
// of it.
func TestParseLenient_RefusesDataAfterTheSnapshot(t *testing.T) {
	t.Parallel()
	plain := abusive.Marshal(counted())
	for _, tail := range []string{"x", "{}", `{"networks":{}}`} {
		if _, err := abusive.ParseLenient(append(slices.Clone(plain), tail...)); err == nil {
			t.Errorf("ParseLenient accepted a file ending in %q", tail)
		}
	}
	if _, err := abusive.ParseLenient(append(slices.Clone(plain), " \n\t"...)); err != nil {
		t.Errorf("ParseLenient refused a file ending in white space: %v", err)
	}
}
