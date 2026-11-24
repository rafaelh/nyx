package spamhaus_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/term/sanitize"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
	tdt "github.com/rafaelh/nyx/internal/threatdata/threatdatatest"
)

// The dates of the test lists: each list has its own, as Spamhaus's do.
var (
	v4Time  = time.Date(2026, 10, 1, 8, 30, 5, 0, time.UTC)
	v6Time  = time.Date(2026, 9, 30, 23, 59, 59, 0, time.UTC)
	asnTime = time.Date(2026, 10, 2, 0, 0, 1, 0, time.UTC)
)

const (
	v4Date  = "2026-10-01T08:30:05Z"
	v6Date  = "2026-09-30T23:59:59Z"
	asnDate = "2026-10-02T00:00:01Z"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// file writes source lines with trailing newlines.
func file(lines ...string) []byte {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return []byte(b.String())
}

func mustDrop(t *testing.T, b []byte, v6 bool) spamhaus.NetworkList {
	t.Helper()
	l, err := spamhaus.ParseDrop(b, v6)
	if err != nil {
		t.Fatalf("ParseDrop(v6=%v): %v\n%s", v6, err, b)
	}
	return l
}

func mustASNDrop(t *testing.T, b []byte) spamhaus.ASNList {
	t.Helper()
	l, err := spamhaus.ParseASNDrop(b)
	if err != nil {
		t.Fatalf("ParseASNDrop: %v\n%s", err, b)
	}
	return l
}

// Fixtures cover unordered nested CIDRs, distinct SBL IDs on one CIDR, absent RIR and nested
// IPv6 ranges.
var (
	v4Rows = []string{
		`{"cidr":"10.0.0.0/8","sblid":"SBL1","rir":"arin"}`,
		`{"cidr":"10.1.2.0/24","sblid":"SBL2","rir":"ripencc"}`,
		`{"cidr":"10.1.0.0/16","sblid":"SBL3","rir":"apnic"}`,
		`{"cidr":"62.60.226.0/24","sblid":"SBL697779","rir":"ripencc"}`,
		`{"cidr":"62.60.226.0/24","sblid":"SBL671779","rir":"ripencc"}`,
		`{"cidr":"192.0.2.7/32","sblid":"SBL4","rir":null}`,
		`{"cidr":"198.51.100.0/24","sblid":"SBL5","rir":"lacnic"}`,
		`{"cidr":"10.1.2.0/24","sblid":"SBL0","rir":"afrinic"}`,
	}
	v6Rows = []string{
		`{"cidr":"2001:db8::/32","sblid":"SBL10","rir":"apnic"}`,
		`{"cidr":"2001:db8:12::/48","sblid":"SBL11","rir":"arin"}`,
	}
	asnRows = []string{
		`{"asn":64500,"rir":"ripencc","domain":"example.net","cc":"RU","asname":"BAD-AS"}`,
		`{"asn":4294967295,"rir":null,"domain":null,"cc":"BR","asname":"Provedor_de_Serviços_Ünïcode_LTDA"}`,
		`{"asn":1,"cc":"AU"}`,
	}
)

func testLists(t *testing.T) spamhaus.Lists {
	t.Helper()
	return spamhaus.Lists{
		V4:   mustDrop(t, tdt.DropFile(v4Time, v4Rows...), false),
		V6:   mustDrop(t, tdt.DropFile(v6Time, v6Rows...), true),
		ASNs: mustASNDrop(t, tdt.DropFile(asnTime, asnRows...)),
	}
}

// matched is each match as "cidr sblid".
func matched(ms []spamhaus.NetworkMatch) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.CIDR+" "+m.SBLID)
	}
	return out
}

// Network matches include endpoints and sort by longest prefix, retaining file order for equal
// lengths.
func TestNetworks_ContainmentAndOrder(t *testing.T) {
	t.Parallel()
	l := testLists(t)
	for _, tc := range []struct {
		addr string
		want []string
	}{
		// A /24's edges and its neighbours.
		{"198.51.100.0", []string{"198.51.100.0/24 SBL5"}},
		{"198.51.100.255", []string{"198.51.100.0/24 SBL5"}},
		{"198.51.99.255", nil},
		{"198.51.101.0", nil},
		// A /32 holds its one address.
		{"192.0.2.7", []string{"192.0.2.7/32 SBL4"}},
		{"192.0.2.6", nil},
		{"192.0.2.8", nil},
		// A /8's edges.
		{"10.0.0.0", []string{"10.0.0.0/8 SBL1"}},
		{"10.255.255.255", []string{"10.0.0.0/8 SBL1"}},
		{"9.255.255.255", nil},
		{"11.0.0.0", nil},
		// Nested CIDRs, listed /8, /24, /16, come longest first; the /24 under two SBL IDs keeps
		// its file order, SBL2 before SBL0.
		{"10.1.2.3", []string{"10.1.2.0/24 SBL2", "10.1.2.0/24 SBL0", "10.1.0.0/16 SBL3", "10.0.0.0/8 SBL1"}},
		{"10.1.2.0", []string{"10.1.2.0/24 SBL2", "10.1.2.0/24 SBL0", "10.1.0.0/16 SBL3", "10.0.0.0/8 SBL1"}},
		{"10.1.2.255", []string{"10.1.2.0/24 SBL2", "10.1.2.0/24 SBL0", "10.1.0.0/16 SBL3", "10.0.0.0/8 SBL1"}},
		{"10.1.3.0", []string{"10.1.0.0/16 SBL3", "10.0.0.0/8 SBL1"}},
		{"10.1.255.255", []string{"10.1.0.0/16 SBL3", "10.0.0.0/8 SBL1"}},
		{"10.2.0.0", []string{"10.0.0.0/8 SBL1"}},
		// One CIDR under two SBL IDs is two entries, in file order.
		{"62.60.226.9", []string{"62.60.226.0/24 SBL697779", "62.60.226.0/24 SBL671779"}},
		// IPv6: a /48 inside a /32, and the edges of each.
		{"2001:db8:12::", []string{"2001:db8:12::/48 SBL11", "2001:db8::/32 SBL10"}},
		{"2001:db8:12:ffff:ffff:ffff:ffff:ffff", []string{"2001:db8:12::/48 SBL11", "2001:db8::/32 SBL10"}},
		{"2001:db8:11:ffff:ffff:ffff:ffff:ffff", []string{"2001:db8::/32 SBL10"}},
		{"2001:db8:13::", []string{"2001:db8::/32 SBL10"}},
		{"2001:db8::", []string{"2001:db8::/32 SBL10"}},
		{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", []string{"2001:db8::/32 SBL10"}},
		{"2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", nil},
		{"2001:db9::", nil},
		// An IPv4-mapped address is its IPv4 address.
		{"::ffff:10.1.3.4", []string{"10.1.0.0/16 SBL3", "10.0.0.0/8 SBL1"}},
		{"::ffff:198.51.100.255", []string{"198.51.100.0/24 SBL5"}},
		{"::ffff:198.51.101.0", nil},
	} {
		if got := matched(l.Networks(addr(tc.addr))); !slices.Equal(got, tc.want) {
			t.Errorf("Networks(%s) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// Matching through the parse's index gives what a scan of every entry gives: the containing
// entries, longest prefix first, then in file order.
func TestNetworks_SameAsAScan(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2))
	// Prefixes inside 10.0.0.0/12 and 2001:db8::/44 nest and repeat often; a CIDR can repeat
	// under another SBL ID.
	var rows4, rows6 []string
	var nets4, nets6 []netip.Prefix
	for i := range 600 {
		p4 := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(rng.IntN(16)), byte(rng.IntN(256)), byte(rng.IntN(256))}), 12+rng.IntN(21)).Masked()
		nets4 = append(nets4, p4)
		rows4 = append(rows4, tdt.NetRow(p4.String(), fmt.Sprintf("SBL%d", i), "arin"))
		b := netip.MustParseAddr("2001:db8::").As16()
		b[5] = byte(rng.IntN(16))
		b[6], b[7] = byte(rng.IntN(256)), byte(rng.IntN(256))
		p6 := netip.PrefixFrom(netip.AddrFrom16(b), 44+rng.IntN(21)).Masked()
		nets6 = append(nets6, p6)
		rows6 = append(rows6, tdt.NetRow(p6.String(), fmt.Sprintf("SBL%d", i), "ripencc"))
	}
	l := spamhaus.Lists{V4: mustDrop(t, tdt.DropFile(v4Time, rows4...), false), V6: mustDrop(t, tdt.DropFile(v6Time, rows6...), true)}
	// scan is the contract: every containing entry, stably sorted by descending prefix length.
	scan := func(nets []netip.Prefix, a netip.Addr) []string {
		var hits []int
		for i, p := range nets {
			if p.Contains(a) {
				hits = append(hits, i)
			}
		}
		slices.SortStableFunc(hits, func(x, y int) int { return nets[y].Bits() - nets[x].Bits() })
		var out []string
		for _, i := range hits {
			out = append(out, fmt.Sprintf("%s SBL%d", nets[i], i))
		}
		return out
	}
	var addrs []netip.Addr
	for range 2000 {
		addrs = append(addrs,
			netip.AddrFrom4([4]byte{10, byte(rng.IntN(17)), byte(rng.IntN(256)), byte(rng.IntN(256))}),
			nets6[rng.IntN(len(nets6))].Addr().Next())
	}
	for _, p := range slices.Concat(nets4, nets6) { // every entry's edges and their neighbours
		b := p.Addr().AsSlice()
		for i := p.Bits(); i < len(b)*8; i++ {
			b[i/8] |= 0x80 >> (i % 8)
		}
		last, _ := netip.AddrFromSlice(b)
		addrs = append(addrs, p.Addr(), p.Addr().Prev(), last, last.Next())
	}
	for _, a := range addrs {
		nets := nets6
		if a.Is4() {
			nets = nets4
		}
		if got, want := matched(l.Networks(a)), scan(nets, a); !slices.Equal(got, want) {
			t.Fatalf("Networks(%s) = %q, want %q", a, got, want)
		}
	}
}

// Unmap IPv4 before matching DROP; IPv6 matches DROPv6 only.
func TestNetworks_EachFamilyItsOwnList(t *testing.T) {
	t.Parallel()
	l := spamhaus.Lists{
		V4:   mustDrop(t, tdt.DropFile(v4Time, `{"cidr":"0.0.0.0/0","sblid":"SBL40","rir":"arin"}`), false),
		V6:   mustDrop(t, tdt.DropFile(v6Time, `{"cidr":"::/0","sblid":"SBL60","rir":"arin"}`), true),
		ASNs: mustASNDrop(t, tdt.DropFile(asnTime, asnRows...)),
	}
	for _, tc := range []struct {
		addr string
		want []string
	}{
		{"198.51.100.5", []string{"0.0.0.0/0 SBL40"}},
		{"::ffff:198.51.100.5", []string{"0.0.0.0/0 SBL40"}},
		{"2001:db8::1", []string{"::/0 SBL60"}},
		{"::1", []string{"::/0 SBL60"}},
	} {
		if got := matched(l.Networks(addr(tc.addr))); !slices.Equal(got, tc.want) {
			t.Errorf("Networks(%s) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// A match carries the entry's CIDR, SBL ID and RIR, a null RIR as "", and its own list's date.
func TestNetworks_MatchCarriesTheEntryAndItsListsDate(t *testing.T) {
	t.Parallel()
	l := testLists(t)
	if got, want := l.Networks(addr("192.0.2.7")), []spamhaus.NetworkMatch{{CIDR: "192.0.2.7/32", SBLID: "SBL4", RIR: "", Updated: v4Date}}; !slices.Equal(got, want) {
		t.Errorf("a /32 with a null RIR = %+v, want %+v", got, want)
	}
	if got, want := l.Networks(addr("198.51.100.1")), []spamhaus.NetworkMatch{{CIDR: "198.51.100.0/24", SBLID: "SBL5", RIR: "lacnic", Updated: v4Date}}; !slices.Equal(got, want) {
		t.Errorf("a v4 match = %+v, want %+v", got, want)
	}
	want6 := []spamhaus.NetworkMatch{
		{CIDR: "2001:db8:12::/48", SBLID: "SBL11", RIR: "arin", Updated: v6Date},
		{CIDR: "2001:db8::/32", SBLID: "SBL10", RIR: "apnic", Updated: v6Date},
	}
	if got := l.Networks(addr("2001:db8:12::5")); !slices.Equal(got, want6) {
		t.Errorf("a v6 match = %+v, want %+v", got, want6)
	}
	if got := l.Networks(addr("203.0.113.1")); len(got) != 0 {
		t.Errorf("an address nothing holds = %+v, want none", got)
	}
}

// ASN matches preserve metadata/text/date and normalise absent optional fields to empty
// strings.
func TestASN_Match(t *testing.T) {
	t.Parallel()
	l := testLists(t)
	for _, tc := range []struct {
		asn  int
		want []spamhaus.ASNMatch
	}{
		{64500, []spamhaus.ASNMatch{{ASN: 64500, ASName: "BAD-AS", Country: "RU", Domain: "example.net", RIR: "ripencc", Updated: asnDate}}},
		{4294967295, []spamhaus.ASNMatch{{ASN: 4294967295, ASName: "Provedor_de_Serviços_Ünïcode_LTDA", Country: "BR", Updated: asnDate}}},
		{1, []spamhaus.ASNMatch{{ASN: 1, Country: "AU", Updated: asnDate}}},
	} {
		if got := l.ASN(tc.asn); !slices.Equal(got, tc.want) {
			t.Errorf("ASN(%d) = %+v, want %+v", tc.asn, got, tc.want)
		}
	}
	for _, n := range []int{64501, 0, 2} {
		if got := l.ASN(n); len(got) != 0 {
			t.Errorf("ASN(%d), unlisted, = %+v, want none", n, got)
		}
	}
}

// The JSON of a match has the keys the nyx ip record gives, in order, and the dates in RFC 3339 UTC.
func TestMatches_JSON(t *testing.T) {
	t.Parallel()
	l := testLists(t)
	nets := l.Networks(addr("192.0.2.7"))
	asns := l.ASN(64500)
	if len(nets) != 1 || len(asns) != 1 {
		t.Fatalf("matches = %+v and %+v, want one of each", nets, asns)
	}
	b, err := json.Marshal(nets[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"cidr":"192.0.2.7/32","sbl_id":"SBL4","rir":"","updated":"` + v4Date + `"}`; string(b) != want {
		t.Errorf("network match = %s\nwant %s", b, want)
	}
	b, err = json.Marshal(asns[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"asn":64500,"as_name":"BAD-AS","country":"RU","domain":"example.net","rir":"ripencc","updated":"` + asnDate + `"}`; string(b) != want {
		t.Errorf("ASN match = %s\nwant %s", b, want)
	}
}

// Sanitise match text even after parsing because non-control Unicode can still affect terminal
// display.
func TestMatches_SanitiseText(t *testing.T) {
	t.Parallel()
	sbl, rir := "SBL\u202e9", "ri\u2066pe\u2069ncc"
	name, cc, domain := "Bad\u202aAS\u202c", "R\u200fU", "ex\u200eample.net"
	l := spamhaus.Lists{
		V4: mustDrop(t, tdt.DropFile(v4Time, `{"cidr":"203.0.113.0/24","sblid":"SBL\u202e9","rir":"ri\u2066pe\u2069ncc"}`), false),
		V6: mustDrop(t, tdt.DropFile(v6Time, v6Rows...), true),
		ASNs: mustASNDrop(t, tdt.DropFile(asnTime,
			`{"asn":64999,"rir":"ri\u2066pe\u2069ncc","domain":"ex\u200eample.net","cc":"R\u200fU","asname":"Bad\u202aAS\u202c"}`)),
	}
	wantNet := []spamhaus.NetworkMatch{{CIDR: "203.0.113.0/24", SBLID: sanitize.Line(sbl), RIR: sanitize.Line(rir), Updated: v4Date}}
	if got := l.Networks(addr("203.0.113.9")); !slices.Equal(got, wantNet) {
		t.Errorf("network match = %+v, want %+v", got, wantNet)
	}
	wantASN := []spamhaus.ASNMatch{{ASN: 64999, ASName: sanitize.Line(name), Country: sanitize.Line(cc), Domain: sanitize.Line(domain), RIR: sanitize.Line(rir), Updated: asnDate}}
	if got := l.ASN(64999); !slices.Equal(got, wantASN) {
		t.Errorf("ASN match = %+v, want %+v", got, wantASN)
	}
	if sanitize.Line(sbl) == sbl || sanitize.Line(name) == name {
		t.Fatal("the test text has nothing to sanitise")
	}
}

// Source timestamps always format in UTC, regardless of their original location.
func TestMeta_Updated(t *testing.T) {
	t.Parallel()
	l := mustDrop(t, tdt.DropFile(v4Time, v4Rows...), false)
	if !l.Meta.Timestamp.Equal(v4Time) {
		t.Errorf("timestamp = %v, want %v", l.Meta.Timestamp, v4Time)
	}
	if got := l.Meta.Updated(); got != v4Date {
		t.Errorf("Updated() = %q, want %q", got, v4Date)
	}
	east := spamhaus.Meta{Timestamp: time.Date(2026, 10, 1, 18, 30, 5, 0, time.FixedZone("AEST", 10*60*60))}
	if got := east.Updated(); got != v4Date {
		t.Errorf("Updated() of a time held in UTC+10 = %q, want %q", got, v4Date)
	}
}

// A parsed list holds its entries in file order, its metadata and the file's bytes as they were.
func TestParseDrop_Contents(t *testing.T) {
	t.Parallel()
	b := tdt.DropFile(v4Time, v4Rows...)
	l := mustDrop(t, b, false)
	if !bytes.Equal(l.Raw, b) {
		t.Errorf("Raw is not the file's bytes:\n%s", l.Raw)
	}
	want := spamhaus.Meta{Timestamp: v4Time, Records: len(v4Rows), Copyright: "(c) 2026 The Spamhaus Project SLU", Terms: "https://www.spamhaus.org/drop/terms/"}
	if !l.Meta.Timestamp.Equal(want.Timestamp) || l.Meta.Records != want.Records || l.Meta.Copyright != want.Copyright || l.Meta.Terms != want.Terms {
		t.Errorf("meta = %+v, want %+v", l.Meta, want)
	}
	if len(l.Entries) != len(v4Rows) {
		t.Fatalf("%d entries, want %d", len(l.Entries), len(v4Rows))
	}
	if got, want := l.Entries[0], (spamhaus.NetworkEntry{CIDR: netip.MustParsePrefix("10.0.0.0/8"), SBLID: "SBL1", RIR: "arin"}); got != want {
		t.Errorf("entry 1 = %+v, want %+v", got, want)
	}
	if got, want := l.Entries[5], (spamhaus.NetworkEntry{CIDR: netip.MustParsePrefix("192.0.2.7/32"), SBLID: "SBL4"}); got != want {
		t.Errorf("entry 6, with a null RIR, = %+v, want %+v", got, want)
	}
	if got := l.Entries[7].SBLID; got != "SBL0" {
		t.Errorf("entry 8 is %q, want SBL0: entries are kept in file order", got)
	}
	a := mustASNDrop(t, tdt.DropFile(asnTime, asnRows...))
	if len(a.Entries) != len(asnRows) {
		t.Fatalf("%d ASN entries, want %d", len(a.Entries), len(asnRows))
	}
	if got, want := a.Entries[1], (spamhaus.ASNEntry{ASN: 4294967295, ASName: "Provedor_de_Serviços_Ünïcode_LTDA", Country: "BR"}); got != want {
		t.Errorf("ASN entry 2 = %+v, want %+v", got, want)
	}
	if !a.Meta.Timestamp.Equal(asnTime) || a.Meta.Records != len(asnRows) {
		t.Errorf("ASN meta = %+v", a.Meta)
	}
}

// v4Many is n distinct DROP rows.
func v4Many(n int) []string {
	rows := make([]string, n)
	for i := range n {
		rows[i] = fmt.Sprintf(`{"cidr":"10.%d.%d.0/24","sblid":"SBL%d","rir":"arin"}`, i/250, i%250, 1000+i)
	}
	return rows
}

// Reject corrupt source text while tolerating unknown fields and absent optional metadata.
func TestParse_Rules(t *testing.T) {
	t.Parallel()
	r1 := `{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"arin"}`
	r2 := `{"cidr":"198.51.100.0/24","sblid":"SBL2","rir":"ripencc"}`
	r6 := `{"cidr":"2001:db8::/32","sblid":"SBL6","rir":"apnic"}`
	a1 := `{"asn":64500,"rir":"ripencc","domain":"example.net","cc":"RU","asname":"BAD-AS"}`
	m := func(records int) string { return tdt.MetaLine(v4Time, records) }
	type list int
	const (
		v4 list = iota
		v6
		asn
	)
	for _, tc := range []struct {
		name string
		list list
		b    []byte
		ok   bool
	}{
		{"a good list", v4, file(r1, r2, m(2)), true},
		{"a good IPv6 list", v6, file(r6, m(1)), true},
		{"a good ASN list", asn, file(a1, m(1)), true},

		// Rows that don't parse.
		{"a row that is not JSON", v4, file(r1, "not json", m(2)), false},
		{"a truncated row", v4, file(r1, `{"cidr":"198.51.100.0/24",`, m(2)), false},
		{"a row that is not an object", v4, file(r1, `["198.51.100.0/24","SBL2"]`, m(2)), false},
		{"a CIDR that is not a string", v4, file(r1, `{"cidr":5,"sblid":"SBL2"}`, m(2)), false},
		{"an ASN row that is not JSON", asn, file(a1, "{asn:64501}", m(2)), false},

		// Required fields.
		{"a missing cidr", v4, file(r1, `{"sblid":"SBL2","rir":"arin"}`, m(2)), false},
		{"a missing sblid", v4, file(r1, `{"cidr":"198.51.100.0/24","rir":"arin"}`, m(2)), false},
		{"a missing IPv6 cidr", v6, file(r6, `{"sblid":"SBL7","rir":"arin"}`, m(2)), false},
		{"a missing asn", asn, file(a1, `{"rir":"arin","domain":"x.example","cc":"US","asname":"X"}`, m(2)), false},

		// CIDRs.
		{"a CIDR with no prefix length", v4, file(r1, `{"cidr":"198.51.100.0","sblid":"SBL2"}`, m(2)), false},
		{"a CIDR that is not one", v4, file(r1, `{"cidr":"somewhere/24","sblid":"SBL2"}`, m(2)), false},
		{"a non-canonical CIDR", v4, file(r1, `{"cidr":"198.51.100.5/24","sblid":"SBL2"}`, m(2)), false},
		{"a non-canonical IPv6 CIDR", v6, file(r6, `{"cidr":"2001:db8:1::1/48","sblid":"SBL7"}`, m(2)), false},
		{"an IPv6 CIDR in DROP", v4, file(r1, `{"cidr":"2001:db8:1::/48","sblid":"SBL2"}`, m(2)), false},
		{"an IPv4 CIDR in DROPv6", v6, file(r6, `{"cidr":"198.51.100.0/24","sblid":"SBL7"}`, m(2)), false},

		// AS numbers.
		{"AS0", asn, file(a1, `{"asn":0,"cc":"US"}`, m(2)), false},
		{"a negative ASN", asn, file(a1, `{"asn":-1,"cc":"US"}`, m(2)), false},
		{"an ASN over 32 bits", asn, file(a1, `{"asn":4294967296,"cc":"US"}`, m(2)), false},
		{"an ASN that is a string", asn, file(a1, `{"asn":"AS64501","cc":"US"}`, m(2)), false},
		{"AS1", asn, file(a1, `{"asn":1,"cc":"US"}`, m(2)), true},
		{"AS4294967295", asn, file(a1, `{"asn":4294967295,"cc":"US"}`, m(2)), true},

		// Control characters, in a row and in the metadata.
		{"a C0 character in a RIR", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","rir":"ar\u0007in"}`, m(2)), false},
		{"an escape in an SBL ID", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL\u001b[31m2"}`, m(2)), false},
		{"a C1 character in a RIR", v6, file(r6, `{"cidr":"2001:db8:1::/48","sblid":"SBL7","rir":"arin\u0085"}`, m(2)), false},
		{"a newline in an AS name", asn, file(a1, `{"asn":64501,"asname":"BAD\nAS","cc":"US"}`, m(2)), false},
		{"a C0 character in a country", asn, file(a1, `{"asn":64501,"cc":"U\u0000S"}`, m(2)), false},
		{"a C1 character in a domain", asn, file(a1, `{"asn":64501,"domain":"x\u009b.example"}`, m(2)), false},
		{"a tab in a domain", asn, file(a1, `{"asn":64501,"domain":"x\t.example"}`, m(2)), false},
		{"a control character in the copyright", v4, file(r1, `{"type":"metadata","timestamp":1790000000,"records":1,"copyright":"(c) Spamhaus\u0007","terms":"https://www.spamhaus.org/drop/terms/"}`), false},
		{"a C1 character in the terms", asn, file(a1, `{"type":"metadata","timestamp":1790000000,"records":1,"copyright":"(c) Spamhaus","terms":"https://www.spamhaus.org/\u0085"}`), false},

		// Entries listed twice.
		{"an identical pair twice", v4, file(r1, r2, r1, m(3)), false},
		{"an identical IPv6 pair twice", v6, file(r6, r6, m(2)), false},
		{"a CIDR under two SBL IDs", v4, file(r1, `{"cidr":"192.0.2.0/24","sblid":"SBL9","rir":"arin"}`, m(2)), true},
		{"an SBL ID over two CIDRs", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL1","rir":"arin"}`, m(2)), true},
		{"an identical pair with another RIR", v4, file(r1, `{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"apnic"}`, m(2)), false},
		{"an ASN twice", asn, file(a1, `{"asn":64500,"cc":"US"}`, m(2)), false},

		// The metadata line.
		{"no metadata line", v4, file(r1, r2), false},
		{"an empty file", v4, nil, false},
		{"only blank lines", asn, file("", ""), false},
		{"the metadata line not last", v4, file(r1, m(2), r2), false},
		{"a last line of another type", v4, file(r1, `{"type":"summary","timestamp":1790000000,"records":1}`), false},
		{"a timestamp of 0", v4, file(r1, `{"type":"metadata","timestamp":0,"records":1}`), false},
		{"a negative timestamp", v6, file(r6, `{"type":"metadata","timestamp":-5,"records":1}`), false},
		{"no timestamp", asn, file(a1, `{"type":"metadata","records":1}`), false},
		{"a negative records count", v4, file(r1, `{"type":"metadata","timestamp":1790000000,"records":-1}`), false},
		{"a metadata line that is not JSON", v4, file(r1, `{"type":"metadata",`), false},
		{"no copyright or terms", v4, file(r1, `{"type":"metadata","timestamp":1790000000,"records":1}`), true},
		{"no rows and records 0", v4, file(m(0)), true},

		// The stated count.
		{"89 of 100 records", v4, file(append(v4Many(89), m(100))...), false},
		{"90 of 100 records", v4, file(append(v4Many(90), m(100))...), true},
		{"9 of 10 records", v4, file(append(v4Many(9), m(10))...), true},
		{"8 of 10 records", v4, file(append(v4Many(8), m(10))...), false},
		{"more rows than records", v4, file(append(v4Many(12), m(10))...), true},
		{"no rows of 1 record", asn, file(m(1)), false},
		{"1 of 2 ASN records", asn, file(a1, m(2)), false},

		// What passes.
		{"an unknown field in a row", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","rir":"arin","added":"2026-09-01"}`, m(2)), true},
		{"an unknown field in an ASN row", asn, file(`{"asn":64500,"rir":"arin","domain":"x.example","cc":"US","asname":"X","notes":["a"]}`, m(1)), true},
		{"an unknown field in the metadata", v4, file(r1, `{"type":"metadata","timestamp":1790000000,"records":1,"version":2}`), true},
		{"a null RIR", v4, file(`{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":null}`, m(1)), true},
		{"no RIR", v6, file(`{"cidr":"2001:db8::/32","sblid":"SBL6"}`, m(1)), true},
		{"null and absent ASN fields", asn, file(`{"asn":64500,"rir":null,"domain":null,"cc":null}`, m(1)), true},
		{"blank lines", v4, file("", r1, "", r2, m(2), ""), true},
		{"no final newline", v4, []byte(r1 + "\n" + m(1)), true},
		{"non-ASCII text", asn, file(`{"asn":64500,"asname":"Serviços Ünïcode – Ltd","cc":"BR"}`, m(1)), true},
	} {
		var err error
		var n int
		switch tc.list {
		case v4, v6:
			var l spamhaus.NetworkList
			l, err = spamhaus.ParseDrop(tc.b, tc.list == v6)
			n = len(l.Entries)
		case asn:
			var l spamhaus.ASNList
			l, err = spamhaus.ParseASNDrop(tc.b)
			n = len(l.Entries)
		}
		switch {
		case tc.ok && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case !tc.ok && err == nil:
			t.Errorf("%s: accepted", tc.name)
		case tc.ok && n == 0 && tc.name != "no rows and records 0":
			t.Errorf("%s: accepted with no entries", tc.name)
		}
	}
}

// Normalise missing optional text and ignore unknown fields without changing entries.
func TestParse_OptionalAndUnknownFields(t *testing.T) {
	t.Parallel()
	l := mustDrop(t, tdt.DropFile(v4Time,
		`{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":null}`,
		`{"cidr":"198.51.100.0/24","sblid":"SBL2"}`,
		`{"cidr":"203.0.113.0/24","sblid":"SBL3","rir":"arin","added":"2026-09-01"}`), false)
	want := []spamhaus.NetworkEntry{
		{CIDR: netip.MustParsePrefix("192.0.2.0/24"), SBLID: "SBL1"},
		{CIDR: netip.MustParsePrefix("198.51.100.0/24"), SBLID: "SBL2"},
		{CIDR: netip.MustParsePrefix("203.0.113.0/24"), SBLID: "SBL3", RIR: "arin"},
	}
	if !slices.Equal(l.Entries, want) {
		t.Errorf("entries = %+v, want %+v", l.Entries, want)
	}
	a := mustASNDrop(t, tdt.DropFile(asnTime,
		`{"asn":64500,"rir":null,"domain":null,"cc":null,"asname":null}`,
		`{"asn":64501}`,
		`{"asn":64502,"rir":"arin","domain":"x.example","cc":"US","asname":"X","notes":["a"]}`))
	wantASN := []spamhaus.ASNEntry{{ASN: 64500}, {ASN: 64501}, {ASN: 64502, ASName: "X", Country: "US", Domain: "x.example", RIR: "arin"}}
	if !slices.Equal(a.Entries, wantASN) {
		t.Errorf("ASN entries = %+v, want %+v", a.Entries, wantASN)
	}
	if m := mustDrop(t, file(`{"cidr":"192.0.2.0/24","sblid":"SBL1"}`, `{"type":"metadata","timestamp":1790000000,"records":1}`), false).Meta; m.Copyright != "" || m.Terms != "" || m.Records != 1 {
		t.Errorf("metadata with no copyright or terms = %+v", m)
	}
}

// Bundles preserve source bytes in fixed marker order, adding only missing final newlines.
func TestBundle_Format(t *testing.T) {
	t.Parallel()
	got := spamhaus.Bundle([]byte("a\nb\n"), []byte("c\n"), []byte("d\ne\n"))
	want := "{\"list\":\"drop_v4\"}\na\nb\n{\"list\":\"drop_v6\"}\nc\n{\"list\":\"asndrop\"}\nd\ne\n"
	if string(got) != want {
		t.Errorf("Bundle = %q\nwant %q", got, want)
	}
	got = spamhaus.Bundle([]byte("a"), []byte("c\n"), []byte("d"))
	want = "{\"list\":\"drop_v4\"}\na\n{\"list\":\"drop_v6\"}\nc\n{\"list\":\"asndrop\"}\nd\n"
	if string(got) != want {
		t.Errorf("Bundle with no final newlines = %q\nwant %q", got, want)
	}
}

// A bundle parses to the three lists, each as it parses alone, and bundling the lists' bytes again
// gives the same bundle.
func TestParseBundle_RoundTrip(t *testing.T) {
	t.Parallel()
	v4, v6, asn := tdt.DropFile(v4Time, v4Rows...), tdt.DropFile(v6Time, v6Rows...), tdt.DropFile(asnTime, asnRows...)
	b := spamhaus.Bundle(v4, v6, asn)
	l, err := spamhaus.ParseBundle(b)
	if err != nil {
		t.Fatalf("ParseBundle: %v\n%s", err, b)
	}
	if !bytes.Equal(l.V4.Raw, v4) || !bytes.Equal(l.V6.Raw, v6) || !bytes.Equal(l.ASNs.Raw, asn) {
		t.Errorf("the lists' bytes are not the files':\n%s\n%s\n%s", l.V4.Raw, l.V6.Raw, l.ASNs.Raw)
	}
	alone := testLists(t)
	if !slices.Equal(l.V4.Entries, alone.V4.Entries) || !slices.Equal(l.V6.Entries, alone.V6.Entries) || !slices.Equal(l.ASNs.Entries, alone.ASNs.Entries) {
		t.Errorf("the bundle's entries differ from each list's alone:\n%+v\n%+v", l, alone)
	}
	if len(l.V4.Entries) != len(v4Rows) || len(l.V6.Entries) != len(v6Rows) || len(l.ASNs.Entries) != len(asnRows) {
		t.Errorf("entries = %d, %d, %d; want %d, %d, %d", len(l.V4.Entries), len(l.V6.Entries), len(l.ASNs.Entries), len(v4Rows), len(v6Rows), len(asnRows))
	}
	if !l.V4.Meta.Timestamp.Equal(v4Time) || !l.V6.Meta.Timestamp.Equal(v6Time) || !l.ASNs.Meta.Timestamp.Equal(asnTime) {
		t.Errorf("dates = %v, %v, %v", l.V4.Meta.Timestamp, l.V6.Meta.Timestamp, l.ASNs.Meta.Timestamp)
	}
	if again := spamhaus.Bundle(l.V4.Raw, l.V6.Raw, l.ASNs.Raw); !bytes.Equal(again, b) {
		t.Errorf("bundling the parsed lists again = %q\nwant %q", again, b)
	}
	// A bundle's lists match as lists parsed alone do.
	if got := matched(l.Networks(addr("10.1.2.3"))); !slices.Equal(got, []string{"10.1.2.0/24 SBL2", "10.1.2.0/24 SBL0", "10.1.0.0/16 SBL3", "10.0.0.0/8 SBL1"}) {
		t.Errorf("Networks from a bundle = %q", got)
	}
	if got := l.ASN(64500); len(got) != 1 || got[0].Updated != asnDate {
		t.Errorf("ASN from a bundle = %+v", got)
	}
}

// Any invalid list or marker ordering rejects the entire bundle.
func TestParseBundle_Refuses(t *testing.T) {
	t.Parallel()
	v4, v6, asn := tdt.DropFile(v4Time, v4Rows...), tdt.DropFile(v6Time, v6Rows...), tdt.DropFile(asnTime, asnRows...)
	marker := func(name string) []byte { return []byte(`{"list":"` + name + `"}` + "\n") }
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	badV4 := tdt.DropFile(v4Time, append(slices.Clone(v4Rows), `{"cidr":"198.51.100.5/24","sblid":"SBL99"}`)...)
	badV6 := tdt.DropFile(v6Time, append(slices.Clone(v6Rows), `{"sblid":"SBL99"}`)...)
	badASN := tdt.DropFile(asnTime, append(slices.Clone(asnRows), `{"asn":0}`)...)
	if _, err := spamhaus.ParseBundle(spamhaus.Bundle(v4, v6, asn)); err != nil {
		t.Fatalf("the good bundle: %v", err)
	}
	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"an empty bundle", nil},
		{"no marker lines", cat(v4, v6, asn)},
		{"lines before the first marker", cat([]byte(v4Rows[0]+"\n"), spamhaus.Bundle(v4, v6, asn))},
		{"the lists out of order", cat(marker("drop_v6"), v6, marker("drop_v4"), v4, marker("asndrop"), asn)},
		{"asndrop first", cat(marker("asndrop"), asn, marker("drop_v4"), v4, marker("drop_v6"), v6)},
		{"no asndrop", cat(marker("drop_v4"), v4, marker("drop_v6"), v6)},
		{"only drop_v4", cat(marker("drop_v4"), v4)},
		{"a list twice", cat(spamhaus.Bundle(v4, v6, asn), marker("asndrop"), asn)},
		{"an unknown list", cat(marker("drop_v4"), v4, marker("drop_v5"), v6, marker("asndrop"), asn)},
		{"an empty list", cat(marker("drop_v4"), v4, marker("drop_v6"), marker("asndrop"), asn)},
		{"DROPv6 under the drop_v4 marker", spamhaus.Bundle(v6, v4, asn)},
		{"a bad drop_v4", spamhaus.Bundle(badV4, v6, asn)},
		{"a bad drop_v6", spamhaus.Bundle(v4, badV6, asn)},
		{"a bad asndrop", spamhaus.Bundle(v4, v6, badASN)},
		{"drop_v4 with no metadata", spamhaus.Bundle(file(v4Rows...), v6, asn)},
	} {
		if _, err := spamhaus.ParseBundle(tc.b); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

// The embedded bundle is the file in the package, it parses and passes every check, and it bundles
// back to itself.
func TestBuiltin_ParsesAndValidates(t *testing.T) {
	t.Parallel()
	onDisk, err := os.ReadFile("builtin.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(spamhaus.Builtin(), onDisk) {
		t.Fatal("Builtin is not builtin.jsonl")
	}
	l, err := spamhaus.ParseBundle(spamhaus.Builtin())
	if err != nil {
		t.Fatalf("the built-in bundle is refused: %v", err)
	}
	if len(l.V4.Entries) == 0 || len(l.V6.Entries) == 0 || len(l.ASNs.Entries) == 0 {
		t.Errorf("entries = %d, %d, %d; want some in each list", len(l.V4.Entries), len(l.V6.Entries), len(l.ASNs.Entries))
	}
	for _, m := range []spamhaus.Meta{l.V4.Meta, l.V6.Meta, l.ASNs.Meta} {
		if m.Timestamp.IsZero() || m.Timestamp.Unix() <= 0 {
			t.Errorf("a list has no date: %+v", m)
		}
	}
	// The run-time credit falls back to the built-in drop_v4's, so it must have one.
	if !strings.Contains(l.V4.Meta.Copyright, "Spamhaus") || !strings.HasPrefix(l.V4.Meta.Terms, "https://") {
		t.Errorf("the built-in drop_v4 credit = %q, %q", l.V4.Meta.Copyright, l.V4.Meta.Terms)
	}
	if again := spamhaus.Bundle(l.V4.Raw, l.V6.Raw, l.ASNs.Raw); !bytes.Equal(again, onDisk) {
		t.Error("bundling the built-in lists again does not give the file")
	}
}

// Every built-in entry matches the addresses its CIDR starts and ends with, and every built-in ASN
// matches itself.
func TestBuiltin_EveryEntryMatches(t *testing.T) {
	t.Parallel()
	l, err := spamhaus.ParseBundle(spamhaus.Builtin())
	if err != nil {
		t.Fatalf("the built-in bundle is refused: %v", err)
	}
	if len(l.V4.Entries) == 0 {
		t.Fatal("the built-in bundle has no DROP entries")
	}
	for _, list := range []spamhaus.NetworkList{l.V4, l.V6} {
		for _, e := range list.Entries {
			want := spamhaus.NetworkMatch{CIDR: e.CIDR.String(), SBLID: sanitize.Line(e.SBLID), RIR: sanitize.Line(e.RIR), Updated: list.Meta.Updated()}
			for _, a := range []netip.Addr{e.CIDR.Addr(), last(e.CIDR)} {
				if !slices.Contains(l.Networks(a), want) {
					t.Fatalf("Networks(%s) = %+v, which lacks %+v", a, l.Networks(a), want)
				}
			}
		}
	}
	for _, e := range l.ASNs.Entries {
		if got := l.ASN(e.ASN); len(got) != 1 || got[0].ASN != e.ASN || got[0].Updated != l.ASNs.Meta.Updated() {
			t.Fatalf("ASN(%d) = %+v", e.ASN, got)
		}
	}
}

// last is the last address a prefix holds.
func last(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}
