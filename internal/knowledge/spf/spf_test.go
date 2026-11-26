package spf_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/knowledge/spf"
)

// A name's SPF record is its one TXT string that starts with v=spf1, compared without regard to
// case; with none, or with more than one, it has no usable record.
func TestRecord(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		txts []string
		want string
		ok   bool
	}{
		{"no TXT strings", nil, "", false},
		{"no SPF record", []string{"google-site-verification=abc123"}, "", false},
		{"one record", []string{"v=spf1 ip4:192.0.3.0/24 -all"}, "v=spf1 ip4:192.0.3.0/24 -all", true},
		{"one record among others",
			[]string{"google-site-verification=abc123", "v=spf1 include:_spf.example.com ~all", "MS=ms12345"},
			"v=spf1 include:_spf.example.com ~all", true},
		{"the version in upper case", []string{"V=SPF1 -all"}, "V=SPF1 -all", true},
		{"the version alone", []string{"v=spf1"}, "v=spf1", true},
		{"two records", []string{"v=spf1 ip4:192.0.3.0/24 -all", "v=spf1 ip4:198.51.101.0/24 -all"}, "", false},
		{"two records in different case", []string{"v=spf1 -all", "V=SPF1 ~all"}, "", false},
		{"a longer version is not SPF", []string{"v=spf10 ip4:192.0.3.0/24 -all"}, "", false},
		{"a longer version beside a record", []string{"v=spf10 -all", "v=spf1 -all"}, "v=spf1 -all", true},
		{"the version not at the start", []string{"text v=spf1 -all"}, "", false},
	} {
		got, ok := spf.Record(tc.txts)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: Record(%q) = %q, %v; want %q, %v", tc.name, tc.txts, got, ok, tc.want, tc.ok)
		}
	}
}

// Surrounding white space does not stop a string being the record.
func TestRecord_SurroundingSpace(t *testing.T) {
	t.Parallel()
	got, ok := spf.Record([]string{"  v=spf1 -all "})
	if !ok || strings.TrimSpace(got) != "v=spf1 -all" {
		t.Errorf("Record = %q, %v; want the record", got, ok)
	}
}

// Parse gives every term after the version in order, with its qualifier ('+' when none is
// written), its name in lower case and the text after its ':' or '='.
func TestParse_Terms(t *testing.T) {
	t.Parallel()
	record := "v=spf1 ip4:192.0.3.0/24 +ip4:198.51.101.7 -IP4:203.0.114.0/24 ~ip6:2a00:1450::/32 " +
		"?a:mail.example.com a mx  include:_spf.example.com MX:mx.example.com/24 exists:%{i}.example.com " +
		"REDIRECT=_spf.example.net exp=explain.example.com -all"
	want := []spf.Term{
		{Qualifier: '+', Name: "ip4", Value: "192.0.3.0/24"},
		{Qualifier: '+', Name: "ip4", Value: "198.51.101.7"},
		{Qualifier: '-', Name: "ip4", Value: "203.0.114.0/24"},
		{Qualifier: '~', Name: "ip6", Value: "2a00:1450::/32"},
		{Qualifier: '?', Name: "a", Value: "mail.example.com"},
		{Qualifier: '+', Name: "a", Value: ""},
		{Qualifier: '+', Name: "mx", Value: ""},
		{Qualifier: '+', Name: "include", Value: "_spf.example.com"},
		{Qualifier: '+', Name: "mx", Value: "mx.example.com/24"},
		{Qualifier: '+', Name: "exists", Value: "%{i}.example.com"},
		{Qualifier: '+', Name: "redirect", Value: "_spf.example.net"},
		{Qualifier: '+', Name: "exp", Value: "explain.example.com"},
		{Qualifier: '-', Name: "all", Value: ""},
	}
	got := spf.Parse(record)
	if !slices.Equal(got.Terms, want) {
		t.Errorf("Parse terms:\n got  %+v\n want %+v", got.Terms, want)
	}
	if !got.HasAll {
		t.Error("a record with -all has all")
	}
}

// HasAll is true for an all mechanism of any qualifier, and false for a record whose only
// fallback is redirect=, which an all mechanism would override.
func TestParse_HasAll(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		record string
		want   bool
	}{
		{"v=spf1 ip4:192.0.3.0/24 redirect=_spf.example.com", false},
		{"v=spf1 redirect=_spf.example.com -all", true},
		{"v=spf1 include:_spf.example.com ~all", true},
		{"v=spf1 ?all", true},
		{"v=spf1 +all", true},
		{"v=spf1 all", true},
		{"v=spf1 ALL", true},
		{"v=spf1 ip4:192.0.3.0/24", false},
		{"v=spf1", false},
	} {
		if got := spf.Parse(tc.record).HasAll; got != tc.want {
			t.Errorf("Parse(%q).HasAll = %v, want %v", tc.record, got, tc.want)
		}
	}
}

// The version is not a term, so a record with nothing after it has none, while one with terms
// gives them.
func TestParse_VersionIsNotATerm(t *testing.T) {
	t.Parallel()
	if got := spf.Parse("v=spf1").Terms; len(got) != 0 {
		t.Errorf("Parse(v=spf1).Terms = %+v, want none", got)
	}
	got := spf.Parse("v=spf1 -all").Terms
	if want := []spf.Term{{Qualifier: '-', Name: "all"}}; !slices.Equal(got, want) {
		t.Errorf("Parse(v=spf1 -all).Terms = %+v, want %+v", got, want)
	}
}

// An ip4 or ip6 term's network is its masked prefix, a single address being a /32 or /128; a
// malformed term, one of the wrong family and any other mechanism have none.
func TestTerm_Network(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, value, want string
	}{
		{"ip4", "192.0.3.0/24", "192.0.3.0/24"},
		{"ip4", "192.0.3.7/24", "192.0.3.0/24"}, // host bits are masked
		{"ip4", "62.253.227.114", "62.253.227.114/32"},
		{"ip4", "192.0.3.7/32", "192.0.3.7/32"},
		{"ip4", "192.0.0.0/15", "192.0.0.0/15"}, // a wide range is still a network
		{"ip6", "2001:db8::1", "2001:db8::1/128"},
		{"ip6", "2a00:1450::/32", "2a00:1450::/32"},
		{"ip6", "2a00:1450:4000::1/36", "2a00:1450:4000::/36"},
	} {
		term := spf.Term{Qualifier: '+', Name: tc.name, Value: tc.value}
		got, ok := term.Network()
		if want := netip.MustParsePrefix(tc.want); !ok || got != want {
			t.Errorf("%s:%s Network() = %v, %v; want %v, true", tc.name, tc.value, got, ok, want)
		}
	}
	// A malformed value, a value of the wrong family and any mechanism other than ip4 or ip6 have
	// no network.
	for _, tc := range []struct{ name, value string }{
		{"ip4", ""},
		{"ip4", "192.0.3"},
		{"ip4", "300.0.3.1"},
		{"ip4", "192.0.3.0/"},
		{"ip4", "192.0.3.0/33"},
		{"ip4", "192.0.3.0/-1"},
		{"ip4", "192.0.3.0/24/8"},
		{"ip4", "192.0.3.0/24x"},
		{"ip4", "mail.example.com"},
		{"ip6", ""},
		{"ip6", "2001:db8::zz"},
		{"ip6", "2001:db8::/129"},
		{"ip4", "2001:db8::1"},    // wrong family
		{"ip4", "2a00:1450::/32"}, // wrong family
		{"ip6", "192.0.2.1"},      // wrong family
		{"ip6", "192.0.3.0/24"},   // wrong family
		{"a", "192.0.3.0/24"},
		{"include", "192.0.3.7"},
		{"exists", "192.0.3.7"},
		{"all", ""},
	} {
		term := spf.Term{Qualifier: '+', Name: tc.name, Value: tc.value}
		if got, ok := term.Network(); ok {
			t.Errorf("%s:%s Network() = %v, true; want false", tc.name, tc.value, got)
		}
	}
}

// Parse and Network together read the shapes a live record has, whatever the mechanism's case.
func TestParse_Networks(t *testing.T) {
	t.Parallel()
	p := spf.Parse("v=spf1 IP4:192.0.3.7/24 +ip4:198.51.101.9 Ip6:2a00:1450:4000::/36 include:_spf.example.com ~all")
	var got []netip.Prefix
	for _, term := range p.Terms {
		if n, ok := term.Network(); ok {
			got = append(got, n)
		}
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.3.0/24"),
		netip.MustParsePrefix("198.51.101.9/32"),
		netip.MustParsePrefix("2a00:1450:4000::/36"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("networks = %v, want %v", got, want)
	}
}

// The domain of an include, redirect, a, mx or exists term is its name in lower case, with no
// final dot and no prefix length; a macro, an address literal or a name that cannot be looked up
// has none.
func TestTerm_Domain(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, tc := range []struct {
		name, value, want string
	}{
		{"include", "_spf.example.com", "_spf.example.com"},
		{"include", "_SPF.Example.COM.", "_spf.example.com"},
		{"redirect", "_spf.example.net", "_spf.example.net"},
		{"a", "mail.example.com", "mail.example.com"},
		{"a", "mail.example.com/24", "mail.example.com"},
		{"a", "mail.example.com/24//64", "mail.example.com"},
		{"mx", "mx.example.com", "mx.example.com"},
		{"mx", "MX.Example.com/28", "mx.example.com"},
		{"exists", "check.example.com", "check.example.com"},
		{"include", long, long}, // 253 characters
	} {
		term := spf.Term{Qualifier: '+', Name: tc.name, Value: tc.value}
		got, ok := term.Domain()
		if !ok || got != tc.want {
			t.Errorf("%s:%s Domain() = %q, %v; want %q, true", tc.name, tc.value, got, ok, tc.want)
		}
	}
	// A macro, an address literal, an empty value, a name that cannot be looked up and any other
	// mechanism or modifier have no domain.
	for _, tc := range []struct{ name, value string }{
		{"include", "%{i}._spf.example.com"},
		{"exists", "%{ir}.%{v}._spf.%{d}"},
		{"redirect", "%{d}.example.com"},
		{"a", "192.0.2.1"},
		{"a", "192.0.2.1/24"},
		{"mx", "2001:db8::1"},
		{"a", ""},
		{"mx", ""},
		{"include", ""},
		{"include", "localhost"},                              // a single label
		{"include", "spf..example.com"},                       // an empty label
		{"include", "-spf.example.com"},                       // a label starting with a hyphen
		{"include", "spf-.example.com"},                       // a label ending with a hyphen
		{"include", "sp*f.example.com"},                       // a character no name has
		{"include", strings.Repeat("a", 64) + ".example.com"}, // a label over 63 characters
		{"include", strings.Repeat("abcdefghi.", 25) + "example.com"}, // over 253 characters
		{"ip4", "192.0.3.0/24"},
		{"ip6", "2a00:1450::/32"},
		{"ptr", "example.com"},
		{"exp", "explain.example.com"},
		{"all", ""},
	} {
		term := spf.Term{Qualifier: '+', Name: tc.name, Value: tc.value}
		if got, ok := term.Domain(); ok {
			t.Errorf("%s:%s Domain() = %q, true; want false", tc.name, tc.value, got)
		}
	}
}

// Parse and Domain together give the domains a record names, in order.
func TestParse_Domains(t *testing.T) {
	t.Parallel()
	p := spf.Parse("v=spf1 INCLUDE:_spf.Example.com a:mail.example.com/24 ip4:192.0.3.0/24 " +
		"exists:%{i}.example.com mx:mx.example.net redirect=_spf.example.org")
	var got []string
	for _, term := range p.Terms {
		if d, ok := term.Domain(); ok {
			got = append(got, d)
		}
	}
	want := []string{"_spf.example.com", "mail.example.com", "mx.example.net", "_spf.example.org"}
	if !slices.Equal(got, want) {
		t.Errorf("domains = %q, want %q", got, want)
	}
	if p.HasAll {
		t.Error("a record without all has no all")
	}
}

// A redirect beside all does not apply; one without all does, and so does every other term.
func TestPolicy_Applies(t *testing.T) {
	t.Parallel()
	with := spf.Parse("v=spf1 include:a.example.com redirect=b.example.com ~all")
	without := spf.Parse("v=spf1 include:a.example.com redirect=b.example.com")
	for _, c := range []struct {
		p    spf.Policy
		i    int
		want bool
	}{{with, 0, true}, {with, 1, false}, {with, 2, true}, {without, 0, true}, {without, 1, true}} {
		if got := c.p.Applies(c.p.Terms[c.i]); got != c.want {
			t.Errorf("Applies(%+v) beside all=%v = %v, want %v", c.p.Terms[c.i], c.p.HasAll, got, c.want)
		}
	}
}

// Mechanisms after the first all do not apply; a modifier after it (exp=) still does, and terms
// before it do.
func TestPolicy_AppliesAfterAll(t *testing.T) {
	t.Parallel()
	p := spf.Parse("v=spf1 ip4:192.0.3.0/24 -all ip4:198.51.101.0/24 include:x.example.com exp=e.example.com")
	want := []bool{true, true, false, false, true}
	if len(p.Terms) != len(want) {
		t.Fatalf("terms = %+v", p.Terms)
	}
	for i, w := range want {
		if got := p.Applies(p.Terms[i]); got != w {
			t.Errorf("Applies(%s:%s) = %v, want %v", p.Terms[i].Name, p.Terms[i].Value, got, w)
		}
	}
}
