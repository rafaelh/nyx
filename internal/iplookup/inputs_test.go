package iplookup

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/clierr"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = addr(s)
	}
	return out
}

func TestParseInputs_Classes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw    string
		active bool
		class  Class
		addr   string // the address of a literal
		prefix string // the range of a CIDR
		host   string // the hostname
		single bool
	}{
		{raw: "1.1.1.1", class: ClassAddress, addr: "1.1.1.1"},
		{raw: "  1.1.1.1\t", class: ClassAddress, addr: "1.1.1.1"},
		{raw: "2001:DB8:0::1", class: ClassAddress, addr: "2001:db8::1"},
		{raw: "::ffff:1.2.3.4", class: ClassAddress, addr: "1.2.3.4"},
		{raw: "::", class: ClassAddress, addr: "::"},
		{raw: "fe80::1%eth0", class: ClassAddress, addr: "fe80::1"},
		{raw: "10.0.0.7/30", class: ClassCIDR, prefix: "10.0.0.4/30"},
		{raw: "10.0.0.1/32", class: ClassCIDR, prefix: "10.0.0.1/32"},
		{raw: "2001:db8::5/126", class: ClassCIDR, prefix: "2001:db8::4/126"},
		{raw: "::ffff:10.0.0.7/126", class: ClassCIDR, prefix: "10.0.0.4/30"},
		{raw: "Example.COM.", class: ClassHostname, host: "example.com"},
		{raw: "www.bücher.example", class: ClassHostname, host: "www.xn--bcher-kva.example"},
		{raw: "co.uk", class: ClassHostname, host: "co.uk"},
		{raw: "intranet", active: true, class: ClassHostname, host: "intranet", single: true},
		{raw: "a.b", active: true, class: ClassHostname, host: "a.b"},
	}
	for _, c := range cases {
		p := ParseInputs([]string{c.raw}, c.active)
		if len(p.Inputs) != 1 {
			t.Fatalf("%q: %d inputs", c.raw, len(p.Inputs))
		}
		in := p.Inputs[0]
		if in.Class != c.class || in.Raw != strings.TrimSpace(c.raw) {
			t.Errorf("%q: class %d raw %q, want class %d", c.raw, in.Class, in.Raw, c.class)
			continue
		}
		switch c.class {
		case ClassAddress:
			if in.Addr.String() != c.addr {
				t.Errorf("%q: address %s, want %s", c.raw, in.Addr, c.addr)
			}
		case ClassCIDR:
			if in.Prefix.String() != c.prefix {
				t.Errorf("%q: prefix %s, want %s", c.raw, in.Prefix, c.prefix)
			}
		case ClassInvalid:
		case ClassHostname:
			if in.Hostname != c.host || in.SingleLabel != c.single {
				t.Errorf("%q: hostname %q single %v, want %q %v", c.raw, in.Hostname, in.SingleLabel, c.host, c.single)
			}
		}
		if in.Err != nil {
			t.Errorf("%q: error %v", c.raw, in.Err)
		}
	}
}

func TestParseInputs_Invalid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw    string
		active bool
		hint   string // what the hint holds
	}{
		{"https://example.com/path?q=1", false, "example.com"},
		{"http://203.0.113.5:8080/", false, "203.0.113.5"},
		{"example.com:8080", false, "example.com"},
		{"203.0.113.5:22", true, "203.0.113.5"},
		{"[2001:db8::1]:443", false, "2001:db8::1"},
		{"intranet", false, "add --active to resolve single-label names through this machine's resolver"},
		{"1.2.3", false, "an address, a hostname"},
		{"123.456", true, "an address, a hostname"},
		{"123456", true, "an address, a hostname"},
		{"1.2.3.4/33", false, "an address, a hostname"},
		{"not a host", false, "an address, a hostname"},
		{"bad_name.example.com", false, "an address, a hostname"},
		{"", false, "an address, a hostname"},
		{"-bad.example.com", false, "an address, a hostname"},
	}
	for _, c := range cases {
		p := ParseInputs([]string{c.raw}, c.active)
		in := p.Inputs[0]
		if in.Class != ClassInvalid || in.Err == nil {
			t.Errorf("%q: class %d, want invalid (hostname %q)", c.raw, in.Class, in.Hostname)
			continue
		}
		if in.Err.Code != clierr.InvalidInput || in.Err.Transient {
			t.Errorf("%q: error %+v", c.raw, in.Err)
		}
		if !strings.Contains(in.Err.Hint, c.hint) {
			t.Errorf("%q: hint %q does not hold %q", c.raw, in.Err.Hint, c.hint)
		}
		if in.Err.Message == "" || !strings.Contains(in.Err.Message, strings.TrimSpace(c.raw)) && c.raw != "" {
			t.Errorf("%q: message %q", c.raw, in.Err.Message)
		}
	}
}

func TestParseInputs_HintsNameTheBareHost(t *testing.T) {
	t.Parallel()
	in := ParseInputs([]string{"https://Example.com:8443/x"}, false).Inputs[0]
	if want := "use the bare host: example.com"; !strings.Contains(in.Err.Hint, want) {
		t.Errorf("hint %q, want it to say %q", in.Err.Hint, want)
	}
	// A single-label name that is the host of a URL needs no --active to be a bare host hint.
	in = ParseInputs([]string{"http://intranet/"}, false).Inputs[0]
	if !strings.Contains(in.Err.Hint, "intranet") {
		t.Errorf("hint %q", in.Err.Hint)
	}
}

func TestParseInputs_OrderAndProblems(t *testing.T) {
	t.Parallel()
	p := ParseInputs([]string{"b.example.com", "bad input", "10.0.0.0/31", "1.2.3.4", "http://x.example/"}, false)
	classes := []Class{ClassHostname, ClassInvalid, ClassCIDR, ClassAddress, ClassInvalid}
	for i, c := range classes {
		if p.Inputs[i].Class != c {
			t.Errorf("input %d (%q): class %d, want %d", i, p.Inputs[i].Raw, p.Inputs[i].Class, c)
		}
	}
	problems := p.Problems()
	if len(problems) != 2 || problems[0].Name != "input" || problems[0].Value != "bad input" || problems[1].Value != "http://x.example/" {
		t.Errorf("problems %+v, want both invalid inputs, in order, as the input argument", problems)
	}
	if problems[1].Hint == "" || problems[1].Message == "" {
		t.Errorf("a problem lacks its message or hint: %+v", problems[1])
	}
	if p.AllInvalid() {
		t.Error("AllInvalid with valid inputs")
	}
	if !ParseInputs([]string{"x y", "z w"}, false).AllInvalid() {
		t.Error("not AllInvalid when every input is invalid")
	}
	if ParseInputs(nil, false).AllInvalid() || len(ParseInputs(nil, false).Problems()) != 0 {
		t.Error("an empty plan is not all invalid")
	}
}

func TestPlan_Hostnames(t *testing.T) {
	t.Parallel()
	p := ParseInputs([]string{"B.example.com", "1.1.1.1", "a.example.com", "b.example.com.", "intranet", "10.0.0.0/30"}, true)
	var got []string
	for _, h := range p.Hostnames() {
		got = append(got, h.Hostname)
	}
	if want := []string{"b.example.com", "a.example.com", "intranet"}; !slices.Equal(got, want) {
		t.Errorf("hostnames %v, want %v", got, want)
	}
	if h := p.Hostnames(); !h[2].SingleLabel || h[0].SingleLabel {
		t.Errorf("single label flags: %+v", h)
	}
}

func TestPlan_LiteralCount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []string
		want int
	}{
		{"none", nil, 0},
		{"hostnames and invalid inputs add nothing", []string{"example.com", "junk junk"}, 0},
		{"a literal", []string{"1.1.1.1"}, 1},
		{"the same literal twice, mapped or not", []string{"1.1.1.1", "::ffff:1.1.1.1", "1.1.1.1"}, 1},
		{"a /30", []string{"10.0.0.0/30"}, 4},
		{"a single-address CIDR", []string{"10.0.0.1/32"}, 1},
		{"a literal inside a CIDR", []string{"10.0.0.0/30", "10.0.0.2"}, 4},
		{"a CIDR inside a CIDR", []string{"10.0.0.0/24", "10.0.0.128/25", "10.0.0.0/24"}, 256},
		{"the same CIDR in a different form", []string{"10.0.0.1/24", "10.0.0.0/24"}, 256},
		{"two disjoint CIDRs and a literal outside", []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.1"}, 513},
		{"IPv6", []string{"2001:db8::/126", "2001:db8::1", "2001:db8::9"}, 5},
		{"a /23 passes the cap", []string{"10.0.0.0/23"}, 512},
	}
	for _, c := range cases {
		if got := ParseInputs(c.in, false).LiteralCount(); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	for _, huge := range []string{"10.0.0.0/8", "0.0.0.0/0", "2001:db8::/64", "::/0", "2001:db8::/32"} {
		got := ParseInputs([]string{huge, huge}, false).LiteralCount()
		if got <= MaxAddresses || got < 0 {
			t.Errorf("%s: count %d, want a count far over the cap", huge, got)
		}
	}
	// Two enormous ranges must not overflow into a small or negative count.
	if got := ParseInputs([]string{"::/0", "0.0.0.0/0"}, false).LiteralCount(); got <= MaxAddresses {
		t.Errorf("enormous ranges added up to %d", got)
	}
}

func TestPlan_ProvisionalCount(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []string
		want int
	}{
		{"nothing", nil, 0},
		{"invalid inputs count nothing", []string{"x y"}, 0},
		{"a hostname is one", []string{"example.com"}, 1},
		{"a literal is one", []string{"1.1.1.1"}, 1},
		{"a CIDR is its size", []string{"10.0.0.0/30"}, 4},
		{"the sum, with no regard for duplicates", []string{"example.com", "example.com", "1.1.1.1", "1.1.1.1", "10.0.0.0/30"}, 8},
	}
	for _, c := range cases {
		if got := ParseInputs(c.in, false).ProvisionalCount(); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	if got := ParseInputs([]string{"::/0", "::/0"}, false).ProvisionalCount(); got <= MaxAddresses || got < 0 {
		t.Errorf("a huge range counts %d", got)
	}
	// The deadline made from it must be positive for any count.
	if d := Deadline(false, ParseInputs([]string{"::/0", "::/0", "0.0.0.0/0"}, false).ProvisionalCount()); d <= 0 {
		t.Errorf("deadline %v", d)
	}
}

func list(as []Address) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.Addr.String()
	}
	return out
}

func TestPlan_Addresses_Order(t *testing.T) {
	t.Parallel()
	p := ParseInputs([]string{"10.0.0.2", "10.0.0.0/30", "a.example.com", "::ffff:9.9.9.9", "2001:db8::1"}, false)
	got, err := p.Addresses(map[string]Resolution{
		"a.example.com": {Addrs: addrs("2001:db8::9", "10.0.0.1", "1.1.1.1", "2001:db8::2", "::ffff:1.1.1.1", "8.8.8.8"), Found: FoundPublicDNS},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.2", "10.0.0.0", "10.0.0.1", "10.0.0.3", "1.1.1.1", "8.8.8.8", "2001:db8::2", "2001:db8::9", "9.9.9.9", "2001:db8::1"}
	if !slices.Equal(list(got), want) {
		t.Errorf("order\n got %v\nwant %v", list(got), want)
	}
}

func TestPlan_Addresses_FoundAndHostnames(t *testing.T) {
	t.Parallel()
	p := ParseInputs([]string{"b.example.com", "10.0.0.0/30", "a.example.com", "10.0.0.1", "A.example.com", "local.example.com", "intranet"}, true)
	got, err := p.Addresses(map[string]Resolution{
		"b.example.com":     {Addrs: addrs("10.0.0.1", "10.0.0.7"), Found: FoundPublicDNS},
		"a.example.com":     {Addrs: addrs("10.0.0.7", "10.0.0.7", "1.1.1.1"), Found: FoundPublicDNS},
		"local.example.com": {Addrs: addrs("10.0.0.7", "192.168.1.1"), Found: FoundLocalDNS},
		"intranet":          {Addrs: addrs("192.168.1.1"), Found: FoundLocalDNS},
	})
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		addr  string
		hosts string
		found Found
	}
	var rows []row
	for _, a := range got {
		rows = append(rows, row{a.Addr.String(), strings.Join(a.Hostnames, ","), a.Found})
	}
	want := []row{
		{"10.0.0.1", "b.example.com", FoundPublicDNS | FoundCIDR | FoundLiteral},
		{"10.0.0.7", "b.example.com,a.example.com,local.example.com", FoundPublicDNS | FoundLocalDNS},
		{"10.0.0.0", "", FoundCIDR},
		{"10.0.0.2", "", FoundCIDR},
		{"10.0.0.3", "", FoundCIDR},
		{"1.1.1.1", "a.example.com", FoundPublicDNS},
		{"192.168.1.1", "local.example.com,intranet", FoundLocalDNS},
	}
	// b.example.com is the first input, so its addresses come first, in its own order.
	if len(rows) != len(want) {
		t.Fatalf("got %v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d: got %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestPlan_Addresses_HostnameAddressesStayAtTheirHostname(t *testing.T) {
	t.Parallel()
	p := ParseInputs([]string{"1.1.1.1", "a.example.com", "2.2.2.2", "b.example.com"}, false)
	got, err := p.Addresses(map[string]Resolution{
		"a.example.com": {Addrs: addrs("3.3.3.3", "1.1.1.1"), Found: FoundPublicDNS},
		"b.example.com": {Addrs: addrs("2.2.2.2", "4.4.4.4"), Found: FoundPublicDNS},
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"1.1.1.1", "3.3.3.3", "2.2.2.2", "4.4.4.4"}; !slices.Equal(list(got), want) {
		t.Errorf("got %v, want %v", list(got), want)
	}
	if got[0].Found != FoundLiteral|FoundPublicDNS || !slices.Equal(got[0].Hostnames, []string{"a.example.com"}) {
		t.Errorf("1.1.1.1: %+v", got[0])
	}
	if got[2].Found != FoundLiteral|FoundPublicDNS || !slices.Equal(got[2].Hostnames, []string{"b.example.com"}) {
		t.Errorf("2.2.2.2: %+v", got[2])
	}
}

func TestPlan_Addresses_Unresolved(t *testing.T) {
	t.Parallel()
	p := ParseInputs([]string{"gone.example.com", "1.1.1.1", "bad input"}, false)
	got, err := p.Addresses(nil)
	if err != nil || !slices.Equal(list(got), []string{"1.1.1.1"}) {
		t.Errorf("got %v, %v", list(got), err)
	}
	if got[0].Hostnames == nil {
		t.Error("an address with no hostnames has nil hostnames, want an empty list")
	}
}

func TestPlan_Addresses_FirstAndLastOfACIDR(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		cidr string
		want []string
	}{
		{"192.0.2.255/30", []string{"192.0.2.252", "192.0.2.253", "192.0.2.254", "192.0.2.255"}},
		{"255.255.255.254/31", []string{"255.255.255.254", "255.255.255.255"}},
		{"2001:db8::7/126", []string{"2001:db8::4", "2001:db8::5", "2001:db8::6", "2001:db8::7"}},
		{"::/127", []string{"::", "::1"}},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127", []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
	} {
		got, err := ParseInputs([]string{c.cidr}, false).Addresses(nil)
		if err != nil || !slices.Equal(list(got), c.want) {
			t.Errorf("%s: got %v, %v, want %v", c.cidr, list(got), err, c.want)
		}
		for _, a := range got {
			if a.Found != FoundCIDR {
				t.Errorf("%s: %s found %d", c.cidr, a.Addr, a.Found)
			}
		}
	}
}

func TestPlan_Addresses_Cap(t *testing.T) {
	t.Parallel()
	// Exactly the cap is fine.
	got, err := ParseInputs([]string{"10.0.0.0/24"}, false).Addresses(nil)
	if err != nil || len(got) != MaxAddresses {
		t.Fatalf("a /24: %d addresses, %v", len(got), err)
	}
	// A range over the cap is refused by its size, before it is expanded.
	for _, huge := range []string{"10.0.0.0/23", "10.0.0.0/8", "0.0.0.0/0", "2001:db8::/64", "::/0"} {
		got, err := ParseInputs([]string{huge}, false).Addresses(nil)
		if got != nil || err == nil {
			t.Errorf("%s: %d addresses, %v", huge, len(got), err)
			continue
		}
		var e *clierr.Error
		if !errors.As(err, &e) || e.Code != clierr.InvalidInput || !strings.Contains(e.Message, "256") {
			t.Errorf("%s: error %v", huge, err)
		}
	}
	// Hostnames count once they resolve.
	var many []netip.Addr
	for i := range 257 {
		many = append(many, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), netip.AddrFrom4([4]byte{198, 51, 101, byte(i)}))
	}
	p := ParseInputs([]string{"a.example.com", "10.0.0.1"}, false)
	if _, err := p.Addresses(map[string]Resolution{"a.example.com": {Addrs: many[:255], Found: FoundPublicDNS}}); err != nil {
		t.Errorf("256 in all: %v", err)
	}
	got, err = p.Addresses(map[string]Resolution{"a.example.com": {Addrs: many[:256], Found: FoundPublicDNS}})
	if got != nil || err == nil || !strings.Contains(err.Error(), "257") {
		t.Errorf("257 in all: %d addresses, %v", len(got), err)
	}
	// Duplicates are not counted twice.
	dup := append(slices.Clone(many[:255]), addr("10.0.0.1"), many[0])
	if got, err := p.Addresses(map[string]Resolution{"a.example.com": {Addrs: dup, Found: FoundPublicDNS}}); err != nil || len(got) != 256 {
		t.Errorf("duplicates: %d addresses, %v", len(got), err)
	}
}

func TestCapError(t *testing.T) {
	t.Parallel()
	e := CapError(300, false)
	if e.Code != clierr.InvalidInput || !strings.Contains(e.Message, "300") || !strings.Contains(e.Message, "256") || e.Hint == "" {
		t.Errorf("%+v", e)
	}
	r := CapError(257, true)
	if !strings.Contains(r.Message, "257") || !strings.Contains(r.Message, "resolve") {
		t.Errorf("resolved: %+v", r)
	}
	if strings.EqualFold(e.Message, r.Message) {
		t.Error("the two causes read alike")
	}
	huge := CapError(1<<50, false)
	if strings.Contains(huge.Message, fmt.Sprint(1<<50)) || !strings.Contains(huge.Message, "256") {
		t.Errorf("a huge count is shown whole: %q", huge.Message)
	}
	if p := CapProblem(300, false); p.Name != "input" || p.Message != e.Message || p.Hint != e.Hint {
		t.Errorf("problem %+v does not match the error", p)
	}
}

func TestFound_OnlyPublicDNS(t *testing.T) {
	t.Parallel()
	for f, want := range map[Found]bool{
		FoundPublicDNS:                 true,
		FoundPublicDNS | FoundLiteral:  false,
		FoundPublicDNS | FoundCIDR:     false,
		FoundPublicDNS | FoundLocalDNS: false,
		FoundLocalDNS:                  false,
		FoundLiteral:                   false,
		0:                              false,
	} {
		if got := f.OnlyPublicDNS(); got != want {
			t.Errorf("Found(%d).OnlyPublicDNS() = %v, want %v", f, got, want)
		}
	}
}
