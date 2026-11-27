package scope_test

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/scope"
)

// byAddressNetblocks are the in-scope netblocks of the by-address tests: a --cidr input, a
// narrower --cidr inside it, a netblock of an --asn input, and an IPv6 netblock. Scope sees them
// all as Config.Netblocks.
var byAddressNetblocks = []netip.Prefix{
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("198.51.100.192/26"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// A candidate name enters scope by address when an address of its lookup is inside an in-scope
// netblock, unless it is under a root, excluded by name, has a lookup address in an excluded
// CIDR or is generic for one of its IPv4 lookup addresses. Its resolved rows come from
// the same lookup, so the test gives both.
func TestByAddress(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		desc       string
		host       string
		lookup     []string
		exclusions []string
		unresolved bool   // the name has a lookup but no resolved rows
		wantAddr   string // "" when the name is not in scope by address
		wantBlock  string
		wantHost   scope.Class // ClassifyHost
		wantName   scope.Class // ClassifyName
	}{
		{desc: "address in a --cidr netblock", host: "shop.example.org", lookup: []string{"198.51.100.7"},
			wantAddr: "198.51.100.7", wantBlock: "198.51.100.0/24", wantHost: scope.InScope, wantName: scope.Candidate},
		{desc: "address in an ASN netblock", host: "asn.example.org", lookup: []string{"192.0.2.7"},
			wantAddr: "192.0.2.7", wantBlock: "192.0.2.0/24", wantHost: scope.InScope, wantName: scope.Candidate},
		{desc: "IPv6 address in a netblock", host: "v6.example.org", lookup: []string{"2001:db8::7"},
			wantAddr: "2001:db8::7", wantBlock: "2001:db8::/32", wantHost: scope.InScope, wantName: scope.Candidate},
		{desc: "one address inside and one outside", host: "two.example.org", lookup: []string{"203.0.113.9", "198.51.100.7"},
			wantAddr: "198.51.100.7", wantBlock: "198.51.100.0/24", wantHost: scope.InScope, wantName: scope.Candidate},
		{desc: "outside every netblock", host: "far.example.org", lookup: []string{"203.0.113.9", "192.0.3.9"},
			wantHost: scope.Candidate, wantName: scope.Candidate},
		{desc: "under a root", host: "www.example.com", lookup: []string{"198.51.100.7"},
			wantHost: scope.InScope, wantName: scope.InScope},
		{desc: "excluded by name", host: "shop.example.org", lookup: []string{"198.51.100.7"}, exclusions: []string{"shop.example.org"},
			wantHost: scope.Excluded, wantName: scope.Excluded},
		{desc: "excluded by a wildcard name", host: "shop.example.org", lookup: []string{"198.51.100.7"}, exclusions: []string{"*.example.org"},
			wantHost: scope.Excluded, wantName: scope.Excluded},
		{desc: "a lookup address in an excluded CIDR outside the netblocks", host: "shop.example.org",
			lookup: []string{"198.51.100.7", "203.0.113.9"}, exclusions: []string{"203.0.113.0/24"}, unresolved: true,
			wantHost: scope.Candidate, wantName: scope.Candidate},
		{desc: "a lookup address in an excluded CIDR inside a netblock", host: "shop.example.org",
			lookup: []string{"198.51.100.7", "198.51.100.200"}, exclusions: []string{"198.51.100.128/25"}, unresolved: true,
			wantHost: scope.Candidate, wantName: scope.Candidate},
		{desc: "generic for its address", host: "198-51-100-7.static.example.org", lookup: []string{"198.51.100.7"},
			wantHost: scope.Candidate, wantName: scope.Candidate},
		{desc: "generic, reversed", host: "7.100.51.198.example.org", lookup: []string{"198.51.100.7"},
			wantHost: scope.Candidate, wantName: scope.Candidate},
		{desc: "generic for one of two qualifying addresses", host: "198-51-100-7.example.org", lookup: []string{"198.51.100.8", "198.51.100.7"},
			wantHost: scope.Candidate, wantName: scope.Candidate},
		{desc: "generic for an address outside the netblocks", host: "203-0-113-9.example.org", lookup: []string{"198.51.100.7", "203.0.113.9"},
			wantHost: scope.Candidate, wantName: scope.Candidate},
		{desc: "near miss of a generic name", host: "198-51-100-70.example.org", lookup: []string{"198.51.100.7"},
			wantAddr: "198.51.100.7", wantBlock: "198.51.100.0/24", wantHost: scope.InScope, wantName: scope.Candidate},
		{desc: "the lowest qualifying address", host: "low.example.org", lookup: []string{"198.51.100.200", "203.0.113.9", "198.51.100.130"},
			wantAddr: "198.51.100.130", wantBlock: "198.51.100.0/24", wantHost: scope.InScope, wantName: scope.Candidate},
		{desc: "the narrowest netblock holding the lowest address", host: "narrow.example.org", lookup: []string{"198.51.100.230", "192.0.3.9", "198.51.100.200"},
			wantAddr: "198.51.100.200", wantBlock: "198.51.100.192/26", wantHost: scope.InScope, wantName: scope.Candidate},
	} {
		lookup := addrs(c.lookup...)
		cfg := scope.Config{
			Roots:              []string{"example.com"},
			Netblocks:          byAddressNetblocks,
			ASNs:               []string{"AS64500"},
			Exclusions:         excl(t, c.exclusions...),
			Lookups:            map[string][]netip.Addr{c.host: lookup},
			MaxNamesPerAddress: 100,
		}
		if !c.unresolved {
			cfg.Resolutions = map[string][]netip.Addr{c.host: lookup}
		}
		s := scope.New(cfg)
		addr, block, ok := s.ByAddress(c.host)
		switch {
		case c.wantAddr == "" && ok:
			t.Errorf("%s: ByAddress(%s) = %s in %s, want not in scope by address", c.desc, c.host, addr, block)
		case c.wantAddr != "" && (!ok || addr != netip.MustParseAddr(c.wantAddr) || block != netip.MustParsePrefix(c.wantBlock)):
			t.Errorf("%s: ByAddress(%s) = %s in %s, %v, want %s in %s", c.desc, c.host, addr, block, ok, c.wantAddr, c.wantBlock)
		}
		if got := s.ClassifyHost(c.host); got.Class != c.wantHost {
			t.Errorf("%s: ClassifyHost(%s) = %v (%s), want %v", c.desc, c.host, got.Class, got.Reason, c.wantHost)
		}
		if got := s.ClassifyName(c.host); got.Class != c.wantName {
			t.Errorf("%s: ClassifyName(%s) = %v (%s), want %v", c.desc, c.host, got.Class, got.Reason, c.wantName)
		}
		if got := s.HostInScope(c.host); got != (c.wantHost == scope.InScope) {
			t.Errorf("%s: HostInScope(%s) = %v, want %v", c.desc, c.host, got, c.wantHost == scope.InScope)
		}
		if len(s.SharedHosting()) != 0 {
			t.Errorf("%s: SharedHosting = %v with one name, want none", c.desc, s.SharedHosting())
		}
	}
}

// With promotion off there are no lookups, and no name is in scope by address, however it
// resolves.
func TestByAddress_NoLookups(t *testing.T) {
	t.Parallel()
	s := scope.New(scope.Config{
		Roots:              []string{"example.com"},
		Netblocks:          byAddressNetblocks,
		Resolutions:        map[string][]netip.Addr{"shop.example.org": addrs("198.51.100.7")},
		MaxNamesPerAddress: 100,
	})
	if addr, block, ok := s.ByAddress("shop.example.org"); ok {
		t.Errorf("ByAddress = %s in %s with no lookups, want not in scope by address", addr, block)
	}
	if got := s.ClassifyHost("shop.example.org"); got.Class != scope.Candidate {
		t.Errorf("ClassifyHost = %v, want candidate", got.Class)
	}
	if got := s.ClassifyName("shop.example.org"); got.Class != scope.Candidate {
		t.Errorf("ClassifyName = %v, want candidate", got.Class)
	}
	if got := s.SharedHosting(); len(got) != 0 {
		t.Errorf("SharedHosting = %v, want none", got)
	}
}

// guardScope gives n names (name-000.example.org, ...) the lookup address 198.51.100.7, and the
// first of them also 198.51.100.8, under the default guard of 100 names per address.
func guardScope(n int) *scope.Scope {
	lookups := map[string][]netip.Addr{}
	for i := range n {
		lookups[fmt.Sprintf("name-%03d.example.org", i)] = addrs("198.51.100.7")
	}
	lookups["name-000.example.org"] = addrs("198.51.100.7", "198.51.100.8")
	return scope.New(scope.Config{
		Roots:              []string{"example.com"},
		Netblocks:          byAddressNetblocks,
		Lookups:            lookups,
		Resolutions:        maps.Clone(lookups),
		MaxNamesPerAddress: 100,
	})
}

// Up to the guard, every name on an address enters scope by it. One name over, none does through
// that address, SharedHosting names it, and a name with another qualifying address enters through
// that one.
func TestByAddress_SharedHostingGuard(t *testing.T) {
	t.Parallel()
	at, at8 := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("198.51.100.8")
	block := netip.MustParsePrefix("198.51.100.0/24")

	// Each loop reports the first name that fails and how many did, not every one.
	s := guardScope(100)
	var wrong []string
	for i := range 100 {
		h := fmt.Sprintf("name-%03d.example.org", i)
		addr, b, ok := s.ByAddress(h)
		if !ok || addr != at || b != block || s.ClassifyHost(h).Class != scope.InScope {
			wrong = append(wrong, fmt.Sprintf("%s: ByAddress = %s in %s, %v; ClassifyHost = %v", h, addr, b, ok, s.ClassifyHost(h).Class))
		}
	}
	if len(wrong) > 0 {
		t.Errorf("100 names: %d of them are not in scope by %s in %s, such as %s", len(wrong), at, block, wrong[0])
	}
	if got := s.SharedHosting(); len(got) != 0 {
		t.Errorf("100 names: SharedHosting = %v, want none", got)
	}

	s = guardScope(101)
	wrong = nil
	for i := 1; i < 101; i++ {
		h := fmt.Sprintf("name-%03d.example.org", i)
		if addr, b, ok := s.ByAddress(h); ok || s.ClassifyHost(h).Class != scope.Candidate {
			wrong = append(wrong, fmt.Sprintf("%s: ByAddress = %s in %s, %v; ClassifyHost = %v", h, addr, b, ok, s.ClassifyHost(h).Class))
		}
	}
	if len(wrong) > 0 {
		t.Errorf("101 names: %d of the names with only %s are not candidates, such as %s", len(wrong), at, wrong[0])
	}
	if got, want := s.SharedHosting(), []netip.Addr{at}; !slices.Equal(got, want) {
		t.Errorf("101 names: SharedHosting = %v, want %v", got, want)
	}
	addr, b, ok := s.ByAddress("name-000.example.org")
	if !ok || addr != at8 || b != block {
		t.Errorf("101 names: ByAddress of the name with a second address = %s in %s, %v, want %s in %s", addr, b, ok, at8, block)
	}
	if got := s.ClassifyHost("name-000.example.org"); got.Class != scope.InScope {
		t.Errorf("101 names: ClassifyHost of the name with a second address = %v, want in scope", got.Class)
	}
}

// The guard counts the names that are candidates or in scope by address: a generic name and a
// name with a lookup address in an excluded CIDR count, though neither enters scope; a name under a
// root and a name excluded by name do not count. Only in-scope addresses are listed, sorted.
func TestByAddress_GuardCounts(t *testing.T) {
	t.Parallel()
	lookups := map[string][]netip.Addr{
		// 198.51.100.9: a generic name, and a name it pushes over a guard of one.
		"198-51-100-9.example.org": addrs("198.51.100.9"),
		"a.example.org":            addrs("198.51.100.9"),
		// 198.51.100.3: a name with an address in an excluded CIDR, and a name it pushes over.
		"b.example.org": addrs("198.51.100.3", "203.0.113.1"),
		"c.example.org": addrs("198.51.100.3"),
		// 198.51.100.11: a rooted name and a name excluded by name do not count.
		"d.example.org":   addrs("198.51.100.11"),
		"www.example.com": addrs("198.51.100.11"),
		"x.example.net":   addrs("198.51.100.11"),
		// 203.0.114.5 is outside every netblock, so it is never shared hosting.
		"e.example.org": addrs("203.0.114.5"),
		"f.example.org": addrs("203.0.114.5"),
	}
	s := scope.New(scope.Config{
		Roots:              []string{"example.com"},
		Netblocks:          byAddressNetblocks,
		Exclusions:         excl(t, "203.0.113.0/24", "x.example.net"),
		Lookups:            lookups,
		MaxNamesPerAddress: 1,
	})
	for _, h := range []string{"198-51-100-9.example.org", "a.example.org", "b.example.org", "c.example.org", "e.example.org", "f.example.org"} {
		if addr, b, ok := s.ByAddress(h); ok {
			t.Errorf("ByAddress(%s) = %s in %s, want not in scope by address", h, addr, b)
		}
	}
	addr, b, ok := s.ByAddress("d.example.org")
	if want := netip.MustParseAddr("198.51.100.11"); !ok || addr != want || b != netip.MustParsePrefix("198.51.100.0/24") {
		t.Errorf("ByAddress(d.example.org) = %s in %s, %v, want %s in 198.51.100.0/24", addr, b, ok, want)
	}
	if got, want := s.SharedHosting(), addrs("198.51.100.3", "198.51.100.9"); !slices.Equal(got, want) {
		t.Errorf("SharedHosting = %v, want %v", got, want)
	}
}

// A name in scope by address may be dialled only at its addresses inside an in-scope netblock; a
// name under a root at all its addresses.
func TestDialAddrs(t *testing.T) {
	t.Parallel()
	both := addrs("203.0.113.9", "198.51.100.7")
	s := scope.New(scope.Config{
		Roots:     []string{"example.com"},
		Netblocks: byAddressNetblocks,
		Lookups:   map[string][]netip.Addr{"shop.example.org": both},
		Resolutions: map[string][]netip.Addr{
			"shop.example.org": both,
			"www.example.com":  both,
		},
		MaxNamesPerAddress: 100,
	})
	if _, _, ok := s.ByAddress("shop.example.org"); !ok {
		t.Error("shop.example.org is not in scope by address")
	}
	if got, want := s.DialAddrs("shop.example.org"), addrs("198.51.100.7"); !slices.Equal(got, want) {
		t.Errorf("DialAddrs(shop.example.org) = %v, want %v", got, want)
	}
	if got, want := s.DialAddrs("www.example.com"), s.Addrs("www.example.com"); !slices.Equal(got, want) || len(got) != 2 {
		t.Errorf("DialAddrs(www.example.com) = %v, want %v", got, want)
	}
}

// An address of a name in scope by address that is outside every in-scope netblock does not
// become port-eligible because of it, even with a known, dedicated owner; the same address of a
// name under a root does.
func TestPortAllowed_ByAddress(t *testing.T) {
	t.Parallel()
	dedicated := func(netip.Addr) (shared, known bool) { return false, true }
	inside, outside := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.9")
	both := []netip.Addr{outside, inside}

	byAddr := scope.New(scope.Config{
		Roots:              []string{"example.com"},
		Netblocks:          byAddressNetblocks,
		Lookups:            map[string][]netip.Addr{"shop.example.org": both},
		Resolutions:        map[string][]netip.Addr{"shop.example.org": both},
		MaxNamesPerAddress: 100,
	})
	if _, _, ok := byAddr.ByAddress("shop.example.org"); !ok {
		t.Error("shop.example.org is not in scope by address")
	}
	if byAddr.PortAllowed(outside, dedicated) {
		t.Errorf("PortAllowed(%s) = true for the outside address of a name in scope by address", outside)
	}
	if !byAddr.PortAllowed(inside, dedicated) {
		t.Errorf("PortAllowed(%s) = false for an address in a netblock", inside)
	}

	rooted := scope.New(scope.Config{
		Roots:              []string{"example.com"},
		Netblocks:          byAddressNetblocks,
		Resolutions:        map[string][]netip.Addr{"www.example.com": both},
		MaxNamesPerAddress: 100,
	})
	if !rooted.PortAllowed(outside, dedicated) {
		t.Errorf("PortAllowed(%s) = false for the address of a name under a root", outside)
	}
}
