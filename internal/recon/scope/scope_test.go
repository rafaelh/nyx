package scope_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/recon/scope"
)

func excl(t *testing.T, entries ...string) []input.Exclusion {
	t.Helper()
	out, err := input.ParseExclusions(entries)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// Classification of hostnames.
func TestClassifyHost(t *testing.T) {
	t.Parallel()
	s := scope.New(scope.Config{
		Roots:      []string{"example.com"},
		Exclusions: excl(t, "admin.example.com", "*.dev.example.com", "198.51.100.0/24"),
		Resolutions: map[string][]netip.Addr{
			"db.example.com":    addrs("198.51.100.7"),
			"www.example.com":   addrs("203.0.113.5"),
			"other.example.org": addrs("198.51.100.9"),
		},
	})
	for _, c := range []struct {
		host string
		want scope.Class
	}{
		{"example.com", scope.InScope},
		{"www.example.com", scope.InScope},
		{"a.b.example.com", scope.InScope},
		{"WWW.Example.COM.", scope.InScope},
		{"notexample.com", scope.Candidate},
		{"example.com.evil.net", scope.Candidate},
		{"admin.example.com", scope.Excluded},
		{"x.dev.example.com", scope.Excluded},
		{"dev.example.com", scope.InScope},
		{"db.example.com", scope.Excluded},    // resolves into an excluded CIDR
		{"other.example.org", scope.Excluded}, // out of scope but excluded still wins
	} {
		got := s.ClassifyHost(c.host)
		if got.Class != c.want {
			t.Errorf("%s = %v (%s), want %v", c.host, got.Class, got.Reason, c.want)
		}
		if got.Class == scope.Excluded && got.Reason == "" {
			t.Errorf("%s excluded without a reason", c.host)
		}
	}
}

func TestExcludedFor(t *testing.T) {
	t.Parallel()
	s := scope.New(scope.Config{
		Roots:       []string{"example.com"},
		Exclusions:  excl(t, "admin.example.com", "198.51.100.0/24"),
		Resolutions: map[string][]netip.Addr{"admin.example.com": addrs("203.0.113.50"), "www.example.com": addrs("203.0.113.5")},
	})
	if ok, why := s.ExcludedFor(netip.MustParseAddr("198.51.100.1"), false); !ok || why == "" {
		t.Errorf("cidr: %v %q", ok, why)
	}
	if ok, why := s.ExcludedFor(netip.MustParseAddr("203.0.113.50"), false); !ok || why == "" {
		t.Errorf("address of excluded host: %v %q", ok, why)
	}
	if ok, _ := s.ExcludedFor(netip.MustParseAddr("203.0.113.5"), false); ok {
		t.Error("address of a normal host is not excluded")
	}
	// Shared infrastructure escapes an exclusion by name, never an excluded CIDR.
	if ok, _ := s.ExcludedFor(netip.MustParseAddr("198.51.100.1"), true); !ok {
		t.Error("a shared address in an excluded CIDR must stay excluded")
	}
	if ok, _ := s.ExcludedFor(netip.MustParseAddr("203.0.113.50"), true); ok {
		t.Error("a shared address of a host excluded by name must not be excluded")
	}
}

func TestInScopeIP(t *testing.T) {
	t.Parallel()
	s := scope.New(scope.Config{
		Netblocks:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Exclusions: excl(t, "203.0.113.128/25"),
	})
	if !s.InScopeIP(netip.MustParseAddr("203.0.113.10")) {
		t.Error("in netblock")
	}
	if s.InScopeIP(netip.MustParseAddr("203.0.114.10")) {
		t.Error("outside netblock")
	}
	// IPs that hostnames resolve to are not themselves in scope.
	s2 := scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: map[string][]netip.Addr{"a.example.com": addrs("192.0.2.1")}})
	if s2.InScopeIP(netip.MustParseAddr("192.0.2.1")) {
		t.Error("resolved IP must not be in scope by itself")
	}
}

// Overlapping netblocks are counted once; IPv6 is not counted.
func TestIPv4AddressCount(t *testing.T) {
	t.Parallel()
	s := scope.New(scope.Config{Netblocks: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.0/25"),   // inside the /24
		netip.MustParsePrefix("10.0.1.0/24"),   // adjacent
		netip.MustParsePrefix("10.0.0.128/25"), // inside the /24
		netip.MustParsePrefix("2001:db8::/32"),
	}})
	if got := s.IPv4AddressCount(); got != 512 {
		t.Errorf("count = %d, want 512", got)
	}
	// IPv4Addrs yields exactly the counted addresses, each once and in order.
	addrs := slices.Collect(s.IPv4Addrs())
	if len(addrs) != 512 || addrs[0] != netip.MustParseAddr("10.0.0.0") || addrs[511] != netip.MustParseAddr("10.0.1.255") ||
		!slices.IsSortedFunc(addrs, netip.Addr.Compare) || len(slices.Compact(slices.Clone(addrs))) != 512 {
		t.Errorf("IPv4Addrs = %d addresses, want 10.0.0.0-10.0.1.255 once each", len(addrs))
	}
	empty := scope.New(scope.Config{})
	if empty.IPv4AddressCount() != 0 {
		t.Error("empty")
	}
}

// The single eligibility function.
func TestPortEligible(t *testing.T) {
	t.Parallel()
	res := map[string][]netip.Addr{
		"www.example.com":   addrs("203.0.113.5"),
		"wild.example.com":  addrs("203.0.113.20"),
		"admin.example.com": addrs("203.0.113.6", "198.51.100.7"),
		"v6.example.com":    addrs("2001:db8::5"),
		"db.example.com":    addrs("192.0.2.9"),
		"other.example.org": addrs("203.0.113.40"),
	}
	s := scope.New(scope.Config{
		Roots:        []string{"example.com"},
		Netblocks:    []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions:   excl(t, "admin.example.com", "192.0.2.0/24"),
		Resolutions:  res,
		WildcardOnly: map[string]bool{"wild.example.com": true},
	})
	cases := []struct {
		name            string
		addr            string
		shared, unknown bool
		want            bool
	}{
		{"in-scope IP", "198.51.100.1", false, false, true},
		{"in-scope IP, shared", "198.51.100.1", true, false, true},
		{"hostname-resolved IP", "203.0.113.5", false, false, true},
		{"hostname-resolved IP that is shared", "203.0.113.5", true, false, false},
		{"hostname-resolved IP whose owner is unknown", "203.0.113.5", false, true, false},
		{"IPv6 hostname-resolved IP", "2001:db8::5", false, false, true},
		{"wildcard-only name does not make an IP eligible", "203.0.113.20", false, false, false},
		{"address of an excluded host", "203.0.113.6", false, false, false},
		{"address of an excluded host whose owner is unknown", "203.0.113.6", false, true, false},
		{"in-scope shared IP that an excluded host also uses", "198.51.100.7", true, false, true},
		{"in-scope IP of an excluded host, not shared", "198.51.100.7", false, false, false},
		{"excluded CIDR always refuses", "192.0.2.9", true, false, false},
		{"candidate hostname's IP", "203.0.113.40", false, false, false},
		{"unrelated IP", "8.8.8.8", false, false, false},
	}
	for _, c := range cases {
		owner := func(netip.Addr) (bool, bool) { return c.shared, !c.unknown }
		ok, why, _ := s.PortEligible(netip.MustParseAddr(c.addr), owner)
		if ok != c.want {
			t.Errorf("%s: PortEligible = %v (%s), want %v", c.name, ok, why, c.want)
		}
		if !ok && why == "" {
			t.Errorf("%s: a refusal needs a reason", c.name)
		}
	}
}

// An in-scope netblock address that no exclusion names is decided
// without asking who owns it, so a netblock sweep costs no owner lookups.
func TestPortEligibleAsksOwnerOnlyWhenNeeded(t *testing.T) {
	t.Parallel()
	s := scope.New(scope.Config{
		Netblocks:  []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions: excl(t, "192.0.2.0/24"),
	})
	asked := 0
	owner := func(netip.Addr) (bool, bool) { asked++; return false, true }
	for _, a := range []string{"198.51.100.1", "192.0.2.9"} {
		s.PortEligible(netip.MustParseAddr(a), owner)
	}
	if asked != 0 {
		t.Errorf("owner asked %d times for a netblock address and an excluded-CIDR address", asked)
	}
	s.PortEligible(netip.MustParseAddr("203.0.113.5"), owner)
	if asked != 1 {
		t.Errorf("owner asked %d times for an address outside the netblocks, want 1", asked)
	}
}

// Ownership units use /24 or /48 unless the containing in-scope netblock is narrower.
func TestOwnerUnit(t *testing.T) {
	t.Parallel()
	pfx := netip.MustParsePrefix
	sc := scope.New(scope.Config{Netblocks: []netip.Prefix{
		pfx("198.51.100.0/22"), pfx("203.0.113.16/28"), pfx("192.0.2.0/24"), pfx("2001:db8:1::/64"), pfx("2001:db8:2::/40"), pfx("2001:db8:3::/120"),
		pfx("10.0.0.0/8"), pfx("10.1.2.128/25"), // an address may be inside two netblocks
	}})
	for _, tc := range []struct {
		addr, want string // want is "" when the address is in no in-scope netblock
	}{
		{"198.51.101.77", "198.51.101.0/24"}, // a /22 is split into /24s
		{"198.51.100.1", "198.51.100.0/24"},
		{"203.0.113.17", "203.0.113.16/28"}, // a netblock smaller than a /24 is the unit
		{"203.0.113.40", ""},                // the rest of that /24 is not in scope
		{"192.0.2.9", "192.0.2.0/24"},
		{"2001:db8:1::5", "2001:db8:1::/64"},   // smaller than a /48
		{"2001:db8:2:5::1", "2001:db8:2::/48"}, // a /40 is split into /48s
		{"2001:db8:3::7", "2001:db8:3::/120"},
		{"10.1.2.130", "10.1.2.128/25"}, // the smallest netblock holding it
		{"10.9.9.9", "10.9.9.0/24"},
		{"::ffff:198.51.100.1", "198.51.100.0/24"},
		{"8.8.8.8", ""},
	} {
		got, ok := sc.OwnerUnit(netip.MustParseAddr(tc.addr))
		if (tc.want == "") == ok || (ok && got.String() != tc.want) {
			t.Errorf("OwnerUnit(%s) = %v, %v, want %q", tc.addr, got, ok, tc.want)
		}
	}
}
