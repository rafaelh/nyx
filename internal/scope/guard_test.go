package scope_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/scope"
)

// Names that are excluded by name, or under an input root, are not counted against the
// shared-hosting guard: 100 other names on the address still enter scope by it.
func TestByAddress_GuardLeavesOutExcludedAndRootedNames(t *testing.T) {
	t.Parallel()
	at := netip.MustParseAddr("198.51.100.7")
	lookups := map[string][]netip.Addr{
		"skip.example.org": {at}, // excluded by name
		"www.example.com":  {at}, // under the input root
	}
	for i := range 100 {
		lookups[fmt.Sprintf("name-%03d.example.org", i)] = []netip.Addr{at}
	}
	excl, err := input.ParseExclusions([]string{"skip.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	s := scope.New(scope.Config{
		Roots:              []string{"example.com"},
		Netblocks:          []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions:         excl,
		Lookups:            lookups,
		MaxNamesPerAddress: 100,
	})
	if got := s.SharedHosting(); len(got) != 0 {
		t.Errorf("SharedHosting = %v, want none: only 100 names count", got)
	}
	for _, h := range []string{"name-000.example.org", "name-099.example.org"} {
		if !s.InScopeByAddress(h) {
			t.Errorf("%s is not in scope by address", h)
		}
	}
	if s.InScopeByAddress("skip.example.org") || s.ClassifyHost("skip.example.org").Class != scope.Excluded {
		t.Errorf("the excluded name is in scope by address or not excluded: %v", s.ClassifyHost("skip.example.org"))
	}
}

// ByAddress and the checks built on it normalise the name they are asked about, as the rest of
// the scope does.
func TestByAddress_NormalisesTheName(t *testing.T) {
	t.Parallel()
	at := netip.MustParseAddr("198.51.100.7")
	s := scope.New(scope.Config{
		Netblocks:          []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Lookups:            map[string][]netip.Addr{"Www.Example.ORG.": {at}},
		Resolutions:        map[string][]netip.Addr{"www.example.org": {at}},
		MaxNamesPerAddress: 100,
	})
	for _, h := range []string{"www.example.org", "WWW.example.org.", "Www.Example.ORG."} {
		if addr, block, ok := s.ByAddress(h); !ok || addr != at || block != netip.MustParsePrefix("198.51.100.0/24") {
			t.Errorf("ByAddress(%q) = %v %v %v, want %v in 198.51.100.0/24", h, addr, block, ok, at)
		}
		if !s.InScopeByAddress(h) || s.ClassifyHost(h).Class != scope.InScope || len(s.DialAddrs(h)) != 1 {
			t.Errorf("%q: InScopeByAddress %v, ClassifyHost %v, DialAddrs %v", h, s.InScopeByAddress(h), s.ClassifyHost(h), s.DialAddrs(h))
		}
	}
}
