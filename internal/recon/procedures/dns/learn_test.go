package dns

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// under gives each name the input root it is under.
func under(root string, names ...string) []learnHost {
	out := make([]learnHost, len(names))
	for i, n := range names {
		out[i] = learnHost{Name: n, Root: root}
	}
	return out
}

func anyZone(string) bool { return true }

// knownOrParent is the skip learned-names uses for the hosts given: a name that is known, or an
// ancestor of a known name below its root (a parent name, which resolve asks). Passing it leaves
// the tests free of whether learnNames leaves those out itself.
func knownOrParent(hosts []learnHost) func(string) bool {
	skip := map[string]bool{}
	for _, h := range hosts {
		for n := h.Name; n != h.Root && n != ""; {
			skip[n] = true
			_, n, _ = strings.Cut(n, ".")
		}
	}
	return func(name string) bool { return skip[name] }
}

// noRepeats fails when a name is planned twice.
func noRepeats(t *testing.T, names []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Errorf("%s is planned more than once", n)
		}
		seen[n] = true
	}
}

// Labels are ranked by how many zones have a known name whose first label it is, most first, then
// alphabetically; each label's names follow with their zones in alphabetical order. Every label
// below the root is learned, not just the first.
func TestLearnNames_Order(t *testing.T) {
	t.Parallel()
	hosts := under("example.com", "api.b.example.com", "api.c.example.com", "staging.a.example.com", "www.example.com")
	got := learnNames(hosts, []string{"example.com"}, anyZone, knownOrParent(hosts))
	want := []string{
		// api is the first label of names in two zones.
		"api.a.example.com", "api.example.com",
		// staging and www in one zone each, alphabetically.
		"staging.b.example.com", "staging.c.example.com", "staging.example.com",
		"www.a.example.com", "www.b.example.com", "www.c.example.com",
		// a, b and c are the first label of no known name.
		"a.a.example.com", "a.b.example.com", "a.c.example.com",
		"b.a.example.com", "b.b.example.com", "b.c.example.com",
		"c.a.example.com", "c.b.example.com", "c.c.example.com",
	}
	if !slices.Equal(got, want) {
		t.Errorf("learnNames =\n%q,\nwant\n%q", got, want)
	}
}

// The done-when case: staging.a and api.b known give staging.b and api.a.
func TestLearnNames_SiblingZones(t *testing.T) {
	t.Parallel()
	hosts := under("example.com", "staging.a.example.com", "api.b.example.com")
	got := learnNames(hosts, []string{"example.com"}, anyZone, knownOrParent(hosts))
	noRepeats(t, got)
	for _, n := range []string{"staging.b.example.com", "api.a.example.com", "staging.example.com", "api.example.com"} {
		if !slices.Contains(got, n) {
			t.Errorf("%s is not planned: %q", n, got)
		}
	}
}

// Every input root is a populated zone, even one with no known name; a host that is its own root
// gives no label.
func TestLearnNames_EveryRootIsAZone(t *testing.T) {
	t.Parallel()
	hosts := under("example.com", "staging.a.example.com")
	got := learnNames(hosts, []string{"example.com", "example.org"}, anyZone, knownOrParent(hosts))
	for _, n := range []string{"staging.example.org", "a.example.org", "staging.example.com"} {
		if !slices.Contains(got, n) {
			t.Errorf("%s is not planned: %q", n, got)
		}
	}
	if got := learnNames(under("example.com", "example.com"), []string{"example.com", "example.org"}, anyZone,
		func(string) bool { return false }); len(got) != 0 {
		t.Errorf("an input root gave labels: %q", got)
	}
}

// A name between a host and its root is a zone: api.dev.example.com makes dev.example.com one.
func TestLearnNames_DeeperZone(t *testing.T) {
	t.Parallel()
	hosts := under("example.com", "api.dev.example.com", "www.example.com")
	got := learnNames(hosts, []string{"example.com"}, anyZone, knownOrParent(hosts))
	want := map[string]bool{
		"www.dev.example.com": true, "api.example.com": true, "dev.dev.example.com": true,
	}
	for n := range want {
		if !slices.Contains(got, n) {
			t.Errorf("%s is not planned: %q", n, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("learnNames = %q, want only %q", got, slices.Sorted(maps.Keys(want)))
	}
}

// Labels are taken below a host's most specific root: under corp.example.com, "corp" is not a
// label. Every root is a zone.
func TestLearnNames_NestedRoots(t *testing.T) {
	t.Parallel()
	hosts := append(under("corp.example.com", "x.dev.corp.example.com"), under("example.com", "y.example.com")...)
	got := learnNames(hosts, []string{"example.com", "corp.example.com"}, anyZone, knownOrParent(hosts))
	noRepeats(t, got)
	for _, n := range got {
		if strings.HasPrefix(n, "corp.") {
			t.Errorf("%s: corp is not below the host's root", n)
		}
	}
	for _, n := range []string{"y.corp.example.com", "y.dev.corp.example.com", "x.example.com", "dev.example.com", "x.corp.example.com"} {
		if !slices.Contains(got, n) {
			t.Errorf("%s is not planned: %q", n, got)
		}
	}
}

// A label gives its hyphen-separated parts too; a digits-only label or part is not learned, and an
// xn-- label is not split.
func TestLearnNames_LabelForms(t *testing.T) {
	t.Parallel()
	hosts := under("example.com", "api-dev2.a.example.com", "2024.a.example.com", "web-2025.a.example.com",
		"xn--bcher-kva.a.example.com", "x.b.example.com")
	got := learnNames(hosts, []string{"example.com"}, anyZone, knownOrParent(hosts))
	noRepeats(t, got)
	for _, n := range []string{"api-dev2.b.example.com", "api.b.example.com", "dev2.b.example.com",
		"web-2025.b.example.com", "web.b.example.com", "xn--bcher-kva.b.example.com"} {
		if !slices.Contains(got, n) {
			t.Errorf("%s is not planned: %q", n, got)
		}
	}
	for _, n := range got {
		label, _, _ := strings.Cut(n, ".")
		if label == "2024" || label == "2025" || label == "xn" || label == "bcher" || label == "kva" {
			t.Errorf("%s: %s is not a learnable form", n, label)
		}
	}
}

// Nothing is planned under a zone zoneOK refuses, the root included; a host under such a zone
// still gives its labels.
func TestLearnNames_ZoneOK(t *testing.T) {
	t.Parallel()
	hosts := under("example.com", "staging.a.example.com", "api.b.example.com", "x.w.example.com")
	refused := map[string]bool{"w.example.com": true, "example.com": true}
	got := learnNames(hosts, []string{"example.com"}, func(z string) bool { return !refused[z] }, knownOrParent(hosts))
	want := []string{
		"api.a.example.com", "staging.b.example.com", "x.a.example.com", "x.b.example.com",
		"w.a.example.com", "w.b.example.com",
		"a.a.example.com", "a.b.example.com", "b.a.example.com", "b.b.example.com",
	}
	if !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
		t.Errorf("learnNames = %q,\nwant (in any order) %q", got, want)
	}
}

// A name skip accepts is left out, and the label's other names keep their order.
func TestLearnNames_Skip(t *testing.T) {
	t.Parallel()
	hosts := under("example.com", "api.b.example.com", "api.c.example.com", "staging.a.example.com", "www.example.com")
	known := knownOrParent(hosts)
	skipped := map[string]bool{"api.example.com": true, "www.b.example.com": true}
	got := learnNames(hosts, []string{"example.com"}, anyZone, func(n string) bool { return skipped[n] || known(n) })
	for n := range skipped {
		if slices.Contains(got, n) {
			t.Errorf("%s was skipped but is planned: %q", n, got)
		}
	}
	if len(got) < 7 || !slices.Equal(got[:7], []string{
		"api.a.example.com",
		"staging.b.example.com", "staging.c.example.com", "staging.example.com",
		"www.a.example.com", "www.c.example.com",
		"a.a.example.com",
	}) {
		t.Errorf("learnNames = %q", got)
	}
}

// A name over 253 characters is not a DNS name and is left out; one of 253 is kept.
func TestLearnNames_TooLong(t *testing.T) {
	t.Parallel()
	a60, b60, c60 := strings.Repeat("a", 60), strings.Repeat("b", 60), strings.Repeat("c", 60)
	k58, m59 := strings.Repeat("k", 58), strings.Repeat("m", 59)
	deepest := a60 + "." + b60 + "." + c60 + ".example.com" // 194 characters
	hosts := under("example.com", "api."+deepest, k58+".example.com", m59+".example.com")
	got := learnNames(hosts, []string{"example.com"}, anyZone, knownOrParent(hosts))
	for _, n := range got {
		if len(n) > 253 {
			t.Errorf("a name of %d characters is planned: %s", len(n), n)
		}
	}
	for _, n := range []string{k58 + "." + deepest, "api.example.com", a60 + ".example.com", m59 + "." + c60 + ".example.com"} {
		if !slices.Contains(got, n) {
			t.Errorf("%s (%d characters) is not planned", n, len(n))
		}
	}
	if slices.Contains(got, m59+"."+deepest) {
		t.Error("a name of 254 characters is planned")
	}
}

// The planning function for 5,000 labels by 500 zones: one pass's enumeration on a very
// large engagement.
func BenchmarkLearnNames(b *testing.B) {
	const zones, labels = 500, 5000
	// 499 zones below the root, plus the root; their 499 labels and 4,501 more.
	var hosts []learnHost
	for i := range labels - (zones - 1) {
		hosts = append(hosts, learnHost{Name: fmt.Sprintf("w%d.z%d.example.com", i, i%(zones-1)), Root: "example.com"})
	}
	roots := []string{"example.com"}
	none := func(string) bool { return false }
	for b.Loop() {
		learnNames(hosts, roots, anyZone, none)
	}
}
