package cli_test

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	dnsproc "github.com/rafaelh/nyx/internal/recon/procedures/dns"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// learnWords is a wordlist whose one word is never a learned label, so the wordlist jobs ask
// nothing a learning test counts.
const learnWords = "zzword\n"

// learnBasicTried are the names learning tries in learnBasic's world, in rank order:
// api and staging each start a known name in one zone, a and b in none; each label's zones go
// alphabetically. Known names (staging.a, api.b) and parent names (a.example.com, b.example.com)
// are left out. None of them exists unless a test says so.
var learnBasicTried = []string{
	"api.a.example.com", "api.example.com",
	"staging.b.example.com", "staging.example.com",
	"a.a.example.com", "a.b.example.com",
	"b.a.example.com", "b.b.example.com",
}

// learnWorld is a world with a wordlist of learnWords and crt.sh answering byRoot.
func learnWorld(t *testing.T, byRoot map[string][]string) (*world, string) {
	t.Helper()
	w := newWorld(t)
	wl := writeFile(t, t.TempDir(), "words.txt", learnWords)
	w.crtsh(byRoot, nil)
	return w, wl
}

// learnBasic is the world of the spec's first done-when: staging.a.example.com and
// api.b.example.com are known and resolve; their parents do not.
func learnBasic(t *testing.T) (*world, string) {
	t.Helper()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"staging.a.example.com", "api.b.example.com"}})
	w.dns.A("staging.a.example.com", "203.0.113.5")
	w.dns.A("api.b.example.com", "203.0.113.6")
	return w, wl
}

// learnRun runs passively with one worker and the test's wordlist, so names are asked in the
// order the procedures yield them. args carries the roots.
func learnRun(w *world, wl string, args ...string) int {
	w.t.Helper()
	return w.run(append([]string{"--passive", "--concurrency", "1", "--wordlist", wl}, args...)...)
}

// learnMustRun is learnRun that fails the test unless the run exits 0.
func learnMustRun(w *world, wl string, args ...string) {
	w.t.Helper()
	if code := learnRun(w, wl, args...); code != 0 {
		w.t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
}

// learnA is the number of A queries the fake DNS received for each name.
func learnA(w *world, names ...string) map[string]int {
	out := map[string]int{}
	for _, n := range names {
		out[n] = w.dns.Count(n, "A")
	}
	return out
}

// learnWantA fails for each name whose A query count is not want.
func learnWantA(t *testing.T, w *world, want int, why string, names ...string) {
	t.Helper()
	for n, got := range learnA(w, names...) {
		if got != want {
			t.Errorf("%s asked for A %d times, want %d: %s", n, got, want, why)
		}
	}
}

// learnJobs are the learned-names jobs the engagement has completed: one per tried name.
func learnJobs(w *world) []string { return w.h.completed(eng, "learned-names") }

// learnFoundBy are the names of the hostname records a procedure produced.
func learnFoundBy(w *world, producer string) []string {
	return queryStrings(w.t, w.h.openDB(eng), "SELECT key FROM observations WHERE kind='hostname' AND producer=?", producer)
}

// learnFixedProbes replaces the wildcard procedure with one whose probe labels are zzprobe0 and
// zzprobe1, so a test can make one zone's probes fail. It returns the probe names under zone.
func learnFixedProbes(t *testing.T, w *world, zone string) []string {
	t.Helper()
	var n atomic.Int32
	label := func() string { return fmt.Sprintf("zzprobe%d", n.Add(1)%2) }
	i := slices.IndexFunc(w.h.procedures, func(p run.Procedure) bool { return p.Name() == "wildcard" })
	if i < 0 {
		t.Fatal("the world has no wildcard procedure")
	}
	w.h.procedures[i] = dnsproc.NewWildcard(label)
	return []string{"zzprobe0." + zone, "zzprobe1." + zone}
}

// --- Learning, populated zones, trying ---

// The first done-when: each label is tried under the other zones; the tried names that exist
// are recorded and resolved, the others are not.
func TestLearnedNames_LabelsAreTriedUnderTheOtherZones(t *testing.T) {
	t.Parallel()
	w, wl := learnBasic(t)
	w.dns.A("staging.b.example.com", "203.0.113.7")
	w.dns.A("api.a.example.com", "203.0.113.8")
	learnMustRun(w, wl, "example.com")

	if got := learnJobs(w); !slices.Equal(got, sorted(learnBasicTried)) {
		t.Errorf("learned-names jobs = %v, want one per tried name %v", got, sorted(learnBasicTried))
	}
	hosts := w.lines(eng, "subdomains.txt")
	for _, n := range []string{"staging.b.example.com", "api.a.example.com"} {
		if !slices.Contains(hosts, n) {
			t.Errorf("%s exists and was tried, yet subdomains.txt is %v", n, hosts)
		}
		if find(w.table(eng, "resolutions.csv"), "name", n) == nil {
			t.Errorf("%s was found by trying but not resolved like any other hostname", n)
		}
	}
	if got := learnFoundBy(w, "learned-names"); !slices.Equal(got, []string{"api.a.example.com", "staging.b.example.com"}) {
		t.Errorf("hostnames learned-names recorded = %v, want the two that exist", got)
	}
	if slices.Contains(hosts, "staging.example.com") {
		t.Errorf("staging.example.com does not exist, yet it was recorded: %v", hosts)
	}
	learnWantA(t, w, 1, "tried once by learning and not found", "staging.example.com", "api.example.com", "a.a.example.com", "b.b.example.com")
}

// A label's hyphen-separated parts are learned too, unless it begins xn--; digits-only labels and
// parts are not.
func TestLearnedNames_HyphenPartsDigitsAndPunycode(t *testing.T) {
	t.Parallel()
	known := []string{"api-dev2.a.example.com", "web-01.a.example.com", "42.a.example.com", "xn--bcher-kva.a.example.com", "x.b.example.com"}
	w, wl := learnWorld(t, map[string][]string{"example.com": known})
	for i, n := range known {
		w.dns.A(n, fmt.Sprintf("203.0.113.%d", 10+i))
	}
	learnMustRun(w, wl, "example.com")

	learnWantA(t, w, 1, "a learned label or part, tried under b.example.com",
		"api-dev2.b.example.com", "api.b.example.com", "dev2.b.example.com",
		"web-01.b.example.com", "web.b.example.com", "xn--bcher-kva.b.example.com")
	learnWantA(t, w, 0, "digits only, or a part of an xn-- label",
		"42.b.example.com", "01.b.example.com", "xn.b.example.com", "bcher.b.example.com", "kva.b.example.com")
}

// A hostname with neither an address nor a CNAME gives no label and makes no zone; one with only
// a CNAME does both.
func TestLearnedNames_NoAnswerGivesNoLabelAndNoZone(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"ghost.c.example.com", "alias.d.example.com", "api.b.example.com"}})
	w.dns.CNAME("alias.d.example.com", "gone.example.net") // a CNAME, and no address
	w.dns.A("api.b.example.com", "203.0.113.6")
	learnMustRun(w, wl, "example.com")

	learnWantA(t, w, 0, "ghost.c.example.com has no address and no CNAME, so gives no label and c.example.com is no zone",
		"ghost.b.example.com", "ghost.example.com", "api.c.example.com", "c.b.example.com")
	learnWantA(t, w, 1, "alias.d.example.com has a CNAME, so gives labels and makes d.example.com a zone",
		"alias.b.example.com", "alias.example.com", "api.d.example.com", "d.b.example.com")
}

// A wildcard-only name gives no label; a name with its own answer under the wildcard zone does.
func TestLearnedNames_WildcardOnlyNameGivesNoLabel(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"junk.w.example.com", "real.w.example.com", "api.b.example.com"}})
	w.dns.Wildcard("w.example.com", "203.0.113.1")
	w.dns.A("real.w.example.com", "203.0.113.50")
	w.dns.A("api.b.example.com", "203.0.113.6")
	learnMustRun(w, wl, "example.com")

	if got := w.lines(eng, "wildcard-excluded.txt"); !slices.Equal(got, []string{"junk.w.example.com"}) {
		t.Fatalf("setup: wildcard-excluded.txt = %v, want junk.w.example.com", got)
	}
	learnWantA(t, w, 0, "junk.w.example.com is wildcard-only", "junk.b.example.com", "junk.example.com")
	learnWantA(t, w, 1, "real.w.example.com has its own answer", "real.b.example.com", "real.example.com")
}

// Every in-scope name between a learnable hostname and its root is a zone that labels are tried
// under.
func TestLearnedNames_AncestorsArePopulatedZones(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"api.dev.eu.example.com", "web.b.example.com"}})
	w.dns.A("api.dev.eu.example.com", "203.0.113.5")
	w.dns.A("web.b.example.com", "203.0.113.6")
	learnMustRun(w, wl, "example.com")

	learnWantA(t, w, 1, "web is tried under each ancestor of api.dev.eu.example.com",
		"web.dev.eu.example.com", "web.eu.example.com", "web.example.com")
	learnWantA(t, w, 1, "the labels of api.dev.eu.example.com are tried under b.example.com",
		"api.b.example.com", "dev.b.example.com", "eu.b.example.com")
}

// With nested roots a name's labels are taken below its most specific root.
func TestLearnedNames_NestedRootsUseTheMostSpecificRoot(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{
		"example.com":      {"api.b.example.com"},
		"corp.example.com": {"vpn.x.corp.example.com"},
	})
	w.dns.A("api.b.example.com", "203.0.113.6")
	w.dns.A("vpn.x.corp.example.com", "203.0.113.7")
	learnMustRun(w, wl, "example.com", "corp.example.com")

	learnWantA(t, w, 1, "a label below corp.example.com, or api under corp.example.com's zones",
		"vpn.b.example.com", "x.b.example.com", "api.corp.example.com", "api.x.corp.example.com")
	learnWantA(t, w, 0, "corp is part of the root corp.example.com, not a label below it",
		"corp.b.example.com", "corp.x.corp.example.com")
}

// --- The learn guard ---

// A name under a zone whose wildcard probes fail gives no label; once a run's check succeeds, it
// does.
func TestLearnedNames_NoLabelUntilTheZonesWildcardCheckCompletes(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"staging.f.example.com", "api.b.example.com"}})
	w.dns.A("staging.f.example.com", "203.0.113.5")
	w.dns.A("api.b.example.com", "203.0.113.6")
	probes := learnFixedProbes(t, w, "f.example.com")
	for _, p := range probes {
		w.dns.Rcode(p, int(mdns.RcodeServerFailure))
	}
	if code := learnRun(w, wl, "example.com"); code != 7 {
		t.Fatalf("exit %d, want 7 (the wildcard job of f.example.com fails)\n%s", code, w.h.stderr.String())
	}
	learnWantA(t, w, 0, "staging.f.example.com's zone has no completed wildcard check",
		"staging.b.example.com", "staging.example.com", "f.b.example.com")
	learnWantA(t, w, 1, "api.b.example.com's zone was checked, so api is learned", "api.example.com")

	for _, p := range probes {
		w.dns.ClearRcode(p)
	}
	learnMustRun(w, wl, "example.com")
	learnWantA(t, w, 1, "the check has completed, so staging is learned", "staging.b.example.com", "staging.example.com")
}

// --- Existence by A or CNAME ---

// A tried name exists when its A lookup gives an address or a CNAME (even one whose target does
// not exist); one answered NXDOMAIN is not recorded.
func TestLearnedNames_ExistsByAddressOrCNAME(t *testing.T) {
	t.Parallel()
	w, wl := learnBasic(t)
	w.dns.A("staging.b.example.com", "203.0.113.7")
	w.dns.CNAME("api.a.example.com", "lb.example.net")
	w.dns.A("lb.example.net", "203.0.113.10")
	w.dns.CNAME("staging.example.com", "gone.example.net") // the target answers NXDOMAIN
	learnMustRun(w, wl, "example.com")

	want := []string{"api.a.example.com", "staging.b.example.com", "staging.example.com"}
	if got := learnFoundBy(w, "learned-names"); !slices.Equal(got, want) {
		t.Errorf("hostnames learned-names recorded = %v, want %v", got, want)
	}
	hosts := w.lines(eng, "subdomains.txt")
	for _, n := range want {
		if !slices.Contains(hosts, n) {
			t.Errorf("%s exists, yet subdomains.txt is %v", n, hosts)
		}
	}
	for _, n := range []string{"api.example.com", "a.a.example.com", "b.b.example.com"} {
		if slices.Contains(hosts, n) {
			t.Errorf("%s answered NXDOMAIN, yet it was recorded", n)
		}
	}
	learnWantA(t, w, 1, "tried and answered NXDOMAIN", "api.example.com", "a.a.example.com")
}

// --- Once ---

// A second run with nothing new sends no learning lookup, and no lookup at all.
func TestLearnedNames_SecondRunWithNothingNewAsksNothing(t *testing.T) {
	t.Parallel()
	w, wl := learnBasic(t)
	learnMustRun(w, wl, "example.com")
	learnWantA(t, w, 1, "tried once in the first run", learnBasicTried...)

	before := w.dns.Total()
	learnMustRun(w, wl, "example.com")
	if after := w.dns.Total(); after != before {
		t.Errorf("the second run sent %d DNS queries, want 0", after-before)
	}
	learnWantA(t, w, 1, "not tried again", learnBasicTried...)
}

// A name answered NXDOMAIN is not asked on the next run; --redo learned-names asks it again.
func TestLearnedNames_TriedOnceUntilRedone(t *testing.T) {
	t.Parallel()
	w, wl := learnBasic(t)
	learnMustRun(w, wl, "example.com")
	learnWantA(t, w, 1, "tried in the first run", learnBasicTried...)
	learnMustRun(w, wl, "example.com")
	learnWantA(t, w, 1, "an NXDOMAIN answer is not asked again", learnBasicTried...)

	learnMustRun(w, wl, "example.com", "--redo", "learned-names")
	learnWantA(t, w, 2, "--redo learned-names tries each name again", learnBasicTried...)
	if got := learnJobs(w); !slices.Equal(got, sorted(learnBasicTried)) {
		t.Errorf("learned-names jobs after the redo = %v, want %v", got, sorted(learnBasicTried))
	}
}

// A name already known is never tried by learning.
func TestLearnedNames_KnownNameIsNotTried(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"staging.a.example.com", "api.b.example.com", "staging.b.example.com"}})
	for i, n := range []string{"staging.a.example.com", "api.b.example.com", "staging.b.example.com"} {
		w.dns.A(n, fmt.Sprintf("203.0.113.%d", 5+i))
	}
	learnMustRun(w, wl, "example.com")

	if n := w.dns.Count("staging.b.example.com", "A"); n != 1 {
		t.Errorf("staging.b.example.com asked for A %d times, want once (by resolve; it is known)", n)
	}
	jobs := learnJobs(w)
	if slices.Contains(jobs, "staging.b.example.com") {
		t.Errorf("learning tried the known staging.b.example.com: %v", jobs)
	}
	if !slices.Contains(jobs, "staging.example.com") || !slices.Contains(jobs, "api.a.example.com") {
		t.Errorf("learned-names jobs = %v, want staging.example.com and api.a.example.com among them", jobs)
	}
}

// learnTwoRoots is a world with roots example.com and example.org and the wordlist "dev": dev and
// a are learned from dev.a.example.com, so dev.example.com and dev.example.org are wordlist names.
func learnTwoRoots(t *testing.T) (*world, string) {
	t.Helper()
	w := newWorld(t)
	wl := writeFile(t, t.TempDir(), "words.txt", "dev\n")
	w.crtsh(map[string][]string{"example.com": {"dev.a.example.com"}}, nil)
	w.dns.A("dev.a.example.com", "203.0.113.5")
	return w, wl
}

// A wordlist label directly under an input root is left to the wordlist job, even while that
// job is deferred: each such name is asked once over two runs.
func TestLearnedNames_WordlistNamesAreLeftToTheWordlistJob(t *testing.T) {
	t.Parallel()
	w, wl := learnTwoRoots(t)
	// One root's wordlist job is 1 word + 5 well-known labels: the cap admits example.com's and
	// defers example.org's.
	args := []string{"--permutations-max-names", "6", "example.com", "example.org"}
	learnMustRun(w, wl, args...)
	if n := deferredOf(t, w.h, "permutations"); n == 0 {
		t.Fatal("setup: example.org's wordlist job was not deferred")
	}
	learnWantA(t, w, 1, "learning tries a, not a wordlist word, under each root", "a.example.org", "a.a.example.com")
	learnWantA(t, w, 1, "example.com's wordlist job asks it, and learning does not", "dev.example.com")
	learnWantA(t, w, 0, "example.org's wordlist job is deferred, and learning leaves the name to it", "dev.example.org")

	learnMustRun(w, wl, args...)
	learnWantA(t, w, 1, "asked once over two runs", "dev.example.com", "dev.example.org")
}

// With --skip permutations learning tries the wordlist labels under the roots, and a later run
// with permutations on asks them again.
func TestLearnedNames_SkipPermutationsTriesWordlistNames(t *testing.T) {
	t.Parallel()
	w, wl := learnTwoRoots(t)
	learnMustRun(w, wl, "--skip", "permutations", "example.com", "example.org")
	learnWantA(t, w, 1, "learning tries the label under each root while permutations is skipped", "dev.example.com", "dev.example.org")

	learnMustRun(w, wl, "example.com", "example.org")
	learnWantA(t, w, 2, "the wordlist jobs ask them again", "dev.example.com", "dev.example.org")
}

// The parent of a resolving name that has no records itself is asked once, by resolve, not again
// by learning.
func TestLearnedNames_ParentNameIsLeftToResolve(t *testing.T) {
	t.Parallel()
	w, wl := learnBasic(t)
	learnMustRun(w, wl, "example.com")
	learnWantA(t, w, 1, "a parent name with no records, asked once by its parent job", "a.example.com", "b.example.com")
	jobs := learnJobs(w)
	if slices.Contains(jobs, "a.example.com") || slices.Contains(jobs, "b.example.com") {
		t.Errorf("learning tried a parent name: %v", jobs)
	}
	if len(jobs) == 0 {
		t.Error("learning tried nothing")
	}
}

// --- Rounds ---

// In one run: a tried name is found, permutations finds a variant of it, and the variant's label
// is tried under another zone. A parent that resolves is learned from in the same run.
func TestLearnedNames_FindsAreLearnedFromInTheSameRun(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"staging.a.example.com", "api.b.example.com", "x.p.example.com"}})
	w.dns.A("staging.a.example.com", "203.0.113.5")
	w.dns.A("api.b.example.com", "203.0.113.6")
	w.dns.A("staging.b.example.com", "203.0.113.7")  // found by trying staging under b
	w.dns.A("staging1.b.example.com", "203.0.113.8") // a variant permutations makes of it
	w.dns.A("p.example.com", "203.0.113.9")          // the parent of x.p.example.com, which does not resolve
	learnMustRun(w, wl, "example.com")

	hosts := w.lines(eng, "subdomains.txt")
	for _, n := range []string{"staging.b.example.com", "staging1.b.example.com", "p.example.com"} {
		if !slices.Contains(hosts, n) {
			t.Errorf("%s not found in the run: %v", n, hosts)
		}
	}
	learnWantA(t, w, 1, "staging1 is learned from the variant permutations found, in the same run", "staging1.example.com")
	learnWantA(t, w, 1, "p is learned from the parent resolve found, in the same run", "p.b.example.com", "p.a.example.com")
}

// learnHexProbe matches the wildcard procedure's random probe names: 16 hex characters.
var learnHexProbe = regexp.MustCompile(`^[0-9a-f]{16}\.`)

// learnSum is the number of queries of one type the fake DNS received in all.
func learnSum(w *world, qtype string) int {
	n := 0
	for _, name := range w.dns.Queried(qtype) {
		n += w.dns.Count(name, qtype)
	}
	return n
}

// A world in which every name tried exists (and no wildcard is detected) still ends, and each
// procedure's lookups stay within its cap.
func TestLearnedNames_EveryNameExistingStillEnds(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"api.a.example.com"}})
	w.dns.AnySuffix("example.com", learnHexProbe.MatchString, "203.0.113.77")
	const permCap, learnCap = 20, 15
	code := learnRun(w, wl, "--timeout", "60s", "--permutations-max", "2",
		"--permutations-max-names", fmt.Sprint(permCap), "--learned-names-max-names", fmt.Sprint(learnCap), "example.com")
	if code != 0 {
		t.Fatalf("exit %d, want the run to end by itself\n%s", code, w.h.stderr.String())
	}
	learned := len(learnJobs(w))
	if learned != learnCap {
		t.Errorf("learned-names tried %d names, want its cap of %d spent", learned, learnCap)
	}
	if n := len(learnFoundBy(w, "learned-names")); n != learned {
		t.Errorf("learned-names recorded %d hostnames from %d tried names, all of which exist", n, learned)
	}
	// resolve, wildcard and parent jobs ask A and AAAA alike; guessing asks only A.
	perm := learnSum(w, "A") - learnSum(w, "AAAA") - learned
	if perm > permCap {
		t.Errorf("permutations asked %d names, over its cap of %d", perm, permCap)
	}
	if n := deferredOf(t, w.h, "learned-names"); n == 0 {
		t.Error("an endless supply of names left nothing deferred for learned-names")
	}
}

// --- The cap ---

// learnRankWorld: zeta starts known names in two zones (a, b), alpha and beta in one (c), and
// a, b and c in none. Learning has 17 names to try, ranked zeta, alpha, beta, a, b, c.
func learnRankWorld(t *testing.T) (*world, string) {
	t.Helper()
	known := []string{"zeta.a.example.com", "zeta.b.example.com", "alpha.c.example.com", "beta.c.example.com"}
	w, wl := learnWorld(t, map[string][]string{"example.com": known})
	for i, n := range known {
		w.dns.A(n, fmt.Sprintf("203.0.113.%d", 20+i))
	}
	return w, wl
}

// learnRanked are learnRankWorld's tried names in rank order.
var learnRanked = []string{
	"zeta.c.example.com", "zeta.example.com",
	"alpha.a.example.com", "alpha.b.example.com", "alpha.example.com",
	"beta.a.example.com", "beta.b.example.com", "beta.example.com",
	"a.a.example.com", "a.b.example.com", "a.c.example.com",
	"b.a.example.com", "b.b.example.com", "b.c.example.com",
	"c.a.example.com", "c.b.example.com", "c.c.example.com",
}

// A cap of N tries the first N names in rank order and defers the rest; the next run tries the
// rest and repeats none.
func TestLearnedNames_CapTriesTheHighestRankedAndDefersTheRest(t *testing.T) {
	t.Parallel()
	w, wl := learnRankWorld(t)
	learnMustRun(w, wl, "--learned-names-max-names", "4", "example.com")
	// zeta (two zones) before alpha and beta (one each, alpha first), its zones alphabetically.
	learnWantA(t, w, 1, "among the 4 highest ranked", learnRanked[:4]...)
	learnWantA(t, w, 0, "ranked below the cap", learnRanked[4:]...)
	if got := learnJobs(w); !slices.Equal(got, sorted(learnRanked[:4])) {
		t.Errorf("learned-names jobs = %v, want %v", got, sorted(learnRanked[:4]))
	}
	if n := deferredOf(t, w.h, "learned-names"); n != len(learnRanked)-4 {
		t.Errorf("learned-names deferred = %d, want %d", n, len(learnRanked)-4)
	}
	if n := deferredOf(t, w.h, "permutations"); n != 0 {
		t.Errorf("permutations deferred = %d, want 0: learning's cap is its own", n)
	}
	if st, _ := stateOf(w, "learned-names"); st != "done" {
		t.Errorf("a deferring learned-names must show done, got %q", st)
	}

	learnMustRun(w, wl, "example.com")
	learnWantA(t, w, 1, "each name is tried once over the two runs", learnRanked...)
	if n := deferredOf(t, w.h, "learned-names"); n != 0 {
		t.Errorf("learned-names deferred after the last run = %d, want 0", n)
	}
}

// The console summary gives learning's deferred names on their own line.
func TestLearnedNames_CapDeferralInTheConsole(t *testing.T) {
	t.Parallel()
	w, wl := learnRankWorld(t)
	code := w.h.exec("--rate-per-source", "1000", "--rate-dns", "100000", "--passive", "--concurrency", "1",
		"--wordlist", wl, "--learned-names-max-names", "4", "example.com")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	block := deferredBlock(t, w.h.stdout.String())
	if !regexp.MustCompile(fmt.Sprintf(`(?m)^\s+learned-names\s+%d$`, len(learnRanked)-4)).MatchString(block) {
		t.Errorf("the deferred block has no line \"learned-names %d\":\n%s", len(learnRanked)-4, block)
	}
}

// A permutations deferral does not defer learning, and the reverse.
func TestLearnedNames_CapsAreSeparate(t *testing.T) {
	t.Parallel()
	t.Run("permutations deferred", func(t *testing.T) {
		t.Parallel()
		w, wl := learnBasic(t)
		// The root's wordlist job (1 word + 5 well-known labels) spends the cap; the seeds wait.
		learnMustRun(w, wl, "--permutations-max-names", "6", "example.com")
		if n := deferredOf(t, w.h, "permutations"); n == 0 {
			t.Fatal("setup: permutations deferred nothing")
		}
		learnWantA(t, w, 1, "learning is not held back by the permutations cap", learnBasicTried...)
		if n := deferredOf(t, w.h, "learned-names"); n != 0 {
			t.Errorf("learned-names deferred = %d, want 0", n)
		}
	})
	t.Run("learning deferred", func(t *testing.T) {
		t.Parallel()
		w, wl := learnBasic(t)
		learnMustRun(w, wl, "--learned-names-max-names", "2", "example.com")
		if n := deferredOf(t, w.h, "learned-names"); n != len(learnBasicTried)-2 {
			t.Errorf("learned-names deferred = %d, want %d", n, len(learnBasicTried)-2)
		}
		if n := deferredOf(t, w.h, "permutations"); n != 0 {
			t.Errorf("permutations deferred = %d, want 0: learning's cap is its own", n)
		}
		learnWantA(t, w, 1, "a variant of a seed: permutations is not held back by learning's cap",
			"staging1.a.example.com", "api1.b.example.com", "zzword.example.com")
	})
}

// --learned-names-max-names must be at least 1; it is checked before anything is sent.
func TestLearnedNames_InvalidCapExits2(t *testing.T) {
	t.Parallel()
	w, wl := learnBasic(t)
	if code := learnRun(w, wl, "--learned-names-max-names", "0", "example.com"); code != 2 {
		t.Errorf("exit %d, want 2", code)
	}
	if !strings.Contains(w.h.stderr.String(), "learned_names.max_names") {
		t.Errorf("the error does not name the setting:\n%s", w.h.stderr.String())
	}
	if n := w.dns.Total(); n != 0 {
		t.Errorf("%d DNS queries after a validation error, want 0", n)
	}
	learnMustRun(w, wl, "--learned-names-max-names", "1", "example.com")
	if got := learnJobs(w); len(got) != 1 {
		t.Errorf("a cap of 1 tried %v, want one name", got)
	}
}

// --- Wildcards ---

// Nothing is tried under a wildcard zone.
func TestLearnedNames_NothingUnderAWildcardZone(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"real.w.example.com", "api.b.example.com"}})
	w.dns.Wildcard("w.example.com", "203.0.113.1")
	w.dns.A("real.w.example.com", "203.0.113.50")
	w.dns.A("api.b.example.com", "203.0.113.6")
	learnMustRun(w, wl, "example.com")

	learnWantA(t, w, 0, "under the wildcard zone w.example.com", "api.w.example.com", "b.w.example.com", "w.w.example.com")
	learnWantA(t, w, 1, "under a zone with no wildcard", "real.b.example.com", "w.b.example.com", "api.example.com")
}

// Nothing is tried under a zone whose wildcard job failed; its names are tried in the run after
// the check succeeds.
func TestLearnedNames_NothingUnderAZoneWhoseWildcardCheckFailed(t *testing.T) {
	t.Parallel()
	// x.g.f.example.com is learnable (its zone g.f.example.com is checked), so f.example.com is a
	// populated zone; only its own wildcard check fails.
	w, wl := learnWorld(t, map[string][]string{"example.com": {"x.g.f.example.com", "web.b.example.com"}})
	w.dns.A("x.g.f.example.com", "203.0.113.5")
	w.dns.A("web.b.example.com", "203.0.113.6")
	probes := learnFixedProbes(t, w, "f.example.com")
	for _, p := range probes {
		w.dns.Rcode(p, int(mdns.RcodeServerFailure))
	}
	under := []string{"x.f.example.com", "web.f.example.com", "b.f.example.com", "f.f.example.com"}
	if code := learnRun(w, wl, "example.com"); code != 7 {
		t.Fatalf("exit %d, want 7 (the wildcard job of f.example.com fails)\n%s", code, w.h.stderr.String())
	}
	learnWantA(t, w, 0, "f.example.com's wildcard job failed", under...)
	learnWantA(t, w, 1, "under zones whose checks completed", "web.g.f.example.com", "x.b.example.com")

	for _, p := range probes {
		w.dns.ClearRcode(p)
	}
	learnMustRun(w, wl, "example.com")
	learnWantA(t, w, 1, "tried once the check has succeeded", under...)
}

// --- Exclusions ---

// An excluded name is never tried, and nothing is tried under one, even a zone whose wildcard
// check completed before it was excluded.
func TestLearnedNames_Exclusions(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"x.c.example.com", "web.b.example.com"}})
	w.dns.A("x.c.example.com", "203.0.113.5")
	w.dns.A("web.b.example.com", "203.0.113.6")
	learnMustRun(w, wl, "-x", "x.b.example.com", "example.com")
	learnWantA(t, w, 0, "excluded", "x.b.example.com")
	learnWantA(t, w, 1, "not excluded", "x.example.com", "web.example.com", "web.c.example.com")

	// c.example.com is excluded now; a new label would otherwise be tried under it.
	w.crtsh(map[string][]string{"example.com": {"x.c.example.com", "web.b.example.com", "fresh.b.example.com"}}, nil)
	w.dns.A("fresh.b.example.com", "203.0.113.7")
	learnMustRun(w, wl, "--redo", "crtsh", "-x", "c.example.com", "example.com")
	learnWantA(t, w, 0, "under the excluded c.example.com", "fresh.c.example.com")
	learnWantA(t, w, 0, "still excluded", "x.b.example.com")
	learnWantA(t, w, 1, "the new label, under a zone that is not excluded", "fresh.example.com")
}

// --- Passive, procedure and switch ---

// Learning runs under --passive, and without --authorised.
func TestLearnedNames_RunsPassiveAndUnauthorised(t *testing.T) {
	t.Parallel()
	for name, mode := range map[string][]string{"passive": {"--passive"}, "not authorised": nil} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w, wl := learnBasic(t)
			args := append(append(slices.Clone(mode), "--concurrency", "1", "--wordlist", wl), "example.com")
			if code := w.run(args...); code != 0 {
				t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
			}
			if st, reason := stateOf(w, "learned-names"); st != "done" {
				t.Errorf("learned-names = %q (%s), want done", st, reason)
			}
			learnWantA(t, w, 1, "tried", learnBasicTried...)
		})
	}
}

// --skip of either procedure leaves the other running.
func TestLearnedNames_SkipEitherLeavesTheOther(t *testing.T) {
	t.Parallel()
	t.Run("skip learned-names", func(t *testing.T) {
		t.Parallel()
		w, wl := learnBasic(t)
		learnMustRun(w, wl, "--skip", "learned-names", "example.com")
		if st, reason := stateOf(w, "learned-names"); st != "not-configured" || reason != "skipped" {
			t.Errorf("learned-names = %s (%s), want not-configured (skipped)", st, reason)
		}
		if st, _ := stateOf(w, "permutations"); st != "done" {
			t.Errorf("permutations = %q, want done", st)
		}
		learnWantA(t, w, 0, "learning is skipped", learnBasicTried...)
		learnWantA(t, w, 1, "permutations still runs", "zzword.example.com", "staging1.a.example.com")
	})
	t.Run("skip permutations", func(t *testing.T) {
		t.Parallel()
		w, wl := learnBasic(t)
		learnMustRun(w, wl, "--skip", "permutations", "example.com")
		if st, reason := stateOf(w, "permutations"); st != "not-configured" || reason != "skipped" {
			t.Errorf("permutations = %s (%s), want not-configured (skipped)", st, reason)
		}
		if st, _ := stateOf(w, "learned-names"); st != "done" {
			t.Errorf("learned-names = %q, want done", st)
		}
		learnWantA(t, w, 1, "learning still runs", learnBasicTried...)
		learnWantA(t, w, 0, "permutations is skipped", "zzword.example.com", "staging1.a.example.com")
	})
}

// --no-permutations turns both procedures off.
func TestLearnedNames_NoPermutationsTurnsBothOff(t *testing.T) {
	t.Parallel()
	w, wl := learnBasic(t)
	learnMustRun(w, wl, "--no-permutations", "example.com")
	for _, p := range []string{"permutations", "learned-names"} {
		if st, reason := stateOf(w, p); st != "not-configured" || reason != "disabled" {
			t.Errorf("%s = %q (%s), want not-configured (disabled)", p, st, reason)
		}
	}
	learnWantA(t, w, 0, "learning is turned off", learnBasicTried...)
}

// --- Failure and re-run ---

// A tried name whose lookup times out fails only its own job; the next run asks just that name.
func TestLearnedNames_TimeoutFailsOnlyThatName(t *testing.T) {
	t.Parallel()
	w, wl := learnBasic(t)
	w.dns.A("api.a.example.com", "203.0.113.8")
	w.dns.A("staging.b.example.com", "203.0.113.7")
	w.dns.Drop("staging.b.example.com")
	w.h.partialFailed(learnRun(w, wl, "example.com"), "learned-names", 1)
	others := slices.DeleteFunc(slices.Clone(learnBasicTried), func(n string) bool { return n == "staging.b.example.com" })
	if got := learnJobs(w); !slices.Equal(got, sorted(others)) {
		t.Errorf("learned-names jobs = %v, want every tried name but the one that timed out: %v", got, sorted(others))
	}
	if hosts := w.lines(eng, "subdomains.txt"); !slices.Contains(hosts, "api.a.example.com") || slices.Contains(hosts, "staging.b.example.com") {
		t.Errorf("subdomains.txt = %v, want api.a.example.com and not the name that timed out", hosts)
	}

	before := learnA(w, others...)
	w.dns.Undrop("staging.b.example.com")
	learnMustRun(w, wl, "example.com")
	if after := learnA(w, others...); !maps.Equal(before, after) {
		t.Errorf("the re-run asked names that had completed: before %v, after %v", before, after)
	}
	if got := learnJobs(w); !slices.Equal(got, sorted(learnBasicTried)) {
		t.Errorf("learned-names jobs after the re-run = %v, want %v", got, sorted(learnBasicTried))
	}
	if hosts := w.lines(eng, "subdomains.txt"); !slices.Contains(hosts, "staging.b.example.com") {
		t.Errorf("the retried name was not recorded: %v", hosts)
	}
}

// An interrupted run keeps the names it completed, and the re-run asks only the rest.
func TestLearnedNames_InterruptKeepsCompletedNames(t *testing.T) {
	t.Parallel()
	w, wl := learnBasic(t)
	w.dns.Slow(100*time.Millisecond, learnBasicTried...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})
	go func() {
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				asked := 0
				for _, n := range learnA(w, learnBasicTried...) {
					asked += n
				}
				if asked >= 3 { // two names answered, the third in flight
					cancel()
					return
				}
			}
		}
	}()
	code := w.h.execCtx(ctx, "--json", "--rate-per-source", "1000", "--rate-dns", "100000",
		"--passive", "--concurrency", "1", "--wordlist", wl, "example.com")
	close(stop)
	if code != 130 {
		t.Fatalf("exit %d, want 130 (interrupted while learning)\n%s", code, w.h.stderr.String())
	}
	kept := learnJobs(w)
	if len(kept) == 0 || len(kept) >= len(learnBasicTried) {
		t.Fatalf("the interrupted run completed %v, want some but not all of %v", kept, learnBasicTried)
	}
	before := learnA(w, kept...)

	learnMustRun(w, wl, "example.com")
	if after := learnA(w, kept...); !maps.Equal(before, after) {
		t.Errorf("the re-run asked names the interrupted run had completed: before %v, after %v", before, after)
	}
	if got := learnJobs(w); !slices.Equal(got, sorted(learnBasicTried)) {
		t.Errorf("learned-names jobs after the re-run = %v, want %v", got, sorted(learnBasicTried))
	}
}
