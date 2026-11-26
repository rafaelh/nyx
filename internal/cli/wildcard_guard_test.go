package cli_test

import (
	"slices"
	"testing"

	mdns "github.com/miekg/dns"
)

// Wildcard guards: a parent name that only its zone's wildcard
// answers records nothing, and parent names and permutations wait for the wildcard check of
// the zone they ask under.

// wguardWildcardAddr is the address the wildcard of example.com answers with.
const wguardWildcardAddr = "203.0.113.1"

// wguardWildcardWorld is a world with *.example.com answering wguardWildcardAddr for every
// otherwise unknown direct child of example.com, and crt.sh returning a.b.example.com, which
// answers NXDOMAIN (the fake's wildcard covers direct children only). b.example.com is its parent
// name.
func wguardWildcardWorld(t *testing.T) (*world, string) {
	t.Helper()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"a.b.example.com"}})
	w.dns.Wildcard("example.com", wguardWildcardAddr)
	return w, wl
}

// wguardRecorded lists the hostname, unresolved and resolution records the engagement holds for
// name, current or not.
func wguardRecorded(w *world, name string) []string {
	w.t.Helper()
	return queryStrings(w.t, w.h.openDB(eng),
		"SELECT kind || ' ' || key FROM observations WHERE (kind IN ('hostname', 'unresolved') AND key = ?) OR (kind = 'resolution' AND key LIKE ?)",
		name, name+"|%")
}

// wguardServfail makes each name answer SERVFAIL.
func wguardServfail(w *world, names []string) {
	for _, n := range names {
		w.dns.Rcode(n, int(mdns.RcodeServerFailure))
	}
}

// wguardClear removes the forced answers wguardServfail set.
func wguardClear(w *world, names []string) {
	for _, n := range names {
		w.dns.ClearRcode(n)
	}
}

// --- Wildcard-answered parent names ---

// A parent name that only its zone's wildcard answers is asked, but records nothing: it is in no
// output file, wildcard-excluded.txt and subdomains.txt included.
func TestWildcardGuard_WildcardAnsweredParentIsInNoFile(t *testing.T) {
	t.Parallel()
	w, wl := wguardWildcardWorld(t)
	learnMustRun(w, wl, "example.com")

	if n := w.dns.Count("b.example.com", "A"); n < 1 {
		t.Fatalf("setup: the parent b.example.com was never asked (A %d times)", n)
	}
	if !slices.Contains(w.lines(eng, "unresolved.txt"), "a.b.example.com") {
		t.Fatalf("setup: a.b.example.com is not in unresolved.txt: %v", w.lines(eng, "unresolved.txt"))
	}
	if hits := parentListedIn(w, "b.example.com"); len(hits) != 0 {
		t.Errorf("the parent b.example.com, answered only by the wildcard of example.com, is listed in %v, want no file", hits)
	}
	if got := w.lines(eng, "subdomains.txt"); slices.Contains(got, "b.example.com") {
		t.Errorf("subdomains.txt = %v, want no wildcard-answered parent", got)
	}
	if got := w.lines(eng, "wildcard-excluded.txt"); slices.Contains(got, "b.example.com") {
		t.Errorf("wildcard-excluded.txt = %v, want no wildcard-answered parent: no source found it", got)
	}
	if got := wguardRecorded(w, "b.example.com"); len(got) != 0 {
		t.Errorf("records of the wildcard-answered parent b.example.com = %v, want none (no hostname, resolution or unresolved)", got)
	}
}

// A parent with its own answer under a wildcard zone is recorded as a hostname like any other.
// (This holds before the follow-up too.)
func TestWildcardGuard_ParentWithItsOwnAnswerUnderAWildcardIsListed(t *testing.T) {
	t.Parallel()
	w, wl := wguardWildcardWorld(t)
	w.dns.A("b.example.com", "203.0.113.11")
	learnMustRun(w, wl, "example.com")

	if got := w.lines(eng, "subdomains.txt"); !slices.Contains(got, "b.example.com") {
		t.Errorf("subdomains.txt = %v, want b.example.com: it has its own address, not the wildcard's", got)
	}
	if got := w.lines(eng, "wildcard-excluded.txt"); slices.Contains(got, "b.example.com") {
		t.Errorf("wildcard-excluded.txt = %v, want no b.example.com: its address is its own", got)
	}
}

// A parent job waits for its zone's wildcard check: while the check fails the parent is not
// asked, and the run after the check succeeds asks it and lists it.
func TestWildcardGuard_ParentWaitsForItsZonesWildcardCheck(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"a.b.example.com"}})
	w.dns.A("a.b.example.com", "203.0.113.10")
	w.dns.A("b.example.com", "203.0.113.11")
	probes := learnFixedProbes(t, w, "example.com")
	wguardServfail(w, probes)
	if code := learnRun(w, wl, "example.com"); code != 7 {
		t.Fatalf("exit %d, want 7 (the wildcard job of example.com fails)\n%s", code, w.h.stderr.String())
	}
	if n := w.dns.Count("b.example.com", "A"); n != 0 {
		t.Errorf("b.example.com asked for A %d times, want 0: the wildcard check of its zone example.com has not completed", n)
	}
	if got := w.lines(eng, "subdomains.txt"); slices.Contains(got, "b.example.com") {
		t.Errorf("subdomains.txt = %v, want no b.example.com before its zone's wildcard check completes", got)
	}

	wguardClear(w, probes)
	learnMustRun(w, wl, "example.com")
	if n := w.dns.Count("b.example.com", "A"); n != 1 {
		t.Errorf("b.example.com asked for A %d times over the two runs, want once, in the run after the check succeeded", n)
	}
	if got := w.lines(eng, "subdomains.txt"); !slices.Contains(got, "b.example.com") {
		t.Errorf("subdomains.txt = %v, want the parent b.example.com once its zone's check has completed", got)
	}
}

// --- Permutations waits for a zone's wildcard check ---

// A root job does not run until its root's wildcard check has completed; it is neither failed nor
// deferred, and runs in the run after the check succeeds.
func TestWildcardGuard_RootJobWaitsForTheRootsWildcardCheck(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, nil)
	probes := learnFixedProbes(t, w, "example.com")
	wguardServfail(w, probes)
	rootNames := []string{"zzword.example.com", "autodiscover.example.com"}

	w.h.partialFailed(learnRun(w, wl, "example.com"), "wildcard", 1)
	learnWantA(t, w, 0, "a wordlist name under example.com, whose wildcard check failed", rootNames...)
	if n := deferredOf(t, w.h, "permutations"); n != 0 {
		t.Errorf("permutations deferred = %d, want 0: a job waiting for a wildcard check is not deferred", n)
	}

	wguardClear(w, probes)
	learnMustRun(w, wl, "example.com")
	learnWantA(t, w, 1, "asked once, in the run after the check succeeded", rootNames...)
}

// A seed's variants are not tried until the wildcard check of the seed's zone has completed; a
// seed under a healthy zone has its variants tried meanwhile.
func TestWildcardGuard_SeedVariantsWaitForTheirZonesWildcardCheck(t *testing.T) {
	t.Parallel()
	w, wl := learnWorld(t, map[string][]string{"example.com": {"api.f.example.com", "web.b.example.com"}})
	w.dns.A("api.f.example.com", "203.0.113.5")
	w.dns.A("web.b.example.com", "203.0.113.6")
	probes := learnFixedProbes(t, w, "f.example.com")
	wguardServfail(w, probes)
	waiting := []string{"api1.f.example.com", "api-zzword.f.example.com"}

	w.h.partialFailed(learnRun(w, wl, "example.com"), "wildcard", 1)
	learnWantA(t, w, 0, "a variant of api.f.example.com, whose zone's wildcard check failed", waiting...)
	learnWantA(t, w, 1, "a variant of web.b.example.com, whose zone's wildcard check completed",
		"web1.b.example.com", "web-zzword.b.example.com")
	if n := deferredOf(t, w.h, "permutations"); n != 0 {
		t.Errorf("permutations deferred = %d, want 0: a job waiting for a wildcard check is not deferred", n)
	}

	wguardClear(w, probes)
	learnMustRun(w, wl, "example.com")
	learnWantA(t, w, 1, "asked once, in the run after the check succeeded", waiting...)
}
