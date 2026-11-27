package cli_test

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// The candidate lookups of the in-netblock procedure (which candidates are asked and when, the
// reverse-IP hostnames on in-netblock addresses, the setting, failures, interrupts and re-runs),
// run with real procedures against the fake DNS and the reverse-IP fake.

// lkCIDR is the in-scope netblock of these worlds. rdns sweeps its four addresses.
const lkCIDR = "198.51.100.0/30"

// The names of lkPromotionWorld.
const (
	lkIn   = "host.hosted.org" // a PTR name at 198.51.100.1 that resolves there: it enters scope
	lkFar  = "far.away.net"    // a PTR name at 198.51.100.2 that resolves outside the netblock
	lkRoot = "other.org"       // a candidate root from reverseip, with no address
)

// lkWorld is a web world whose HackerTarget fake answers "No records found" for every address
// it has not been given, so reverseip completes.
func lkWorld(t *testing.T) (*web, *htReverse) {
	t.Helper()
	x := newWeb(t)
	return x, x.hackerTarget()
}

// lkPromotionWorld is lkWorld with lkIn, lkFar and lkRoot.
func lkPromotionWorld(t *testing.T) (*web, *htReverse) {
	t.Helper()
	x, ht := lkWorld(t)
	x.dns.PTR("198.51.100.1", lkIn)
	x.host(lkIn, "198.51.100.1")
	x.dns.PTR("198.51.100.2", lkFar)
	x.host(lkFar, "192.0.2.10")
	ht.set("203.0.113.250", "www."+lkRoot)
	return x, ht
}

// lkAsked is the number of A and AAAA queries the fake DNS received for name.
func lkAsked(x *web, name string) int { return x.dns.Count(name, "A") + x.dns.Count(name, "AAAA") }

// lkAskedAll is lkAsked of each name, by name.
func lkAskedAll(x *web, names ...string) map[string]int {
	out := map[string]int{}
	for _, n := range names {
		out[n] = lkAsked(x, n)
	}
	return out
}

// lkWantAsked checks that each name was asked A n times and AAAA n times.
func lkWantAsked(t *testing.T, x *web, n int, names ...string) {
	t.Helper()
	for _, name := range names {
		if a, aaaa := x.dns.Count(name, "A"), x.dns.Count(name, "AAAA"); a != n || aaaa != n {
			t.Errorf("%s was asked A %d and AAAA %d times, want %d of each", name, a, aaaa, n)
		}
	}
}

// lkCandidateRow is the candidates.csv row of the type and value, nil when there is none.
func lkCandidateRow(x *web, typ, value string) map[string]string {
	for _, r := range x.candidates() {
		if r["type"] == typ && r["value"] == value {
			return r
		}
	}
	return nil
}

// lkInScope reports whether name is listed in subdomains.txt.
func lkInScope(x *web, name string) bool {
	return slices.Contains(x.lines(eng, "subdomains.txt"), name)
}

// lkCurrentResolutions are the current rows of resolutions.csv for name.
func lkCurrentResolutions(x *web, name string) []map[string]string {
	var out []map[string]string
	for _, r := range current(x.table(eng, "resolutions.csv")) {
		if r["name"] == name {
			out = append(out, r)
		}
	}
	return out
}

// lkFiles are the engagement's output files (not its .nyx directory), by name.
func lkFiles(t *testing.T, x *web) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(x.h.eng(eng))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(x.h.eng(eng), e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// lkWantSameFiles reports each file that differs between two sets of output files.
func lkWantSameFiles(t *testing.T, got, want map[string]string, what string) {
	t.Helper()
	for _, name := range slices.Sorted(maps.Keys(want)) {
		if g, ok := got[name]; !ok {
			t.Errorf("%s: %s is missing", what, name)
		} else if g != want[name] {
			t.Errorf("%s: %s differs\n got:\n%s\nwant:\n%s", what, name, g, want[name])
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("%s: %s is extra", what, name)
		}
	}
}

// --- which candidates are looked up, and when ---

// With no in-scope netblock, no candidate hostname or root is looked up.
func TestInNetblockLookup_NoNetblockNoLookup(t *testing.T) {
	t.Parallel()
	x, ht := lkWorld(t)
	ht.set("203.0.113.250", "www."+lkRoot)
	x.plain("203.0.113.250", 80, redirectTo(http.StatusFound, "https://login.partner.net/"))
	x.host("login.partner.net", "198.51.100.1")
	x.host(lkRoot, "198.51.100.2")
	x.mustRun()

	if lkCandidateRow(x, "hostname", "login.partner.net") == nil || lkCandidateRow(x, "root", lkRoot) == nil {
		t.Fatalf("the test needs a candidate hostname and a candidate root:\n%s", x.file(eng, "candidates.csv"))
	}
	lkWantAsked(t, x, 0, "login.partner.net", lkRoot)
}

// With a netblock, each candidate hostname and root is asked A and AAAA once, and a second run
// asks nothing.
func TestInNetblockLookup_EachCandidateIsAskedOnce(t *testing.T) {
	t.Parallel()
	x, _ := lkPromotionWorld(t)
	x.mustPassive("--cidr", lkCIDR)

	if lkCandidateRow(x, "hostname", lkFar) == nil || lkCandidateRow(x, "root", lkRoot) == nil {
		t.Fatalf("the test needs a candidate hostname and a candidate root:\n%s", x.file(eng, "candidates.csv"))
	}
	lkWantAsked(t, x, 1, lkIn, lkFar, lkRoot)
	if !lkInScope(x, lkIn) {
		t.Errorf("%s, looked up into the netblock, is not in subdomains.txt: %v", lkIn, x.lines(eng, "subdomains.txt"))
	}

	before := lkAskedAll(x, lkIn, lkFar, lkRoot)
	x.mustPassive("--cidr", lkCIDR)
	if after := lkAskedAll(x, lkIn, lkFar, lkRoot); !maps.Equal(before, after) {
		t.Errorf("a second run asked again: before %v, after %v", before, after)
	}
}

// The lookups follow the order of candidates.csv up to the cap; the rest are deferred, not
// failed, and later runs finish them.
func TestInNetblockLookup_CapFollowsTheOrderOfCandidates(t *testing.T) {
	t.Parallel()
	x, ht := lkWorld(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	// zz-twice.org is found on two addresses, so it ranks first although it sorts last.
	ht.set("203.0.113.250", "www.zz-twice.org", "www.aa.org", "www.bb.org", "www.cc.org")
	ht.set("203.0.113.7", "mail.zz-twice.org", "www.dd.org")
	args := []string{"--cidr", lkCIDR, "--in-netblock-max-lookups", "2"}

	x.mustPassive(args...)
	var order []string
	for _, r := range x.candidates() {
		order = append(order, r["value"])
	}
	want := []string{"zz-twice.org", "aa.org", "bb.org", "cc.org", "dd.org"}
	if !slices.Equal(order, want) {
		t.Fatalf("candidates.csv lists %v, want %v", order, want)
	}
	for i, wantAsked := range []int{2, 4, 5} {
		if i > 0 {
			x.mustPassive(args...)
		}
		lkWantAsked(t, x, 1, want[:wantAsked]...)
		lkWantAsked(t, x, 0, want[wantAsked:]...)
		if n, wantDeferred := deferredOf(t, x.h, "in-netblock"), len(want)-wantAsked; n != wantDeferred {
			t.Errorf("run %d deferred %d in-netblock lookups, want %d", i+1, n, wantDeferred)
		}
		if st, _ := stateOf(x.world, "in-netblock"); st != "done" {
			t.Errorf("run %d: in-netblock = %s, want done: deferred lookups are not failures", i+1, st)
		}
	}
}

// --redo in-netblock asks every name again, the names in scope by address included.
func TestInNetblockLookup_RedoAsksAgainNamesInScopeIncluded(t *testing.T) {
	t.Parallel()
	x, _ := lkPromotionWorld(t)
	x.mustPassive("--cidr", lkCIDR)
	if !lkInScope(x, lkIn) {
		t.Fatalf("%s did not enter scope: %v", lkIn, x.lines(eng, "subdomains.txt"))
	}
	lkWantAsked(t, x, 1, lkIn, lkFar, lkRoot)

	x.mustPassive("--cidr", lkCIDR, "--redo", "in-netblock")
	lkWantAsked(t, x, 2, lkIn, lkFar, lkRoot)
	if !lkInScope(x, lkIn) {
		t.Errorf("after --redo in-netblock %s left scope: %v", lkIn, x.lines(eng, "subdomains.txt"))
	}
}

// A candidate that stops being current, and is found again, is asked again.
func TestInNetblockLookup_ACandidateFoundAgainIsAskedAgain(t *testing.T) {
	t.Parallel()
	x, ht := lkWorld(t)
	ht.set("203.0.113.250", "www.gone.org")
	x.mustPassive("--cidr", lkCIDR)
	lkWantAsked(t, x, 1, "gone.org")

	ht.set("203.0.113.250", "No records found")
	x.mustPassive("--cidr", lkCIDR, "--redo", "reverseip")
	if r := lkCandidateRow(x, "root", "gone.org"); r != nil && r["current"] == "true" {
		t.Fatalf("gone.org is still a current candidate after reverseip stopped finding it: %v", r)
	}
	lkWantAsked(t, x, 1, "gone.org")

	ht.set("203.0.113.250", "www.gone.org")
	x.mustPassive("--cidr", lkCIDR, "--redo", "reverseip")
	if r := lkCandidateRow(x, "root", "gone.org"); r == nil || r["current"] != "true" {
		t.Fatalf("gone.org is not a current candidate again: %v", r)
	}
	lkWantAsked(t, x, 2, "gone.org")
}

// A netblock added on a later run brings in a name looked up before it, with no new lookup.
func TestInNetblockLookup_ANetblockAddedLaterNeedsNoNewLookup(t *testing.T) {
	t.Parallel()
	x, _ := lkWorld(t)
	x.dns.PTR("198.51.100.2", lkFar)
	x.host(lkFar, "192.0.2.10")
	x.mustPassive("--cidr", lkCIDR)
	lkWantAsked(t, x, 1, lkFar)
	if lkInScope(x, lkFar) {
		t.Fatalf("%s entered scope with its address outside every netblock", lkFar)
	}

	x.mustPassive("--cidr", lkCIDR, "--cidr", "192.0.2.0/28")
	if !lkInScope(x, lkFar) {
		t.Errorf("%s did not enter scope once its netblock did: %v", lkFar, x.lines(eng, "subdomains.txt"))
	}
	lkWantAsked(t, x, 1, lkFar)
}

// A candidate gets DNS lookups through the resolvers and nothing else: its addresses are never
// dialled, and the canaries see nothing.
func TestInNetblockLookup_CandidatesAreNeverContacted(t *testing.T) {
	t.Parallel()
	x, ht := lkWorld(t)
	x.dns.PTR("198.51.100.2", lkFar)
	x.host(lkFar, "192.0.2.10")
	ht.set("203.0.113.250", "www."+lkRoot)
	x.host(lkRoot, "192.0.2.11")
	x.plain("203.0.113.250", 80, redirectTo(http.StatusFound, "https://login.partner.net/"))
	x.host("login.partner.net", "192.0.2.12")
	var sites []*site
	for _, a := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		sites = append(sites, x.plain(a, 80, page("candidate")), x.silent(a, 443))
	}
	x.mustRun("--cidr", lkCIDR)

	for _, c := range []struct{ typ, value string }{{"hostname", lkFar}, {"root", lkRoot}, {"hostname", "login.partner.net"}} {
		if lkCandidateRow(x, c.typ, c.value) == nil {
			t.Errorf("%s is not a candidate %s:\n%s", c.value, c.typ, x.file(eng, "candidates.csv"))
		}
	}
	lkWantAsked(t, x, 1, lkFar, lkRoot, "login.partner.net")
	for i, s := range sites {
		if n := s.hits() + int(s.conns.Load()); n != 0 {
			t.Errorf("a candidate's address was contacted: site %d got %d requests or connections", i, n)
		}
	}
	if n := x.h.network(); n != 0 {
		t.Errorf("%d requests reached the canaries", n)
	}
}

// The registrable domain of a name in scope by address, found by in-netblock alone, is never
// looked up, even where its own address would qualify.
func TestInNetblockLookup_ARootOnlyInNetblockFoundIsNeverAsked(t *testing.T) {
	t.Parallel()
	x, _ := lkWorld(t)
	x.dns.PTR("198.51.100.1", lkIn)
	x.host(lkIn, "198.51.100.1")
	x.host("hosted.org", "198.51.100.2")
	x.mustPassive("--cidr", lkCIDR)

	if !lkInScope(x, lkIn) {
		t.Fatalf("%s did not enter scope: %v", lkIn, x.lines(eng, "subdomains.txt"))
	}
	if r := lkCandidateRow(x, "root", "hosted.org"); r == nil || r["sources"] != "in-netblock" {
		t.Errorf("hosted.org = %v, want a candidate root found by in-netblock alone", r)
	}
	lkWantAsked(t, x, 0, "hosted.org")
	if lkInScope(x, "hosted.org") {
		t.Error("hosted.org entered scope without being found by another source")
	}
	x.mustPassive("--cidr", lkCIDR)
	lkWantAsked(t, x, 0, "hosted.org")
}

// --- reverse-IP hostnames on in-netblock addresses ---

// lkReverseWorld records nb.example.com at 198.51.100.1, inside lkCIDR, with a known owner.
func lkReverseWorld(t *testing.T) (*web, *htReverse) {
	t.Helper()
	x, ht := lkWorld(t)
	x.names("nb.example.com")
	x.host("nb.example.com", "198.51.100.1")
	x.owner("198.51.100.1", 64500, "ACME-NET")
	return x, ht
}

// For an address inside the netblock, a returned name under no in-scope root is a candidate
// hostname, and its registrable domain a candidate root.
func TestInNetblockLookup_ReverseIPKeepsHostnamesOnInNetblockAddresses(t *testing.T) {
	t.Parallel()
	x, ht := lkReverseWorld(t)
	ht.set("198.51.100.1", "www.hosted.org", "new.example.com")
	x.host("new.example.com", "203.0.113.8")
	x.mustPassive("--cidr", lkCIDR)

	if r := lkCandidateRow(x, "hostname", "www.hosted.org"); r == nil || !strings.Contains(r["sources"], "reverseip") {
		t.Errorf("www.hosted.org = %v, want a candidate hostname found by reverseip:\n%s", r, x.file(eng, "candidates.csv"))
	}
	if r := lkCandidateRow(x, "root", "hosted.org"); r == nil || !strings.Contains(r["sources"], "reverseip") {
		t.Errorf("hosted.org = %v, want a candidate root found by reverseip", r)
	}
	if !lkInScope(x, "new.example.com") {
		t.Errorf("a name under the root is in scope, as today: %v", x.lines(eng, "subdomains.txt"))
	}
	if lkCandidateRow(x, "hostname", "new.example.com") != nil {
		t.Error("a name under the root is listed as a candidate hostname")
	}
}

// For an address outside every in-scope netblock, reverseip keeps roots only, as today.
func TestInNetblockLookup_ReverseIPOutsideTheNetblockKeepsRootsOnly(t *testing.T) {
	t.Parallel()
	x, ht := lkWorld(t)
	ht.set("203.0.113.250", "www.outside.org")
	x.mustPassive("--cidr", lkCIDR)

	if r := lkCandidateRow(x, "root", "outside.org"); r == nil || r["sources"] != "reverseip" {
		t.Errorf("outside.org = %v, want a candidate root found by reverseip", r)
	}
	if lkCandidateRow(x, "hostname", "www.outside.org") != nil {
		t.Error("a name on an address outside the netblock is a candidate hostname")
	}
	if slices.Contains(x.hostnameKeys(), "www.outside.org") {
		t.Error("a name on an address outside the netblock was recorded as a hostname")
	}
}

// Above reverseip.max_domains, an in-netblock address gives nothing, as today.
func TestInNetblockLookup_ReverseIPOverTheCapGivesNothing(t *testing.T) {
	t.Parallel()
	x, ht := lkReverseWorld(t)
	ht.set("198.51.100.1", manyDomains(101)...)
	x.mustPassive("--cidr", lkCIDR)

	if n := len(x.candidates()); n != 0 {
		t.Errorf("%d candidates from an address over the cap:\n%s", n, x.file(eng, "candidates.csv"))
	}
	if slices.Contains(x.hostnameKeys(), "www.site000.org") {
		t.Error("a name from an address over the cap was recorded")
	}
	if warns := x.h.messages("warning", "198.51.100.1"); len(warns) != 1 || !strings.Contains(warns[0], "max_domains") {
		t.Errorf("want one warning naming the address and the setting, got %q", warns)
	}
}

// An address asked before its netblock came into scope is asked exactly once more, and its
// support stays one item.
func TestInNetblockLookup_ReverseIPAsksOnceMoreWhenTheNetblockArrives(t *testing.T) {
	t.Parallel()
	x, ht := lkReverseWorld(t)
	ht.set("198.51.100.1", "www.hosted.org")
	asked := func() int {
		n := 0
		for _, a := range x.htAsked() {
			if a == "198.51.100.1" {
				n++
			}
		}
		return n
	}

	x.mustPassive()
	if n := asked(); n != 1 {
		t.Fatalf("198.51.100.1 asked %d times without the netblock, want once", n)
	}
	if lkCandidateRow(x, "hostname", "www.hosted.org") != nil {
		t.Fatal("a name on an address outside every netblock is a candidate hostname")
	}

	x.mustPassive("--cidr", lkCIDR)
	if n := asked(); n != 2 {
		t.Errorf("198.51.100.1 asked %d times once its netblock is in scope, want 2", n)
	}
	if lkCandidateRow(x, "hostname", "www.hosted.org") == nil {
		t.Errorf("www.hosted.org is not a candidate hostname after the netblock arrived:\n%s", x.file(eng, "candidates.csv"))
	}
	if r := lkCandidateRow(x, "root", "hosted.org"); r == nil || r["evidence_count"] != "1" {
		t.Errorf("hosted.org = %v, want one item of support", r)
	}

	x.mustPassive("--cidr", lkCIDR)
	if n := asked(); n != 2 {
		t.Errorf("a third run asked 198.51.100.1 again: %d in all", n)
	}
}

// --- the setting ---

// Turned off by the flag or the config key, nothing is looked up and nothing enters scope by
// address.
func TestInNetblockLookup_OffLooksUpNothing(t *testing.T) {
	t.Parallel()
	for name, off := range map[string]func(x *web) []string{
		"flag":       func(*web) []string { return []string{"--no-in-netblock"} },
		"config key": func(x *web) []string { x.h.set("in_netblock.enabled", false); return nil },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			x, _ := lkPromotionWorld(t)
			x.mustPassive(append(off(x), "--cidr", lkCIDR)...)
			lkWantAsked(t, x, 0, lkIn, lkFar, lkRoot)
			if lkInScope(x, lkIn) {
				t.Errorf("%s entered scope with promotion off", lkIn)
			}
			if lkCandidateRow(x, "hostname", lkIn) == nil {
				t.Errorf("%s is not a candidate hostname:\n%s", lkIn, x.file(eng, "candidates.csv"))
			}
		})
	}
}

// Turned off, names that had entered scope are candidates again and their rows not current;
// turned on again, nothing already asked is asked again.
func TestInNetblockLookup_OffSendsNamesBackAndOnAsksNothingAgain(t *testing.T) {
	t.Parallel()
	x, _ := lkPromotionWorld(t)
	x.mustPassive("--cidr", lkCIDR)
	if !lkInScope(x, lkIn) || len(lkCurrentResolutions(x, lkIn)) == 0 {
		t.Fatalf("%s did not enter scope with its rows: %v\n%s", lkIn, x.lines(eng, "subdomains.txt"), x.file(eng, "resolutions.csv"))
	}

	x.mustPassive("--cidr", lkCIDR, "--no-in-netblock")
	if lkInScope(x, lkIn) {
		t.Errorf("%s is still in subdomains.txt with promotion off", lkIn)
	}
	if find(x.table(eng, "scope.csv"), "value", lkIn) != nil {
		t.Errorf("%s is still in scope.csv with promotion off", lkIn)
	}
	if lkCandidateRow(x, "hostname", lkIn) == nil {
		t.Errorf("%s is not a candidate hostname again:\n%s", lkIn, x.file(eng, "candidates.csv"))
	}
	if rows := lkCurrentResolutions(x, lkIn); len(rows) != 0 {
		t.Errorf("%s keeps current resolutions.csv rows with promotion off: %v", lkIn, rows)
	}
	lkWantAsked(t, x, 1, lkIn, lkFar, lkRoot)

	x.mustPassive("--cidr", lkCIDR)
	lkWantAsked(t, x, 1, lkIn, lkFar, lkRoot)
	if !lkInScope(x, lkIn) {
		t.Errorf("%s did not enter scope again from its kept lookup: %v", lkIn, x.lines(eng, "subdomains.txt"))
	}
}

// --redo in-netblock while it is off discards the lookups, so the next run with it on asks
// everything again.
func TestInNetblockLookup_RedoWhileOffDiscardsTheLookups(t *testing.T) {
	t.Parallel()
	x, _ := lkPromotionWorld(t)
	x.mustPassive("--cidr", lkCIDR)
	lkWantAsked(t, x, 1, lkIn, lkFar, lkRoot)

	x.mustPassive("--cidr", lkCIDR, "--redo", "in-netblock", "--no-in-netblock")
	lkWantAsked(t, x, 1, lkIn, lkFar, lkRoot)

	x.mustPassive("--cidr", lkCIDR)
	lkWantAsked(t, x, 2, lkIn, lkFar, lkRoot)
	if !lkInScope(x, lkIn) {
		t.Errorf("%s is not in scope after the lookups were made again: %v", lkIn, x.lines(eng, "subdomains.txt"))
	}
}

// nyx recon export after a run with promotion off classes names as that run's files do, though
// the config file leaves it on.
func TestInNetblockLookup_ExportClassesNamesAsTheLastRun(t *testing.T) {
	t.Parallel()
	x, _ := lkPromotionWorld(t)
	x.mustPassive("--cidr", lkCIDR)
	x.mustPassive("--cidr", lkCIDR, "--no-in-netblock")
	if lkInScope(x, lkIn) || lkCandidateRow(x, "hostname", lkIn) == nil {
		t.Fatalf("the --no-in-netblock run's files do not class %s as a candidate", lkIn)
	}
	scopeOf := func() string {
		t.Helper()
		e := export(x.h, "-e", eng)
		if e.code != 0 {
			t.Fatalf("export exit %d: %s", e.code, e.stderr)
		}
		return exportLine(t, e.lines(t), "hostname", lkIn).str("scope")
	}
	if got := scopeOf(); got != "candidate" {
		t.Errorf("after a --no-in-netblock run, export classes %s as %q, want candidate", lkIn, got)
	}

	x.mustPassive("--cidr", lkCIDR)
	if !lkInScope(x, lkIn) {
		t.Fatalf("%s is not in scope with promotion on again", lkIn)
	}
	if got := scopeOf(); got != "in-scope" {
		t.Errorf("after a run with promotion on, export classes %s as %q, want in-scope", lkIn, got)
	}
}

// --- Settings ---

// --skip in-netblock is accepted: nothing new is looked up and names already in scope stay.
// --redo in-netblock is accepted too.
func TestInNetblockLookup_SkipAndRedoAreAccepted(t *testing.T) {
	t.Parallel()
	x, ht := lkPromotionWorld(t)
	x.mustPassive("--cidr", lkCIDR)
	if !lkInScope(x, lkIn) {
		t.Fatalf("%s did not enter scope: %v", lkIn, x.lines(eng, "subdomains.txt"))
	}

	ht.set("203.0.113.250", "www."+lkRoot, "www.later.org")
	x.mustPassive("--cidr", lkCIDR, "--skip", "in-netblock", "--redo", "reverseip")
	if st, reason := stateOf(x.world, "in-netblock"); st != "not-configured" || reason != "skipped" {
		t.Errorf("in-netblock = %s (%s), want not-configured (skipped)", st, reason)
	}
	if lkCandidateRow(x, "root", "later.org") == nil {
		t.Fatalf("later.org is not a candidate:\n%s", x.file(eng, "candidates.csv"))
	}
	lkWantAsked(t, x, 0, "later.org")
	if !lkInScope(x, lkIn) {
		t.Errorf("--skip in-netblock dropped %s from scope: %v", lkIn, x.lines(eng, "subdomains.txt"))
	}

	x.mustPassive("--cidr", lkCIDR, "--redo", "in-netblock")
	lkWantAsked(t, x, 1, "later.org")
}

// nyx help procedures lists in-netblock, with its contact and what it does.
func TestInNetblockLookup_HelpListsTheProcedure(t *testing.T) {
	t.Parallel()
	h := newHarness(t, defaultProcedureList()...)
	row := procedureRow(h.proceduresHelp(), "in-netblock")
	_, what, ok := strings.Cut(row, "third party")
	if !ok || strings.TrimSpace(what) == "" {
		t.Errorf("help procedures row = %q, want in-netblock, third party, and what it does", row)
	}
}

// --- Across behaviours ---

// A DNS timeout fails only that candidate's lookup: the other candidates of the pass are looked
// up and the ones that qualify enter scope, the run exits 7, and the next run asks it alone.
func TestInNetblockLookup_ATimeoutFailsOnlyThatLookup(t *testing.T) {
	t.Parallel()
	x, _ := lkWorld(t)
	names := []string{"a.hosted.org", "b.hosted.org", "c.hosted.org"}
	for i, n := range names {
		addr := fmt.Sprintf("198.51.100.%d", i+1)
		x.dns.PTR(addr, n)
		x.host(n, addr)
	}
	x.dns.Drop("c.hosted.org")
	x.h.partialFailed(x.passive("--cidr", lkCIDR), "in-netblock", 1)
	for _, n := range names[:2] {
		if !lkInScope(x, n) {
			t.Errorf("%s did not enter scope beside the failed lookup: %v", n, x.lines(eng, "subdomains.txt"))
		}
	}
	if lkInScope(x, "c.hosted.org") {
		t.Error("the name whose lookup timed out entered scope")
	}

	x.dns.Undrop("c.hosted.org")
	before := lkAskedAll(x, names...)
	x.mustPassive("--cidr", lkCIDR)
	after := lkAskedAll(x, names...)
	for _, n := range names[:2] {
		if after[n] != before[n] {
			t.Errorf("the next run asked %s again (%d, then %d)", n, before[n], after[n])
		}
	}
	if after["c.hosted.org"] <= before["c.hosted.org"] {
		t.Error("the next run did not ask the name whose lookup failed")
	}
	if !lkInScope(x, "c.hosted.org") {
		t.Errorf("the retried name did not enter scope: %v", x.lines(eng, "subdomains.txt"))
	}
}

// SERVFAIL, NXDOMAIN and an empty answer each complete the lookup.
func TestInNetblockLookup_NegativeAnswersCompleteTheLookup(t *testing.T) {
	t.Parallel()
	x, _ := lkWorld(t)
	names := []string{"servfail.hosted.org", "nxdomain.hosted.org", "www.nodata.org"}
	for i, n := range names {
		x.dns.PTR(fmt.Sprintf("198.51.100.%d", i+1), n)
	}
	x.dns.Rcode("servfail.hosted.org", mdns.RcodeServerFailure)
	x.dns.NoDataSuffix("nodata.org")
	x.mustPassive("--cidr", lkCIDR)

	done := x.completedKeys("in-netblock")
	for _, n := range names {
		if lkAsked(x, n) == 0 {
			t.Errorf("%s was not looked up", n)
		}
		if !slices.Contains(done, n) {
			t.Errorf("the lookup of %s did not complete: %v", n, done)
		}
	}
	before := lkAskedAll(x, names...)
	x.mustPassive("--cidr", lkCIDR)
	if after := lkAskedAll(x, names...); !maps.Equal(before, after) {
		t.Errorf("a completed lookup was asked again: before %v, after %v", before, after)
	}
}

// A spent HackerTarget quota in a world with a netblock behaves as today: reverseip fails,
// transiently, and the next run asks again and records the in-netblock address's names.
func TestInNetblockLookup_ReverseIPQuotaBehavesAsToday(t *testing.T) {
	t.Parallel()
	x, ht := lkReverseWorld(t)
	ht.answerAll(func(rw http.ResponseWriter) {
		_, _ = rw.Write([]byte("API count exceeded - Increase Quota with Membership"))
	})
	f := x.h.partial(x.passive("--cidr", lkCIDR, "--concurrency", "1"), true)
	if !f.transient || !strings.Contains(f.msg, "reverseip") || strings.Contains(f.msg, "in-netblock") {
		t.Errorf("error = %+v, want a transient failure of reverseip alone", f)
	}
	if done := x.completedKeys("reverseip"); len(done) != 0 {
		t.Errorf("a spent quota was recorded as done: %v", done)
	}
	if warns := x.h.messages("warning", "reverseip"); len(warns) != 1 || !strings.Contains(warns[0], "quota") {
		t.Errorf("want one quota warning naming reverseip, got %q", warns)
	}

	ht.answerAll(nil)
	ht.set("198.51.100.1", "www.hosted.org")
	x.mustPassive("--cidr", lkCIDR, "--concurrency", "1")
	if lkCandidateRow(x, "hostname", "www.hosted.org") == nil {
		t.Errorf("the retried in-netblock address's name is not a candidate hostname:\n%s", x.file(eng, "candidates.csv"))
	}
}

// A run cancelled during slow lookups keeps the lookups it completed, retires nothing, and the
// next run asks only the rest.
func TestInNetblockLookup_InterruptKeepsCompletedLookups(t *testing.T) {
	t.Parallel()
	x, ht := lkWorld(t)
	x.dns.PTR("198.51.100.1", lkIn)
	x.host(lkIn, "198.51.100.1")
	ht.set("203.0.113.250", "www.old.org")
	x.mustPassive("--cidr", lkCIDR)
	if !lkInScope(x, lkIn) || !slices.Contains(x.completedKeys("in-netblock"), "old.org") {
		t.Fatalf("the first run did not bring %s in and look up old.org: %v, %v", lkIn, x.lines(eng, "subdomains.txt"), x.completedKeys("in-netblock"))
	}

	// reverseip no longer finds old.org, so its lookup is no longer listed; six new roots answer
	// slowly.
	var roots, hosts []string
	for i := range 6 {
		roots = append(roots, fmt.Sprintf("r%d.org", i))
		hosts = append(hosts, fmt.Sprintf("www.r%d.org", i))
	}
	ht.set("203.0.113.250", hosts...)
	x.dns.Slow(100*time.Millisecond, roots...)
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
				for _, n := range lkAskedAll(x, roots...) {
					asked += min(n, 1)
				}
				if asked >= 3 { // two roots answered, the third in flight
					cancel()
					return
				}
			}
		}
	}()
	x.fill()
	code := x.h.execCtx(ctx, "--json", "--rate-per-source", "1000", "--rate-dns", "100000", "--passive", "--no-permutations",
		"--concurrency", "1", "--cidr", lkCIDR, "--redo", "reverseip", "example.com")
	close(stop)
	if code != 130 {
		t.Fatalf("exit %d, want 130 (interrupted while looking up)\n%s", code, x.h.stderr.String())
	}
	done := x.completedKeys("in-netblock")
	var kept []string
	for _, r := range roots {
		if slices.Contains(done, r) {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 || len(kept) == len(roots) {
		t.Fatalf("the interrupted run completed %v, want some but not all of %v", kept, roots)
	}
	if !slices.Contains(done, "old.org") {
		t.Error("the interrupted run retired the lookup of old.org: the sweep must be skipped")
	}
	if !lkInScope(x, lkIn) {
		t.Errorf("the interrupted run sent %s out of scope: %v", lkIn, x.lines(eng, "subdomains.txt"))
	}

	before := lkAskedAll(x, kept...)
	x.mustPassive("--cidr", lkCIDR)
	if after := lkAskedAll(x, kept...); !maps.Equal(before, after) {
		t.Errorf("the next run asked roots the interrupted run had completed: before %v, after %v", before, after)
	}
	done = x.completedKeys("in-netblock")
	for _, r := range roots {
		if !slices.Contains(done, r) {
			t.Errorf("the next run did not look up %s: %v", r, done)
		}
	}
}

// A re-run after a successful run sends no DNS query and leaves every file byte for byte.
func TestInNetblockLookup_RerunAfterSuccessChangesNothing(t *testing.T) {
	t.Parallel()
	x, _ := lkPromotionWorld(t)
	x.mustPassive("--cidr", lkCIDR)
	if !lkInScope(x, lkIn) {
		t.Fatalf("%s did not enter scope: %v", lkIn, x.lines(eng, "subdomains.txt"))
	}
	files, queries := lkFiles(t, x), x.dns.Total()

	x.mustPassive("--cidr", lkCIDR)
	if n := x.dns.Total() - queries; n != 0 {
		t.Errorf("the re-run sent %d DNS queries, want none", n)
	}
	lkWantSameFiles(t, lkFiles(t, x), files, "the re-run")
}

// A re-run after a partial failure ends where an uninterrupted run ends.
func TestInNetblockLookup_RerunAfterFailureEndsAsAnUninterruptedRun(t *testing.T) {
	t.Parallel()
	const late = "late.hosted.org"
	build := func(t *testing.T) *web {
		t.Helper()
		x, _ := lkPromotionWorld(t)
		x.dns.PTR("198.51.100.3", late)
		x.host(late, "198.51.100.3")
		return x
	}
	whole := build(t)
	whole.mustPassive("--cidr", lkCIDR)
	if !lkInScope(whole, late) {
		t.Fatalf("%s did not enter scope in the uninterrupted run: %v", late, whole.lines(eng, "subdomains.txt"))
	}

	x := build(t)
	x.dns.Drop(late)
	x.h.partialFailed(x.passive("--cidr", lkCIDR), "in-netblock", 1)
	x.dns.Undrop(late)
	x.mustPassive("--cidr", lkCIDR)

	got, want := lkFiles(t, x), lkFiles(t, whole)
	delete(got, "changes.csv") // the re-run's changes are its own
	delete(want, "changes.csv")
	lkWantSameFiles(t, got, want, "after the failure and the re-run")
}
