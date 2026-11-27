package cli_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
)

// Behaviour tests of candidate names on in-scope addresses: a candidate hostname or root
// whose looked-up address is inside an in-scope netblock enters scope, within the shared-hosting
// guard, and is contacted only at its in-netblock addresses.

// nbBlock is the --cidr of most of these worlds, and nbBlockAddrs its four addresses.
const nbBlock = "198.51.100.0/30"

var nbBlockAddrs = []string{"198.51.100.0", "198.51.100.1", "198.51.100.2", "198.51.100.3"}

// nbWeb is the web world with every address of nbBlock kept off the network.
func nbWeb(t *testing.T) *web {
	t.Helper()
	x := newWeb(t)
	nbKeep(x, nbBlockAddrs...)
	return x
}

// nbPorts is the ports world with every address of nbBlock kept off the network.
func nbPorts(t *testing.T) *pworld {
	t.Helper()
	p := newPorts(t)
	nbKeep(p.web, nbBlockAddrs...)
	return p
}

// nbKeep marks addresses so that fill maps every port a probe could try at them.
func nbKeep(x *web, addrs ...string) {
	for _, a := range addrs {
		x.ips[a] = true
	}
}

// nbPTR makes name a candidate hostname, found by rdns as a PTR name of ptrAddr, and gives it addrs
// (none leaves its A and AAAA records to the test).
func nbPTR(x *web, ptrAddr, name string, addrs ...string) {
	x.dns.PTR(ptrAddr, name)
	nbKeep(x, ptrAddr)
	if len(addrs) > 0 {
		x.host(name, addrs...)
	}
}

// nbScopeRow is the hostname row of scope.csv for name, nil when there is none.
func nbScopeRow(x *web, name string) map[string]string {
	for _, r := range x.table(eng, "scope.csv") {
		if r["type"] == "hostname" && r["value"] == name {
			return r
		}
	}
	return nil
}

// nbScopeHostnames are the values of the current hostname rows of scope.csv, sorted.
func nbScopeHostnames(x *web) []string {
	var out []string
	for _, r := range x.table(eng, "scope.csv") {
		if r["type"] == "hostname" && r["current"] == "true" {
			out = append(out, r["value"])
		}
	}
	slices.Sort(out)
	return out
}

// nbCandidateRow is the candidates.csv row of the type and value, nil when there is none.
func nbCandidateRow(x *web, typ, value string) map[string]string {
	for _, r := range x.candidates() {
		if r["type"] == typ && r["value"] == value {
			return r
		}
	}
	return nil
}

// nbIsCandidateHostname reports whether name is a current hostname row of candidates.csv.
func nbIsCandidateHostname(x *web, name string) bool {
	r := nbCandidateRow(x, "hostname", name)
	return r != nil && r["current"] == "true"
}

// nbSubdomain reports whether name is listed in subdomains.txt.
func nbSubdomain(x *web, name string) bool {
	return slices.Contains(x.lines(eng, "subdomains.txt"), name)
}

// nbWantInScope checks that name entered scope through addr inside block: the scope.csv row
// and the subdomains.txt line.
func nbWantInScope(t *testing.T, x *web, name, addr, block string) {
	t.Helper()
	r := nbScopeRow(x, name)
	if r == nil || r["current"] != "true" || r["source"] != addr+" in "+block {
		t.Errorf("scope.csv row of %s = %v, want a current hostname row with the source %q\n%s", name, r, addr+" in "+block, x.file(eng, "scope.csv"))
	}
	if !nbSubdomain(x, name) {
		t.Errorf("%s is not in subdomains.txt: %v", name, x.lines(eng, "subdomains.txt"))
	}
}

// nbWantNotInScope checks that name has no hostname row in scope.csv and no line in
// subdomains.txt.
func nbWantNotInScope(t *testing.T, x *web, name string) {
	t.Helper()
	if r := nbScopeRow(x, name); r != nil {
		t.Errorf("scope.csv has a hostname row for %s: %v", name, r)
	}
	if nbSubdomain(x, name) {
		t.Errorf("%s is in subdomains.txt", name)
	}
}

// nbResolutionRows are the resolutions.csv rows whose name is name.
func nbResolutionRows(x *web, name string) []map[string]string {
	var out []map[string]string
	for _, r := range x.table(eng, "resolutions.csv") {
		if r["name"] == name {
			out = append(out, r)
		}
	}
	return out
}

// nbIPRow is the ips.csv row of addr, nil when there is none.
func nbIPRow(x *web, addr string) map[string]string { return find(x.table(eng, "ips.csv"), "ip", addr) }

// nbChanges are the rows of the engagement's changes.csv as "change kind key", sorted.
func nbChanges(x *web) []string {
	var out []string
	for _, r := range x.table(eng, "changes.csv") {
		out = append(out, r["change"]+" "+r["kind"]+" "+r["key"])
	}
	slices.Sort(out)
	return out
}

// nbEnvelope is the --json envelope on stdout, by key, read without report.Envelope so that a
// key it does not know yet can be seen.
type nbEnvelope struct {
	Data map[string]json.RawMessage `json:"data"`
	Meta struct {
		Warnings []string `json:"warnings"`
	} `json:"meta"`
}

func nbEnvelopeOf(t *testing.T, h *harness) nbEnvelope {
	t.Helper()
	var env nbEnvelope
	if err := json.Unmarshal(h.stdout.Bytes(), &env); err != nil || env.Data == nil {
		t.Fatalf("stdout is not the --json envelope (%v):\n%s", err, h.stdout.String())
	}
	return env
}

// nbNamesGuard reports whether a warning names the shared-hosting setting, by its key
// (in_netblock.max_names_per_address) or its flag.
func nbNamesGuard(w string) bool {
	return strings.Contains(w, "max_names_per_address") || strings.Contains(w, "max-names-per-address")
}

// nbGuardWarnings are the warnings of the last --json run that name the shared-hosting setting,
// from the events and from the envelope's meta.warnings.
func nbGuardWarnings(t *testing.T, h *harness) (events, meta []string) {
	t.Helper()
	for _, w := range h.messages("warning", "") {
		if nbNamesGuard(w) {
			events = append(events, w)
		}
	}
	for _, w := range nbEnvelopeOf(t, h).Meta.Warnings {
		if nbNamesGuard(w) {
			meta = append(meta, w)
		}
	}
	return events, meta
}

// nbRunCtx is x.run under ctx: an authorised, non-passive --json run for example.com.
func nbRunCtx(ctx context.Context, x *web, args ...string) int {
	x.t.Helper()
	x.fill()
	full := append([]string{"--json", "--rate-per-source", "1000", "--rate-dns", "100000", "--authorised", "--rate-per-host", "1000", "--no-permutations"}, args...)
	return x.h.execCtx(ctx, append(full, "example.com")...)
}

// nbPassiveText is a --passive run in text mode, for the console summary.
func nbPassiveText(x *web, args ...string) int {
	x.t.Helper()
	x.fill()
	full := append([]string{"--passive", "--no-permutations", "--rate-per-source", "1000", "--rate-dns", "100000"}, args...)
	return x.h.exec(append(full, "example.com")...)
}

// --- a name and a root whose addresses are in the netblock enter scope ---

func TestInNetblock_PTRNameAndReverseIPRootEnterScope(t *testing.T) {
	t.Parallel()
	x := nbWeb(t)
	ht := x.hackerTarget()
	// A PTR name in the netblock, and a reverse-IP name on the input root's address (outside the
	// netblock), whose registrable domain becomes a candidate root.
	nbPTR(x, "198.51.100.2", "ptr.other.org", "198.51.100.2")
	ht.set("203.0.113.250", "www.partner.net")
	x.host("partner.net", "198.51.100.1")
	ptrSite := x.plain("198.51.100.2", 80, page("<title>ptr</title>"))
	rootSite := x.plain("198.51.100.1", 80, page("<title>partner</title>"))
	x.mustRun("--cidr", nbBlock)

	// Both are in scope, with the address and netblock that brought them in.
	nbWantInScope(t, x, "ptr.other.org", "198.51.100.2", nbBlock)
	nbWantInScope(t, x, "partner.net", "198.51.100.1", nbBlock)
	// The hostname's candidate row is gone, and the root's stays.
	if r := nbCandidateRow(x, "hostname", "ptr.other.org"); r != nil {
		t.Errorf("candidates.csv still has the hostname row of a name in scope: %v", r)
	}
	if r := nbCandidateRow(x, "root", "partner.net"); r == nil || r["current"] != "true" {
		t.Errorf("candidates.csv root row of partner.net = %v, want it kept\n%s", r, x.file(eng, "candidates.csv"))
	}
	// Their rows in resolutions.csv and ips.csv come from the candidate lookup.
	for name, addr := range map[string]string{"ptr.other.org": "198.51.100.2", "partner.net": "198.51.100.1"} {
		rows := nbResolutionRows(x, name)
		if !slices.ContainsFunc(rows, func(r map[string]string) bool {
			return r["type"] == "A" && r["value"] == addr && r["current"] == "true"
		}) {
			t.Errorf("resolutions.csv rows of %s = %v, want a current A %s", name, rows, addr)
		}
		if r := nbIPRow(x, addr); r == nil || r["current"] != "true" || !strings.Contains(r["hostnames"], name) {
			t.Errorf("ips.csv row of %s = %v, want a current row naming %s", addr, r, name)
		}
		// resolve does not ask it again: one A and one AAAA, the candidate lookup's.
		if a, aaaa := x.dns.Count(name, "A"), x.dns.Count(name, "AAAA"); a != 1 || aaaa != 1 {
			t.Errorf("%s was asked A %d and AAAA %d times, want once each", name, a, aaaa)
		}
	}
	// With --authorised, each is probed at its in-netblock address, by name.
	if got := ptrSite.hostHeaders(); !slices.Contains(got, "ptr.other.org") {
		t.Errorf("the site at 198.51.100.2 saw Host %v, want ptr.other.org", got)
	}
	if got := rootSite.hostHeaders(); !slices.Contains(got, "partner.net") {
		t.Errorf("the site at 198.51.100.1 saw Host %v, want partner.net", got)
	}
}

// The job that lists a name's rows is outside the lookup cap, so a name whose lookup lands in
// the netblock is probed in the run that looked it up, however many candidates wait.
func TestInNetblock_ACapSmallerThanTheCandidatesStillProbesTheNameThisRun(t *testing.T) {
	t.Parallel()
	x := nbWeb(t)
	names := []string{"a.other.org", "b.other.org", "c.other.org"}
	for _, n := range names {
		nbPTR(x, "198.51.100.2", n, "198.51.100.2")
	}
	s := x.plain("198.51.100.2", 80, page("<title>shared</title>"))
	x.mustRun("--cidr", nbBlock, "--in-netblock-max-lookups", "1")

	in := nbScopeHostnames(x)
	if len(in) != 1 || !slices.Contains(names, in[0]) {
		t.Fatalf("with a cap of one lookup, scope.csv hostnames = %v, want exactly one of %v", in, names)
	}
	if got := s.hostHeaders(); !slices.Contains(got, in[0]) {
		t.Errorf("%s entered scope but was not probed in the same run: the site saw Host %v", in[0], got)
	}
}

// --- generic names ---

func TestInNetblock_GenericNamesStayCandidates(t *testing.T) {
	t.Parallel()
	x := nbWeb(t)
	generic := []string{
		"198-51-100-2.static.other.net", // forwards, with "-"
		"2.100.51.198.other.net",        // backwards, with "."
		"198-051-100-002.other.net",     // zero-padded
	}
	const nearMiss = "198-51-100-20.other.net" // its last run is 20, not 2
	for _, n := range append(slices.Clone(generic), nearMiss) {
		nbPTR(x, "198.51.100.2", n, "198.51.100.2")
	}
	s := x.plain("198.51.100.2", 80, page("<title>shared</title>"))
	x.mustRun("--cidr", nbBlock)

	for _, n := range generic {
		nbWantNotInScope(t, x, n)
		if !nbIsCandidateHostname(x, n) {
			t.Errorf("generic name %s is not a current candidate hostname:\n%s", n, x.file(eng, "candidates.csv"))
		}
		if slices.Contains(s.hostHeaders(), n) {
			t.Errorf("generic name %s was probed", n)
		}
	}
	nbWantInScope(t, x, nearMiss, "198.51.100.2", nbBlock)
	if !slices.Contains(s.hostHeaders(), nearMiss) {
		t.Errorf("the near miss %s was not probed: Host %v", nearMiss, s.hostHeaders())
	}
}

// --- shared hosting ---

// nbSharedAddr is the address the names of the shared-hosting worlds resolve to, and
// nbSharedBlock the netblock holding it.
const (
	nbSharedAddr  = "198.51.100.200"
	nbSharedBlock = "198.51.100.0/24"
)

// nbSharedName is the i'th name of a shared-hosting world.
func nbSharedName(i int) string { return fmt.Sprintf("n%03d.hosting.net", i) }

// nbSharedWorld gives n candidate hostnames, each the PTR name of its own address in
// nbSharedBlock (one PTR record per answer), all resolving to nbSharedAddr.
func nbSharedWorld(t *testing.T, n int) *web {
	t.Helper()
	x := newWeb(t)
	for i := 1; i <= n; i++ {
		nbPTR(x, fmt.Sprintf("198.51.100.%d", i), nbSharedName(i), nbSharedAddr)
	}
	return x
}

func TestInNetblock_SharedHostingGuard(t *testing.T) {
	t.Parallel()
	t.Run("100 names on one address enter", func(t *testing.T) {
		t.Parallel()
		x := nbSharedWorld(t, 100)
		x.mustPassive("--cidr", nbSharedBlock)
		if got := nbScopeHostnames(x); len(got) != 100 {
			t.Errorf("%d names in scope by address, want all 100", len(got))
		}
		nbWantInScope(t, x, nbSharedName(1), nbSharedAddr, nbSharedBlock)
		if ev, meta := nbGuardWarnings(t, x.h); len(ev) != 0 || len(meta) != 0 {
			t.Errorf("an address at the guard was warned about: events %q, meta %q", ev, meta)
		}
	})
	t.Run("a 101st brings none in", func(t *testing.T) {
		t.Parallel()
		x := nbSharedWorld(t, 101)
		// One name also has a second in-netblock address, with no other name on it.
		x.dns.A(nbSharedName(1), "198.51.100.201")
		x.mustPassive("--cidr", nbSharedBlock)
		if got := nbScopeHostnames(x); !slices.Equal(got, []string{nbSharedName(1)}) {
			t.Errorf("names in scope by address = %v, want only %s, through its other address", got, nbSharedName(1))
		}
		nbWantInScope(t, x, nbSharedName(1), "198.51.100.201", nbSharedBlock)
		for _, i := range []int{2, 50, 101} {
			nbWantNotInScope(t, x, nbSharedName(i))
			if !nbIsCandidateHostname(x, nbSharedName(i)) {
				t.Errorf("%s is not a current candidate hostname", nbSharedName(i))
			}
		}
		ev, meta := nbGuardWarnings(t, x.h)
		if len(ev) != 1 || !strings.Contains(ev[0], nbSharedAddr) {
			t.Errorf("warning events = %q, want one naming %s and the setting", ev, nbSharedAddr)
		}
		if len(meta) != 1 || !strings.Contains(meta[0], nbSharedAddr) {
			t.Errorf("--json meta.warnings = %q, want one naming %s and the setting", meta, nbSharedAddr)
		}
		if got := x.h.messages("warning", "198.51.100.201"); len(got) != 0 {
			t.Errorf("an address within the guard was warned about: %q", got)
		}
	})
}

// Names enter as their lookups come in, and leave when a later lookup pushes their address
// over the guard.
func TestInNetblock_GuardTrippedOnALaterRunSendsTheNamesBack(t *testing.T) {
	t.Parallel()
	x := nbSharedWorld(t, 101)
	x.mustPassive("--cidr", nbSharedBlock, "--in-netblock-max-lookups", "60")
	entered := nbScopeHostnames(x)
	if len(entered) != 60 {
		t.Fatalf("the first run brought %d names in, want the 60 it looked up", len(entered))
	}

	x.mustPassive("--cidr", nbSharedBlock, "--in-netblock-max-lookups", "60")
	if got := nbScopeHostnames(x); len(got) != 0 {
		t.Errorf("after the 101st lookup, %d names are still in scope by address", len(got))
	}
	changes := nbChanges(x)
	for _, n := range entered {
		nbWantNotInScope(t, x, n)
		for _, want := range []string{"gone hostname " + n, "new candidate " + n} {
			if !slices.Contains(changes, want) {
				t.Errorf("changes.csv has no %q", want)
			}
		}
	}
	if ev, _ := nbGuardWarnings(t, x.h); len(ev) != 1 || !strings.Contains(ev[0], nbSharedAddr) {
		t.Errorf("warning events = %q, want one naming %s", ev, nbSharedAddr)
	}
}

// A wildcard of a zone that is not in scope is never checked, so names its wildcard answers
// into the netblock are held back by the guard alone.
func TestInNetblock_AWildcardOutsideScopeIsHeldOnlyByTheGuard(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		names int
		enter bool
	}{{3, true}, {4, false}} {
		t.Run(fmt.Sprintf("%d names", c.names), func(t *testing.T) {
			t.Parallel()
			x := nbWeb(t)
			x.dns.Wildcard("hosting.example", "198.51.100.2")
			var names []string
			for i := 1; i <= c.names; i++ {
				n := fmt.Sprintf("w%d.hosting.example", i)
				names = append(names, n)
				nbPTR(x, "198.51.100.2", n) // only the wildcard answers it
			}
			x.mustPassive("--cidr", nbBlock, "--in-netblock-max-names-per-address", "3")
			wildOnly := x.lines(eng, "wildcard-excluded.txt")
			for _, n := range names {
				if c.enter {
					nbWantInScope(t, x, n, "198.51.100.2", nbBlock)
				} else {
					nbWantNotInScope(t, x, n)
				}
				if slices.Contains(wildOnly, n) {
					t.Errorf("%s is wildcard-only: the zone hosting.example is not in scope and is never checked", n)
				}
			}
			ev, _ := nbGuardWarnings(t, x.h)
			if c.enter && len(ev) != 0 {
				t.Errorf("warnings %q within the guard", ev)
			}
			if !c.enter && (len(ev) != 1 || !strings.Contains(ev[0], "198.51.100.2")) {
				t.Errorf("warning events = %q, want one naming 198.51.100.2", ev)
			}
		})
	}
}

// --- only its in-netblock addresses are dialled ---

// nbDualSite serves a page with one crawlable link.
func nbDualSite() http.HandlerFunc {
	return routes(map[string]http.HandlerFunc{"/": page(`<title>dual</title><a href="/about">about</a>`), "/about": page("about")})
}

func TestInNetblock_OnlyItsInNetblockAddressesAreDialled(t *testing.T) {
	t.Parallel()
	const name, outside = "dual.other.org", "192.0.2.9"
	t.Run("probe, crawl and ports", func(t *testing.T) {
		t.Parallel()
		p := nbPorts(t)
		nbPTR(p.web, "198.51.100.2", name, "198.51.100.2", outside)
		p.owner(outside, 64500, "ACME-NET") // a known, dedicated owner: eligible, were the name rooted
		in := p.plain("198.51.100.2", 80, nbDualSite())
		out := p.plain(outside, 80, nbDualSite())
		inPort := p.serve("198.51.100.2", 8080, hello)
		outPort := p.serve(outside, 8080, hello)
		p.sweep([]int{8080}, "--cidr", nbBlock)

		nbWantInScope(t, p.web, name, "198.51.100.2", nbBlock)
		if !slices.Contains(in.hostHeaders(), name) || in.count("/about") == 0 {
			t.Errorf("the in-netblock site was not probed and crawled for %s: %+v", name, in.requests())
		}
		if out.hits() != 0 {
			t.Errorf("the outside address got %d requests for a name in scope by address: %+v", out.hits(), out.requests())
		}
		if inPort.conns.Load() == 0 {
			t.Error("the in-netblock address was not port-checked")
		}
		if n := outPort.conns.Load(); n != 0 || slices.Contains(p.checked(), outside+":8080") {
			t.Errorf("the outside address was port-checked: %d connections, jobs %v", n, p.checked())
		}
		r := nbIPRow(p.web, outside)
		if r == nil || r["port_eligible"] == "true" {
			t.Errorf("ips.csv row of %s = %v, want a row that is not port-eligible", outside, r)
		}
	})
	t.Run("a rooted name on the outside address", func(t *testing.T) {
		t.Parallel()
		x := nbWeb(t)
		nbPTR(x, "198.51.100.2", name, "198.51.100.2", outside)
		x.owner(outside, 64500, "ACME-NET")
		x.names("r.example.com")
		x.host("r.example.com", outside)
		in := x.plain("198.51.100.2", 80, nbDualSite())
		out := x.plain(outside, 80, nbDualSite())
		x.mustRun("--cidr", nbBlock)

		nbWantInScope(t, x, name, "198.51.100.2", nbBlock)
		if got := out.hostHeaders(); !slices.Equal(got, []string{"r.example.com"}) {
			t.Errorf("the outside address saw Host %v, want only the rooted name r.example.com", got)
		}
		if !slices.Contains(in.hostHeaders(), name) {
			t.Errorf("the in-netblock address saw Host %v, want %s", in.hostHeaders(), name)
		}
	})
}

// --- exclusions ---

func TestInNetblock_ExcludedNamesNeverEnter(t *testing.T) {
	t.Parallel()
	x := nbWeb(t)
	nbPTR(x, "198.51.100.2", "ex.other.org", "198.51.100.2")                    // matches --exclude
	nbPTR(x, "198.51.100.2", "split.other.org", "198.51.100.2", "198.51.100.3") // one address excluded
	nbPTR(x, "198.51.100.2", "ok.other.org", "198.51.100.2")
	s := x.plain("198.51.100.2", 80, page("<title>shared</title>"))
	excludedSite := x.plain("198.51.100.3", 80, page("<title>excluded</title>"))
	x.mustRun("--cidr", nbBlock, "-x", "ex.other.org", "-x", "198.51.100.3/32")

	for _, n := range []string{"ex.other.org", "split.other.org"} {
		nbWantNotInScope(t, x, n)
		if slices.Contains(s.hostHeaders(), n) {
			t.Errorf("excluded %s was dialled", n)
		}
	}
	if excludedSite.hits() != 0 {
		t.Errorf("the excluded address got %d requests", excludedSite.hits())
	}
	// A name with no excluded part enters in the same run.
	nbWantInScope(t, x, "ok.other.org", "198.51.100.2", nbBlock)
}

// --- leaving ---

// nbWantLeft checks what leaving scope means for a name that was in scope by address and no
// longer is, and returns the rows of changes.csv.
//
// An excluded name is still resolved, as any excluded name another source finds is, so that its
// addresses are excluded too: its resolutions.csv rows stay current and are not checked.
func nbWantLeft(t *testing.T, x *web, name string, excluded bool) []string {
	t.Helper()
	nbWantNotInScope(t, x, name)
	for _, r := range nbResolutionRows(x, name) {
		if r["current"] == "true" && !excluded {
			t.Errorf("resolutions.csv row of %s is still current: %v", name, r)
		}
	}
	if slices.Contains(x.serviceURLs(), "http://"+name) {
		t.Errorf("the web service of %s is still shown", name)
	}
	if r := nbCandidateRow(x, "root", "other.org"); r != nil && r["current"] == "true" && strings.Contains(r["sources"], "in-netblock") {
		t.Errorf("the root other.org keeps its in-netblock evidence: %v", r)
	}
	changes := nbChanges(x)
	if !slices.Contains(changes, "gone hostname "+name) {
		t.Errorf("changes.csv = %q, want a gone hostname row for %s", changes, name)
	}
	return changes
}

// nbWantEntered checks the state of a name in scope by address before it leaves.
func nbWantEntered(t *testing.T, x *web, name string) {
	t.Helper()
	nbWantInScope(t, x, name, "198.51.100.2", nbBlock)
	if !slices.ContainsFunc(nbResolutionRows(x, name), func(r map[string]string) bool { return r["current"] == "true" }) {
		t.Errorf("%s has no current resolutions.csv row", name)
	}
	if !slices.Contains(x.serviceURLs(), "http://"+name) {
		t.Errorf("%s has no web service: %v", name, x.serviceURLs())
	}
	if r := nbCandidateRow(x, "root", "other.org"); r == nil || !strings.Contains(r["sources"], "in-netblock") {
		t.Errorf("the root other.org = %v, want in-netblock evidence while %s is in scope", r, name)
	}
}

func TestInNetblock_LeavesScope(t *testing.T) {
	t.Parallel()
	const name = "moved.other.org"
	t.Run("redo with the answer outside the netblock", func(t *testing.T) {
		t.Parallel()
		x := nbWeb(t)
		nbPTR(x, "198.51.100.2", name)
		x.dns.CNAME(name, "in.hosting.net")
		x.host("in.hosting.net", "198.51.100.2")
		x.host("out.hosting.net", "192.0.2.9")
		x.plain("198.51.100.2", 80, page("<title>moved</title>"))
		x.mustRun("--cidr", nbBlock)
		nbWantEntered(t, x, name)

		x.dns.CNAME(name, "out.hosting.net")
		x.mustRun("--cidr", nbBlock, "--redo", "in-netblock")
		changes := nbWantLeft(t, x, name, false)
		if !nbIsCandidateHostname(x, name) {
			t.Errorf("%s is not a candidate again:\n%s", name, x.file(eng, "candidates.csv"))
		}
		if !slices.Contains(changes, "new candidate "+name) {
			t.Errorf("changes.csv = %q, want a new candidate row for %s", changes, name)
		}
	})
	t.Run("excluded on a later run", func(t *testing.T) {
		t.Parallel()
		x := nbWeb(t)
		nbPTR(x, "198.51.100.2", name, "198.51.100.2")
		x.plain("198.51.100.2", 80, page("<title>moved</title>"))
		x.mustRun("--cidr", nbBlock)
		nbWantEntered(t, x, name)

		x.mustRun("--cidr", nbBlock, "-x", name)
		changes := nbWantLeft(t, x, name, true)
		if find(x.table(eng, "excluded.csv"), "value", name) == nil {
			t.Errorf("excluded.csv has no %s", name)
		}
		if !slices.Contains(changes, "new excluded "+name) {
			t.Errorf("changes.csv = %q, want a new excluded row for %s", changes, name)
		}
	})
	t.Run("its only other source stops finding it", func(t *testing.T) {
		t.Parallel()
		x := nbWeb(t)
		nbPTR(x, "198.51.100.2", name, "198.51.100.2")
		x.plain("198.51.100.2", 80, page("<title>moved</title>"))
		x.mustRun("--cidr", nbBlock)
		nbWantEntered(t, x, name)

		// The PTR record is gone: rdns, asked again, finds nothing.
		x.dns.Rcode(dnsname.ReverseName(mustAddr("198.51.100.2")), mdns.RcodeNameError)
		x.mustRun("--cidr", nbBlock, "--redo", "rdns")
		nbWantLeft(t, x, name, false)
		if nbIsCandidateHostname(x, name) {
			t.Errorf("%s, which no source finds, is still a current candidate", name)
		}
	})
	t.Run("an answer in an excluded CIDR ends the run", func(t *testing.T) {
		t.Parallel()
		x := nbWeb(t)
		nbPTR(x, "198.51.100.2", name, "198.51.100.2")
		x.plain("198.51.100.2", 80, page("<title>moved</title>"))
		x.mustRun("--cidr", nbBlock, "-x", "198.51.100.3/32")
		nbWantEntered(t, x, name)

		x.dns.A(name, "198.51.100.3") // the answer now holds an excluded address too
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		code := nbRunCtx(ctx, x, "--cidr", nbBlock, "--redo", "in-netblock")
		if ctx.Err() != nil {
			t.Fatalf("the run did not end within a minute: it repeats its passes (exit %d)", code)
		}
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, x.h.stdout.String())
		}
		nbWantLeft(t, x, name, false)
	})
}

// --- authorisation ---

func TestInNetblock_EnteringScopeDoesNotRelaxThePassiveBoundary(t *testing.T) {
	t.Parallel()
	const name = "ptr.other.org"
	for _, c := range []struct {
		name string
		run  func(p *pworld) int
	}{
		{"passive", func(p *pworld) int { return p.run("--passive", "--cidr", nbBlock, "--ports", "8080") }},
		{"not authorised", func(p *pworld) int {
			p.fill()
			return p.world.run("--rate-per-host", "1000", "--no-permutations", "--cidr", nbBlock, "--ports", "8080", "example.com")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			p := nbPorts(t)
			nbPTR(p.web, "198.51.100.2", name, "198.51.100.2")
			s := p.plain("198.51.100.2", 80, page("<title>ptr</title>"))
			port := p.serve("198.51.100.2", 8080, hello)
			if code := c.run(p); code != 0 {
				t.Fatalf("exit %d\n%s", code, p.h.stdout.String())
			}
			nbWantInScope(t, p.web, name, "198.51.100.2", nbBlock)
			if !slices.ContainsFunc(nbResolutionRows(p.web, name), func(r map[string]string) bool {
				return r["type"] == "A" && r["value"] == "198.51.100.2" && r["current"] == "true"
			}) {
				t.Errorf("resolutions.csv has no current A row for %s: %v", name, nbResolutionRows(p.web, name))
			}
			if s.hits() != 0 || port.conns.Load() != 0 {
				t.Errorf("the name was contacted: %d HTTP requests, %d TCP connections", s.hits(), port.conns.Load())
			}
			if n := p.h.network(); n != 0 {
				t.Errorf("%d requests reached the canaries", n)
			}
		})
	}
}

// --- reported ---

func TestInNetblock_SummaryCountsHostsInScopeByAddress(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		want int
	}{{"none", 0}, {"one", 1}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			x := nbWeb(t)
			if c.want > 0 {
				nbPTR(x, "198.51.100.2", "ptr.other.org", "198.51.100.2")
			}
			x.mustPassive("--cidr", nbBlock)
			raw, ok := nbEnvelopeOf(t, x.h).Data["hosts_in_scope_by_address"]
			var n int
			if !ok || json.Unmarshal(raw, &n) != nil || n != c.want {
				t.Errorf("data.hosts_in_scope_by_address = %s (present %v), want %d", raw, ok, c.want)
			}

			if code := nbPassiveText(x, "--cidr", nbBlock); code != 0 {
				t.Fatalf("exit %d\n%s", code, x.h.stderr.String())
			}
			out := x.h.stdout.String()
			line := fmt.Sprintf("%d hosts in scope by address", c.want)
			if c.want == 1 {
				line = "1 host in scope by address"
			}
			if c.want > 0 && !strings.Contains(out, line) {
				t.Errorf("the console summary lacks %q:\n%s", line, out)
			}
			if c.want == 0 && strings.Contains(out, "hosts in scope by address") {
				t.Errorf("a summary with no host in scope by address has the line:\n%s", out)
			}
		})
	}
}

// --- findings ---

// A name in scope by address is checked for findings like any in-scope hostname: the version its
// page discloses is a web-posture finding of its own service.
func TestInNetblock_ItsServiceIsCheckedForFindings(t *testing.T) {
	t.Parallel()
	const name = "ptr.other.org"
	x := nbWeb(t)
	nbPTR(x, "198.51.100.2", name, "198.51.100.2")
	x.plain("198.51.100.2", 80, posturePage("<title>ptr</title>", map[string]string{"Server": "Apache/2.4.41 (Ubuntu)"}))
	x.mustRun("--cidr", nbBlock, "--crawl-pages", "0")

	nbWantInScope(t, x, name, "198.51.100.2", nbBlock)
	if got := x.postureTypes(); !slices.Contains(got, "version-disclosure=http://"+name) {
		t.Errorf("posture findings = %v, want version-disclosure for http://%s\n%s", got, name, x.file(eng, "risk-web-posture.csv"))
	}
}

// --- settled follow-ups: support from names in scope by address, and the summary's wording ---

// stKept, stAlpha and stBeta are PTR names, each resolving to its own PTR address in nbBlock.
// The PTR records of stAlpha and stBeta go away; the one of stKept stays, so rdns still finds it.
const (
	stKept  = "kept.other.org"
	stAlpha = "alpha.other.org"
	stBeta  = "beta.other.org"
)

// stAddr is the address of each name, inside nbBlock.
var stAddr = map[string]string{stKept: "198.51.100.1", stAlpha: "198.51.100.2", stBeta: "198.51.100.3"}

// stNotCurrentInScope checks that name, which was in scope by address, left: no hostname row of
// scope.csv and no subdomains.txt line, no current resolutions.csv row, no web service shown, and
// a gone hostname row in changes.csv.
func stNotCurrentInScope(t *testing.T, x *web, name string) {
	t.Helper()
	nbWantNotInScope(t, x, name)
	for _, r := range nbResolutionRows(x, name) {
		if r["current"] == "true" {
			t.Errorf("resolutions.csv row of %s is still current: %v", name, r)
		}
	}
	if slices.Contains(x.serviceURLs(), "https://"+name) {
		t.Errorf("the web service of %s is still shown", name)
	}
	if changes := nbChanges(x); !slices.Contains(changes, "gone hostname "+name) {
		t.Errorf("changes.csv = %q, want a gone hostname row for %s", changes, name)
	}
}

// stWorld is the netblock world of the three names, each serving HTTPS at its address. The
// certificate of stAlpha and stBeta lists both; stKept's lists itself, and the pair too when
// keptLists is set. The first run brings all three into scope by address.
func stWorld(t *testing.T, keptLists bool) *web {
	t.Helper()
	x := nbWeb(t)
	for _, n := range []string{stKept, stAlpha, stBeta} {
		nbPTR(x, stAddr[n], n, stAddr[n])
	}
	pair := selfSigned(t, leafSpec{cn: stAlpha, dns: []string{stAlpha, stBeta}})
	x.secure(stAddr[stAlpha], 443, pair, page("<title>alpha</title>"))
	x.secure(stAddr[stBeta], 443, pair, page("<title>beta</title>"))
	keptSANs := []string{stKept}
	if keptLists {
		keptSANs = append(keptSANs, stAlpha, stBeta)
	}
	x.secure(stAddr[stKept], 443, selfSigned(t, leafSpec{cn: stKept, dns: keptSANs}), page("<title>kept</title>"))
	x.mustRun("--cidr", nbBlock)

	for _, n := range []string{stKept, stAlpha, stBeta} {
		nbWantInScope(t, x, n, stAddr[n], nbBlock)
	}
	// The loop the test is about: httpprobe recorded each of the pair from the other's
	// certificate.
	if got := x.observedBy("hostname", "httpprobe"); !slices.Contains(got, stAlpha) || !slices.Contains(got, stBeta) {
		t.Fatalf("httpprobe hostnames = %v, want %s and %s from the certificates", got, stAlpha, stBeta)
	}
	return x
}

// stPairPTRsGone removes the PTR records of stAlpha and stBeta and runs with --redo rdns, so that
// rdns finds only stKept. httpprobe's completed jobs about the pair stay, so a rule that let them
// count again once the pair left would bring it back: the run must still end.
func stPairPTRsGone(t *testing.T, x *web) {
	t.Helper()
	for _, n := range []string{stAlpha, stBeta} {
		x.dns.Rcode(dnsname.ReverseName(mustAddr(stAddr[n])), mdns.RcodeNameError)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code := nbRunCtx(ctx, x, "--cidr", nbBlock, "--redo", "rdns")
	if ctx.Err() != nil {
		t.Fatalf("the run did not end within a minute: it repeats its passes (exit %d)", code)
	}
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, x.h.stdout.String())
	}
}

// A certificate SAN that httpprobe records while probing a name in scope by address is not
// another source finding that SAN: two names whose certificates list each other leave scope once
// the source that first found them stops finding them, and so does a name that only another name
// in scope by address lists. A name rdns still finds stays.
func TestInNetblockSettled_NamesInScopeByAddressDoNotKeepEachOtherIn(t *testing.T) {
	t.Parallel()
	t.Run("two names that list each other", func(t *testing.T) {
		t.Parallel()
		x := stWorld(t, false)
		stPairPTRsGone(t, x)
		for _, n := range []string{stAlpha, stBeta} {
			stNotCurrentInScope(t, x, n)
		}
		// The positive control: the name rdns still finds stays in scope by address.
		nbWantInScope(t, x, stKept, stAddr[stKept], nbBlock)
	})
	t.Run("and a name rdns still finds lists them too", func(t *testing.T) {
		t.Parallel()
		x := stWorld(t, true)
		stPairPTRsGone(t, x)
		for _, n := range []string{stAlpha, stBeta} {
			stNotCurrentInScope(t, x, n)
		}
		nbWantInScope(t, x, stKept, stAddr[stKept], nbBlock)
		// stKept's certificate still lists the pair, so they stay listed as candidates.
		changes := nbChanges(x)
		for _, n := range []string{stAlpha, stBeta} {
			if !nbIsCandidateHostname(x, n) {
				t.Errorf("%s, which stKept's certificate lists, is not a current candidate hostname:\n%s", n, x.file(eng, "candidates.csv"))
			}
			if !slices.Contains(changes, "new candidate "+n) {
				t.Errorf("changes.csv = %q, want a new candidate row for %s", changes, n)
			}
		}
	})
}

// The summary line is singular for one host and plural for two or more.
func TestInNetblockSettled_SummaryLineIsPluralForTwoHosts(t *testing.T) {
	t.Parallel()
	x := nbWeb(t)
	nbPTR(x, "198.51.100.2", "a.other.org", "198.51.100.2")
	nbPTR(x, "198.51.100.3", "b.other.org", "198.51.100.3")
	if code := nbPassiveText(x, "--cidr", nbBlock); code != 0 {
		t.Fatalf("exit %d\n%s", code, x.h.stderr.String())
	}
	out := x.h.stdout.String()
	if !strings.Contains(out, "2 hosts in scope by address") {
		t.Errorf("the console summary lacks %q:\n%s", "2 hosts in scope by address", out)
	}
	if strings.Contains(out, "2 host in scope by address") {
		t.Errorf("the console summary uses the singular for two hosts:\n%s", out)
	}
}
