package cli_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

// Shared name servers and mail hosts. The tests drive cli.Execute with the real
// dnsroot, email and nsreverse stages. api.securitytrails.com is a fake that
// answers a domain search filtered by name server (ns) or mail host (mx);
// nothing leaves the machine.

// stServers are the servers SecurityTrails' domain search was asked about, as
// "ns|<host>" and "mx|<host>", sorted.
func (x *risk) stServers() []string {
	var out []string
	for _, r := range x.requests("api.securitytrails.com") {
		var q stQuery
		if strings.HasPrefix(r.URI, "/v1/domains/list") && json.Unmarshal([]byte(r.Body), &q) == nil && q.server() != "" {
			out = append(out, q.server())
		}
	}
	return sorted(out)
}

// sharedWorld is an engagement for example.com whose name servers and mail hosts
// are each a different case:
//
//	ns1.example.com            in scope
//	ns.nbhosted.test           outside scope, in the in-scope netblock 198.51.100.0/24
//	ns-eligible.other.test     outside scope, on the dedicated address app.example.com has
//	ns.cloudflare.com          a known provider's domain
//	ns.shared.test             on the shared address cdn.example.com has
//	ns.unknown.test            on an address nobody knows the owner of
//	mail.example.com           (mx) in scope
//	mail.nbhosted.test         (mx) in the in-scope netblock
//	mx.shared.test             (mx) on the shared address
//
// run it with sharedArgs. The fake knows domains for every server, including the
// ones that must never be asked.
func sharedWorld(t *testing.T, key bool) (*risk, *stReverse) {
	t.Helper()
	x := newRisk(t, "email")
	x.names("app.example.com", "cdn.example.com")
	x.host("app.example.com", "203.0.113.12")
	x.owner("203.0.113.12", 64500, "ACME-NET")
	x.host("cdn.example.com", "104.16.0.5")
	x.owner("104.16.0.5", 13335, "CLOUDFLARENET")
	x.host("ns1.example.com", "203.0.113.11")
	x.owner("203.0.113.11", 64500, "ACME-NET")
	x.host("mail.example.com", "203.0.113.13")
	x.owner("203.0.113.13", 64500, "ACME-NET")

	for _, ns := range []string{"ns1.example.com", "ns.nbhosted.test", "ns-eligible.other.test", "ns.cloudflare.com", "ns.shared.test", "ns.unknown.test"} {
		x.dns.NS("example.com", ns)
	}
	x.dns.A("ns.nbhosted.test", "198.51.100.5")
	x.dns.A("ns-eligible.other.test", "203.0.113.12")
	x.dns.A("ns.cloudflare.com", "198.51.100.77") // inside the netblock, but a provider's name
	x.dns.A("ns.shared.test", "104.16.0.5")
	x.dns.A("ns.unknown.test", "192.0.2.77")

	m := healthy()
	m.mx = []string{"10 mail.nbhosted.test", "20 mx.shared.test", "30 mail.example.com"}
	m.apply(x.dns, "example.com")
	x.dns.A("mail.nbhosted.test", "198.51.100.6")
	x.dns.A("mx.shared.test", "104.16.0.5")

	if !key {
		return x, nil
	}
	f := &stReverse{
		byNS: map[string][]string{
			"ns1.example.com":        {"a.alpha-corp.test"},
			"ns.nbhosted.test":       {"sister-org.test", "www.sister-org.test", "example.com"},
			"ns-eligible.other.test": {"eligible-co.test"},
			"ns.cloudflare.com":      {"wrong-cloudflare.test"},
			"ns.shared.test":         {"wrong-shared.test"},
			"ns.unknown.test":        {"wrong-unknown.test"},
		},
		byMX: map[string][]string{
			"mail.nbhosted.test": {"sister-org.test", "mx-only.test"},
			"mail.example.com":   {"mailco.test"},
			"mx.shared.test":     {"wrong-mx.test"},
		},
		total: map[string]int{},
	}
	x.h.setenv("NYX_KEYS_SECURITYTRAILS", securityTrailsKey)
	x.handle("api.securitytrails.com", f.serve)
	return x, f
}

var sharedArgs = []string{"--cidr", "198.51.100.0/24"}

func (x *risk) mustShared(extra ...string) {
	x.t.Helper()
	x.mustPassive(append(slices.Clone(sharedArgs), extra...)...)
}

func (x *risk) resolutionRows(typ string) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, r := range x.table(eng, "resolutions.csv") {
		if r["type"] == typ && r["name"] == "example.com" {
			out[r["value"]] = r
		}
	}
	return out
}

// --- Markers ---

// Name servers and mail hosts that are in scope, in an in-scope netblock or on a
// dedicated address an in-scope host uses are self-hosted; a known provider's
// name, a shared address and an address of unknown owner are not. The marker is
// on NS rows of resolutions.csv and in email-posture.csv.
func TestNSReverse_MarkersInBothFiles(t *testing.T) {
	t.Parallel()
	x, _ := sharedWorld(t, true)
	x.mustShared()

	ns := x.resolutionRows("NS")
	for host, want := range map[string]string{
		"ns1.example.com": "yes", "ns.nbhosted.test": "yes", "ns-eligible.other.test": "yes",
		"ns.cloudflare.com": "no", "ns.shared.test": "no", "ns.unknown.test": "no",
	} {
		if r := ns[host]; r == nil || r["self_hosted"] != want {
			t.Errorf("NS %s: row %v, want self_hosted %s", host, r, want)
		}
	}
	for _, r := range x.table(eng, "resolutions.csv") {
		if r["type"] != "NS" && r["self_hosted"] != "" {
			t.Errorf("a %s row has self_hosted %q, want it blank", r["type"], r["self_hosted"])
		}
	}
	posture := x.table(eng, "email-posture.csv")
	if len(posture) != 1 || posture[0]["mx_self_hosted"] != "mail.example.com;mail.nbhosted.test" {
		t.Errorf("email-posture.csv = %v, want mx_self_hosted mail.example.com;mail.nbhosted.test", posture)
	}
	cols := strings.Split(strings.SplitN(x.file(eng, "resolutions.csv"), "\n", 2)[0], ",")
	if i := slices.Index(cols, "source"); i < 0 || cols[i+1] != "self_hosted" || cols[i+2] != "historical_first_seen" {
		t.Errorf("resolutions.csv columns = %v, want self_hosted after source and before the historical dates", cols)
	}
	cols = strings.Split(strings.SplitN(x.file(eng, "email-posture.csv"), "\n", 2)[0], ",")
	if i := slices.Index(cols, "mta_sts"); i < 0 || cols[i+1] != "mx_self_hosted" {
		t.Errorf("email-posture.csv columns = %v, want mx_self_hosted after mta_sts", cols)
	}
}

// Without the key the stage is not-configured, nothing is fetched, and the
// markers are still produced.
func TestNSReverse_WithoutKeyOnlyTheMarkers(t *testing.T) {
	t.Parallel()
	x, _ := sharedWorld(t, false)
	x.mustShared()

	if st, reason := stateOf(x.world, "nsreverse"); st != "not-configured" || reason != "no key" {
		t.Errorf("nsreverse = %s (%s), want not-configured (no key)", st, reason)
	}
	for _, r := range x.requests("api.securitytrails.com") {
		if strings.HasPrefix(r.URI, "/v1/domains/list") && (strings.Contains(r.Body, `"ns"`) || strings.Contains(r.Body, `"mx"`)) {
			t.Errorf("a server was looked up without a key: %s", r.Body)
		}
	}
	if r := x.resolutionRows("NS")["ns.nbhosted.test"]; r == nil || r["self_hosted"] != "yes" {
		t.Errorf("the marker is missing without the key: %v", r)
	}
	if p := x.table(eng, "email-posture.csv"); len(p) != 1 || p[0]["mx_self_hosted"] != "mail.example.com;mail.nbhosted.test" {
		t.Errorf("email-posture.csv = %v", p)
	}
	if len(x.candidates()) != 0 {
		t.Errorf("candidates without the key: %v", x.candidates())
	}
}

// A name server's or mail host's address is looked up when it is outside scope
// and not a known provider's name; a failed lookup neither fails the check nor
// loses the NS rows or the posture.
func TestNSReverse_AddressLookupsAreBestEffort(t *testing.T) {
	t.Parallel()
	x, _ := sharedWorld(t, true)
	x.dns.Rcode("ns.nbhosted.test", int(mdns.RcodeServerFailure))
	x.dns.Rcode("mail.nbhosted.test", int(mdns.RcodeServerFailure))
	x.mustShared()

	if got := x.dns.Count("ns.cloudflare.com", "A") + x.dns.Count("ns.cloudflare.com", "AAAA"); got != 0 {
		t.Errorf("a known provider's name server was resolved (%d queries)", got)
	}
	if x.dns.Count("ns.unknown.test", "A") == 0 || x.dns.Count("ns.unknown.test", "AAAA") == 0 {
		t.Errorf("an unknown name server's A and AAAA were not both asked")
	}
	if st, _ := stateOf(x.world, "dnsroot"); st != "done" {
		t.Errorf("dnsroot = %s, want done: a failed address lookup is not a failed check", st)
	}
	if st, _ := stateOf(x.world, "email"); st != "done" {
		t.Errorf("email = %s, want done: a failed MX address lookup is not a failed check", st)
	}
	if r := x.resolutionRows("NS")["ns.nbhosted.test"]; r == nil || r["self_hosted"] != "no" {
		t.Errorf("a server whose address could not be looked up is not self-hosted: %v", r)
	}
	if p := x.table(eng, "email-posture.csv"); len(p) != 1 || p[0]["mx_self_hosted"] != "mail.example.com" {
		t.Errorf("email-posture.csv = %v", p)
	}
}

// --- What is fetched ---

func TestNSReverse_AsksOnlySelfHostedServers(t *testing.T) {
	t.Parallel()
	x, _ := sharedWorld(t, true)
	x.mustShared()

	want := []string{"mx|mail.example.com", "mx|mail.nbhosted.test", "ns|ns-eligible.other.test", "ns|ns.nbhosted.test", "ns|ns1.example.com"}
	if got := x.stServers(); !slices.Equal(got, want) {
		t.Errorf("asked %v, want %v", got, want)
	}
	if s, reason := stateOf(x.world, "nsreverse"); s != "done" {
		t.Errorf("nsreverse = %s (%s), want done under --passive", s, reason)
	}
	done := sorted(x.completedKeys("nsreverse"))
	wantKeys := []string{"mx|mail.example.com|max=1000", "mx|mail.nbhosted.test|max=1000", "ns|ns-eligible.other.test|max=1000",
		"ns|ns.nbhosted.test|max=1000", "ns|ns1.example.com|max=1000"}
	if !slices.Equal(done, wantKeys) {
		t.Errorf("completed checks = %v, want %v", done, wantKeys)
	}
	for _, wrong := range []string{"wrong-cloudflare.test", "wrong-shared.test", "wrong-unknown.test", "wrong-mx.test"} {
		if x.candidate(wrong) != nil {
			t.Errorf("%s came from a server that is not self-hosted", wrong)
		}
	}
}

// --- Candidates ---

// Each domain is a candidate root with shared-ns or shared-mx as its source and
// is at least medium. A root both a name server and a mail host give has both
// sources and counts their two pieces of evidence, but is one family, so not high.
func TestNSReverse_CandidatesAreSharedAndMedium(t *testing.T) {
	t.Parallel()
	x, _ := sharedWorld(t, true)
	x.mustShared()

	for root, want := range map[string]struct{ sources, count string }{
		"alpha-corp.test":  {"shared-ns", "1"},
		"eligible-co.test": {"shared-ns", "1"},
		"mx-only.test":     {"shared-mx", "1"},
		"mailco.test":      {"shared-mx", "1"},
		"sister-org.test":  {"shared-mx;shared-ns", "2"},
	} {
		c := x.candidate(root)
		if c == nil {
			t.Errorf("%s is not a candidate: %v", root, x.candidates())
			continue
		}
		if c["type"] != "root" || c["sources"] != want.sources || c["evidence_count"] != want.count || c["confidence"] != "medium" {
			t.Errorf("%s = %v, want a root from %s with %s evidence at medium", root, c, want.sources, want.count)
		}
	}
	if x.candidate("example.com") != nil {
		t.Error("the engagement's own root is a candidate")
	}
	if len(x.candidates()) != 5 {
		t.Errorf("%d candidates, want 5: %v", len(x.candidates()), x.candidates())
	}
}

// An excluded root a server's domain list gives stays excluded.
func TestNSReverse_ExcludedRootStaysExcluded(t *testing.T) {
	t.Parallel()
	x, _ := sharedWorld(t, true)
	x.mustShared("-x", "sister-org.test")

	if x.candidate("sister-org.test") != nil {
		t.Error("an excluded root became a candidate")
	}
	if x.candidate("mx-only.test") == nil {
		t.Error("the other roots are still recorded")
	}
}

// Changing the cap asks again, and the cap is left out of the evidence item, so
// a root found under both settings still counts once.
func TestNSReverse_ChangingTheCapAsksAgainWithoutCountingTwice(t *testing.T) {
	t.Parallel()
	x, _ := sharedWorld(t, true)
	x.mustShared()
	before := len(x.stServers())
	x.mustShared("--nsreverse-max-domains", "999")
	if got := len(x.stServers()) - before; got != before {
		t.Errorf("changing the cap asked %d servers again, want all %d", got, before)
	}
	if c := x.candidate("sister-org.test"); c == nil || c["evidence_count"] != "2" {
		t.Errorf("sister-org.test = %v, want evidence_count 2 under both caps", c)
	}
}

// --- The cap ---

// A server whose total is above nsreverse.max_domains records nothing, whatever
// its first page lists, and a WARN line names it. Exactly the cap is recorded.
// Raising the cap asks again.
func TestNSReverse_CapRecordsNothingAndWarns(t *testing.T) {
	t.Parallel()
	x, st := sharedWorld(t, true)
	st.byNS["ns.nbhosted.test"] = []string{"one.test", "two.test", "three.test"}
	st.total["ns|ns.nbhosted.test"] = 3 // at the cap
	st.byNS["ns-eligible.other.test"] = []string{"big-a.test", "big-b.test"}
	st.total["ns|ns-eligible.other.test"] = 4 // over it, though the page is short
	x.mustShared("--nsreverse-max-domains", "3")

	if x.candidate("one.test") == nil || x.candidate("three.test") == nil {
		t.Errorf("a server at the cap must be recorded: %v", x.candidates())
	}
	if x.candidate("big-a.test") != nil || x.candidate("big-b.test") != nil {
		t.Errorf("a server over the cap was recorded: %v", x.candidates())
	}
	warns := messages(x.world, "warning", "ns-eligible.other.test")
	if len(warns) != 1 || !strings.Contains(warns[0], "nsreverse.max_domains") {
		t.Errorf("want one warning naming the server and the setting, got %q", warns)
	}
	if got := messages(x.world, "warning", "ns.nbhosted.test"); len(got) != 0 {
		t.Errorf("a server within the cap was warned about: %q", got)
	}
	if n := len(slices.DeleteFunc(x.stServers(), func(s string) bool { return s != "ns|ns-eligible.other.test" })); n != 1 {
		t.Errorf("the over-cap server was asked %d times, want only its first page", n)
	}
	if s, _ := stateOf(x.world, "nsreverse"); s != "done" {
		t.Errorf("nsreverse = %s, want done: a server over the cap is a completed check", s)
	}

	st.total["ns|ns-eligible.other.test"] = 2
	x.mustShared("--nsreverse-max-domains", "4")
	if x.candidate("big-a.test") == nil {
		t.Errorf("with the cap raised the server is recorded: %v", x.candidates())
	}
}

// A reply without a usable total still cannot pass the cap: the domains listed
// across pages are counted, and once they pass it nothing the server listed is
// recorded.
func TestNSReverse_CapCountsPagesWithoutATotal(t *testing.T) {
	t.Parallel()
	x, st := sharedWorld(t, true)
	st.pageSize = 2
	st.byNS["ns-eligible.other.test"] = []string{"big-a.test", "big-b.test", "big-c.test", "big-d.test"}
	st.total["ns|ns-eligible.other.test"] = 0 // no record_count
	x.mustShared("--nsreverse-max-domains", "3")

	for _, root := range []string{"big-a.test", "big-b.test", "big-c.test", "big-d.test"} {
		if x.candidate(root) != nil {
			t.Errorf("%s was recorded from a server over the cap", root)
		}
	}
	if warns := messages(x.world, "warning", "ns-eligible.other.test"); len(warns) != 1 {
		t.Errorf("want one warning naming the server, got %q", warns)
	}
	if x.candidate("sister-org.test") == nil {
		t.Errorf("a server within the cap is still recorded: %v", x.candidates())
	}
}

// --- Quota ---

// A refused key or spent quota stops the stage, completes nothing, and the checks
// are made on the next run.
func TestNSReverse_QuotaStopsTheStage(t *testing.T) {
	t.Parallel()
	x, st := sharedWorld(t, true)
	st.setStatus(http.StatusTooManyRequests)
	// A keyed 429 is a rate limit, so waiting helps: the error is transient.
	if f := x.h.partial(x.passive(append(slices.Clone(sharedArgs), "--concurrency", "1")...), true); !f.transient || !strings.Contains(f.msg, "nsreverse 5") {
		t.Errorf("error = %+v, want a transient failure naming nsreverse 5", f)
	}

	if s, _ := stateOf(x.world, "nsreverse"); s != "failed" {
		t.Errorf("nsreverse = %s, want failed", s)
	}
	if done := x.completedKeys("nsreverse"); len(done) != 0 {
		t.Errorf("a spent quota was recorded as done: %v", done)
	}
	if n := len(x.stServers()); n != 1 {
		t.Errorf("the stage should stop after the first answer, saw %d", n)
	}
	st.setStatus(0)
	x.mustShared("--concurrency", "1")
	if done := x.completedKeys("nsreverse"); len(done) != 5 {
		t.Errorf("the next run completed %v, want all five", done)
	}
	if x.candidate("sister-org.test") == nil {
		t.Error("the retried checks did not record their domains")
	}
}

// --- The passive boundary ---

// Candidate roots are never resolved, and no looked-up server address is
// contacted or made a hostname, address to probe or port-check target: a full,
// authorised run sends nothing to any address a server was looked up at.
func TestNSReverse_NothingFoundIsContacted(t *testing.T) {
	t.Parallel()
	x, _ := sharedWorld(t, true)
	var sites []*site
	for _, ip := range []string{"198.51.100.5", "198.51.100.6", "198.51.100.77", "192.0.2.77"} {
		for _, p := range []int{25, 53, 80, 443} {
			sites = append(sites, x.silent(ip, p))
		}
	}
	x.mustRun(sharedArgs...)

	for _, s := range sites {
		if s.conns.Load() != 0 {
			t.Fatalf("a looked-up server address was contacted")
		}
	}
	for _, root := range []string{"sister-org.test", "alpha-corp.test", "mx-only.test", "eligible-co.test", "mailco.test"} {
		if n := x.dns.Count(root, "A") + x.dns.Count(root, "AAAA"); n != 0 {
			t.Errorf("candidate root %s was resolved (%d queries)", root, n)
		}
		if x.dns.Count(root, "NS")+x.dns.Count(root, "SOA")+x.dns.Count(root, "TXT")+x.dns.Count(root, "MX") != 0 {
			t.Errorf("candidate root %s was looked up", root)
		}
	}
	for _, n := range []string{"ns.nbhosted.test", "mail.nbhosted.test", "ns.unknown.test", "ns-eligible.other.test"} {
		if slices.Contains(x.probed(), n) {
			t.Errorf("server %s was offered for probing", n)
		}
		if r := resolutionRow(x.world, n, "A"); r != nil {
			t.Errorf("server %s has a resolution row: %v", n, r)
		}
	}
	for _, a := range []string{"198.51.100.5", "198.51.100.6", "192.0.2.77"} {
		if ip := find(x.table(eng, "ips.csv"), "ip", a); ip != nil {
			t.Errorf("server address %s is in ips.csv: %v", a, ip)
		}
	}
	if x.h.network() != 0 {
		t.Errorf("a canary saw %d requests", x.h.network())
	}
}

// The NS and email check keys carry a token for the address lookups, so an
// engagement from before has them looked up once and not again.
func TestNSReverse_ExistingEngagementLooksUpAddressesOnce(t *testing.T) {
	t.Parallel()
	x, _ := sharedWorld(t, false)
	x.mustShared()
	asked := func() int { return x.dns.Count("ns.unknown.test", "A") }
	if asked() != 1 {
		t.Fatalf("first run asked %d times, want 1", asked())
	}
	rerun := func() {
		t.Helper()
		x.fill()
		if code := x.world.run("--passive", "--no-permutations", "-e", eng); code != 0 {
			t.Fatalf("exit %d", code)
		}
	}
	rerun()
	if asked() != 1 {
		t.Errorf("an unchanged engagement asked again: %d", asked())
	}

	// Make the checks look like the ones an earlier build stored.
	if _, err := x.h.openDB(eng).Exec("UPDATE checks SET key = replace(key, '|addrs', '') WHERE stage IN ('dnsroot', 'email')"); err != nil {
		t.Fatal(err)
	}
	rerun()
	if asked() != 2 {
		t.Errorf("the old checks did not look the addresses up: %d", asked())
	}
	if got := x.completedKeys("email"); len(got) < 1 || !strings.HasSuffix(got[len(got)-1], "|addrs") {
		t.Errorf("email check keys = %v", got)
	}
	rerun()
	if asked() != 2 {
		t.Errorf("the checks ran a third time: %d", asked())
	}
}
