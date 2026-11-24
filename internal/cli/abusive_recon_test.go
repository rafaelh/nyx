package cli_test

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
	"github.com/rafaelh/nyx/internal/threatdata/abusive"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
)

// Recon tests use supplied threat snapshots because fixture addresses do not occur in the real
// lists.

const abusiveFile = "risk-abusive-network.csv"

func abNet(rank int, start, end, tag string, score float64, org, typ string) abusive.NetworkEntry {
	return abusive.NetworkEntry{Rank: rank, Start: netip.MustParseAddr(start), End: netip.MustParseAddr(end), ScoreTag: tag, AbuseScore: score, Org: org, OrgType: typ}
}

func abASN(rank, asn int, tag string, score float64, org, typ string) abusive.ASNEntry {
	return abusive.ASNEntry{Rank: rank, ASN: asn, ScoreTag: tag, AbuseScore: score, Org: org, OrgType: typ}
}

// abSnapshot is a snapshot of the entries, ready to match, whose lists are dated 2026-11-21
// (networks) and 2026-11-20 (ASNs).
func abSnapshot(nets []abusive.NetworkEntry, asns []abusive.ASNEntry) *abusive.Snapshot {
	return abSnapshotOn("2026-11-21", "2026-11-20", nets, asns)
}

// abSnapshotOn fixes both list dates and accurate stated counts.
func abSnapshotOn(netsDate, asnsDate string, nets []abusive.NetworkEntry, asns []abusive.ASNEntry) *abusive.Snapshot {
	return abusive.Load(abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: netsDate, Stated: len(nets), Entries: nets},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: asnsDate, Stated: len(asns), Entries: asns},
	})
}

// abWorld is a web world run under --passive with the abusive check's procedures.
type abWorld struct {
	*web
	history *testkit.Procedure
	histIPs []string
}

func newAbWorld(t *testing.T) *abWorld {
	t.Helper()
	x := &abWorld{web: newWeb(t)}
	// A procedure whose addresses come from DNS history, which names the addresses of histIPs.
	x.history = &testkit.Procedure{ProcedureName: "fakehistory", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job {
			if len(x.histIPs) == 0 {
				return nil
			}
			return []run.Job{{Key: "history"}}
		},
		RunFn: func(context.Context, run.Job, egress.Clients) ([]run.Observation, error) {
			var out []run.Observation
			for _, a := range x.histIPs {
				out = append(out, run.Observation{Kind: "ip", Key: a})
			}
			return out, nil
		}}
	x.h.procedures = append(x.h.procedures, historicalProcedure{x.history})
	return x
}

// historicalProcedure is a procedure that says its addresses come from DNS history.
type historicalProcedure struct{ *testkit.Procedure }

func (historicalProcedure) HistoricalAddresses() {}

// origin scripts Team Cymru's answer for the first address of a unit: its AS and announced prefix.
func (x *abWorld) origin(addr string, asn int) {
	x.dns.TXT(dnsname.CymruOrigin(netip.MustParseAddr(addr)), fmt.Sprintf("%d | 0.0.0.0/0 | US | arin | 2000-01-01", asn))
}

// originQueries are the names the public resolvers were asked Team Cymru's origin zone for, sorted.
func (x *abWorld) originQueries() []string {
	var out []string
	for _, n := range x.dns.Queried("TXT") {
		if strings.Contains(n, ".origin.asn.cymru.com") || strings.Contains(n, ".origin6.asn.cymru.com") {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// originFor lists queried ownership-unit first-address names.
func originFor(addrs ...string) []string {
	var out []string
	for _, a := range addrs {
		out = append(out, dnsname.CymruOrigin(netip.MustParseAddr(a)))
	}
	slices.Sort(out)
	return out
}

// flagged extracts sorted current address/severity pairs from the risk file.
func (x *abWorld) flagged() []string {
	var out []string
	for _, r := range current(x.table(eng, abusiveFile)) {
		out = append(out, r["ip"]+"="+r["severity"])
	}
	slices.Sort(out)
	return out
}

func (x *abWorld) row(addr string) map[string]string {
	x.t.Helper()
	return find(current(x.table(eng, abusiveFile)), "ip", addr)
}

// Include in-scope hostname/netblock addresses, but reject excluded and history-only addresses.
func TestAbusiveRecon_WhichAddressesAreFlagged(t *testing.T) {
	t.Parallel()
	x := newAbWorld(t)
	x.names("app.example.com", "cdn.example.com", "ex.example.com", "asn.example.com")
	x.host("app.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	x.host("cdn.example.com", "104.16.0.5") // shared provider infrastructure
	x.owner("104.16.0.5", 13335, "CLOUDFLARENET")
	x.host("ex.example.com", "203.0.113.70") // inside an excluded CIDR
	x.owner("203.0.113.70", 64500, "ACME-NET")
	x.host("asn.example.com", "192.0.2.10") // listed by its AS alone
	x.owner("192.0.2.10", 64998, "BAD-AS")
	x.dns.PTR("198.51.100.5", "p5.example.com")   // a netblock address a PTR names
	x.dns.PTR("198.51.100.10", "p10.example.com") // named by a PTR and by history
	x.histIPs = []string{"198.51.100.9", "198.51.100.10"}
	x.origin("198.51.100.0", 64999)
	x.h.abusive = abSnapshot([]abusive.NetworkEntry{
		abNet(901, "203.0.113.7", "203.0.113.7", "Very High", 99.5, "Seven Org", "business"),
		abNet(902, "203.0.113.64", "203.0.113.79", "High", 70, "Excluded Org", "isp"),
		abNet(903, "104.16.0.0", "104.16.255.255", "High", 60, "Shared Org", "hosting"),
		abNet(904, "198.51.100.0", "198.51.100.255", "High", 55.25, "Netblock Org", "isp"),
	}, []abusive.ASNEntry{abASN(905, 64998, "Elevated", 33, "Bad AS Org", "unknown")})
	x.mustPassive("--cidr", "198.51.100.0/24", "-x", "203.0.113.64/28")

	want := []string{"104.16.0.5=medium", "192.0.2.10=low", "198.51.100.10=medium", "198.51.100.5=medium", "203.0.113.7=medium"}
	if got := x.flagged(); !slices.Equal(got, want) {
		t.Errorf("flagged %v\nwant    %v", got, want)
	}
	seven := x.row("203.0.113.7")
	if seven["type"] != "network" || seven["networks_updated"] != "2026-11-21" || seven["asns_updated"] != "" ||
		!strings.Contains(seven["networks"], "203.0.113.7/32 Very High 99.5% Seven Org (business)") || seven["hostnames"] != "app.example.com" {
		t.Errorf("203.0.113.7 = %v", seven)
	}
	asn := x.row("192.0.2.10")
	if asn["type"] != "asn" || asn["networks"] != "" || asn["asns_updated"] != "2026-11-20" ||
		!strings.Contains(asn["asn"], "AS64998 Elevated 33% Bad AS Org (unknown)") {
		t.Errorf("192.0.2.10 = %v", asn)
	}
	if r := x.row("198.51.100.5"); r["hostnames"] != "p5.example.com" {
		t.Errorf("198.51.100.5 = %v", r)
	}
	// The medium ones are in the run summary; the low one is not.
	targets := map[string]string{}
	for _, f := range summaryFindingsOf(x.h) {
		targets[fmt.Sprint(f["target"])] = fmt.Sprint(f["severity"])
	}
	for _, a := range []string{"104.16.0.5", "198.51.100.5", "198.51.100.10", "203.0.113.7"} {
		if targets[a] != "medium" {
			t.Errorf("the summary lacks %s as medium: %v", a, targets)
		}
	}
	if _, ok := targets["192.0.2.10"]; ok {
		t.Errorf("a low finding is in the summary: %v", targets)
	}
}

// summaryFindingsOf are the findings of the last run's summary event.
func summaryFindingsOf(h *harness) []map[string]any {
	var out []map[string]any
	list, _ := h.summaryEvent()["findings"].([]any)
	for _, f := range list {
		out = append(out, f.(map[string]any))
	}
	return out
}

// Netblock ownership queries are grouped by routing unit and remain available in passive mode.
func TestAbusiveRecon_OriginIsAskedOncePerUnit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		cidr  string
		hosts map[string]string // hostname -> an address inside the netblock
		ptrs  []string          // more addresses named by a PTR answer
		units []string          // the first address of each unit asked
	}{
		{"one /24", "198.51.100.0/24", nil, []string{"198.51.100.5", "198.51.100.9", "198.51.100.200"}, []string{"198.51.100.0"}},
		{"two /24s", "198.51.100.0/23", nil, []string{"198.51.100.5", "198.51.101.9", "198.51.101.200"}, []string{"198.51.100.0", "198.51.101.0"}},
		{"a /28", "198.51.100.16/28", nil, []string{"198.51.100.17", "198.51.100.30"}, []string{"198.51.100.16"}},
		{"an IPv6 /48 of a /32", "2001:db8::/32", map[string]string{"v6a.example.com": "2001:db8:5::1", "v6b.example.com": "2001:db8:5:1::2", "v6c.example.com": "2001:db8:6::3"},
			nil, []string{"2001:db8:5::", "2001:db8:6::"}},
		{"an IPv6 netblock smaller than a /48", "2001:db8:7::/64", map[string]string{"v6d.example.com": "2001:db8:7::9"}, nil, []string{"2001:db8:7::"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			x := newAbWorld(t)
			var names []string
			for h, a := range tc.hosts {
				names = append(names, h)
				x.host(h, a)
			}
			x.names(names...)
			for i, a := range tc.ptrs {
				x.dns.PTR(a, fmt.Sprintf("p%d.example.com", i))
			}
			x.h.abusive = abSnapshot(nil, nil)
			x.mustPassive("--cidr", tc.cidr)
			// The origin queries about the netblock's own addresses are the units' and no others.
			var got []string
			for _, q := range x.originQueries() {
				if !strings.HasPrefix(q, "250.113.0.203.") { // the root's address is asked by ipowner
					got = append(got, q)
				}
			}
			if want := originFor(tc.units...); !slices.Equal(got, want) {
				t.Errorf("origin queries\n got %v\nwant %v", got, want)
			}
			if st, reason := stateOf(x.world, "netblockowner"); st != "done" {
				t.Errorf("netblockowner = %s (%s), want done under --passive", st, reason)
			}
		})
	}
}

// Unknown AS ownership completes empty; transient failures retry only the affected job.
func TestAbusiveRecon_OriginFailuresAndRetries(t *testing.T) {
	t.Parallel()
	x := newAbWorld(t)
	x.names()
	x.dns.PTR("198.51.100.5", "p5.example.com")
	x.dns.PTR("198.51.101.5", "q5.example.com")
	x.dns.PTR("198.51.102.5", "r5.example.com")
	x.origin("198.51.101.0", 64999)
	x.dns.Rcode(dnsname.CymruOrigin(netip.MustParseAddr("198.51.102.0")), 2) // SERVFAIL
	x.h.abusive = abSnapshot([]abusive.NetworkEntry{abNet(1, "198.51.100.0", "198.51.102.255", "High", 50, "Block Org", "isp")},
		[]abusive.ASNEntry{abASN(2, 64999, "High", 90, "Bad AS", "hosting")})
	if f := x.partialPassive("--cidr", "198.51.100.0/22"); f.msg != "1 jobs failed: netblockowner 1" {
		t.Errorf("error = %+v, want the one failed netblockowner job", f)
	}
	// The network matches come out whether the AS is unknown, known or failed; the AS adds only where known.
	for addr, wantType := range map[string]string{"198.51.100.5": "network", "198.51.101.5": "network", "198.51.102.5": "network"} {
		if r := x.row(addr); r == nil || r["type"] != wantType || r["severity"] != "medium" {
			t.Errorf("%s = %v", addr, r)
		}
	}
	if r := x.row("198.51.101.5"); !strings.Contains(r["asn"], "AS64999") {
		t.Errorf("198.51.101.5 (AS known) = %v", r)
	}
	if r := x.row("198.51.100.5"); r["asn"] != "" {
		t.Errorf("198.51.100.5 (AS unknown, NXDOMAIN) has an AS: %v", r)
	}
	if r := x.row("198.51.102.5"); r["asn"] != "" {
		t.Errorf("198.51.102.5 (lookup failed) has an AS: %v", r)
	}
	if done := x.completedKeys("netblockowner"); !slices.Equal(done, []string{"198.51.100.0/24", "198.51.101.0/24"}) {
		t.Errorf("completed jobs = %v: a failed job is not completed, an unknown one is", done)
	}
	// The next run retries only the failed job, now that the resolver answers.
	x.dns.ClearRcode(dnsname.CymruOrigin(netip.MustParseAddr("198.51.102.0")))
	x.origin("198.51.102.0", 64999)
	units := []string{"198.51.100.0", "198.51.101.0", "198.51.102.0"}
	count := func() (n []int) {
		for _, u := range units {
			n = append(n, x.dns.Count(dnsname.CymruOrigin(netip.MustParseAddr(u)), "TXT"))
		}
		return n
	}
	before := count()
	x.mustPassive("--cidr", "198.51.100.0/22")
	after := count()
	if after[0] != before[0] || after[1] != before[1] || after[2] != before[2]+1 {
		t.Errorf("origin queries per unit went from %v to %v: only the failed unit is asked again", before, after)
	}
	if r := x.row("198.51.102.5"); !strings.Contains(r["asn"], "AS64999") {
		t.Errorf("198.51.102.5 after the retry = %v", r)
	}
	if r := x.row("198.51.102.5"); r["severity"] != "medium" || r["type"] != "network" {
		t.Errorf("198.51.102.5 = %v", r)
	}
}

// Threat matches can change findings without changing provider labels, contact eligibility or
// candidate classification.
func TestAbusiveRecon_InformationOnly(t *testing.T) { // mutation target
	t.Parallel()
	build := func(snap *abusive.Snapshot, drop *spamhaus.Lists, args ...string) *abWorld {
		x := newAbWorld(t)
		x.names("app.example.com", "other.example.com")
		x.host("app.example.com", "198.51.100.7")
		x.host("other.example.com", "203.0.113.9")
		x.owner("203.0.113.9", 64500, "ACME-NET")
		x.dns.PTR("198.51.100.5", "p5.example.com")
		x.origin("198.51.100.0", 13335) // an AS the provider data knows: Cloudflare
		x.h.abusive, x.h.drop = snap, drop
		x.mustPassive(append([]string{"--cidr", "198.51.100.0/24"}, args...)...)
		return x
	}
	listed := abSnapshot([]abusive.NetworkEntry{
		abNet(1, "198.51.100.0", "198.51.100.255", "High", 80, "Block Org", "isp"),
		abNet(2, "203.0.113.0", "203.0.113.255", "High", 80, "Other Org", "isp"),
	}, []abusive.ASNEntry{abASN(3, 13335, "High", 80, "Cloudflare", "hosting")})
	// DROP holds the netblock and the other host's /24 (the root's address too), and ASN-DROP lists
	// the netblock's origin AS and the hosts'.
	dropped := dropListsAt(t, time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC),
		[]spamhaus.NetworkEntry{dropNet("198.51.100.0/24", "SBL1001", "arin"), dropNet("203.0.113.0/24", "SBL1002", "apnic")},
		[]spamhaus.ASNEntry{dropASN(13335, "CLOUDFLARENET", "US", "cloudflare.com", "arin"), dropASN(64500, "ACME-NET", "AU", "acme.example", "apnic")})
	with := build(listed, nil)
	withDrop := build(nil, dropped)
	none := build(abSnapshot(nil, nil), nil)
	without := build(abSnapshot(nil, nil), nil, "--skip", "netblockowner")
	if rows := current(with.table(eng, abusiveFile)); len(rows) != 4 {
		t.Fatalf("%d flagged addresses with the snapshot, want 4 (the netblock's two, the host's and the root's): %v", len(rows), rows)
	}
	rows := current(withDrop.table(eng, abusiveFile))
	if len(rows) != 4 {
		t.Fatalf("%d flagged addresses with DROP, want 4 (the netblock's two, the host's and the root's): %v", len(rows), rows)
	}
	for _, r := range rows {
		if r["type"] != "drop-network" || r["severity"] != "high" {
			t.Errorf("%s = %v, want a high drop-network finding", r["ip"], r)
		}
	}
	if rows := without.table(eng, abusiveFile); len(rows) != 0 {
		t.Errorf("the empty snapshot flagged %v", rows)
	}
	if rows := none.table(eng, abusiveFile); len(rows) != 0 {
		t.Errorf("the empty lists flagged %v", rows)
	}
	for _, file := range []string{"ips.csv", "hostnames.csv", "netblocks.csv"} {
		if a, b := with.file(eng, file), without.file(eng, file); a != b {
			t.Errorf("%s differs:\nwith the abusive check:\n%s\nwithout:\n%s", file, a, b)
		}
		if a, b := withDrop.file(eng, file), none.file(eng, file); a != b {
			t.Errorf("%s differs:\nwith DROP:\n%s\nwithout:\n%s", file, a, b)
		}
	}
	with.netblockUnchanged()
	withDrop.netblockUnchanged()
	if a, b := with.candidateKeys(), without.candidateKeys(); !slices.Equal(a, b) {
		t.Errorf("candidate_rank records differ:\nwith    %v\nwithout %v", a, b)
	}
	if a, b := withDrop.candidateKeys(), none.candidateKeys(); !slices.Equal(a, b) {
		t.Errorf("candidate_rank records differ:\nwith DROP %v\nwithout   %v", a, b)
	}
	// What is sent does not change with DROP: the same queries and the same requests.
	if a, b := namesAsked(withDrop), namesAsked(none); !slices.Equal(a, b) {
		t.Errorf("DNS queries differ:\nwith DROP %v\nwithout   %v", a, b)
	}
	if a, b := withDrop.sent(), none.sent(); !slices.Equal(a, b) {
		t.Errorf("requests differ:\nwith DROP %v\nwithout   %v", a, b)
	}
	// A netblock_owner record is not a scope kind, so the AS 13335 did not make the netblock a provider's.
	for _, x := range []*abWorld{with, withDrop} {
		if x.h.network() != 0 {
			t.Error("a network canary was hit")
		}
	}
}

// netblockUnchanged verifies netblock ownership/contact classification independently of threat
// matches.
func (x *abWorld) netblockUnchanged() {
	x.t.Helper()
	for _, r := range x.table(eng, "ips.csv") {
		if strings.HasPrefix(r["ip"], "198.51.100.") {
			if r["provider"] != "" || r["owner"] != "in-scope netblock" || r["port_eligible"] != "true" {
				x.t.Errorf("%s in ips.csv = %v: the AS Team Cymru gave the netblock, or a match, changed it", r["ip"], r)
			}
		}
	}
}

// randomLabel is the first label of a wildcard probe: a random name under an in-scope domain.
var randomLabel = regexp.MustCompile(`^[0-9a-f]{16}\.`)

// namesAsked returns sorted queries without random wildcard probes, making runs comparable.
func namesAsked(x *abWorld) []string {
	return slices.DeleteFunc(dnsNames(x.dns), randomLabel.MatchString)
}

// sent are the requests the world's third-party fakes received, as "<host> <method> <URI>", sorted.
func (x *abWorld) sent() []string {
	var out []string
	for host, s := range x.src {
		for _, r := range s.requestLog() {
			out = append(out, host+" "+r.Method+" "+r.URI)
		}
	}
	slices.Sort(out)
	return out
}

// candidateKeys returns sorted stored candidate-rank keys.
func (x *abWorld) candidateKeys() []string {
	var out []string
	for k, a := range x.obsAttrs(eng, kinds.CandidateRank.Name()) {
		out = append(out, k+"="+a)
	}
	slices.Sort(out)
	return out
}

// checkRebuiltRows verifies removed, retained, escalated and newly added findings after
// replacing the snapshot.
func checkRebuiltRows(t *testing.T, rows []map[string]string, firstSeen string) {
	t.Helper()
	byIP := func(ip string) map[string]string { return find(rows, "ip", ip) }
	if r := byIP("203.0.113.1"); r == nil || r["current"] != "false" {
		t.Errorf("203.0.113.1 (dropped) = %v, want a row that is not current", r)
	}
	if r := byIP("203.0.113.2"); r == nil || r["current"] != "true" || r["first_seen"] != firstSeen ||
		!strings.Contains(r["networks"], "Kept Org Renamed") {
		t.Errorf("203.0.113.2 (kept) = %v", r)
	}
	if r := byIP("203.0.113.3"); r == nil || r["severity"] != "medium" || r["type"] != "network" || r["asn"] != "" {
		t.Errorf("203.0.113.3 (low to medium) = %v", r)
	}
	if r := byIP("203.0.113.4"); r == nil || r["current"] != "true" || r["severity"] != "medium" {
		t.Errorf("203.0.113.4 (new) = %v", r)
	}
}

// Rebuilt data updates findings without network contact, preserving history and announcing only
// new findings or severity increases.
func TestAbusiveRecon_ARebuiltSnapshotReachesAnOldEngagement(t *testing.T) {
	t.Parallel()
	x := newAbWorld(t)
	x.names("drop.example.com", "kept.example.com", "rise.example.com", "new.example.com")
	for h, a := range map[string]string{"drop.example.com": "203.0.113.1", "kept.example.com": "203.0.113.2", "rise.example.com": "203.0.113.3", "new.example.com": "203.0.113.4"} {
		x.host(h, a)
		asn := 64998
		if a == "203.0.113.4" {
			asn = 64999 // listed by neither snapshot's ASN list, so only snapshot B's network flags it
		}
		x.owner(a, asn, "BAD-AS")
	}
	snapA := abSnapshot([]abusive.NetworkEntry{
		abNet(10, "203.0.113.1", "203.0.113.1", "High", 70, "Drop Org", "isp"),
		abNet(11, "203.0.113.2", "203.0.113.2", "High", 71, "Kept Org", "isp"),
	}, []abusive.ASNEntry{abASN(12, 64998, "Elevated", 40, "Bad AS", "unknown")})
	// Snapshot B removes .1, updates .2, escalates .3 and adds .4.
	snapB := abSnapshot([]abusive.NetworkEntry{
		abNet(21, "203.0.113.2", "203.0.113.2", "Very High", 99, "Kept Org Renamed", "hosting"),
		abNet(22, "203.0.113.3", "203.0.113.3", "High", 60, "Rise Org", "isp"),
		abNet(23, "203.0.113.4", "203.0.113.4", "High", 61, "New Org", "isp"),
	}, nil)

	x.h.abusive = snapA
	x.mustPassive()
	// Under A, .1 and .2 are held by networks, .3 only by its AS and .4 by nothing.
	if got, want := x.flagged(), []string{"203.0.113.1=medium", "203.0.113.2=medium", "203.0.113.3=low"}; !slices.Equal(got, want) {
		t.Fatalf("after run 1: %v, want %v", got, want)
	}
	firstSeen := x.row("203.0.113.2")["first_seen"]
	foundBefore := x.foundFindings()
	for _, a := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"} {
		if !slices.Contains(foundBefore, a) {
			t.Errorf("run 1 did not announce %s: %v", a, foundBefore)
		}
	}
	queries, hits := x.dns.Total(), x.h.network()

	x.h.abusive = snapB
	x.mustPassive()
	if got := x.dns.Total() - queries; got != 0 {
		t.Errorf("the second run sent %d DNS queries, want none", got)
	}
	if x.h.network() != hits {
		t.Error("a network canary was hit by the second run")
	}
	checkRebuiltRows(t, x.table(eng, abusiveFile), firstSeen)
	// A new finding and a rise are announced, and a kept address is not announced again.
	announced := x.foundFindings() // the second run's events only: the harness keeps the last call's
	if !slices.Contains(announced, "203.0.113.3") {
		t.Errorf("the rise of 203.0.113.3 was not announced: %v", announced)
	}
	if !slices.Contains(announced, "203.0.113.4") {
		t.Errorf("the new finding of 203.0.113.4 was not announced: %v", announced)
	}
	if slices.Contains(announced, "203.0.113.2") {
		t.Errorf("a kept finding was announced as new: %v", announced)
	}
	// The changes report lists a finding that is new, not one that rose.
	changes := x.table(eng, "changes.csv")
	var listed []string
	for _, r := range changes {
		if r["kind"] == "finding" {
			listed = append(listed, r["change"]+" "+r["key"])
		}
	}
	if slices.Contains(listed, "new abusive-network|203.0.113.3") || slices.Contains(listed, "new abusive-network|203.0.113.2") {
		t.Errorf("changes.csv lists a finding that stayed shown as new: %v", listed)
	}
	if !slices.Contains(listed, "new abusive-network|203.0.113.4") {
		t.Errorf("changes.csv lacks the finding of the address newly listed: %v", listed)
	}

	// An export shows the findings as of the last run, which is run 2: the dropped address is not current.
	x.h.stdout.Reset()
	x.h.stderr.Reset()
	e := export(x.h, "-e", eng, "--kind", "finding")
	if e.code != 0 {
		t.Fatalf("export exit %d: %s", e.code, e.stderr)
	}
	current := map[string]bool{}
	for _, l := range e.lines(t) {
		if ip, ok := strings.CutPrefix(l.str("key"), "abusive-network|"); ok {
			current[ip] = l["current"] == true
		}
	}
	want := map[string]bool{"203.0.113.1": false, "203.0.113.2": true, "203.0.113.3": true, "203.0.113.4": true}
	if fmt.Sprint(current) != fmt.Sprint(want) {
		t.Errorf("exported findings (current) = %v, want %v", current, want)
	}
}

// foundFindings are the addresses of the abusive-network findings the last call announced.
func (x *abWorld) foundFindings() []string {
	var out []string
	for _, e := range ofType(x.h.events(), "found") {
		if strings.HasSuffix(e.str("category"), "abusive-network") {
			out = append(out, e.str("value"))
		}
	}
	slices.Sort(out)
	return out
}

// Text from the snapshot is sanitised in the risk file, the console and the JSON findings.
func TestAbusiveRecon_SnapshotTextIsSanitised(t *testing.T) {
	t.Parallel()
	x := newAbWorld(t)
	x.names("app.example.com")
	x.host("app.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64998, "BAD-AS")
	x.h.abusive = abSnapshot([]abusive.NetworkEntry{abNet(1, "203.0.113.0", "203.0.113.255", "Hi\x1b[31mgh", 80, "Evil\x1b]0;x\x07 Org\u202e", "is\np")},
		[]abusive.ASNEntry{abASN(2, 64998, "High", 70, "A\x1b[2Jb", "t\x07")})
	x.mustPassive()
	for name, text := range map[string]string{"risk file": x.file(eng, abusiveFile), "stdout": x.h.stdout.String(), "stderr": x.h.stderr.String()} {
		if strings.ContainsAny(text, "\x1b\x07\u202e") {
			t.Errorf("%s holds unsanitised text: %q", name, text)
		}
	}
	if r := x.row("203.0.113.7"); !strings.Contains(r["networks"], "Evil") || !strings.Contains(r["asn"], "Ab") {
		t.Errorf("the text itself was lost: %v", r)
	}
}
