package cli_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rafaelh/nyx/internal/run"
)

// RDAP for netblocks and registrants. The tests drive cli.Execute with the real
// rdap stage. data.iana.org is a fake bootstrap file and each registry is a
// fake that answers address lookups, organisation searches and an entity's
// networks, in the shape that registry uses, so nothing leaves the machine.

const (
	hostIANA    = "data.iana.org"
	hostARIN    = "rdap.arin.net"
	hostRIPE    = "rdap.db.ripe.net"
	hostAPNIC   = "rdap.apnic.net"
	hostLACNIC  = "rdap.lacnic.net"
	hostAFRINIC = "rdap.afrinic.net"
)

// rdapBase is the path each registry serves RDAP under, which the IANA
// bootstrap file gives as its service URL.
var rdapBase = map[string]string{hostARIN: "/registry/", hostRIPE: "/", hostAPNIC: "/", hostLACNIC: "/rdap/", hostAFRINIC: "/rdap/"}

var rdapRegistries = []string{hostARIN, hostRIPE, hostAPNIC, hostLACNIC, hostAFRINIC}

// rdapNet is a registered netblock and the registrant of it.
type rdapNet struct{ start, end, handle, registrant string }

// rdapEntity is an organisation a registry holds: what an entity search returns.
type rdapEntity struct {
	handle, name string
	nets         []rdapNet
	asns         []int
	asnRange     [2]int // an autnum object that names a range of systems, if set
}

// rdapFake is one registry.
type rdapFake struct {
	mu    sync.Mutex
	base  string
	nets  []rdapNet
	ents  []rdapEntity
	embed bool // the search result carries the networks (APNIC); otherwise /entity/<handle> does (ARIN)

	redirect map[string]string // address -> the Location its lookup answers with
	status   int               // if set, every request answers with it
}

func vcard(name string) []any {
	return []any{"vcard", []any{[]any{"version", map[string]any{}, "text", "4.0"}, []any{"fn", map[string]any{}, "text", name}}}
}

func (n rdapNet) json() map[string]any {
	return map[string]any{"objectClassName": "ip network", "handle": n.handle, "startAddress": n.start, "endAddress": n.end,
		"ipVersion": "v4", "name": "NET-" + n.handle,
		"entities": []any{
			map[string]any{"objectClassName": "entity", "handle": "ABUSE", "roles": []string{"abuse"}, "vcardArray": vcard("Abuse Desk")},
			map[string]any{"objectClassName": "entity", "handle": "ORG-" + n.handle, "roles": []string{"registrant"}, "vcardArray": vcard(n.registrant)},
		}}
}

func (e rdapEntity) networks() map[string]any {
	var nets, asns []any
	for _, n := range e.nets {
		nets = append(nets, map[string]any{"objectClassName": "ip network", "handle": n.handle, "startAddress": n.start, "endAddress": n.end, "ipVersion": "v4"})
	}
	for _, a := range e.asns {
		asns = append(asns, map[string]any{"objectClassName": "autnum", "handle": fmt.Sprintf("AS%d", a), "startAutnum": a, "endAutnum": a})
	}
	if r := e.asnRange; r[0] != 0 {
		asns = append(asns, map[string]any{"objectClassName": "autnum", "handle": fmt.Sprintf("AS%d-AS%d", r[0], r[1]), "startAutnum": r[0], "endAutnum": r[1]})
	}
	return map[string]any{"networks": nets, "autnums": asns}
}

func (e rdapEntity) json(embed bool) map[string]any {
	m := map[string]any{"objectClassName": "entity", "handle": e.handle, "vcardArray": vcard(e.name)}
	if embed {
		for k, v := range e.networks() {
			m[k] = v
		}
	}
	return m
}

func inRange(addr, start, end string) bool {
	a, s, e := netip.MustParseAddr(addr), netip.MustParseAddr(start), netip.MustParseAddr(end)
	return a.Compare(s) >= 0 && a.Compare(e) <= 0
}

func (f *rdapFake) serve(rw http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status != 0 {
		http.Error(rw, "no", f.status)
		return
	}
	write := func(v any) {
		rw.Header().Set("Content-Type", "application/rdap+json")
		_ = json.NewEncoder(rw).Encode(v)
	}
	rest, ok := strings.CutPrefix(r.URL.Path, f.base)
	switch {
	case !ok:
		http.NotFound(rw, r)
	case strings.HasPrefix(rest, "ip/"):
		addr := strings.TrimPrefix(rest, "ip/")
		if loc, ok := f.redirect[addr]; ok {
			rw.Header().Set("Location", loc)
			rw.WriteHeader(http.StatusFound)
			return
		}
		for _, n := range f.nets {
			if inRange(addr, n.start, n.end) {
				write(n.json())
				return
			}
		}
		http.NotFound(rw, r)
	case rest == "entities":
		if !strings.HasSuffix(r.URL.Query().Get("fn"), "*") {
			http.Error(rw, "bad search", http.StatusBadRequest)
			return
		}
		var out []any
		for _, e := range f.ents {
			out = append(out, e.json(f.embed))
		}
		write(map[string]any{"entitySearchResults": out})
	case strings.HasPrefix(rest, "entity/"):
		for _, e := range f.ents {
			if e.handle == strings.TrimPrefix(rest, "entity/") {
				write(e.json(true))
				return
			}
		}
		http.NotFound(rw, r)
	default:
		http.NotFound(rw, r)
	}
}

// rdapWorld is a world whose registries and bootstrap file are scripted.
type rdapWorld struct {
	*world
	reg map[string]*rdapFake
}

// newRDAP returns a world with the named hosts in example.com, a bootstrap file
// that sends 203/8 and 104/8 to ARIN and 198/8 to RIPE, and an empty registry
// at each host. A host is "name=address" and has a known owner.
func newRDAP(t *testing.T, hosts ...string) *rdapWorld {
	t.Helper()
	x := &rdapWorld{world: newWorld(t), reg: map[string]*rdapFake{}}
	w := x.world
	for _, h := range rdapRegistries {
		f := &rdapFake{base: rdapBase[h]}
		x.reg[h] = f
		w.handle(h, f.serve)
	}
	x.bootstrap("203.0.0.0/8", hostARIN, "104.0.0.0/8", hostARIN, "198.0.0.0/8", hostRIPE, "100.0.0.0/8", hostAPNIC)
	serveAWSElsewhere(w)
	x.hosts(hosts...)
	// RIPEstat is the asn stage's source; an input ASN has no prefixes here.
	w.handle("stat.ripe.net", jsonBody(`{"status":"ok","data":{"prefixes":[]}}`))
	return x
}

// bootstrap serves ipv4.json from prefix, registry host pairs, and an empty ipv6.json.
func (x *rdapWorld) bootstrap(pairs ...string) {
	var services []any
	for i := 0; i+1 < len(pairs); i += 2 {
		services = append(services, []any{[]string{pairs[i]}, []string{"https://" + pairs[i+1] + rdapBase[pairs[i+1]]}})
	}
	body, _ := json.Marshal(map[string]any{"version": "1.0", "services": services})
	x.handle(hostIANA, func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/ipv4.json"):
			_, _ = rw.Write(body)
		case strings.HasSuffix(r.URL.Path, "/ipv6.json"):
			_, _ = rw.Write([]byte(`{"version":"1.0","services":[]}`))
		default:
			http.NotFound(rw, r)
		}
	})
}

// hosts makes each "name=address" an in-scope host with a known, dedicated
// owner. An address ending in "?" has no owner record.
func (x *rdapWorld) hosts(hosts ...string) {
	var names []string
	for _, h := range hosts {
		name, addr, _ := strings.Cut(h, "=")
		addr, noOwner := strings.CutSuffix(addr, "?")
		names = append(names, name+".example.com")
		x.dns.A(name+".example.com", addr)
		if !noOwner {
			x.owner(addr, 64500, "ACME-NET")
		}
	}
	x.crtsh(map[string][]string{"example.com": names}, nil)
}

// net registers a netblock at a registry host.
func (x *rdapWorld) net(host string, n rdapNet) {
	f := x.reg[host]
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nets = append(f.nets, n)
}

func (x *rdapWorld) entities(host string, embed bool, ents ...rdapEntity) {
	f := x.reg[host]
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ents, f.embed = ents, embed
}

func (x *rdapWorld) fake(host string) *rdapFake { return x.reg[host] }

// lookupsAt are the addresses asked of a registry's /ip/ path, sorted.
func (x *rdapWorld) lookupsAt(host string) []string {
	var out []string
	for _, r := range x.requests(host) {
		if rest, ok := strings.CutPrefix(r.path(), rdapBase[host]+"ip/"); ok {
			out = append(out, rest)
		}
	}
	slices.Sort(out)
	return out
}

func (x *rdapWorld) lookups() int {
	n := 0
	for _, h := range rdapRegistries {
		n += len(x.lookupsAt(h))
	}
	return n
}

func (x *rdapWorld) bootstrapFetches() int {
	return x.src[hostIANA].count("GET", "/rdap/ipv4.json")
}

// searches counts the entity searches a registry received.
func (x *rdapWorld) searches(host string) int {
	return x.src[host].count("GET", rdapBase[host]+"entities")
}

// scan runs a passive engagement for example.com without permutations. A run of
// an existing engagement is scan("-e", eng, ...).
func (x *rdapWorld) scan(args ...string) int {
	x.t.Helper()
	return x.run(rootArgs(append([]string{"--no-permutations"}, args...))...)
}

func (x *rdapWorld) mustScan(args ...string) {
	x.t.Helper()
	if code := x.scan(args...); code != 0 {
		x.t.Fatalf("exit %d\n%s\n%s", code, x.h.stdout.String(), x.h.stderr.String())
	}
}

func (x *rdapWorld) ipRow(addr string) map[string]string {
	return find(x.table(eng, "ips.csv"), "ip", addr)
}

func (x *rdapWorld) candidate(value string) map[string]string {
	return find(x.table(eng, "candidates.csv"), "value", value)
}

func (x *rdapWorld) candidateTypes() []string {
	var out []string
	for _, r := range x.table(eng, "candidates.csv") {
		out = append(out, r["type"]+" "+r["value"])
	}
	slices.Sort(out)
	return out
}

func globexNets() (r1, r2, r3 rdapNet) {
	return rdapNet{"203.0.113.0", "203.0.113.127", "NET-R1", "Globex Holdings Ltd"},
		rdapNet{"203.0.113.128", "203.0.113.255", "NET-R2", "Globex Holdings Ltd"},
		rdapNet{"203.0.114.0", "203.0.114.255", "NET-R3", "Globex Holdings Ltd"}
}

// --- address lookups ---

// An address is looked up at the registry the bootstrap file names, and a second
// address in the same registered range costs no request.
func TestRDAP_AddressLookupAtBootstrapRegistry(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=203.0.113.7", "b=198.51.100.7", "c=203.0.113.8")
	x.net(hostARIN, rdapNet{"203.0.113.0", "203.0.113.255", "NET-203-0-113-0-1", "Acme Holdings Pty Ltd"})
	x.net(hostRIPE, rdapNet{"198.51.100.0", "198.51.100.255", "198.51.100.0 - 198.51.100.255", "Acme Europe BV"})
	x.mustScan()

	if got := x.lookupsAt(hostARIN); len(got) != 1 {
		t.Errorf("ARIN lookups = %v, want one for the range of 203.0.113.7, .8 and the root's address", got)
	}
	if got := x.lookupsAt(hostRIPE); !slices.Equal(got, []string{"198.51.100.7"}) {
		t.Errorf("RIPE lookups = %v", got)
	}
	for _, h := range []string{hostAPNIC, hostLACNIC, hostAFRINIC} {
		if n := len(x.requests(h)); n != 0 {
			t.Errorf("%s got %d requests", h, n)
		}
	}
	if hdr := strings.SplitN(x.file(eng, "ips.csv"), "\n", 2)[0]; hdr !=
		"ip,asn,owner,provider,service,in_scope,port_eligible,hostnames,registrant,registrant_netblock,registry,srv_ports,current,first_seen,last_seen" {
		t.Errorf("ips.csv header = %q", hdr)
	}
	for _, a := range []string{"203.0.113.7", "203.0.113.8", "203.0.113.250"} {
		r := x.ipRow(a)
		if r == nil || r["registrant"] != "Acme Holdings Pty Ltd" || r["registrant_netblock"] != "203.0.113.0/24" || r["registry"] != "arin" || r["owner"] != "ACME-NET" {
			t.Errorf("ips.csv row for %s = %v", a, r)
		}
	}
}

// An IPv6 address is looked up at the registry IANA's ipv6.json names.
func TestRDAP_IPv6AddressLookup(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=2001:db8::7")
	x.handle(hostIANA, func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/ipv6.json"):
			_, _ = rw.Write([]byte(`{"version":"1.0","services":[[["2001:db8::/32"],["https://` + hostAPNIC + `/"]]]}`))
		case strings.HasSuffix(r.URL.Path, "/ipv4.json"):
			_, _ = rw.Write([]byte(`{"version":"1.0","services":[]}`))
		default:
			http.NotFound(rw, r)
		}
	})
	x.net(hostAPNIC, rdapNet{"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "NET6-1", "Acme Pacific Pty Ltd"})
	x.mustScan()
	if got := x.lookupsAt(hostAPNIC); !slices.Equal(got, []string{"2001:db8::7"}) {
		t.Errorf("APNIC lookups = %v", got)
	}
	if r := x.ipRow("2001:db8::7"); r == nil || r["registrant"] != "Acme Pacific Pty Ltd" || r["registrant_netblock"] != "2001:db8::/32" || r["registry"] != "apnic" {
		t.Errorf("ips.csv row = %v", r)
	}
}

// A registered range that is not aligned is shown with its two addresses.
func TestRDAP_RegisteredNetblockText(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=198.51.100.7")
	x.net(hostRIPE, rdapNet{"198.51.100.5", "198.51.100.20", "HANDLE-1", "Acme Europe BV"})
	x.mustScan()
	if r := x.ipRow("198.51.100.7"); r == nil || r["registrant_netblock"] != "198.51.100.5-198.51.100.20" || r["registry"] != "ripe" {
		t.Errorf("row = %v", r)
	}
}

// Addresses in an input netblock, on shared provider infrastructure, with no
// known owner, or excluded are not looked up.
func TestRDAP_ExcludedClassesAreNotLookedUp(t *testing.T) {
	t.Parallel()
	x := newRDAP(t,
		"inblock=198.18.0.5",   // inside --cidr
		"nowner=203.0.113.99?", // owner unknown
		"excl=198.51.101.200",  // --exclude
		"cdn=104.16.0.1?",      // Cloudflare (owner below)
		"ok=198.51.100.7",
	)
	x.owner("104.16.0.1", 13335, "CLOUDFLARENET")
	x.net(hostARIN, rdapNet{"203.0.113.0", "203.0.113.255", "R-ARIN", "Acme"})
	x.net(hostARIN, rdapNet{"104.16.0.0", "104.31.255.255", "R-CF", "Cloudflare, Inc."})
	x.net(hostRIPE, rdapNet{"198.51.100.0", "198.51.100.255", "R-RIPE", "Acme Europe BV"})
	x.net(hostRIPE, rdapNet{"198.51.101.0", "198.51.101.255", "R-RIPE2", "Acme Europe BV"})
	x.net(hostRIPE, rdapNet{"198.18.0.0", "198.18.0.255", "R-RIPE3", "Acme Europe BV"})
	x.mustScan("--cidr", "198.18.0.0/24", "--exclude", "excl.example.com")

	if got := x.lookupsAt(hostRIPE); !slices.Equal(got, []string{"198.51.100.7"}) {
		t.Errorf("RIPE lookups = %v, want only the dedicated, in-scope, uncovered address", got)
	}
	for _, a := range x.lookupsAt(hostARIN) {
		if a == "104.16.0.1" {
			t.Errorf("a shared provider address was looked up")
		}
	}
	if r := x.ipRow("104.16.0.1"); r != nil && r["registrant"] != "" {
		t.Errorf("shared address has a registrant: %v", r)
	}
}

// --- referrals ---

func TestRDAP_ReferralInsideTheSixIsFollowed(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=203.0.113.7")
	x.net(hostARIN, rdapNet{"203.0.113.128", "203.0.113.255", "NET-ARIN", "Acme"})
	x.net(hostAPNIC, rdapNet{"203.0.113.0", "203.0.113.127", "NET-APNIC", "Acme Pacific Pty Ltd"})
	x.fake(hostARIN).redirect = map[string]string{"203.0.113.7": "https://" + hostAPNIC + "/ip/203.0.113.7"}
	x.mustScan()
	r := x.ipRow("203.0.113.7")
	if r == nil || r["registry"] != "apnic" || r["registrant"] != "Acme Pacific Pty Ltd" {
		t.Errorf("ips.csv row = %v, want the answer of APNIC", r)
	}
}

func TestRDAP_ReferralOutsideTheSixCompletesWithAWarning(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=203.0.113.7")
	x.net(hostARIN, rdapNet{"203.0.113.128", "203.0.113.255", "NET-ARIN", "Acme"})
	x.fake(hostARIN).redirect = map[string]string{"203.0.113.7": "https://rdap.elsewhere.example.org/ip/203.0.113.7"}
	x.mustScan()
	if r := x.ipRow("203.0.113.7"); r == nil || r["registrant"] != "" || r["registry"] != "" {
		t.Errorf("row = %v, want no registration", r)
	}
	if !slices.Contains(x.h.completed(eng, "rdap"), "ip|203.0.113.7") {
		t.Errorf("the lookup is not completed: %v", x.h.completed(eng, "rdap"))
	}
	if w := x.warnings(); !strings.Contains(w, "203.0.113.7") || !strings.Contains(w, "elsewhere.example.org") {
		t.Errorf("warnings = %q, want one naming the address and the host", w)
	}
}

// A referral is followed three times at most.
func TestRDAP_ReferralLoopStops(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=203.0.113.7")
	x.net(hostARIN, rdapNet{"203.0.113.128", "203.0.113.255", "NET-ARIN", "Acme"})
	x.fake(hostARIN).redirect = map[string]string{"203.0.113.7": "https://" + hostARIN + "/registry/ip/203.0.113.7"}
	x.mustScan()
	if got := x.lookupsAt(hostARIN); len(got) != 4+1 { // the original and three hops, and the root's address
		t.Errorf("ARIN lookups = %v, want 1 + 3 hops for 203.0.113.7 and 1 for the root", got)
	}
	if r := x.ipRow("203.0.113.7"); r == nil || r["registrant"] != "" {
		t.Errorf("row = %v", r)
	}
}

// --- organisation search ---

func acmeEntities(x *rdapWorld) {
	x.entities(hostARIN, false,
		rdapEntity{handle: "ACME-1", name: "Acme Widgets, Inc.",
			nets: []rdapNet{{"192.0.2.0", "192.0.2.255", "NET-A", ""}, {"198.51.100.0", "198.51.100.191", "NET-B", ""}}, asns: []int{64501}},
		rdapEntity{handle: "GADGETS-1", name: "Acme Gadgets Inc", nets: []rdapNet{{"203.0.113.0", "203.0.113.255", "NET-G", ""}}, asns: []int{64599}})
	x.entities(hostAPNIC, true,
		rdapEntity{handle: "ORG-AW1-AP", name: "ACME WIDGETS PTY LTD", nets: []rdapNet{{"100.64.0.0", "100.64.0.255", "NET-P", ""}}, asns: []int{64502}})
}

// Only entities whose name has every word of the organisation are kept; their
// netblocks and autonomous systems are candidates and never in scope.
func TestRDAP_OrganisationSearchKeepsWordRuleMatches(t *testing.T) {
	t.Parallel()
	x := newRDAP(t)
	acmeEntities(x)
	x.mustScan("--org", "Acme Widgets Pty Ltd")

	want := []string{"asn AS64501", "asn AS64502", "netblock 100.64.0.0/24", "netblock 192.0.2.0/24", "netblock 198.51.100.0/25", "netblock 198.51.100.128/26"}
	if got := x.candidateTypes(); !slices.Equal(got, want) {
		t.Errorf("candidates = %v, want %v", got, want)
	}
	for _, v := range []string{"AS64501", "192.0.2.0/24", "100.64.0.0/24"} {
		if r := x.candidate(v); r == nil || r["sources"] != "rdap" || r["evidence_count"] != "1" || r["confidence"] != "medium" {
			t.Errorf("candidate %s = %v, want rdap, 1, medium", v, r)
		}
	}
	if x.file(eng, "netblocks.csv") != "" {
		t.Errorf("a netblock found by search entered scope:\n%s", x.file(eng, "netblocks.csv"))
	}
	if n := x.h.total("netblocks"); n != 0 {
		t.Errorf("summary netblocks = %d", n)
	}
	// ARIN needed the entity's own request for its networks; APNIC did not.
	if n := x.src[hostARIN].count("GET", "/registry/entity/ACME-1"); n != 1 {
		t.Errorf("ARIN entity requests = %d, want 1", n)
	}
	if n := x.src[hostARIN].count("GET", "/registry/entity/GADGETS-1"); n != 0 {
		t.Errorf("a non-matching entity was fetched")
	}
	if n := x.src[hostAPNIC].count("GET", "/entity/ORG-AW1-AP"); n != 0 {
		t.Errorf("APNIC entity requests = %d, want 0 (the search result carries the networks)", n)
	}
	if code := x.h.stderr.String(); strings.Contains(code, "Gadgets") {
		t.Errorf("a non-matching entity was reported: %s", code)
	}
}

// A registry whose RDAP does not return an organisation's networks completes
// with no results and a note; it is not asked.
func TestRDAP_RegistryWithoutSearchCompletesWithANote(t *testing.T) {
	t.Parallel()
	x := newRDAP(t)
	acmeEntities(x)
	x.mustScan("--org", "Acme Widgets Pty Ltd")
	for _, h := range []string{hostRIPE, hostLACNIC, hostAFRINIC} {
		if n := len(x.requests(h)); n != 0 {
			t.Errorf("%s got %d requests, want none", h, n)
		}
		if w := x.warnings(); !strings.Contains(w, h) {
			t.Errorf("no note names %s: %q", h, w)
		}
	}
	done := x.h.completed(eng, "rdap")
	for _, r := range []string{"ripe", "lacnic", "afrinic", "arin", "apnic"} {
		if !slices.Contains(done, "org|Acme Widgets Pty Ltd|"+r) {
			t.Errorf("check for %s not completed: %v", r, done)
		}
	}
}

// At most 50 results are kept per registry, and the cut is a warning.
func TestRDAP_SearchKeepsFiftyPerRegistry(t *testing.T) {
	t.Parallel()
	x := newRDAP(t)
	var nets []rdapNet
	for i := 0; i < 60; i++ {
		nets = append(nets, rdapNet{fmt.Sprintf("100.%d.0.0", i), fmt.Sprintf("100.%d.0.255", i), fmt.Sprintf("N%d", i), ""})
	}
	x.entities(hostAPNIC, true, rdapEntity{handle: "ORG-AW1-AP", name: "Acme Widgets", nets: nets})
	x.entities(hostARIN, false, rdapEntity{handle: "ACME-1", name: "Acme Widgets", nets: []rdapNet{
		{"101.0.0.0", "101.0.0.255", "M0", ""}, {"101.1.0.0", "101.1.0.255", "M1", ""}, {"101.2.0.0", "101.2.0.255", "M2", ""}}})
	x.mustScan("--org", "Acme Widgets")
	n := 0
	for _, r := range x.table(eng, "candidates.csv") {
		if r["type"] == "netblock" && (strings.HasPrefix(r["value"], "100.") || strings.HasPrefix(r["value"], "101.")) {
			n++
		}
	}
	if n != 50+3 {
		t.Errorf("%d netblock candidates, want 50 from APNIC and 3 from ARIN", n)
	}
	if w := x.warnings(); !strings.Contains(w, hostAPNIC) || !strings.Contains(w, "50") {
		t.Errorf("warnings = %q, want one naming the registry and the cap", w)
	}
	if strings.Contains(x.warnings(), hostARIN+" returned more") {
		t.Errorf("ARIN's result was not cut: %q", x.warnings())
	}
}

// Each autonomous system of an autnum range counts toward the 50, and the cut is
// a warning.
func TestRDAP_ASNRangeCountsTowardTheFifty(t *testing.T) {
	t.Parallel()
	x := newRDAP(t)
	x.entities(hostAPNIC, true, rdapEntity{handle: "ORG-AW1-AP", name: "Acme Widgets", asnRange: [2]int{64600, 64659}})
	x.mustScan("--org", "Acme Widgets")
	n := 0
	for _, r := range x.table(eng, "candidates.csv") {
		if r["type"] == "asn" {
			n++
		}
	}
	if n != 50 {
		t.Errorf("%d asn candidates from a range of 60, want 50", n)
	}
	if w := x.warnings(); !strings.Contains(w, hostAPNIC+") returned more than 50") {
		t.Errorf("warnings = %q, want one naming the registry and the cap", w)
	}
}

// An organisation with no words keeps no results.
func TestRDAP_OrganisationWithNoWordsMatchesNothing(t *testing.T) {
	t.Parallel()
	x := newRDAP(t)
	acmeEntities(x)
	x.mustScan("--org", "Pty Ltd")
	if rows := x.table(eng, "candidates.csv"); len(rows) != 0 {
		t.Errorf("candidates = %v", rows)
	}
}

// --- registrants ---

func registrantWorld(t *testing.T, hosts ...string) *rdapWorld {
	x := newRDAP(t, hosts...)
	r1, r2, r3 := globexNets()
	x.net(hostARIN, r1)
	x.net(hostARIN, r2)
	x.net(hostARIN, r3)
	return x
}

// A registrant on three registered netblocks is an organisation candidate; two
// addresses of one range count once.
func TestRDAP_RegistrantOnThreeRangesIsACandidate(t *testing.T) {
	t.Parallel()
	x := registrantWorld(t, "a=203.0.113.7", "b=203.0.114.7", "c=203.0.113.8") // the root's address is in R2
	x.mustScan()
	r := x.candidate("Globex Holdings Ltd")
	if r == nil || r["type"] != "organisation" {
		t.Fatalf("candidates = %v", x.candidateTypes())
	}
	wantRow(t, r, "rdap", "3", "low")
	if n := len(x.lookupsAt(hostARIN)); n != 3 {
		t.Errorf("ARIN lookups = %d, want one per range", n)
	}
	// The summary counts it among the candidates.
	if n := x.h.total("candidates"); n != 1 {
		t.Errorf("summary candidates = %d, want 1", n)
	}
}

// One whose third range is found on a later run appears then.
func TestRDAP_ThirdRangeFoundOnALaterRun(t *testing.T) {
	t.Parallel()
	x := registrantWorld(t, "a=203.0.113.7")
	x.mustScan()
	if r := x.candidate("Globex Holdings Ltd"); r != nil {
		t.Fatalf("two ranges made a candidate: %v", r)
	}
	x.hosts("b=203.0.114.7")
	x.mustScan("-e", eng, "--redo", "crtsh")
	r := x.candidate("Globex Holdings Ltd")
	if r == nil {
		t.Fatalf("candidates = %v", x.candidateTypes())
	}
	wantRow(t, r, "rdap", "3", "low")
}

// A registrant that matches an --org input is not a candidate; one with a
// shared address inside its ranges is not either.
func TestRDAP_RegistrantMatchingOrgOrOnSharedAddressesIsNotACandidate(t *testing.T) {
	t.Parallel()
	x := registrantWorld(t, "a=203.0.113.7", "b=203.0.114.7")
	x.mustScan("--org", "Globex")
	if r := x.candidate("Globex Holdings Ltd"); r != nil {
		t.Errorf("a registrant matching --org is a candidate: %v", r)
	}

	y := registrantWorld(t, "a=203.0.113.7", "b=203.0.114.7", "d=203.0.114.200?")
	y.owner("203.0.114.200", 13335, "CLOUDFLARENET")
	y.mustScan()
	if r := y.candidate("Globex Holdings Ltd"); r != nil {
		t.Errorf("a registrant with a shared address in its ranges is a candidate: %v", r)
	}
	// It stays on record, and so is a candidate again once the address is not shared.
	if n := len(y.obsAttrs(eng, "organisation")); n == 0 {
		t.Errorf("the organisation was not recorded")
	}
}

// --- ranking and promotion ---

// asn and organisation rows carry the rank of their evidence, and a netblock or
// asn from an --org search alone is medium.
func TestRDAP_RanksAndPromotionHints(t *testing.T) {
	t.Parallel()
	x := registrantWorld(t, "a=203.0.113.7", "b=203.0.114.7", "c=203.0.113.8")
	x.entities(hostARIN, false, rdapEntity{handle: "ACME-1", name: "Acme Widgets", nets: []rdapNet{{"192.0.2.0", "192.0.2.255", "NET-A", ""}}, asns: []int{64501}})
	// Two other families agree about the organisation and about the ASN.
	for i, s := range x.h.stages {
		if n := s.Name(); n == "wayback" || n == "virustotal" {
			x.h.stages[i] = newSrc(n, finds("k", list(obs("asn", "AS64501"), obs("organisation", "Globex Holdings Ltd"))))
		}
	}
	x.mustScan("--org", "Acme Widgets")
	asn := x.candidate("AS64501")
	if asn == nil || asn["type"] != "asn" {
		t.Fatalf("candidates = %v", x.candidateTypes())
	}
	wantRow(t, asn, "rdap;virustotal;wayback", "3", "high")
	org := x.candidate("Globex Holdings Ltd")
	if org == nil || org["type"] != "organisation" {
		t.Fatalf("candidates = %v", x.candidateTypes())
	}
	wantRow(t, org, "rdap;virustotal;wayback", "5", "high") // three ranges, and one from each fake
	var promote []string
	for _, c := range x.h.envelope().Data.Candidates {
		promote = append(promote, c.Promote)
	}
	slices.Sort(promote)
	if want := []string{"--asn AS64501", "--org 'Globex Holdings Ltd'"}; !slices.Equal(promote, want) {
		t.Errorf("promote hints = %v, want %v", promote, want)
	}
	// An asn from the search alone is medium.
	if r := x.candidate("192.0.2.0/24"); r == nil || r["confidence"] != "medium" {
		t.Errorf("netblock from the search = %v", r)
	}
}

// Passing the ASN as --asn removes its candidate row.
func TestRDAP_ASNInputRemovesItsCandidateRow(t *testing.T) {
	t.Parallel()
	x := newRDAP(t)
	x.entities(hostARIN, false, rdapEntity{handle: "ACME-1", name: "Acme Widgets", asns: []int{64501}})
	x.mustScan("--org", "Acme Widgets")
	if r := x.candidate("AS64501"); r == nil || r["type"] != "asn" {
		t.Fatalf("candidates = %v", x.candidateTypes())
	}
	x.mustScan("--asn", "AS64501")
	if r := x.candidate("AS64501"); r != nil && r["current"] == "true" && r["type"] == "asn" {
		// The row of a record that is not a candidate any more is not listed.
		t.Errorf("AS64501 is still a candidate after it became an input: %v", r)
	}
}

// --- limits and repeats ---

// A 429 from a registry stops the stage; the checks run on the next run.
func TestRDAP_QuotaStopsTheStageAndTheChecksRunNextTime(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=203.0.113.7", "b=203.0.114.7")
	r1, _, r3 := globexNets()
	x.net(hostARIN, r1)
	x.net(hostARIN, r3)
	x.fake(hostARIN).status = http.StatusTooManyRequests
	// A spent allowance fails the checks and clears with time: the error is transient.
	if f := x.h.partial(x.scan(), true); !f.transient || !strings.Contains(f.msg, "rdap") {
		t.Errorf("error = %+v, want a transient failure naming rdap", f)
	}
	if got := len(x.h.completed(eng, "rdap")); got != 0 {
		t.Errorf("completed checks = %v, want none", x.h.completed(eng, "rdap"))
	}
	if n := len(x.lookupsAt(hostARIN)); n != 1 {
		t.Errorf("ARIN was asked %d times after a 429, want 1", n)
	}
	quota := x.h.messages("warning", "rdap")
	if len(quota) != 1 || !strings.Contains(quota[0], "retried next run") {
		t.Errorf("quota warnings = %q", quota)
	}
	x.fake(hostARIN).mu.Lock()
	x.fake(hostARIN).status = 0
	x.fake(hostARIN).mu.Unlock()
	x.mustScan("-e", eng)
	if r := x.ipRow("203.0.113.7"); r == nil || r["registrant"] != "Globex Holdings Ltd" {
		t.Errorf("row = %v, want the lookup made on the next run", r)
	}
}

// Each lookup is made once per engagement, again only with --redo rdap. After a
// redo two addresses of one range fetch the range once, and an organisation
// search is made again.
func TestRDAP_LookupsOnceAndRefreshedByRedo(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=203.0.113.7", "b=203.0.113.8")
	x.net(hostARIN, rdapNet{"203.0.113.0", "203.0.113.255", "NET-203", "Acme Holdings Pty Ltd"})
	x.mustScan()
	first := len(x.lookupsAt(hostARIN))
	if first != 1 {
		t.Fatalf("first run: %d lookups, want 1", first)
	}
	x.mustScan("-e", eng)
	if got := x.lookups(); got != first {
		t.Errorf("a second run made %d lookups in all, want %d", got, first)
	}
	x.mustScan("-e", eng, "--redo", "rdap")
	if got := len(x.lookupsAt(hostARIN)); got != first+1 {
		t.Errorf("--redo rdap: %d lookups in all, want %d (the range fetched again once)", got, first+1)
	}
	if r := x.ipRow("203.0.113.8"); r == nil || r["registrant"] != "Acme Holdings Pty Ltd" || r["current"] != "true" {
		t.Errorf("row after the redo = %v", r)
	}
}

// An address that turns up inside a range already looked up, on a later run, costs no request.
func TestRDAP_AddressInAKnownRangeOnALaterRunCostsNoRequest(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=203.0.113.7")
	x.net(hostARIN, rdapNet{"203.0.113.0", "203.0.113.255", "NET-203", "Acme Holdings Pty Ltd"})
	x.mustScan()
	x.hosts("b=203.0.113.8")
	x.mustScan("-e", eng, "--redo", "crtsh")
	if got := len(x.lookupsAt(hostARIN)); got != 1 {
		t.Errorf("ARIN lookups = %d, want 1", got)
	}
	if r := x.ipRow("203.0.113.8"); r == nil || r["registrant"] != "Acme Holdings Pty Ltd" {
		t.Errorf("row = %v, want the registration of the range", r)
	}
}

func TestRDAP_OrganisationSearchOnceAndRefreshedByRedo(t *testing.T) {
	t.Parallel()
	x := newRDAP(t)
	acmeEntities(x)
	x.mustScan("--org", "Acme Widgets Pty Ltd")
	x.mustScan("-e", eng)
	if n := x.searches(hostARIN); n != 1 {
		t.Errorf("ARIN searches = %d after two runs, want 1", n)
	}
	x.mustScan("-e", eng, "--redo", "rdap")
	if n := x.searches(hostARIN); n != 2 {
		t.Errorf("ARIN searches = %d after the redo, want 2", n)
	}
}

// The bootstrap file is fetched once per run, and a failure to fetch it fails the
// checks of that run only.
func TestRDAP_BootstrapOncePerRun(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=203.0.113.7", "b=198.51.100.7", "c=100.64.0.7")
	x.net(hostARIN, rdapNet{"203.0.113.0", "203.0.113.255", "N1", "Acme"})
	x.net(hostRIPE, rdapNet{"198.51.100.0", "198.51.100.255", "N2", "Acme"})
	x.net(hostAPNIC, rdapNet{"100.64.0.0", "100.64.0.255", "N3", "Acme"})
	x.mustScan()
	if n := x.bootstrapFetches(); n != 1 {
		t.Errorf("ipv4.json fetched %d times in a run, want 1", n)
	}
	x.mustScan("-e", eng, "--redo", "rdap")
	if n := x.bootstrapFetches(); n != 2 {
		t.Errorf("ipv4.json fetched %d times in two runs, want 2", n)
	}
}

func TestRDAP_BootstrapFailureRetriesNextRun(t *testing.T) {
	t.Parallel()
	x := newRDAP(t, "a=203.0.113.7")
	x.net(hostARIN, rdapNet{"203.0.113.0", "203.0.113.255", "N1", "Acme"})
	x.handle(hostIANA, status(503))
	x.scan()
	if got := x.h.completed(eng, "rdap"); len(got) != 0 {
		t.Errorf("completed = %v after a failed bootstrap", got)
	}
	if n := x.lookups(); n != 0 {
		t.Errorf("%d lookups without a bootstrap file", n)
	}
	x.bootstrap("203.0.0.0/8", hostARIN)
	x.mustScan("-e", eng)
	if r := x.ipRow("203.0.113.7"); r == nil || r["registrant"] != "Acme" {
		t.Errorf("row = %v", r)
	}
}

// The stage is available under --passive and contacts only IANA and the
// registries: it is in the registry after dnsroot and is a third-party stage.
func TestRDAP_RunsUnderPassiveAndIsRegistered(t *testing.T) {
	t.Parallel()
	var names []string
	var rd run.Stage
	for _, s := range defaultStageList() {
		names = append(names, s.Name())
		if s.Name() == "rdap" {
			rd = s
		}
	}
	if rd == nil || rd.Contact() != run.ThirdParty {
		t.Fatalf("rdap stage = %v", rd)
	}
	if i := slices.Index(names, "rdap"); i != slices.Index(names, "dnsroot")+1 {
		t.Errorf("rdap is at %d, want right after dnsroot (%d)", i, slices.Index(names, "dnsroot"))
	}
	want := []string{hostIANA, hostARIN, hostRIPE, hostAPNIC, hostLACNIC, hostAFRINIC}
	got := slices.Clone(rd.Sources())
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("sources = %v, want %v", got, want)
	}

	x := newRDAP(t, "a=203.0.113.7")
	x.net(hostARIN, rdapNet{"203.0.113.0", "203.0.113.255", "N1", "Acme"})
	x.mustScan()
	if st, _ := stateOf(x.world, "rdap"); st != "done" {
		t.Errorf("rdap = %s under --passive", st)
	}
}
