package cli_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress/egresstest"
)

// IP tests build a complete loopback world with counting source, DNS and target fakes.
// newIPWorld wires the harness; seed supplies facts; run/lookup helpers execute commands;
// ipEnvelope/ipRecord decode output. Assertions can reject all traffic or only traffic
// concerning selected addresses.
//
// Sources default to realistic empty/404 replies. Test pacing is raised to 1000/s unless a test
// explicitly overrides SourceRates, keeping unrelated tests fast.

// Hosts nyx ip asks, besides the RDAP hosts (hostIANA, hostARIN and the others of rdap_test.go).
const (
	ipHostInternetDB   = "internetdb.shodan.io"
	ipHostRIPEstat     = "stat.ripe.net"
	ipHostHackerTarget = "api.hackertarget.com"
)

// ipDefaultKeys are the keys of a record in the default mode, in order: address, hostnames and kind
// first, failures last.
var ipDefaultKeys = []string{
	"address", "hostnames", "kind",
	"asn", "as_name", "as_prefix", "rdap_netblock", "rdap_org", "rdap_registry", "ptr", "provider", "provider_class",
	"geo_country", "geo_city", "internetdb_ports", "internetdb_hostnames", "internetdb_tags", "internetdb_cpes",
	"internetdb_vulns", "reverse_ip", "reverse_ip_count", "abusive_networks", "abusive_asn", "drop_networks", "drop_asn",
	"failures",
}

// ipActiveKeys are the keys --active adds, in order, between the threat-data keys and failures.
var ipActiveKeys = []string{"not_contacted", "ports", "tls", "web"}

// ipSourceKeys are the keys a source's answer gives (everything between kind and failures), in order.
func ipSourceKeys(active bool) []string {
	keys := ipDefaultKeys[3 : len(ipDefaultKeys)-1]
	if active {
		keys = append(slices.Clone(keys), ipActiveKeys...)
	}
	return keys
}

// ipAllKeys are the keys of a record that --fields all gives, in order.
func ipAllKeys(active bool) []string {
	return slices.Concat(ipDefaultKeys[:3], ipSourceKeys(active), []string{"failures"})
}

// ipExpectKeys combines mandatory fields, table-ordered selections and trailing failures.
func ipExpectKeys(selected ...string) []string {
	all := ipAllKeys(true)
	out := slices.Clone(all[:3])
	for _, k := range all[3 : len(all)-1] {
		if slices.Contains(selected, k) {
			out = append(out, k)
		}
	}
	return append(out, "failures")
}

// The probe ports of --active: the built-in common ports, the TLS ports and the web ports.
var (
	ipProbePorts = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 853, 993, 995,
		1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9200, 9443, 11211, 27017}
	ipTLSPorts = []int{443, 465, 636, 853, 993, 995, 8443, 9443}
	ipWebPorts = []int{80, 443, 8000, 8080, 8443, 8888, 9443}
)

// ---- fake HTTP hosts ----

// ipSource logs and validates requests, choosing address-specific, global or fallback responses
// in that order.
type ipSource struct {
	t     *testing.T
	host  string
	valid func(*http.Request) bool
	key   func(*http.Request) string

	mu       sync.Mutex
	reqs     []string // each request's method and URI
	keys     []string // each request's key
	byKey    map[string]http.HandlerFunc
	all      http.HandlerFunc
	fallback http.HandlerFunc
}

func (s *ipSource) serve(rw http.ResponseWriter, r *http.Request) {
	if !s.valid(r) {
		s.t.Errorf("%s was sent a request nyx ip does not make: %s %s", s.host, r.Method, r.URL.RequestURI())
		http.NotFound(rw, r)
		return
	}
	k := s.key(r)
	s.mu.Lock()
	s.reqs = append(s.reqs, r.Method+" "+r.URL.RequestURI())
	s.keys = append(s.keys, k)
	h := s.all
	if h == nil {
		h = s.byKey[k]
	}
	if h == nil {
		h = s.fallback
	}
	s.mu.Unlock()
	h(rw, r)
}

// set answers the requests about key (an address) with h.
func (s *ipSource) set(key string, h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byKey[key] = h
}

// setAll answers every request with h, whatever it is about.
func (s *ipSource) setAll(h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.all = h
}

// requests are the requests received, each as "METHOD URI".
func (s *ipSource) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

// count is how many requests were received.
func (s *ipSource) count() int { return len(s.requests()) }

// countFor is how many requests were about the address (or other key).
func (s *ipSource) countFor(key string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, k := range s.keys {
		if k == key {
			n++
		}
	}
	return n
}

// Handlers for the failures a source may show.

func ipReply(status int, body string) http.HandlerFunc {
	return func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(status)
		_, _ = io.WriteString(rw, body)
	}
}

// ipStatus is a reply with a status and no useful body: 429, 500 and the like.
func ipStatus(status int) http.HandlerFunc { return ipReply(status, "no") }

// ipTruncated promises a long body and sends the start of one.
func ipTruncated() http.HandlerFunc {
	return func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Length", "4000")
		rw.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(rw, `{"ports":[`)
	}
}

// ipHang never answers: the request waits until nyx gives up.
func ipHang() http.HandlerFunc {
	return func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
}

// ---- the world ----

// ipWorld is the fakes of one test.
type ipWorld struct {
	t *testing.T
	h *harness

	// dns serves public Cymru/PTR/A/AAAA queries. local serves active single-label/fallback
	// names and non-public PTR lookups.
	dns, local *egresstest.DNS

	idb, geo, ht, iana *ipSource
	rdap               map[string]*ipSource // by registry host: hostARIN, hostRIPE, ...

	mu      sync.Mutex
	nets    map[string][]rdapNet // registered netblocks, by registry host
	routes  []ipRoute            // bootstrap entries, besides the defaults
	targets map[string]*ipTarget // probe targets, by "address:port"
}

// ipRoute sends a prefix of the IANA bootstrap to a registry.
type ipRoute struct {
	prefix netip.Prefix
	host   string
}

// newIPWorld wires unseeded fakes returning realistic no-data answers, so default records
// contain empty source fields.
func newIPWorld(t *testing.T) *ipWorld {
	t.Helper()
	h := newHarness(t)
	// Use empty fixed threat lists by default so future embedded refreshes cannot change
	// fixture outcomes.
	h.abusive = abSnapshot(nil, nil)
	w := &ipWorld{t: t, h: h, nets: map[string][]rdapNet{}, targets: map[string]*ipTarget{}, rdap: map[string]*ipSource{}}
	w.dns, w.local = egresstest.NewDNS(t), egresstest.NewDNS(t)
	h.eopts.ResolverAddrs = []string{w.dns.Addr}
	h.eopts.LocalResolverAddr = w.local.Addr
	h.eopts.SourceBaseURLs = map[string]string{}
	h.eopts.DialMap = map[string]string{}
	h.eopts.RateDNS, h.eopts.RatePerHost, h.eopts.RatePerSource = 1000, 1000, 1000
	h.eopts.SourceRates = map[string]float64{ipHostInternetDB: 1000, ipHostRIPEstat: 1000, ipHostHackerTarget: 1000}

	lastPath := func(prefix string) func(*http.Request) string {
		return func(r *http.Request) string { return strings.TrimPrefix(r.URL.Path, prefix) }
	}
	w.idb = w.newSource(ipHostInternetDB,
		func(r *http.Request) bool { return r.Method == http.MethodGet && ipAddrPath.MatchString(r.URL.Path) },
		lastPath("/"), ipReply(404, `{"detail":"No information available"}`))
	w.geo = w.newSource(ipHostRIPEstat,
		func(r *http.Request) bool {
			q := r.URL.Query()
			return r.Method == http.MethodGet && r.URL.Path == "/data/maxmind-geo-lite/data.json" && q.Get("sourceapp") == "nyx" && q.Get("resource") != ""
		},
		func(r *http.Request) string { return r.URL.Query().Get("resource") }, nil)
	w.geo.fallback = func(rw http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(rw, ipGeoBody(r.URL.Query().Get("resource"), nil))
	}
	w.ht = w.newSource(ipHostHackerTarget,
		func(r *http.Request) bool {
			return r.Method == http.MethodGet && r.URL.Path == "/reverseiplookup/" && r.URL.Query().Get("q") != ""
		},
		func(r *http.Request) string { return r.URL.Query().Get("q") }, ipReply(200, "No records found"))
	w.iana = w.newSource(hostIANA,
		func(r *http.Request) bool {
			return r.Method == http.MethodGet && (r.URL.Path == "/rdap/ipv4.json" || r.URL.Path == "/rdap/ipv6.json")
		},
		func(r *http.Request) string { return r.URL.Path }, w.bootstrap)
	for _, host := range rdapRegistries {
		base := rdapBase[host]
		w.rdap[host] = w.newSource(host,
			func(r *http.Request) bool {
				return r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, base+"ip/")
			},
			lastPath(base+"ip/"), w.registration(host))
	}
	return w
}

// ipAddrPath is the path of an InternetDB lookup: "/" and an address.
var ipAddrPath = regexp.MustCompile(`^/[0-9a-fA-F:.]+$`)

// newSource starts a fake host, maps its source pattern to it, and closes it with the test.
func (w *ipWorld) newSource(host string, valid func(*http.Request) bool, key func(*http.Request) string, fallback http.HandlerFunc) *ipSource {
	s := &ipSource{t: w.t, host: host, valid: valid, key: key, byKey: map[string]http.HandlerFunc{}, fallback: fallback}
	srv := httptest.NewServer(http.HandlerFunc(s.serve))
	w.t.Cleanup(srv.Close)
	w.h.eopts.SourceBaseURLs[host] = srv.URL
	return s
}

// bootstrap answers the IANA bootstrap files: every address goes to ARIN unless a route (see route)
// says otherwise.
func (w *ipWorld) bootstrap(rw http.ResponseWriter, r *http.Request) {
	v4 := r.URL.Path == "/rdap/ipv4.json"
	w.mu.Lock()
	routes := append([]ipRoute{
		{netip.MustParsePrefix("0.0.0.0/1"), hostARIN}, {netip.MustParsePrefix("128.0.0.0/1"), hostARIN},
		{netip.MustParsePrefix("2000::/3"), hostARIN},
	}, w.routes...)
	w.mu.Unlock()
	byHost := map[string][]string{}
	for _, rt := range routes {
		if rt.prefix.Addr().Is4() == v4 {
			byHost[rt.host] = append(byHost[rt.host], rt.prefix.String())
		}
	}
	var services []any
	for _, host := range rdapRegistries {
		if p := byHost[host]; len(p) > 0 {
			services = append(services, []any{p, []string{"https://" + host + rdapBase[host]}})
		}
	}
	rw.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(rw).Encode(map[string]any{"version": "1.0", "services": services})
}

// route makes the bootstrap send the prefix to a registry host (hostRIPE and so on) instead of ARIN.
func (w *ipWorld) route(prefix, host string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.routes = append(w.routes, ipRoute{netip.MustParsePrefix(prefix), host})
}

// registration is a registry's answer to an address lookup: the registered netblock that holds the
// address, or a 404.
func (w *ipWorld) registration(host string) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		addr := strings.TrimPrefix(r.URL.Path, rdapBase[host]+"ip/")
		w.mu.Lock()
		nets := slices.Clone(w.nets[host])
		w.mu.Unlock()
		for _, n := range nets {
			if inRange(addr, n.start, n.end) {
				rw.Header().Set("Content-Type", "application/rdap+json")
				_ = json.NewEncoder(rw).Encode(n.json())
				return
			}
		}
		http.NotFound(rw, r)
	}
}

// netblock registers a netblock at a registry host: its range, handle and registrant organisation.
func (w *ipWorld) netblock(host, start, end, handle, registrant string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.nets[host] = append(w.nets[host], rdapNet{start: start, end: end, handle: handle, registrant: registrant})
}

// refer makes a registry host answer the lookup of addr with a redirect to another registry's.
func (w *ipWorld) refer(from, to, addr string) {
	w.rdap[from].set(addr, func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Location", "https://"+to+rdapBase[to]+"ip/"+addr)
		rw.WriteHeader(http.StatusFound)
	})
}

// owner scripts Team Cymru's answers for an address: its origin AS, announced prefix and AS name.
func (w *ipWorld) owner(addr string, asn int, prefix, name string) {
	w.dns.TXT(dnsname.CymruOrigin(netip.MustParseAddr(addr)), fmt.Sprintf("%d | %s | US | arin | 2000-01-01", asn, prefix))
	w.dns.TXT(fmt.Sprintf("as%d.asn.cymru.com", asn), fmt.Sprintf("%d | US | arin | 2000-01-01 | %s, US", asn, name))
}

// ipLoc is one location of RIPEstat's geolocation answer.
type ipLoc struct {
	Country, City string
	Covered       float64
}

// ipGeoBody is RIPEstat's maxmind-geo-lite answer for an address.
func ipGeoBody(addr string, locs []ipLoc) string {
	var ls []any
	for _, l := range locs {
		ls = append(ls, map[string]any{"country": l.Country, "city": l.City, "resources": []string{"1.1.1.0/24"}, "covered_percentage": l.Covered})
	}
	if ls == nil {
		ls = []any{}
	}
	b, _ := json.Marshal(map[string]any{"status": "ok", "status_code": 200, "data": map[string]any{
		"located_resources": []any{map[string]any{"resource": addr, "locations": ls}}}})
	return string(b)
}

// locate scripts RIPEstat's geolocation of an address.
func (w *ipWorld) locate(addr string, locs ...ipLoc) {
	w.geo.set(addr, ipReply(200, ipGeoBody(addr, locs)))
}

// internetDB supplies realistic per-address JSON, normalising nil lists to empty lists.
func (w *ipWorld) internetDB(addr string, ports []int, hostnames, tags, cpes, vulns []string) {
	strs := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	if ports == nil {
		ports = []int{}
	}
	b, _ := json.Marshal(map[string]any{"cpes": strs(cpes), "hostnames": strs(hostnames), "ip": addr, "ports": ports,
		"tags": strs(tags), "vulns": strs(vulns)})
	w.idb.set(addr, ipReply(200, string(b)))
}

// reverse scripts HackerTarget's reverse-IP answer for an address: one name per line, as given.
func (w *ipWorld) reverse(addr string, lines ...string) {
	w.ht.set(addr, ipReply(200, strings.Join(lines, "\n")))
}

// ptr scripts the public resolvers' PTR answer for an address.
func (w *ipWorld) ptr(addr string, names ...string) {
	for _, n := range names {
		w.dns.PTR(addr, n)
	}
}

// ---- probe targets ----

// ipTarget counts accepted connections and received bytes for one DialMap destination.
type ipTarget struct {
	Addr  string
	Port  int
	conns atomic.Int32
	recv  atomic.Int64
	close func()
}

// connections is how many connections the target accepted.
func (t *ipTarget) connections() int { return int(t.conns.Load()) }

// received is how many bytes nyx sent on its connections.
func (t *ipTarget) received() int { return int(t.recv.Load()) }

func ipKey(addr string, port int) string { return net.JoinHostPort(addr, strconv.Itoa(port)) }

// target maps addr:port to t. A second target for the same pair replaces the first.
func (w *ipWorld) target(addr string, port int, t *ipTarget) {
	t.Addr, t.Port = addr, port
	w.mu.Lock()
	defer w.mu.Unlock()
	w.targets[ipKey(addr, port)] = t
}

// listen installs a TCP target that sends an optional greeting, then counts received data.
func (w *ipWorld) listen(addr string, port int, banner string) *ipTarget {
	w.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		w.t.Fatal(err)
	}
	t := &ipTarget{close: func() { ln.Close() }}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.conns.Add(1)
			go func() {
				defer c.Close()
				if banner != "" {
					_, _ = io.WriteString(c, banner)
				}
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				n, _ := io.Copy(io.Discard, countWriter{&t.recv, c})
				_ = n
			}()
		}
	}()
	w.t.Cleanup(t.close)
	w.mapDial(addr, port, ln.Addr().String())
	w.target(addr, port, t)
	return t
}

// countWriter counts the bytes read from the connection it wraps.
type countWriter struct {
	n *atomic.Int64
	r io.Reader
}

func (c countWriter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (w *ipWorld) mapDial(addr string, port int, to string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.h.eopts.DialMap[ipKey(addr, port)] = to
}

// serveHTTP maps addr:port to an HTTP server running h, and counts its connections.
func (w *ipWorld) serveHTTP(addr string, port int, h http.Handler) *ipTarget {
	return w.serveHTTPS(addr, port, h, false)
}

// serveTLS maps addr:port to an HTTPS server (a self-signed certificate for 127.0.0.1 and
// example.com) running h, and counts its connections.
func (w *ipWorld) serveTLS(addr string, port int, h http.Handler) *ipTarget {
	return w.serveHTTPS(addr, port, h, true)
}

func (w *ipWorld) serveHTTPS(addr string, port int, h http.Handler, useTLS bool) *ipTarget {
	w.t.Helper()
	t := &ipTarget{}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			t.conns.Add(1)
		}
	}
	if useTLS {
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.close = srv.Close
	w.t.Cleanup(srv.Close)
	w.mapDial(addr, port, srv.Listener.Addr().String())
	w.target(addr, port, t)
	return t
}

// closedPort uses loopback port 1 to avoid freed-port reuse races with parallel tests.
func (w *ipWorld) closedPort(addr string, port int) {
	w.t.Helper()
	w.mapDial(addr, port, "127.0.0.1:1")
}

// sealProbes maps every unconfigured probe port to a counting listener. This both contains
// traffic and proves default-mode silence.
func (w *ipWorld) sealProbes(addrs []string, extra ...int) {
	w.t.Helper()
	for _, a := range addrs {
		for _, p := range slices.Concat(ipProbePorts, extra) {
			w.mu.Lock()
			_, have := w.targets[ipKey(a, p)]
			w.mu.Unlock()
			if !have {
				w.listen(a, p, "")
			}
		}
	}
}

// contacted are the "address:port" of every target that accepted a connection, sorted.
func (w *ipWorld) contacted() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for k, t := range w.targets {
		if t.connections() > 0 {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// target returns the target mapped for addr:port, or fails.
func (w *ipWorld) targetAt(addr string, port int) *ipTarget {
	w.t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	t := w.targets[ipKey(addr, port)]
	if t == nil {
		w.t.Fatalf("no target is mapped at %s", ipKey(addr, port))
	}
	return t
}

// ---- seeding ----

// ipFacts describes source answers and expected data. Unset facts become realistic
// empty/404/NXDOMAIN responses.
type ipFacts struct {
	Addr                         string
	ASN                          int
	ASName, ASPrefix             string
	Netblock, Org, Registry      string // as rdap_netblock, rdap_org and rdap_registry
	PTR                          []string
	Provider, Class              string // what the provider data says of the ASN; "" for none
	Country, City                string
	Ports                        []int
	Hostnames, Tags, CPEs, Vulns []string
	Reverse                      []string // reverse_ip as nyx returns it: cleaned, sorted, at most 100
	ReverseCount                 int
	NotAskedReverse              bool // HackerTarget is not asked (shared provider address, IPv6): both keys are null
}

// seed supplies a complete dedicated address across all sources, including ownership, ARIN
// allocation, PTR, location, services and reverse names. mods adjusts facts before serving;
// returned facts drive record assertions.
func (w *ipWorld) seed(addr string, mods ...func(*ipFacts)) ipFacts {
	w.t.Helper()
	a := netip.MustParseAddr(addr)
	bits := 24
	if a.Is6() {
		bits = 64
	}
	pfx := netip.PrefixFrom(a, bits).Masked()
	dashed := strings.NewReplacer(".", "-", ":", "-").Replace(addr)
	f := ipFacts{
		Addr: addr, ASN: 64500, ASName: "EXAMPLE-NET", ASPrefix: pfx.String(),
		Netblock: pfx.String(), Org: "Example Org Pty Ltd", Registry: "arin",
		PTR:     []string{"host-" + dashed + ".example.net"},
		Country: "AU", City: "Sydney",
		Ports: []int{22, 80, 443}, Hostnames: []string{"idb-" + dashed + ".example.net"}, Tags: []string{"self-signed"},
		CPEs: []string{"cpe:/a:apache:http_server:2.4.41"}, Vulns: []string{"CVE-2021-41773"},
		Reverse: []string{"a." + dashed + ".example.org", "b." + dashed + ".example.org"}, ReverseCount: 2,
	}
	for _, m := range mods {
		m(&f)
	}
	if f.ASN != 0 {
		w.owner(addr, f.ASN, f.ASPrefix, f.ASName)
	}
	if f.Netblock != "" {
		start, end := ipRange(f.Netblock)
		w.netblock(hostARIN, start, end, "NET-"+dashed, f.Org)
	}
	w.ptr(addr, f.PTR...)
	if f.Country != "" {
		w.locate(addr, ipLoc{f.Country, f.City, 100})
	}
	if f.Ports != nil || f.Hostnames != nil || f.Tags != nil || f.CPEs != nil || f.Vulns != nil {
		w.internetDB(addr, f.Ports, f.Hostnames, f.Tags, f.CPEs, f.Vulns)
	}
	if len(f.Reverse) > 0 {
		lines := slices.Clone(f.Reverse)
		slices.Reverse(lines) // served in the opposite order: nyx sorts them
		w.reverse(addr, lines...)
	}
	return f
}

// ipRange extracts CIDR endpoints or parses a start-end range.
func ipRange(s string) (start, end string) {
	if a, b, ok := strings.Cut(s, "-"); ok {
		return a, b
	}
	p := netip.MustParsePrefix(s)
	last := p.Addr().AsSlice()
	for i := p.Bits(); i < len(last)*8; i++ {
		last[i/8] |= 1 << (7 - i%8)
	}
	l, _ := netip.AddrFromSlice(last)
	return p.Addr().String(), l.String()
}

// ipOwnedBy is a seed modifier: the address is announced by the AS.
func ipOwnedBy(asn int, name string) func(*ipFacts) {
	return func(f *ipFacts) { f.ASN, f.ASName = asn, name }
}

// ipProviderOf replaces ownership with a known provider/class, allowing shared-hosting and
// reverse-IP selection tests.
func ipProviderOf(provider, class string, notAsked bool) func(*ipFacts) {
	return func(f *ipFacts) { f.Provider, f.Class, f.NotAskedReverse = provider, class, notAsked }
}

// Seed modifiers for the three providers the tests use.
var (
	ipCloudflare = []func(*ipFacts){ipOwnedBy(13335, "CLOUDFLARENET"), ipProviderOf("cloudflare", "cdn", true)}
	ipAWS        = []func(*ipFacts){ipOwnedBy(16509, "AMAZON-02"), ipProviderOf("aws", "hyperscaler", false)}
	ipDigitalOcn = []func(*ipFacts){ipOwnedBy(14061, "DIGITALOCEAN-ASN"), ipProviderOf("digitalocean", "hyperscaler", false)}
)

// check asserts that the record holds every fact. Keys in skip are not compared.
func (f ipFacts) check(t *testing.T, r ipRecord, skip ...string) {
	t.Helper()
	nilIfEmpty := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	want := map[string]any{
		"address": f.Addr, "kind": "public",
		"asn": nil, "as_name": nilIfEmpty(f.ASName), "as_prefix": nilIfEmpty(f.ASPrefix),
		"rdap_netblock": nilIfEmpty(f.Netblock), "rdap_org": nilIfEmpty(f.Org), "rdap_registry": nilIfEmpty(f.Registry),
		"ptr": ipAnyList(f.PTR), "provider": nilIfEmpty(f.Provider), "provider_class": nilIfEmpty(f.Class),
		"geo_country": nilIfEmpty(f.Country), "geo_city": nilIfEmpty(f.City),
		"internetdb_ports": ipAnyList(f.Ports), "internetdb_hostnames": ipAnyList(f.Hostnames), "internetdb_tags": ipAnyList(f.Tags),
		"internetdb_cpes": ipAnyList(f.CPEs), "internetdb_vulns": ipAnyList(f.Vulns),
		"reverse_ip": ipAnyList(f.Reverse), "reverse_ip_count": float64(f.ReverseCount),
	}
	if f.ASN != 0 {
		want["asn"] = float64(f.ASN)
	}
	if f.NotAskedReverse {
		want["reverse_ip"], want["reverse_ip_count"] = nil, nil
	}
	for k, w := range want {
		if slices.Contains(skip, k) {
			continue
		}
		if k == "reverse_ip_count" && len(f.Reverse) == 0 && !f.NotAskedReverse && (r.m[k] == nil || r.m[k] == float64(0)) {
			continue // an answer with no names has a count of 0 or none
		}
		if got := r.m[k]; fmt.Sprint(got) != fmt.Sprint(w) || (got == nil) != (w == nil) {
			t.Errorf("%s: %s = %v, want %v", f.Addr, k, got, w)
		}
	}
}

// ipAnyList requires JSON-style non-nil []any values.
func ipAnyList[T any](s []T) []any {
	out := []any{}
	for _, v := range s {
		switch x := any(v).(type) {
		case int:
			out = append(out, float64(x))
		default:
			out = append(out, v)
		}
	}
	return out
}

// ---- running ----

// run runs nyx ip with the arguments, in the human layout, and returns the exit code.
func (w *ipWorld) run(args ...string) int {
	w.t.Helper()
	return w.h.execRoot(append([]string{"ip"}, args...)...)
}

// runJSON is run with --json added.
func (w *ipWorld) runJSON(args ...string) int {
	w.t.Helper()
	return w.h.execRoot(append([]string{"ip"}, append(slices.Clone(args), "--json")...)...)
}

// lookup runs nyx ip with --json, requires exit 0, and returns the envelope.
func (w *ipWorld) lookup(args ...string) ipEnvelope {
	w.t.Helper()
	if code := w.runJSON(args...); code != 0 {
		w.t.Fatalf("nyx ip %v: exit %d\nstdout %q\nstderr %q", args, code, w.h.stdout.String(), w.h.stderr.String())
	}
	return w.h.ipEnvelope()
}

// record is lookup for a call that gives exactly one record.
func (w *ipWorld) record(args ...string) ipRecord {
	w.t.Helper()
	env := w.lookup(args...)
	if len(env.Records) != 1 {
		w.t.Fatalf("nyx ip %v: %d records, want 1: %s", args, len(env.Records), w.h.stdout.String())
	}
	return env.Records[0]
}

// partial runs nyx ip with --json, requires exit 7 with a PARTIAL error, and returns the envelope
// and the error.
func (w *ipWorld) partial(args ...string) (ipEnvelope, failure) {
	w.t.Helper()
	code := w.runJSON(args...)
	if code != 7 {
		w.t.Fatalf("nyx ip %v: exit %d, want 7\nstdout %q\nstderr %q", args, code, w.h.stdout.String(), w.h.stderr.String())
	}
	f := w.h.theError(true)
	if f.code != "PARTIAL" {
		w.t.Errorf("nyx ip %v: code %s, want PARTIAL: %+v", args, f.code, f)
	}
	return w.h.ipEnvelope(), f
}

// ---- what was asked ----

// httpSources are every fake HTTP host.
func (w *ipWorld) httpSources() []*ipSource {
	out := []*ipSource{w.idb, w.geo, w.ht, w.iana}
	for _, host := range rdapRegistries {
		out = append(out, w.rdap[host])
	}
	return out
}

// httpRequests is how many requests the fake HTTP hosts received, in all.
func (w *ipWorld) httpRequests() int {
	n := 0
	for _, s := range w.httpSources() {
		n += s.count()
	}
	return n
}

// rdapRequests is how many requests the IANA bootstrap and the five registries received, in all.
func (w *ipWorld) rdapRequests() int {
	n := w.iana.count()
	for _, host := range rdapRegistries {
		n += w.rdap[host].count()
	}
	return n
}

// dnsTypes are the query types dnsNames asks the fake about.
var dnsTypes = []string{"A", "AAAA", "PTR", "TXT", "MX", "NS", "SOA", "CAA", "SRV", "CNAME"}

// dnsNames are the names a fake DNS server was asked about, of any type, sorted and without repeats.
func dnsNames(d *egresstest.DNS) []string {
	var out []string
	for _, ty := range dnsTypes {
		out = append(out, d.Queried(ty)...)
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// reverseLabel supplies the reversed address prefix shared by PTR/Cymru query names.
func reverseLabel(addr string) string {
	rev, err := mdns.ReverseAddr(addr)
	if err != nil {
		panic(err)
	}
	rev = strings.TrimSuffix(rev, ".")
	rev = strings.TrimSuffix(rev, ".in-addr.arpa")
	return strings.TrimSuffix(rev, ".ip6.arpa")
}

// untouched rejects any source, DNS, target or canary traffic.
func (w *ipWorld) untouched() {
	w.t.Helper()
	if n := w.httpRequests(); n != 0 {
		w.t.Errorf("%d HTTP requests were made", n)
	}
	if n := w.dns.Total(); n != 0 {
		w.t.Errorf("the public resolvers were asked %d times: %v", n, dnsNames(w.dns))
	}
	if n := w.local.Total(); n != 0 {
		w.t.Errorf("this machine's resolver was asked %d times: %v", n, dnsNames(w.local))
	}
	if c := w.contacted(); len(c) != 0 {
		w.t.Errorf("connections were made to %v", c)
	}
	if w.h.network() != 0 {
		w.t.Error("a network canary was hit")
	}
}

// neverSent rejects source/public-DNS/target traffic concerning selected addresses.
// Local-resolver assertions use sawOnly separately.
func (w *ipWorld) neverSent(addrs ...string) {
	w.t.Helper()
	for _, a := range addrs {
		for _, s := range w.httpSources() {
			for _, r := range s.requests() {
				if strings.Contains(strings.ToLower(r), strings.ToLower(a)) {
					w.t.Errorf("%s was asked about %s: %s", s.host, a, r)
				}
			}
		}
		rev := reverseLabel(a) + "."
		for _, n := range dnsNames(w.dns) {
			if strings.HasPrefix(n, rev) {
				w.t.Errorf("the public resolvers were asked for %s", n)
			}
		}
		for _, c := range w.contacted() {
			if strings.HasPrefix(c, a+":") || strings.HasPrefix(c, "["+a+"]:") {
				w.t.Errorf("a connection was made to %s", c)
			}
		}
	}
}

// sawOnly fails the test unless the names a DNS server was asked about, of the type, are exactly
// the wanted ones.
func sawOnly(t *testing.T, d *egresstest.DNS, qtype string, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := d.Queried(qtype); !slices.Equal(got, want) {
		t.Errorf("%s queries = %v, want %v", qtype, got, want)
	}
}

// ---- results ----

// ipRecord is one record of the result, decoded.
type ipRecord struct {
	t    *testing.T
	raw  json.RawMessage
	keys []string       // in the order they were written
	m    map[string]any // every key's value as JSON decodes it: numbers are float64
}

func (r ipRecord) address() string { s, _ := r.m["address"].(string); return s }

// isNull reports whether the key is present with the value null.
func (r ipRecord) isNull(key string) bool {
	v, ok := r.m[key]
	return ok && v == nil
}

// emptyValue reports whether the key is present and empty: null or an empty list.
func (r ipRecord) emptyValue(key string) bool {
	v, ok := r.m[key]
	if !ok {
		return false
	}
	l, isList := v.([]any)
	return v == nil || isList && len(l) == 0
}

// str is the string at the key, or "" when it is null, absent or not a string.
func (r ipRecord) str(key string) string { s, _ := r.m[key].(string); return s }

// strs is the list of strings at the key; a null, absent or other value is nil.
func (r ipRecord) strs(key string) []string {
	var out []string
	l, _ := r.m[key].([]any)
	for _, v := range l {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// list is the list at the key, nil when it is not one.
func (r ipRecord) list(key string) []any { l, _ := r.m[key].([]any); return l }

// ipFailure is one entry of a record's failures.
type ipFailure struct {
	Source    string `json:"source"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Transient bool   `json:"transient"`
	Quota     bool   `json:"quota"`
}

// failures are the entries of the record's failures, which must be a list whose entries have the
// five keys, in order.
func (r ipRecord) failures() []ipFailure {
	r.t.Helper()
	var wrap struct {
		F []json.RawMessage `json:"failures"`
	}
	if err := json.Unmarshal(r.raw, &wrap); err != nil || wrap.F == nil {
		r.t.Fatalf("failures is not a list in %s (%v)", r.raw, err)
	}
	out := []ipFailure{}
	for _, raw := range wrap.F {
		if keys := keysOf(r.t, raw); !slices.Equal(keys, []string{"source", "code", "message", "transient", "quota"}) {
			r.t.Errorf("failure keys = %v", keys)
		}
		var f ipFailure
		if err := json.Unmarshal(raw, &f); err != nil {
			r.t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

// failureOf is the one failure of the source, failing the test unless there is exactly one.
func (r ipRecord) failureOf(source string) ipFailure {
	r.t.Helper()
	var got []ipFailure
	for _, f := range r.failures() {
		if f.Source == source {
			got = append(got, f)
		}
	}
	if len(got) != 1 {
		r.t.Fatalf("%s: %d failures of %s, want 1: %s", r.address(), len(got), source, r.raw)
	}
	return got[0]
}

// ipMetaError is one entry of meta.errors: the five keys of an error.
type ipMetaError struct {
	Error     string         `json:"error"`
	Code      string         `json:"code"`
	Hint      *string        `json:"hint"`
	Input     map[string]any `json:"input"`
	Transient bool           `json:"transient"`
}

// inputs extracts original arguments from error metadata.
func (e ipMetaError) inputs() []string {
	var out []string
	l, _ := e.Input["input"].([]any)
	for _, v := range l {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// address is the entry's input "address": the address that failed, "" for an input that failed.
func (e ipMetaError) address() string { s, _ := e.Input["address"].(string); return s }

// ipEnvelope is the result of nyx ip --json.
type ipEnvelope struct {
	Records []ipRecord
	Meta    struct {
		Count    int           `json:"count"`
		Errors   []ipMetaError `json:"errors"`
		Warnings []string      `json:"warnings"`
		Hint     *string       `json:"hint"`
	}
}

// addresses are the address of each record, in order.
func (e ipEnvelope) addresses() []string {
	var out []string
	for _, r := range e.Records {
		out = append(out, r.address())
	}
	return out
}

// ipEnvelope verifies compact ordered JSON, object records, list-valued errors/warnings and
// matching count.
func (h *harness) ipEnvelope() ipEnvelope {
	h.t.Helper()
	out := h.stdout.String()
	if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
		h.t.Fatalf("stdout is not one line: %q", out)
	}
	line := strings.TrimSuffix(out, "\n")
	var top struct {
		Data []json.RawMessage `json:"data"`
		Meta json.RawMessage   `json:"meta"`
	}
	if err := json.Unmarshal([]byte(line), &top); err != nil || top.Data == nil {
		h.t.Fatalf("stdout is not the envelope: %v\n%s", err, line)
	}
	if got := keysOf(h.t, json.RawMessage(line)); !slices.Equal(got, []string{"data", "meta"}) {
		h.t.Fatalf("envelope keys = %v", got)
	}
	if got := keysOf(h.t, top.Meta); !slices.Equal(got, []string{"count", "errors", "warnings", "hint"}) {
		h.t.Fatalf("meta keys = %v", got)
	}
	var env ipEnvelope
	dec := json.NewDecoder(bytes.NewReader(top.Meta))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env.Meta); err != nil {
		h.t.Fatalf("meta: %v\n%s", err, line)
	}
	if env.Meta.Errors == nil || env.Meta.Warnings == nil || env.Meta.Count != len(top.Data) {
		h.t.Errorf("meta.errors or meta.warnings is null, or count is not the number of records: %s", line)
	}
	for _, raw := range top.Data {
		rec := ipRecord{t: h.t, raw: raw, keys: keysOf(h.t, raw)}
		if err := json.Unmarshal(raw, &rec.m); err != nil {
			h.t.Fatalf("record is not an object: %s", raw)
		}
		env.Records = append(env.Records, rec)
	}
	for _, e := range env.Meta.Errors {
		if e.Code == "" || e.Error == "" {
			h.t.Errorf("meta.errors entry is not an error: %+v", e)
		}
	}
	return env
}
