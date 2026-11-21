package egress_test

import (
	"cmp"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/egress/egresstest"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/scope"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func mustExcl(t *testing.T, entries ...string) []input.Exclusion {
	t.Helper()
	out, err := input.ParseExclusions(entries)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func portOf(t *testing.T, hostport string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return n
}

// --- DNS ---

// resolver is the DNS client of an Egress that sends every query to server.
func resolver(server string, timeout time.Duration) egress.Resolver {
	return egress.New(egress.Options{ResolverAddrs: []string{server}, DNSTimeout: timeout, RateDNS: 1000}).Clients(false, nil).DNS
}

func TestResolverResults(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	d.Rcode("nx.example.com", mdns.RcodeNameError)
	d.Rcode("nodata.example.com", mdns.RcodeSuccess) // NOERROR, no answers
	d.Rcode("fail.example.com", mdns.RcodeServerFailure)
	d.CNAME("alias.example.com", "real.example.com")
	d.A("real.example.com", "192.0.2.1")
	dnsc := resolver(d.Addr, 300*time.Millisecond)

	res, err := dnsc.Query(context.Background(), "nx.example.com", mdns.TypeA)
	if err != nil || res.RCode != egress.RCodeNXDomain {
		t.Errorf("NXDOMAIN: %+v %v", res, err)
	}
	res, err = dnsc.Query(context.Background(), "nodata.example.com", mdns.TypeA)
	if err != nil || res.RCode != egress.RCodeSuccess || len(res.Answers) != 0 {
		t.Errorf("NODATA: %+v %v", res, err)
	}
	res, err = dnsc.Query(context.Background(), "fail.example.com", mdns.TypeA)
	if err != nil || res.RCode != egress.RCodeServFail {
		t.Errorf("SERVFAIL: %+v %v", res, err)
	}
	res, err = dnsc.Query(context.Background(), "alias.example.com", mdns.TypeA)
	if err != nil || len(res.CNAMEs) != 1 || res.CNAMEs[0] != (egress.CNAME{Name: "alias.example.com", Target: "real.example.com"}) || len(res.Answers) != 1 || res.Answers[0].Value != "192.0.2.1" {
		t.Errorf("CNAME: %+v %v", res, err)
	}
}

func TestResolverTimeoutIsError(t *testing.T) {
	t.Parallel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, err = resolver(pc.LocalAddr().String(), 100*time.Millisecond).Query(context.Background(), "x.example.com", mdns.TypeA)
	if err == nil {
		t.Fatal("timeout must be an error, not a result")
	}
}

func TestResolverHasNoZoneTransfer(t *testing.T) {
	t.Parallel()
	tt := reflect.TypeFor[egress.Resolver]()
	if tt.NumMethod() != 1 || tt.Method(0).Name != "Query" {
		t.Errorf("Resolver has methods beyond Query")
	}
	// A transfer query type must be refused rather than sent.
	d := egresstest.NewDNS(t)
	dnsc := resolver(d.Addr, 200*time.Millisecond)
	if _, err := dnsc.Query(context.Background(), "example.com", mdns.TypeAXFR); err == nil {
		t.Error("AXFR must be refused")
	}
	if _, err := dnsc.Query(context.Background(), "example.com", mdns.TypeIXFR); err == nil {
		t.Error("IXFR must be refused")
	}
	if n := d.Total(); n != 0 {
		t.Errorf("a refused transfer query reached the server (%d queries)", n)
	}
	for _, qt := range []uint16{egress.TypeNS, egress.TypeSOA, egress.TypeCAA} {
		if _, err := dnsc.Query(context.Background(), "example.com", qt); err != nil {
			t.Errorf("query type %d: %v", qt, err)
		}
	}
}

// --- TCP ---

func tcpPolicy(ports ...int) *egress.Policy {
	return &egress.Policy{
		Scope: scope.New(scope.Config{Netblocks: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("192.0.2.0/24")}}),
		Ack:   true,
		Ports: ports,
	}
}

func TestTCPOutcomes(t *testing.T) {
	t.Parallel()
	openPort := serveTCP(t, sshBanner)
	closedPort := portOf(t, closedAddr(t))

	const connectTimeout = 300 * time.Millisecond
	eg := egress.New(egress.Options{ConnectTimeout: connectTimeout, BannerWait: 500 * time.Millisecond, RatePerHost: 1000,
		DialMap: map[string]string{
			"192.0.2.1:" + strconv.Itoa(closedPort): "10.255.255.1:81",
			"192.0.2.2:" + strconv.Itoa(closedPort): "127.0.0.1:99999",
		}})
	eg.SetPolicy(tcpPolicy(openPort, closedPort))
	tcp := eg.Clients(true, nil).TCP

	res, err := tcp.Connect(context.Background(), addr("127.0.0.1"), openPort)
	if o, ok := res.(egress.Open); err != nil || !ok || !strings.HasPrefix(string(o.Banner), "SSH-2.0") {
		t.Errorf("open: %#v %v", res, err)
	}
	res, err = tcp.Connect(context.Background(), addr("127.0.0.1"), closedPort)
	if _, ok := res.(egress.Closed); err != nil || !ok {
		t.Errorf("closed: %#v %v", res, err)
	}
	// Anything that is neither a refusal nor a connection is Filtered. An
	// unusable mapped address makes the dial fail without being refused.
	res, err = tcp.Connect(context.Background(), addr("192.0.2.2"), closedPort)
	if _, ok := res.(egress.Filtered); err != nil || !ok {
		t.Errorf("filtered (dial failure): %#v %v", res, err)
	}
	// A genuinely blackholed address times out as Filtered. Where the network
	// answers before the connect timeout instead, there is no timeout to check.
	start := time.Now()
	res, err = tcp.Connect(context.Background(), addr("192.0.2.1"), closedPort)
	_, filtered := res.(egress.Filtered)
	switch el := time.Since(start); {
	case el < connectTimeout:
		t.Logf("10.255.255.1 is not blackholed here (%#v %v after %v)", res, err, el)
	case err != nil || !filtered:
		t.Errorf("filtered (timeout): %#v %v", res, err)
	case el > 3*time.Second:
		t.Error("filtered took too long")
	}
}

// Port list, scope, passive and ack are enforced.
func TestTCPPolicyRefusals(t *testing.T) {
	t.Parallel()
	p := tcpPolicy(8080)
	eg := egress.New(egress.Options{ConnectTimeout: 100 * time.Millisecond, RatePerHost: 1000})
	eg.SetPolicy(p)
	tcp := eg.Clients(true, nil).TCP
	check := func(name string, res egress.TCPResult, err error) {
		t.Helper()
		if _, ok := res.(egress.Refused); err != nil || !ok {
			t.Errorf("%s: want Refused, got %#v %v", name, res, err)
		}
	}
	res, err := tcp.Connect(context.Background(), addr("127.0.0.1"), 9999)
	check("port not in list", res, err)
	res, err = tcp.Connect(context.Background(), addr("8.8.8.8"), 8080)
	check("address out of scope", res, err)

	p2 := tcpPolicy(8080)
	p2.Passive = true
	eg.SetPolicy(p2)
	res, err = tcp.Connect(context.Background(), addr("127.0.0.1"), 8080)
	check("passive", res, err)

	p3 := tcpPolicy(8080)
	p3.Ack = false
	eg.SetPolicy(p3)
	res, err = tcp.Connect(context.Background(), addr("127.0.0.1"), 8080)
	check("no ack", res, err)
}

// Addresses of excluded hosts and excluded CIDRs are refused; the guard reports it.
func TestTCPExclusions(t *testing.T) {
	t.Parallel()
	var reported []string
	p := &egress.Policy{
		Scope: scope.New(scope.Config{
			Roots:       []string{"example.com"},
			Netblocks:   []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
			Exclusions:  mustExcl(t, "admin.example.com", "127.0.0.9/32"),
			Resolutions: map[string][]netip.Addr{"admin.example.com": {addr("127.0.0.5")}, "www.example.com": {addr("127.0.0.5"), addr("127.0.0.6")}},
		}),
		Ack:         true,
		Ports:       []int{8080},
		Resolutions: map[string][]netip.Addr{"admin.example.com": {addr("127.0.0.5")}, "www.example.com": {addr("127.0.0.5"), addr("127.0.0.6")}},
		Excluded:    func(v, why string) { reported = append(reported, v+"|"+why) },
	}
	eg := egress.New(egress.Options{ConnectTimeout: 100 * time.Millisecond, RatePerHost: 1000})
	eg.SetPolicy(p)
	tcp := eg.Clients(true, nil).TCP
	for _, a := range []string{"127.0.0.5", "127.0.0.9"} {
		res, err := tcp.Connect(context.Background(), addr(a), 8080)
		if _, ok := res.(egress.Refused); err != nil || !ok {
			t.Errorf("%s: want refused, got %#v %v", a, res, err)
		}
	}
	if len(reported) != 2 {
		t.Errorf("guard should report both exclusions: %v", reported)
	}
	res, _ := tcp.Connect(context.Background(), addr("127.0.0.6"), 8080)
	if _, ok := res.(egress.Refused); ok {
		t.Errorf("non-excluded address must be allowed through policy: %#v", res)
	}
}

// --- HTTP ---

type httpFixture struct {
	srv  *httptest.Server
	port int
	hits atomic.Int32
	eg   *egress.Egress
	pol  *egress.Policy
}

// newHTTPFixture serves h on loopback, where www, a and b.example.com resolve.
// Zero RatePerHost, HTTPTimeout and ConnectTimeout in opts get test defaults.
func newHTTPFixture(t *testing.T, opts egress.Options, h http.HandlerFunc) *httpFixture {
	t.Helper()
	f := &httpFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	f.port = portOf(t, strings.TrimPrefix(f.srv.URL, "http://"))
	res := map[string][]netip.Addr{
		"www.example.com": {addr("127.0.0.1")},
		"a.example.com":   {addr("127.0.0.1")},
		"b.example.com":   {addr("127.0.0.1")},
	}
	f.pol = &egress.Policy{
		Scope:          scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: res}),
		Ack:            true,
		Ports:          []int{f.port},
		SensitivePaths: []string{"/.git/HEAD", "/server-status"},
		Resolutions:    res,
	}
	opts.RatePerHost = cmp.Or(opts.RatePerHost, 1000)
	opts.HTTPTimeout = cmp.Or(opts.HTTPTimeout, 2*time.Second)
	opts.ConnectTimeout = cmp.Or(opts.ConnectTimeout, time.Second)
	f.eg = egress.New(opts)
	f.eg.SetPolicy(f.pol)
	return f
}

func (f *httpFixture) client() egress.TargetHTTP { return f.eg.Clients(true, nil).HTTP }

func TestHTTPRootAndHeaders(t *testing.T) {
	t.Parallel()
	var gotUA, gotAuth, gotCookie, gotMethod, gotHost string
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotAuth, gotCookie, gotMethod, gotHost = r.UserAgent(), r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Method, r.Host
		http.SetCookie(w, &http.Cookie{Name: "s", Value: "1"})
		w.Header().Set("X-Test", "yes")
		_, _ = w.Write([]byte("hello"))
	})
	res, err := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	r, ok := res.(egress.Response)
	if err != nil || !ok || r.Status != 200 || string(r.Body) != "hello" || r.Header["X-Test"][0] != "yes" {
		t.Fatalf("%#v %v", res, err)
	}
	if gotUA == "" || strings.HasPrefix(gotUA, "Go-http-client") || gotAuth != "" || gotCookie != "" || gotMethod != "GET" || !strings.HasPrefix(gotHost, "www.example.com") {
		t.Errorf("request shape: ua=%q auth=%q cookie=%q method=%q host=%q", gotUA, gotAuth, gotCookie, gotMethod, gotHost)
	}
	// No cookie jar: a second request carries no cookie.
	_, _ = f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	if gotCookie != "" {
		t.Error("cookies must not be replayed")
	}
	res, _ = f.client().Head(context.Background(), egress.Root("www.example.com", "http", f.port))
	if r, ok := res.(egress.Response); !ok || gotMethod != "HEAD" || len(r.Body) != 0 {
		t.Errorf("head: %#v method=%s", res, gotMethod)
	}
}

// RootAt dials only the given address, and only if the name may be reached there.
func TestHTTPRootAtPinsTheAddress(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	if res, err := f.client().Get(context.Background(), egress.RootAt("www.example.com", "http", f.port, addr("127.0.0.1"))); err != nil {
		t.Fatal(err)
	} else if r, ok := res.(egress.Response); !ok || r.Status != 200 {
		t.Fatalf("pinned to a permitted address: %#v", res)
	}
	before := f.hits.Load()
	res, err := f.client().Get(context.Background(), egress.RootAt("www.example.com", "http", f.port, addr("127.0.0.2")))
	if err != nil || !isRefused(res) {
		t.Errorf("pinned to an address the name does not resolve to: %#v %v, want Refused", res, err)
	}
	if f.hits.Load() != before {
		t.Error("a refused pinned request reached the server")
	}
}

func TestHTTPSensitivePathAndLink(t *testing.T) {
	t.Parallel()
	var paths []string
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.RequestURI())
		_, _ = w.Write([]byte(`<a href="/next">x</a>`))
	})
	svc := egress.Service{Host: "www.example.com", Scheme: "http", Port: f.port}
	_, _ = f.client().Get(context.Background(), egress.SensitivePath(svc, 1))
	if len(paths) != 1 || paths[0] != "/server-status" {
		t.Errorf("sensitive path: %v", paths)
	}
	// Out-of-range index is refused rather than panicking.
	if res, _ := f.client().Get(context.Background(), egress.SensitivePath(svc, 9)); !isRefused(res) {
		t.Errorf("bad index: %#v", res)
	}

	root, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	resp := root.(egress.Response)
	req, err := egress.Link(resp, "/next")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.client().Get(context.Background(), req)
	if paths[len(paths)-1] != "/next" {
		t.Errorf("link not followed: %v", paths)
	}
	hits := f.hits.Load()
	if _, err := egress.Link(resp, "http://other.example.com:"+strconv.Itoa(f.port)+"/x"); err == nil {
		t.Error("Link to another host must be refused")
	}
	if _, err := egress.Link(egress.Response{}, "/x"); err == nil {
		t.Error("Link from a Response not produced by egress must be refused")
	}
	if f.hits.Load() != hits {
		t.Error("refused link must not send traffic")
	}
}

func isRefused(res egress.HTTPResult) bool { _, ok := res.(egress.Refused); return ok }

func TestHTTPRedirectNotFollowed(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/landing", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("landed"))
	})
	res, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	r := res.(egress.Response)
	if r.Status != 302 || r.Location != "/landing" || f.hits.Load() != 1 {
		t.Fatalf("redirect: %+v hits=%d", r, f.hits.Load())
	}
	req, err := egress.Redirect(r)
	if err != nil {
		t.Fatal(err)
	}
	res, _ = f.client().Get(context.Background(), req)
	if r2 := res.(egress.Response); string(r2.Body) != "landed" {
		t.Errorf("explicit redirect: %+v", r2)
	}
	if _, err := egress.Redirect(egress.Response{Status: 200}); err == nil {
		t.Error("no Location, no redirect request")
	}
}

func TestHTTPPolicyRefusals(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) {})
	cases := map[string]egress.Request{
		"out of scope host": egress.Root("www.example.org", "http", f.port),
		"port not in list":  egress.Root("www.example.com", "http", 9),
		"bad scheme":        egress.Root("www.example.com", "ftp", f.port),
		"userinfo":          egress.Root("user:pw@www.example.com", "http", f.port),
		"path in host":      egress.Root("www.example.com/x", "http", f.port),
	}
	for name, req := range cases {
		if res, err := f.client().Get(context.Background(), req); err != nil || !isRefused(res) {
			t.Errorf("%s: want Refused, got %#v %v", name, res, err)
		}
	}
	f.pol.Passive = true
	if res, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port)); !isRefused(res) {
		t.Error("passive must refuse")
	}
	f.pol.Passive = false
	f.pol.Ack = false
	if res, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port)); !isRefused(res) {
		t.Error("missing ack must refuse")
	}
	if f.hits.Load() != 0 {
		t.Errorf("refused requests reached the server %d times", f.hits.Load())
	}
}

func TestHTTPNoService(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) {})
	dead := portOf(t, closedAddr(t))
	f.pol.Ports = append(f.pol.Ports, dead)
	res, err := f.client().Get(context.Background(), egress.Root("www.example.com", "http", dead))
	ns, ok := res.(egress.NoService)
	if err != nil || !ok || ns.Reason != egress.NoServiceRefused {
		t.Errorf("%#v %v", res, err)
	}
}

// Excluded host's address is refused unless labelled shared.
func TestHTTPExclusionAndSharedInfra(t *testing.T) {
	t.Parallel()
	var reported []string
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(r.Host)) })
	res := map[string][]netip.Addr{"www.example.com": {addr("127.0.0.1")}, "admin.example.com": {addr("127.0.0.1")}}
	f.pol.Scope = scope.New(scope.Config{Roots: []string{"example.com"}, Exclusions: mustExcl(t, "admin.example.com"), Resolutions: res})
	f.pol.Resolutions = res
	f.pol.Excluded = func(v, why string) { reported = append(reported, v) }

	if r, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port)); !isRefused(r) {
		t.Errorf("non-shared address of an excluded host must be refused: %#v", r)
	}
	if r, _ := f.client().Get(context.Background(), egress.Root("admin.example.com", "http", f.port)); !isRefused(r) {
		t.Error("excluded name must be refused")
	}
	if f.hits.Load() != 0 {
		t.Fatalf("traffic reached the excluded address (%d hits)", f.hits.Load())
	}
	if len(reported) == 0 {
		t.Error("guard should report the address that triggered an exclusion")
	}

	f.pol.Shared = func(a netip.Addr) bool { return a == addr("127.0.0.1") }
	r, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	if resp, ok := r.(egress.Response); !ok || !strings.HasPrefix(string(resp.Body), "www.example.com") {
		t.Errorf("shared infra: in-scope host must be allowed: %#v", r)
	}
	if r, _ := f.client().Get(context.Background(), egress.Root("admin.example.com", "http", f.port)); !isRefused(r) {
		t.Error("the excluded hostname itself is never requested, even on shared infra")
	}
}

// Dial map test hook: policy logic sees the real address, the dial goes elsewhere.
func TestHTTPDialMap(t *testing.T) {
	t.Parallel()
	// The fixture's port is known only once it is serving, so the map is filled
	// after the Egress holding it is built.
	dial := map[string]string{}
	f := newHTTPFixture(t, egress.Options{DialMap: dial}, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	dial["203.0.113.5:"+strconv.Itoa(f.port)] = "127.0.0.1:" + strconv.Itoa(f.port)
	res := map[string][]netip.Addr{"www.example.com": {addr("203.0.113.5")}}
	f.pol.Resolutions = res
	f.pol.Scope = scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: res})
	r, err := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	if resp, ok := r.(egress.Response); err != nil || !ok || string(resp.Body) != "ok" {
		t.Errorf("%#v %v", r, err)
	}
}

// API shape. No method other than Get/Head, no raw URLs, no connections.
func TestTargetAPIShape(t *testing.T) {
	t.Parallel()
	ht := reflect.TypeFor[egress.TargetHTTP]()
	var names []string
	for method := range ht.Methods() {
		names = append(names, method.Name)
	}
	if strings.Join(names, ",") != "Get,Head" {
		t.Errorf("TargetHTTP methods = %v", names)
	}
	reqT := reflect.TypeFor[egress.Request]()
	for method := range ht.Methods() {
		if method.Type.In(1) != reqT {
			t.Errorf("%s must take the typed Request", method.Name)
		}
	}
	// Request can't be implemented outside the package.
	for method := range reqT.Methods() {
		if method.IsExported() {
			t.Errorf("Request has exported method %s; it must not be implementable externally", method.Name)
		}
	}
	tt := reflect.TypeFor[egress.TargetTCP]()
	if tt.NumMethod() != 1 || tt.Method(0).Name != "Connect" {
		t.Error("TargetTCP must expose only Connect")
	}
	for _, v := range []any{egress.Open{}, egress.Closed{}, egress.Filtered{}, egress.Refused{}} {
		ty := reflect.TypeOf(v)
		for field := range ty.Fields() {
			ft := field.Type
			if ft.Implements(reflect.TypeFor[net.Conn]()) || ft.Kind() == reflect.Interface {
				t.Errorf("%s exposes a connection-like field %s", ty, field.Name)
			}
		}
		if reflect.PointerTo(ty).Implements(reflect.TypeOf((*interface{ Write([]byte) (int, error) })(nil)).Elem()) {
			t.Errorf("%s is writable", ty)
		}
	}
	c := egress.Clients{}
	ct := reflect.TypeOf(c)
	for field := range ct.Fields() {
		switch field.Name {
		case "DNS", "ThirdParty", "HTTP", "TCP":
		default:
			t.Errorf("unexpected Clients field %s", field.Name)
		}
	}
}

// Target clients are only given to Target stages.
func TestClientsForThirdPartyStageHaveNoTargetClients(t *testing.T) {
	t.Parallel()
	eg := egress.New(egress.Options{})
	c := eg.Clients(false, []string{"stat.ripe.net"})
	if c.HTTP != nil || c.TCP != nil {
		t.Error("ThirdParty stage must not get Target clients")
	}
	if c.ThirdParty == nil || c.DNS == nil {
		t.Error("ThirdParty and DNS clients expected")
	}
	c = eg.Clients(true, nil)
	if c.HTTP == nil || c.TCP == nil {
		t.Error("Target stage gets Target clients")
	}
}

// --- ThirdPartyHTTP ---

func TestThirdParty(t *testing.T) {
	t.Parallel()
	var gotPath, gotMethod string
	c := thirdPartyServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.RequestURI(), r.Method
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, egress.Options{}, "stat.ripe.net", "*.s3.amazonaws.com")

	resp, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://stat.ripe.net/data/x.json?resource=AS1"})
	if err != nil || resp.Status != 200 || string(resp.Body) != `{"ok":true}` || gotPath != "/data/x.json?resource=AS1" {
		t.Fatalf("%+v %v path=%s", resp, err, gotPath)
	}
	if _, err = c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://bucket.s3.amazonaws.com/"}); err != nil {
		t.Errorf("wildcard source: %v", err)
	}
	if _, err = c.Do(context.Background(), egress.ThirdPartyRequest{Method: "POST", URL: "https://stat.ripe.net/q", Body: []byte("{}")}); err != nil || gotMethod != "POST" {
		t.Errorf("POST: %v %s", err, gotMethod)
	}
	hits := gotPath
	for name, req := range map[string]egress.ThirdPartyRequest{
		"host outside sources": {Method: "GET", URL: "https://evil.example.net/"},
		"in-scope host":        {Method: "GET", URL: "https://www.example.com/"},
		"excluded host":        {Method: "GET", URL: "https://bad.example.net/"},
		"method":               {Method: "DELETE", URL: "https://stat.ripe.net/"},
		"userinfo":             {Method: "GET", URL: "https://u:p@stat.ripe.net/"},
	} {
		if _, err := c.Do(context.Background(), req); err == nil {
			t.Errorf("%s should be refused", name)
		}
	}
	if gotPath != hits {
		t.Error("refused requests were sent")
	}
	// A source that is itself in scope is refused too.
	c2 := thirdPartyEgress(t, nil, egress.Options{}).Clients(false, []string{"www.example.com"}).ThirdParty
	if _, err := c2.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://www.example.com/"}); err == nil {
		t.Error("in-scope host must be refused even if listed in Sources()")
	}
}

func TestThirdPartyDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var other atomic.Int32
	o := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.Add(1) }))
	defer o.Close()
	c := thirdPartyServer(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, o.URL, http.StatusFound) }, egress.Options{}, "src.example.net")
	resp, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://src.example.net/"})
	if err != nil || resp.Status != 302 || other.Load() != 0 {
		t.Errorf("%+v %v other=%d", resp, err, other.Load())
	}
}

// A key never appears in a transport error, which includes the URL: neither a
// key in the URL the stage gives nor one egress adds as a (percent-encoded)
// query parameter.
func TestThirdPartyKeyScrubbedFromErrors(t *testing.T) {
	t.Parallel()
	base := "http://" + closedAddr(t) // nothing answers, so the request fails in the transport
	for name, tc := range map[string]struct {
		key, leak string
		req       egress.ThirdPartyRequest
	}{
		"in the URL": {"KEY-12345", "KEY-12345",
			egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/x?key=KEY-12345"}},
		"added as a query parameter": {"abc+def/ghi=", "abc",
			egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/x", KeySource: "src", KeyParam: "key"}},
	} {
		eg := thirdPartyEgress(t, map[string]string{"api.example.net": base}, egress.Options{
			Keys: map[string]config.Secret{"src": config.Secret(tc.key)}, Redactor: config.NewRedactor(tc.key)})
		_, err := eg.Clients(false, []string{"api.example.net"}).ThirdParty.Do(context.Background(), tc.req)
		if err == nil || strings.Contains(err.Error(), tc.leak) {
			t.Errorf("%s: error must be scrubbed: %v", name, err)
		}
	}
}

// --- Rate limits ---

func TestPerIPRateLimit(t *testing.T) {
	t.Parallel()
	port := serveTCP(t, nil)
	eg := egress.New(egress.Options{RatePerHost: 20, ConnectTimeout: time.Second, BannerWait: 20 * time.Millisecond})
	eg.SetPolicy(tcpPolicy(port))
	tcp := eg.Clients(true, nil).TCP
	start := time.Now()
	for range 5 {
		_, _ = tcp.Connect(context.Background(), addr("127.0.0.1"), port)
	}
	if el := time.Since(start); el < 180*time.Millisecond {
		t.Errorf("5 connects at 20/s took %v; want >= 200ms", el)
	}
}

func TestVhostsShareALimiter(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{RatePerHost: 20}, func(w http.ResponseWriter, r *http.Request) {})
	c := f.client()
	start := time.Now()
	for range 3 {
		_, _ = c.Get(context.Background(), egress.Root("a.example.com", "http", f.port))
		_, _ = c.Get(context.Background(), egress.Root("b.example.com", "http", f.port))
	}
	if el := time.Since(start); el < 220*time.Millisecond {
		t.Errorf("6 requests to one IP across two vhosts took %v; want >= 250ms", el)
	}
}

// Waiting for a rate-limit token does not count against HTTPTimeout.
func TestRateLimitWaitOutsideHTTPTimeout(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{RatePerHost: 4, HTTPTimeout: 150 * time.Millisecond},
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	c := f.client()
	for i := range 2 { // the second request waits ~250ms for its token
		res, err := c.Get(context.Background(), egress.Root("www.example.com", "http", f.port))
		if r, ok := res.(egress.Response); err != nil || !ok || string(r.Body) != "ok" {
			t.Fatalf("request %d: %#v %v", i, res, err)
		}
	}
}

// A body cut short is a transient error, not a (truncated) Response.
func TestHTTPTruncatedBodyIsError(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{HTTPTimeout: 200 * time.Millisecond}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		<-r.Context().Done() // hold the body open until the client gives up
	})
	res, err := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	if err == nil {
		t.Errorf("want error, got %#v", res)
	}
}

// A sensitive path that is not absolute could change the request's host.
func TestRelativeSensitivePathRefused(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) {})
	f.pol.SensitivePaths = []string{"admin/.env", "@other.com/x"}
	for i := range f.pol.SensitivePaths {
		svc := egress.Service{Host: "www.example.com", Scheme: "http", Port: f.port}
		res, err := f.client().Get(context.Background(), egress.SensitivePath(svc, i))
		if _, ok := res.(egress.Refused); err != nil || !ok {
			t.Errorf("%s: %#v %v", f.pol.SensitivePaths[i], res, err)
		}
	}
	if f.hits.Load() != 0 {
		t.Errorf("hits = %d", f.hits.Load())
	}
}

// HTTPS: verification is skipped for the connection but the chain is checked separately.
func TestHTTPSCertTrustReported(t *testing.T) {
	t.Parallel()
	r := getTLS(t, "www.example.com", tlsServer(t, &tls.Config{}))
	resp, ok := r.(egress.Response)
	if !ok || string(resp.Body) != "secure" {
		t.Fatalf("%#v", r)
	}
	if len(resp.PeerCerts) == 0 || resp.CertTrust() == "" || resp.CertTrust() == "trusted" {
		t.Errorf("self-signed certificate must be fetched and flagged: certs=%d trust=%q", len(resp.PeerCerts), resp.CertTrust())
	}
	// A non-TLS port spoken to as https is NoService, not an error.
	f := newHTTPFixture(t, egress.Options{}, func(http.ResponseWriter, *http.Request) {})
	r, err := f.client().Get(context.Background(), egress.Root("www.example.com", "https", f.port))
	if ns, ok := r.(egress.NoService); err != nil || !ok || ns.Reason != egress.NoServiceTLSFailed {
		t.Errorf("tls failure: %#v %v", r, err)
	}
}

// Every request carries Options.UserAgent, nyx/devel when it is not set, to a
// third-party source and to a target alike.
func TestUserAgentOption(t *testing.T) {
	t.Parallel()
	for set, want := range map[string]string{"nyx/v9.9.9": "nyx/v9.9.9", "": "nyx/devel"} {
		var gotSource string
		c := thirdPartyServer(t, func(w http.ResponseWriter, r *http.Request) { gotSource = r.UserAgent() }, egress.Options{UserAgent: set}, "src.example.net")
		if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://src.example.net/"}); err != nil {
			t.Fatal(err)
		}
		if gotSource != want {
			t.Errorf("UserAgent %q: the source saw %q, want %q", set, gotSource, want)
		}

		var gotTarget string
		f := newHTTPFixture(t, egress.Options{UserAgent: set}, func(w http.ResponseWriter, r *http.Request) { gotTarget = r.UserAgent() })
		if _, err := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port)); err != nil {
			t.Fatal(err)
		}
		if gotTarget != want {
			t.Errorf("UserAgent %q: the target saw %q, want %q", set, gotTarget, want)
		}
	}
}
