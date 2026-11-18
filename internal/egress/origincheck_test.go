package egress_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/scope"
)

// originFixture is an HTTPS and an HTTP server on loopback that stand in for a candidate origin.
// DialMap sends the addresses the policy sees to them, so the policy decisions are made on the
// real addresses and nothing leaves the machine.
type originFixture struct {
	mu            sync.Mutex
	hosts, snis   []string
	methods, uris []string
	plainAddr     string            // host:port of the plain HTTP server
	dial          map[string]string // the Egress's DialMap: address:port -> the server dialled
	handler       http.HandlerFunc
	pol           *egress.Policy
	eg            *egress.Egress
}

// The address the fixture's two servers answer on is any of these, each allowed or refused by the
// policy for a different reason.
const (
	netblockAddr = "198.51.100.7"  // inside an in-scope netblock
	hostAddr     = "203.0.113.10"  // the current address of www.example.com, owner known, dedicated
	strangerAddr = "203.0.113.99"  // a known owner, but not in a netblock and not any host's address
	sharedAddr   = "203.0.113.77"  // shared provider infrastructure, and a host's address
	unknownAddr  = "203.0.113.88"  // owner unknown, and a host's address
	excludedAddr = "198.51.100.66" // inside an in-scope netblock and an excluded CIDR
	exclHostAddr = "203.0.113.55"  // the address of an excluded hostname
)

func newOriginFixture(t *testing.T) *originFixture {
	t.Helper()
	f := &originFixture{}
	f.handler = func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<title>Acme</title>")) }
	record := func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hosts, f.methods, f.uris = append(f.hosts, r.Host), append(f.methods, r.Method), append(f.uris, r.URL.RequestURI())
		f.mu.Unlock()
		f.handler(w, r)
	}
	secure := httptest.NewUnstartedServer(http.HandlerFunc(record))
	secure.TLS = &tls.Config{GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		f.mu.Lock()
		f.snis = append(f.snis, hi.ServerName)
		f.mu.Unlock()
		return nil, nil
	}}
	secure.StartTLS()
	plain := httptest.NewServer(http.HandlerFunc(record))
	t.Cleanup(secure.Close)
	t.Cleanup(plain.Close)

	res := map[string][]netip.Addr{
		"www.example.com":    {addr(hostAddr)},
		"shared.example.com": {addr(sharedAddr)},
		"unk.example.com":    {addr(unknownAddr)},
		"admin.example.com":  {addr(exclHostAddr)},
	}
	f.dial = map[string]string{}
	f.plainAddr = strings.TrimPrefix(plain.URL, "http://")
	secureAt := strings.TrimPrefix(secure.URL, "https://")
	for _, a := range []string{netblockAddr, hostAddr, strangerAddr, sharedAddr, unknownAddr, excludedAddr, exclHostAddr} {
		f.dial[a+":443"], f.dial[a+":80"] = secureAt, f.plainAddr
	}
	f.pol = &egress.Policy{
		Scope: scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: res,
			Netblocks:  []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
			Exclusions: mustExcl(t, "198.51.100.66", "admin.example.com")}),
		Ack: true, Resolutions: res,
		Candidates:   map[string]bool{"cand.example.org": true},
		Shared:       func(a netip.Addr) bool { return a == addr(sharedAddr) },
		OwnerUnknown: func(a netip.Addr) bool { return a == addr(unknownAddr) },
	}
	f.eg = egress.New(egress.Options{RatePerHost: 1000, HTTPTimeout: 2 * time.Second, ConnectTimeout: time.Second, DialMap: f.dial})
	f.eg.SetPolicy(f.pol)
	return f
}

func (f *originFixture) get(host, scheme, a string) (egress.HTTPResult, error) {
	return f.eg.Clients(true, nil).HTTP.Get(context.Background(), egress.OriginCheck(host, scheme, addr(a)))
}

// requests is how many requests reached either server.
func (f *originFixture) requests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.hosts)
}

func (f *originFixture) seen() (hosts, snis, methods, uris []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hosts...), append([]string(nil), f.snis...), append([]string(nil), f.methods...), append([]string(nil), f.uris...)
}

// The request is one GET of "/" to the address, on 443 for https and 80 for http, with the host as
// both the TLS server name and the Host header, whichever address it is sent to.
func TestOriginCheck_RequestShape(t *testing.T) {
	t.Parallel()
	f := newOriginFixture(t)
	for _, a := range []string{netblockAddr, hostAddr} {
		for _, scheme := range []string{"https", "http"} {
			res, err := f.get("www.example.com", scheme, a)
			if r, ok := res.(egress.Response); err != nil || !ok || r.Status != 200 || !strings.Contains(string(r.Body), "Acme") {
				t.Fatalf("%s %s: %#v %v", scheme, a, res, err)
			}
		}
	}
	hosts, snis, methods, uris := f.seen()
	if len(hosts) != 4 || len(snis) != 2 {
		t.Fatalf("requests = %d (want one per address and scheme, 4), TLS handshakes = %d (want 2)", len(hosts), len(snis))
	}
	for i := range hosts {
		if hosts[i] != "www.example.com" || methods[i] != "GET" || uris[i] != "/" {
			t.Errorf("request %d: host %q method %q uri %q", i, hosts[i], methods[i], uris[i])
		}
	}
	for _, sni := range snis {
		if sni != "www.example.com" {
			t.Errorf("server name = %q", sni)
		}
	}
}

// A 3xx is returned as it is: the redirect is not followed, and only one request is sent.
func TestOriginCheck_NeverFollowsARedirect(t *testing.T) {
	t.Parallel()
	f := newOriginFixture(t)
	f.handler = func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/elsewhere", http.StatusFound) }
	for _, scheme := range []string{"https", "http"} {
		res, err := f.get("www.example.com", scheme, netblockAddr)
		if r, ok := res.(egress.Response); err != nil || !ok || r.Status != 302 || r.Location == "" {
			t.Fatalf("%s: %#v %v, want the 302 itself", scheme, res, err)
		}
	}
	if n := f.requests(); n != 2 {
		t.Errorf("%d requests reached the server, want one per scheme", n)
	}
}

// What the policy refuses is refused without a connection: an address nothing allows, an excluded
// one, a host that is a candidate or excluded, a scheme or a run that may not contact the target.
func TestOriginCheck_Refusals(t *testing.T) {
	t.Parallel()
	f := newOriginFixture(t)
	var reported []string
	f.pol.Excluded = func(v, why string) { reported = append(reported, v) }
	refused := map[string]struct{ host, scheme, addr string }{
		"outside every netblock, and no host's address":    {"www.example.com", "https", strangerAddr},
		"shared provider infrastructure":                   {"www.example.com", "https", sharedAddr},
		"owner unknown":                                    {"www.example.com", "https", unknownAddr},
		"an excluded CIDR inside an in-scope netblock":     {"www.example.com", "https", excludedAddr},
		"the address of an excluded hostname":              {"www.example.com", "https", exclHostAddr},
		"an excluded host":                                 {"admin.example.com", "https", netblockAddr},
		"a candidate host":                                 {"cand.example.org", "https", netblockAddr},
		"a host that is not in scope":                      {"www.example.net", "https", netblockAddr},
		"an address given as the host":                     {netblockAddr, "https", netblockAddr},
		"a scheme that is not http or https":               {"www.example.com", "ftp", netblockAddr},
		"a host with a path in it":                         {"www.example.com/x", "https", netblockAddr},
		"http to an address outside every netblock (also)": {"www.example.com", "http", strangerAddr},
	}
	for name, c := range refused {
		if res, err := f.get(c.host, c.scheme, c.addr); err != nil || !isRefused(res) {
			t.Errorf("%s: %#v %v, want Refused", name, res, err)
		}
	}
	if len(reported) == 0 {
		t.Error("an address that triggered an exclusion is reported")
	}
	f.pol.Passive = true
	if res, _ := f.get("www.example.com", "https", netblockAddr); !isRefused(res) {
		t.Error("--passive must refuse")
	}
	f.pol.Passive, f.pol.Ack = false, false
	if res, _ := f.get("www.example.com", "https", netblockAddr); !isRefused(res) {
		t.Error("an unacknowledged run must refuse")
	}
	if n := f.requests(); n != 0 {
		t.Errorf("refused requests reached the server %d times", n)
	}
}

// The address need not be one the host resolves to: that is the one thing that separates this
// request from RootAt. A host's address that is dedicated and known, or any address in an in-scope
// netblock, is enough; the host is still the one the policy knows.
func TestOriginCheck_AddressNeedNotBeTheHosts(t *testing.T) {
	t.Parallel()
	f := newOriginFixture(t)
	// shared.example.com resolves to the shared address, so www's address is not its own.
	res, err := f.get("shared.example.com", "https", hostAddr)
	if r, ok := res.(egress.Response); err != nil || !ok || r.Status != 200 {
		t.Fatalf("%#v %v: another host's dedicated address is allowed", res, err)
	}
	res, err = f.get("www.example.com", "https", netblockAddr)
	if r, ok := res.(egress.Response); err != nil || !ok || r.Status != 200 {
		t.Fatalf("%#v %v: an in-scope netblock address is allowed", res, err)
	}
}

// Nothing answering is NoService, with the reason the caller uses to decide whether to try http.
func TestOriginCheck_NoServiceReasons(t *testing.T) {
	t.Parallel()
	f := newOriginFixture(t)
	f.dial[netblockAddr+":443"], f.dial[hostAddr+":443"] = f.plainAddr, closedAddr(t)
	res, _ := f.get("www.example.com", "https", netblockAddr) // a plain server answering a TLS hello
	if ns, ok := res.(egress.NoService); !ok || ns.Reason != egress.NoServiceTLSFailed {
		t.Errorf("TLS to a plain server = %#v, want tls-failed", res)
	}
	res, _ = f.get("www.example.com", "https", hostAddr)
	if ns, ok := res.(egress.NoService); !ok || ns.Reason != egress.NoServiceRefused {
		t.Errorf("a closed port = %#v, want refused", res)
	}
}

// closedAddr is a loopback address and port nothing listens on.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}
