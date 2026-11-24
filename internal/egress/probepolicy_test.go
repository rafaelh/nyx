package egress_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
)

func TestProbePolicy(t *testing.T) {
	t.Parallel()
	a := netip.MustParseAddr("8.8.4.4")
	p := egress.ProbePolicy(a, []string{"a.example.com", "b.example.com"}, []int{80, 443})
	if p == nil {
		t.Fatal("no policy")
	}
	if !p.Ack || p.Passive || p.Shared != nil || !slices.Equal(p.Ports, []int{80, 443}) || p.Scope == nil {
		t.Errorf("policy = %+v", p)
	}
	for _, h := range []string{"a.example.com", "b.example.com"} {
		if !slices.Equal(p.Scope.Addrs(h), []netip.Addr{a}) {
			t.Errorf("resolutions[%s] = %v", h, p.Scope.Addrs(h))
		}
	}
	if !p.Scope.InScopeIP(a) || p.Scope.InScopeIP(netip.MustParseAddr("8.8.4.5")) {
		t.Error("the scope is not exactly the address")
	}
	p6 := egress.ProbePolicy(netip.MustParseAddr("2001:db8::1"), nil, []int{80})
	if p6 == nil || !p6.Scope.InScopeIP(netip.MustParseAddr("2001:db8::1")) || p6.Scope.InScopeIP(netip.MustParseAddr("2001:db8::2")) {
		t.Error("the IPv6 scope is not exactly the address")
	}
}

// Probe GETs stay pinned to one address while choosing hostname or literal Host headers
// correctly.
func TestProbeGetByHostnameAndByAddress(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		addr, host string
	}{
		{"192.0.2.77", "app.corp.example.com"},
		{"2001:db8::77", "app.corp.example.com"},
		{"192.0.2.78", "intranet"},                // a single-label name, which --active allows
		{"192.0.2.79", "someone.github.io"},       // under a public suffix
		{"192.0.2.80", "github.io"},               // a public suffix itself
		{"10.1.2.3", "internal.corp.example.com"}, // private (RFC 1918) addresses are not refused
		{"127.0.0.1", "loop.example.com"},         // nor is loopback
	} {
		t.Run(tc.addr+"/"+tc.host, func(t *testing.T) {
			t.Parallel()
			hosts := make(chan string, 4)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hosts <- r.Host
				_, _ = w.Write([]byte("hello"))
			}))
			t.Cleanup(srv.Close)
			port := portOf(t, strings.TrimPrefix(srv.URL, "http://"))
			a := addr(tc.addr)
			opts := egress.Options{
				RatePerHost: 1000, HTTPTimeout: 2 * time.Second, ConnectTimeout: time.Second,
				DialMap: map[string]string{netJoin(tc.addr, port): "127.0.0.1:" + strconv.Itoa(port)},
			}
			probe := egress.NewProbe(opts, egress.ProbePolicy(a, []string{tc.host}, []int{port}))

			res, err := probe.HTTP.Get(context.Background(), egress.RootAt(tc.host, "http", port, a))
			if r, ok := res.(egress.Response); err != nil || !ok || r.Status != 200 || string(r.Body) != "hello" {
				t.Fatalf("by hostname: %#v %v", res, err)
			}
			if got, want := <-hosts, tc.host+":"+strconv.Itoa(port); got != want {
				t.Errorf("Host header = %q, want %q", got, want)
			}

			res, err = probe.HTTP.Get(context.Background(), egress.Root(a.String(), "http", port))
			if r, ok := res.(egress.Response); err != nil || !ok || r.Status != 200 {
				t.Fatalf("by address: %#v %v", res, err)
			}
			lit := a.String()
			if a.Is6() {
				lit = "[" + lit + "]"
			}
			if got, want := <-hosts, lit+":"+strconv.Itoa(port); got != want {
				t.Errorf("Host header = %q, want %q", got, want)
			}
		})
	}
}

// Per-address policy rejects other addresses and unselected ports.
func TestProbePolicyRefusesOtherTargets(t *testing.T) {
	t.Parallel()
	a := addr("192.0.2.77")
	probe := egress.NewProbe(egress.Options{RatePerHost: 1000, ConnectTimeout: 100 * time.Millisecond}, egress.ProbePolicy(a, []string{"app.example.com"}, []int{8080}))
	for name, req := range map[string]egress.Request{
		"another address":  egress.Root("192.0.2.78", "http", 8080),
		"another port":     egress.Root(a.String(), "http", 9999),
		"another hostname": egress.Root("other.example.com", "http", 8080),
		"pinned elsewhere": egress.RootAt("app.example.com", "http", 8080, addr("192.0.2.78")),
	} {
		if res, err := probe.HTTP.Get(context.Background(), req); !isRefused(res) || err != nil {
			t.Errorf("%s: %#v %v, want a refusal", name, res, err)
		}
	}
}

func netJoin(a string, port int) string {
	if strings.Contains(a, ":") {
		a = "[" + a + "]"
	}
	return a + ":" + strconv.Itoa(port)
}

// The same policy serves the TLS handshake, by hostname (as the server name) and by address.
func TestProbePolicyServesTheHandshake(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "app.example.com")}})
	a := addr("192.0.2.77")
	opts := handshakeOpts()
	opts.DialMap = map[string]string{netJoin("192.0.2.77", srv.port): "127.0.0.1:" + strconv.Itoa(srv.port)}
	probe := egress.NewProbe(opts, egress.ProbePolicy(a, []string{"app.example.com"}, []int{srv.port}))
	if res, err := probe.TLS.Handshake(context.Background(), a, srv.port, "app.example.com"); err != nil {
		t.Fatal(err)
	} else if _, ok := res.(egress.TLSCert); !ok {
		t.Fatalf("result = %#v, want a certificate", res)
	}
	if got := srv.serverName(t); got != "app.example.com" {
		t.Errorf("server name = %q", got)
	}
	if res, err := probe.TLS.Handshake(context.Background(), addr("192.0.2.78"), srv.port, ""); !isRefusedTLS(res) || err != nil {
		t.Errorf("another address: %#v %v, want a refusal", res, err)
	}
}

func isRefusedTLS(r egress.TLSResult) bool { _, ok := r.(egress.Refused); return ok }
