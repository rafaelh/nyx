package egress_test

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/egress/egresstest"
	"github.com/rafaelh/nyx/internal/scope"
)

// CNAME links keep their owner names, in answer order, and survive
// NXDOMAIN and NODATA so a dangling chain can be seen.
func TestResolverCNAMEsOnEveryRcode(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	d.CNAME("a.example.com", "b.example.com")
	d.CNAME("b.example.com", "c.example.net") // c.example.net does not exist: NXDOMAIN
	d.CNAME("nodata.example.com", "t.example.net")
	d.A("t.example.net", "2001:db8::1") // exists, but has no A record: NODATA for A
	dnsc := resolver(d.Addr, 300*time.Millisecond)

	res, err := dnsc.Query(context.Background(), "a.example.com", egress.TypeA)
	want := []egress.CNAME{{Name: "a.example.com", Target: "b.example.com"}, {Name: "b.example.com", Target: "c.example.net"}}
	if err != nil || res.RCode != egress.RCodeNXDomain || len(res.CNAMEs) != 2 || res.CNAMEs[0] != want[0] || res.CNAMEs[1] != want[1] {
		t.Errorf("dangling chain: %+v %v", res, err)
	}
	res, err = dnsc.Query(context.Background(), "nodata.example.com", egress.TypeA)
	if err != nil || res.RCode != egress.RCodeSuccess || len(res.Answers) != 0 || len(res.CNAMEs) != 1 {
		t.Errorf("NODATA keeps its CNAMEs: %+v %v", res, err)
	}
	res, err = dnsc.Query(context.Background(), "t.example.net", egress.TypeAAAA)
	if err != nil || len(res.Answers) != 1 || res.Answers[0].Type != "AAAA" || res.Answers[0].Value != "2001:db8::1" {
		t.Errorf("AAAA: %+v %v", res, err)
	}
}

// thirdPartyEgress redirects declared sources while retaining real scope/exclusion policy and
// filling test defaults.
func thirdPartyEgress(t *testing.T, base map[string]string, opts egress.Options) *egress.Egress {
	t.Helper()
	opts.SourceBaseURLs = base
	opts.RatePerSource = cmp.Or(opts.RatePerSource, 1000)
	if opts.Keys == nil {
		opts.Keys = map[string]config.Secret{"whoisxml": "sekrit-key"}
	}
	eg := egress.New(opts)
	eg.SetPolicy(&egress.Policy{
		Scope: scope.New(scope.Config{Roots: []string{"example.com"}, Exclusions: mustExcl(t, "bad.example.net", "bad.blob.core.windows.net")}),
	})
	return eg
}

// thirdPartyServer serves h as each of sources (api.example.net if none is
// given) and returns the client of a procedure with those sources.
func thirdPartyServer(t *testing.T, h http.HandlerFunc, opts egress.Options, sources ...string) egress.ThirdPartyHTTP {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	if len(sources) == 0 {
		sources = []string{"api.example.net"}
	}
	base := map[string]string{}
	for _, s := range sources {
		base[s] = srv.URL
	}
	return thirdPartyEgress(t, base, opts).Clients(false, sources).ThirdParty
}

// A body over the 10 MiB cap is cut and flagged, never silently complete.
func TestThirdPartyTruncated(t *testing.T) {
	t.Parallel()
	big := bytes.Repeat([]byte("x"), 10<<20+500)
	c := thirdPartyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/small" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		_, _ = w.Write(big)
	}, egress.Options{})
	resp, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/big"})
	if err != nil || !resp.Truncated || len(resp.Body) != 10<<20 {
		t.Errorf("big: truncated=%v len=%d err=%v", resp.Truncated, len(resp.Body), err)
	}
	resp, err = c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/small"})
	if err != nil || resp.Truncated {
		t.Errorf("small: %+v %v", resp, err)
	}
}

// A request may ask for a longer timeout than the default, capped at 120 s.
func TestThirdPartyTimeout(t *testing.T) {
	t.Parallel()
	c := thirdPartyServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done(): // the client gave up
		case <-time.After(150 * time.Millisecond):
		}
		_, _ = w.Write([]byte("slow"))
	}, egress.Options{HTTPTimeout: 30 * time.Millisecond})
	_, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/"})
	var to interface{ Timeout() bool }
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &to) || !to.Timeout() {
		t.Errorf("the default timeout should apply and be recognisable as a timeout: %v", err)
	}
	resp, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/", Timeout: 5 * time.Second})
	if err != nil || string(resp.Body) != "slow" {
		t.Errorf("explicit timeout: %+v %v", resp, err)
	}
}

// The client puts the key into the JSON body; the procedure never sees it.
func TestThirdPartyKeyBodyField(t *testing.T) {
	t.Parallel()
	var got map[string]any
	c := thirdPartyServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
	}, egress.Options{})
	_, err := c.Do(context.Background(), egress.ThirdPartyRequest{
		Method: "POST", URL: "https://api.example.net/api/v2", ContentType: "application/json",
		Body: []byte(`{"mode":"purchase"}`), KeySource: "whoisxml", KeyBodyField: "apiKey",
	})
	if err != nil || got["apiKey"] != "sekrit-key" || got["mode"] != "purchase" {
		t.Errorf("body = %v err = %v", got, err)
	}
	if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{
		Method: "POST", URL: "https://api.example.net/api/v2", Body: []byte(`not json`), KeySource: "whoisxml", KeyBodyField: "apiKey",
	}); err == nil {
		t.Error("a body that is not a JSON object cannot take a key field")
	} else if strings.Contains(err.Error(), "sekrit-key") {
		t.Error("key leaked into error")
	}
}

// KeyPrefix goes before the key in the key header, and Accept sets the Accept header.
func TestThirdPartyKeyPrefixAndAccept(t *testing.T) {
	t.Parallel()
	var auth, accept string
	c := thirdPartyServer(t, func(w http.ResponseWriter, r *http.Request) {
		auth, accept = r.Header.Get("Authorization"), r.Header.Get("Accept")
	}, egress.Options{})
	_, err := c.Do(context.Background(), egress.ThirdPartyRequest{
		Method: "GET", URL: "https://api.example.net/x", KeySource: "whoisxml",
		KeyHeader: "Authorization", KeyPrefix: "Bearer ", Accept: "application/json",
	})
	if err != nil || auth != "Bearer sekrit-key" || accept != "application/json" {
		t.Errorf("Authorization = %q, Accept = %q, err = %v", auth, accept, err)
	}
	_, err = c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/x"})
	if err != nil || auth != "" || accept == "application/json" {
		t.Errorf("a request without them sent Authorization = %q, Accept = %q, err = %v", auth, accept, err)
	}
}

// --- TCP eligibility ---

type tcpEnv struct {
	t    *testing.T
	port int
	tcp  egress.TargetTCP
}

// newTCPEnv builds a policy for example.com with the given scope pieces and a
// listener that every address is dialled to.
func newTCPEnv(t *testing.T, cfg scope.Config, mutate func(*egress.Policy), dialled ...string) *tcpEnv {
	t.Helper()
	port := serveTCP(t, nil)
	dm := map[string]string{}
	for _, a := range dialled {
		dm[net.JoinHostPort(a, strconv.Itoa(port))] = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	if cfg.Resolutions == nil {
		cfg.Resolutions = map[string][]netip.Addr{}
	}
	p := &egress.Policy{Scope: scope.New(cfg), Ack: true, Ports: []int{port}}
	if mutate != nil {
		mutate(p)
	}
	eg := egress.New(egress.Options{ConnectTimeout: 200 * time.Millisecond, BannerWait: 20 * time.Millisecond, RatePerHost: 1000, DialMap: dm})
	eg.SetPolicy(p)
	return &tcpEnv{t: t, port: port, tcp: eg.Clients(true, nil).TCP}
}

func (e *tcpEnv) refused(a string) bool {
	e.t.Helper()
	res, err := e.tcp.Connect(context.Background(), addr(a), e.port)
	if err != nil {
		e.t.Fatal(err)
	}
	_, ok := res.(egress.Refused)
	return ok
}

// A hostname-resolved address is port-checked unless it is shared;
// wildcard-only names do not count; an unknown owner fails closed.
func TestTCPEligibility(t *testing.T) {
	t.Parallel()
	res := map[string][]netip.Addr{
		"www.example.com":     {addr("203.0.113.5")},
		"cdn.example.com":     {addr("203.0.113.9")},
		"wild.example.com":    {addr("203.0.113.20")},
		"v6.example.com":      {addr("2001:db8::5")},
		"mystery.example.com": {addr("203.0.113.30")},
	}
	shared := map[netip.Addr]bool{addr("203.0.113.9"): true}
	unknown := map[netip.Addr]bool{addr("203.0.113.30"): true}
	env := newTCPEnv(t, scope.Config{
		Roots:        []string{"example.com"},
		Netblocks:    []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Resolutions:  res,
		WildcardOnly: map[string]bool{"wild.example.com": true},
	}, func(p *egress.Policy) {
		p.Shared = func(a netip.Addr) bool { return shared[a] }
		p.OwnerUnknown = func(a netip.Addr) bool { return unknown[a] }
	}, "198.51.100.7", "203.0.113.5", "203.0.113.9", "203.0.113.20", "203.0.113.30", "2001:db8::5", "203.0.113.77")

	for a, wantRefused := range map[string]bool{
		"198.51.100.7": false, // in-scope IP
		"203.0.113.5":  false, // in-scope hostname resolves here
		"2001:db8::5":  false, // IPv4 and IPv6 are treated alike
		"203.0.113.9":  true,  // shared provider infrastructure
		"203.0.113.20": true,  // only a wildcard-only name resolves here
		"203.0.113.30": true,  // owner unknown: fail closed
		"203.0.113.77": true,  // nothing in scope points here
	} {
		if got := env.refused(a); got != wantRefused {
			t.Errorf("%s: refused=%v, want %v", a, got, wantRefused)
		}
	}
}

// An excluded host's address is allowed only when it is shared and
// otherwise eligible (an in-scope IP); an excluded CIDR always refuses.
func TestTCPExcludedHostOnSharedInfra(t *testing.T) {
	t.Parallel()
	res := map[string][]netip.Addr{"admin.example.com": {addr("198.51.100.7"), addr("198.51.100.8")}}
	shared := map[netip.Addr]bool{addr("198.51.100.7"): true}
	env := newTCPEnv(t, scope.Config{
		Roots:       []string{"example.com"},
		Netblocks:   []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions:  mustExcl(t, "admin.example.com", "198.51.100.200/32"),
		Resolutions: res,
	}, func(p *egress.Policy) { p.Shared = func(a netip.Addr) bool { return shared[a] } },
		"198.51.100.7", "198.51.100.8", "198.51.100.200")
	if env.refused("198.51.100.7") {
		t.Error("in-scope, shared IP that an excluded host also uses must be port-checked")
	}
	if !env.refused("198.51.100.8") {
		t.Error("a non-shared address of an excluded host is refused")
	}
	if !env.refused("198.51.100.200") {
		t.Error("an excluded CIDR always refuses")
	}
}

// Fail-closed owner status must not widen HTTP: only true shared infrastructure
// lets an excluded host's address through.
func TestHTTPUnknownOwnerIsNotShared(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	res := map[string][]netip.Addr{"www.example.com": {addr("127.0.0.1")}, "admin.example.com": {addr("127.0.0.1")}}
	f.pol.Scope = scope.New(scope.Config{Roots: []string{"example.com"}, Exclusions: mustExcl(t, "admin.example.com"), Resolutions: res})
	f.pol.OwnerUnknown = func(netip.Addr) bool { return true }
	r, _ := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	if !isRefused(r) {
		t.Errorf("an unknown owner must not be treated as shared for HTTP: %#v", r)
	}
}
