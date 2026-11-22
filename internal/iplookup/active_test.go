package iplookup

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/provider"
)

func TestProbePorts(t *testing.T) {
	t.Parallel()
	builtin := []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 853, 993, 995,
		1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8080, 8443, 8888, 9200, 9443, 11211, 27017}
	if got := probePorts(nil); !slices.Equal(got, builtin) {
		t.Errorf("built-in ports = %v, want %v", got, builtin)
	}
	got := probePorts([]int{9999, 22, 8081, 0, 70000, 8081, 1})
	want := append(slices.Clone(builtin), 1, 8081, 9999)
	if !slices.Equal(got, want) {
		t.Errorf("with extras = %v, want the built-in list then 1 8081 9999", got)
	}
	var many []int
	for p := 20000; p < 20200; p++ {
		many = append(many, p)
	}
	slices.Reverse(many)
	got = probePorts(many)
	if len(got) != len(builtin)+64 || got[len(builtin)] != 20000 || got[len(got)-1] != 20063 {
		t.Errorf("capped = %d ports from %d to %d, want the 64 lowest extras", len(got), got[len(builtin)], got[len(got)-1])
	}
}

func TestPortKinds(t *testing.T) {
	t.Parallel()
	for p, want := range map[int]bool{443: true, 465: true, 636: true, 853: true, 993: true, 995: true, 8443: true, 9443: true, 80: false, 22: false, 8080: false} {
		if tlsPort(p) != want {
			t.Errorf("tlsPort(%d) = %v", p, !want)
		}
	}
	for p, want := range map[int]bool{80: true, 443: true, 8000: true, 8080: true, 8443: true, 8888: true, 9443: true, 22: false, 465: false, 853: false} {
		if webPort(p) != want {
			t.Errorf("webPort(%d) = %v", p, !want)
		}
	}
}

func TestNotContacted(t *testing.T) {
	t.Parallel()
	cf := provider.Result{Known: true, Shared: true, Provider: "cloudflare", Class: "cdn", Evidence: "asn"}
	aws := provider.Result{Known: true, Shared: true, Provider: "aws", Class: "hyperscaler", Evidence: "asn"}
	rng := provider.Result{Known: true, Shared: true, Provider: "someone", Evidence: "range"}
	ownerFailed := &Failure{Source: SourceCymru, Code: clierr.Timeout}
	cases := []struct {
		name string
		in   contactInput
		want string // a prefix; "" is contacted
	}{
		{"public", contactInput{Addr: addr("8.8.4.4"), Kind: addrkind.Public, Found: FoundLiteral}, ""},
		{"public from public dns", contactInput{Addr: addr("8.8.4.4"), Kind: addrkind.Public, Found: FoundPublicDNS}, ""},
		{"unspecified", contactInput{Addr: addr("0.0.0.0"), Kind: "unspecified", Found: FoundLiteral}, "unspecified address"},
		{"unspecified v6", contactInput{Addr: addr("::"), Kind: "unspecified", Found: FoundLiteral}, "unspecified address"},
		{"this-network", contactInput{Addr: addr("0.1.2.3"), Kind: "this-network", Found: FoundCIDR}, "this-network address"},
		{"multicast", contactInput{Addr: addr("224.0.0.1"), Kind: "multicast", Found: FoundLiteral}, "multicast address"},
		{"multicast from local dns", contactInput{Addr: addr("ff02::1"), Kind: "multicast", Found: FoundLocalDNS}, "multicast address"},
		{"broadcast", contactInput{Addr: addr("255.255.255.255"), Kind: "broadcast", Found: FoundLiteral}, "broadcast address"},
		{"ipv6 link-local", contactInput{Addr: addr("fe80::1"), Kind: "link-local", Found: FoundLiteral}, "IPv6 link-local address (needs a zone"},
		{"ipv4 link-local", contactInput{Addr: addr("169.254.1.1"), Kind: "link-local", Found: FoundLiteral}, ""},
		{"private literal", contactInput{Addr: addr("10.0.0.1"), Kind: "private", Found: FoundLiteral}, ""},
		{"private in a cidr", contactInput{Addr: addr("10.0.0.1"), Kind: "private", Found: FoundCIDR}, ""},
		{"private from local dns", contactInput{Addr: addr("10.0.0.1"), Kind: "private", Found: FoundLocalDNS}, ""},
		{"private from public dns only", contactInput{Addr: addr("10.0.0.1"), Kind: "private", Found: FoundPublicDNS}, "non-public address from public DNS"},
		{"private from public dns and a literal", contactInput{Addr: addr("10.0.0.1"), Kind: "private", Found: FoundPublicDNS | FoundLiteral}, ""},
		{"private from both resolvers", contactInput{Addr: addr("10.0.0.1"), Kind: "private", Found: FoundPublicDNS | FoundLocalDNS}, ""},
		{"owner unknown", contactInput{Addr: addr("8.8.4.4"), Kind: addrkind.Public, Found: FoundLiteral, OwnerFailed: ownerFailed}, "owner unknown: cymru TIMEOUT"},
		{"shared cdn", contactInput{Addr: addr("1.1.1.1"), Kind: addrkind.Public, Found: FoundLiteral, Provider: cf}, "shared provider infrastructure (cloudflare, cdn)"},
		{"shared range with no class", contactInput{Addr: addr("1.1.1.1"), Kind: addrkind.Public, Found: FoundLiteral, Provider: rng}, "shared provider infrastructure (someone)"},
		{"cloud", contactInput{Addr: addr("8.8.4.4"), Kind: addrkind.Public, Found: FoundLiteral, Provider: aws}, ""},
	}
	for _, tc := range cases {
		got := notContacted(tc.in)
		if tc.want == "" && got != "" || tc.want != "" && !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s: not contacted = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// --- The probe, against fake clients ---

type fakeTCP struct {
	fn    func(ctx context.Context, port int) (egress.TCPResult, error)
	mu    sync.Mutex
	ports []int
}

func (f *fakeTCP) Connect(ctx context.Context, _ netip.Addr, port int) (egress.TCPResult, error) {
	f.mu.Lock()
	f.ports = append(f.ports, port)
	f.mu.Unlock()
	return f.fn(ctx, port)
}

type fakeTLS struct {
	fn    func(port int, name string) (egress.TLSResult, error)
	mu    sync.Mutex
	calls []string
}

func (f *fakeTLS) Handshake(_ context.Context, _ netip.Addr, port int, name string) (egress.TLSResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, fmt.Sprintf("%d/%s", port, name))
	f.mu.Unlock()
	return f.fn(port, name)
}

type fakeGet struct {
	fn    func() (egress.HTTPResult, error)
	calls atomic.Int32
}

func (f *fakeGet) Get(context.Context, egress.Request) (egress.HTTPResult, error) {
	f.calls.Add(1)
	return f.fn()
}

func (f *fakeGet) Head(context.Context, egress.Request) (egress.HTTPResult, error) {
	return nil, errors.New("not used")
}

func openOn(open map[int]string) func(context.Context, int) (egress.TCPResult, error) {
	return func(_ context.Context, port int) (egress.TCPResult, error) {
		if b, ok := open[port]; ok {
			return egress.Open{Banner: []byte(b)}, nil
		}
		return egress.Closed{}, nil
	}
}

func portStates(o probeOutcome) map[int]string {
	m := map[int]string{}
	for _, p := range o.Ports {
		m[p.Port] = p.State
	}
	return m
}

func TestRunProbe_PortStates(t *testing.T) {
	t.Parallel()
	tcp := &fakeTCP{fn: func(_ context.Context, port int) (egress.TCPResult, error) {
		switch port {
		case 22:
			return egress.Open{Banner: []byte("SSH-2.0-x\r\n\xff")}, nil
		case 80:
			return egress.Open{}, nil
		case 23:
			return egress.Filtered{}, nil
		}
		return egress.Closed{}, nil
	}}
	p := egress.Probe{TCP: tcp}
	o := runProbe(context.Background(), p, probeJob{Addr: addr("8.8.4.4"), Ports: []int{80, 22, 23, 21}})
	if o.Failure != nil {
		t.Fatalf("failure = %+v", o.Failure)
	}
	var order []int
	for _, e := range o.Ports {
		order = append(order, e.Port)
	}
	if !slices.Equal(order, []int{21, 22, 23, 80}) {
		t.Errorf("ports in order %v, want ascending", order)
	}
	if got := portStates(o); got[21] != PortClosed || got[22] != PortOpen || got[23] != PortNoAnswer || got[80] != PortOpen {
		t.Errorf("states = %v", got)
	}
	for _, e := range o.Ports {
		switch e.Port {
		case 22:
			if deref(e.Banner) != "SSH-2.0-x\r\n\uFFFD" {
				t.Errorf("banner = %q, want invalid UTF-8 replaced", deref(e.Banner))
			}
		default:
			if e.Banner != nil {
				t.Errorf("port %d has a banner %q", e.Port, *e.Banner)
			}
		}
	}
	if len(tcp.ports) != 4 {
		t.Errorf("%d connections, want 4", len(tcp.ports))
	}
}

func TestRunProbe_TheDeadlineLeavesPortsNotProbed(t *testing.T) {
	t.Parallel()
	tcp := &fakeTCP{fn: func(ctx context.Context, port int) (egress.TCPResult, error) {
		if port == 80 {
			return egress.Open{}, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	tl := &fakeTLS{fn: func(int, string) (egress.TLSResult, error) { return nil, errors.New("must not be called") }}
	ctx, cancel := contextWithTimeout(150 * time.Millisecond)
	defer cancel()
	o := runProbe(ctx, egress.Probe{TCP: tcp, TLS: tl}, probeJob{Addr: addr("8.8.4.4"), Ports: []int{80, 443, 22}, TLS: true, Web: true})
	if got := portStates(o); got[80] != PortOpen || got[443] != PortNotProbed || got[22] != PortNotProbed {
		t.Errorf("states = %v", got)
	}
	if o.Failure != nil {
		t.Errorf("a deadline is no source failure: %+v", o.Failure)
	}
	if len(tl.calls) != 0 {
		t.Errorf("handshakes after the deadline: %v", tl.calls)
	}
	for _, e := range o.Web {
		if e.Outcome != OutcomeNotProbed {
			t.Errorf("web entry after the deadline: %+v", e)
		}
	}
}

func TestRunProbe_AFailureOfThisMachineIsAProbeFailure(t *testing.T) {
	t.Parallel()
	tcp := &fakeTCP{fn: func(_ context.Context, port int) (egress.TCPResult, error) {
		if port == 22 {
			return nil, errors.New("socket: too many open files")
		}
		return egress.Closed{}, nil
	}}
	o := runProbe(context.Background(), egress.Probe{TCP: tcp}, probeJob{Addr: addr("8.8.4.4"), Ports: []int{21, 22, 23}})
	f := o.Failure
	if f == nil || f.Source != SourceProbe || f.Code != clierr.NetworkError || !f.Transient || f.Quota || !strings.Contains(f.Message, "too many open files") {
		t.Fatalf("failure = %+v", f)
	}
	if got := portStates(o); got[22] != PortNotProbed || got[21] != PortClosed || got[23] != PortClosed {
		t.Errorf("states = %v", got)
	}
}

func TestRunProbe_ARefusalIsAProbeFailure(t *testing.T) {
	t.Parallel()
	tcp := &fakeTCP{fn: func(context.Context, int) (egress.TCPResult, error) { return egress.Refused{Reason: "policy"}, nil }}
	o := runProbe(context.Background(), egress.Probe{TCP: tcp}, probeJob{Addr: addr("8.8.4.4"), Ports: []int{80}})
	if o.Failure == nil || o.Failure.Source != SourceProbe || !strings.Contains(o.Failure.Message, "policy") || portStates(o)[80] != PortNotProbed {
		t.Errorf("outcome = %+v", o)
	}
}

func TestRunProbe_PortsAloneMakesNoHandshakeOrRequest(t *testing.T) {
	t.Parallel()
	tcp := &fakeTCP{fn: openOn(map[int]string{443: "", 80: ""})}
	tl := &fakeTLS{fn: func(int, string) (egress.TLSResult, error) { return egress.TLSCert{}, nil }}
	get := &fakeGet{fn: func() (egress.HTTPResult, error) { return egress.NoService{Reason: egress.NoServiceRefused}, nil }}
	o := runProbe(context.Background(), egress.Probe{TCP: tcp, TLS: tl, HTTP: get}, probeJob{Addr: addr("8.8.4.4"), Ports: []int{80, 443}})
	if len(tl.calls) != 0 || get.calls.Load() != 0 || o.TLS != nil || o.Web != nil {
		t.Errorf("tls calls %v, gets %d, tls %v web %v", tl.calls, get.calls.Load(), o.TLS, o.Web)
	}
}

func TestRunProbe_TLSOutcomes(t *testing.T) {
	t.Parallel()
	exp := time.Date(2027, 3, 4, 23, 59, 0, 0, time.FixedZone("x", -10*3600))
	tcp := &fakeTCP{fn: openOn(map[int]string{443: "", 465: "", 636: "", 853: "", 993: "", 80: "", 995: ""})}
	tl := &fakeTLS{fn: func(port int, _ string) (egress.TLSResult, error) {
		switch port {
		case 443:
			return egress.TLSCert{Names: []string{"a.example.com", "10.0.0.1"}, Issuer: "CN=Test CA", NotAfter: exp, Version: "TLS 1.3"}, nil
		case 465:
			return egress.NoService{Reason: egress.NoServiceTimeout}, nil
		case 636:
			return egress.NoService{Reason: egress.NoServiceRefused}, nil
		case 853:
			return egress.NoService{Reason: egress.NoServiceTLSFailed}, nil
		case 993:
			return egress.NoService{Reason: egress.NoServiceOther}, nil
		}
		return egress.TLSCert{}, nil // 995: a handshake with no certificate
	}}
	o := runProbe(context.Background(), egress.Probe{TCP: tcp, TLS: tl}, probeJob{Addr: addr("8.8.4.4"), Ports: []int{80, 443, 465, 636, 853, 993, 995}, TLS: true})
	if o.Failure != nil || len(o.TLS) != 6 {
		t.Fatalf("outcome = %+v", o)
	}
	byPort := map[int]TLSEntry{}
	for _, e := range o.TLS {
		byPort[e.Port] = e
		if e.ServerName != nil || e.Names == nil {
			t.Errorf("port %d: server name %v, names %#v; want null and a list", e.Port, e.ServerName, e.Names)
		}
	}
	e := byPort[443]
	if e.Outcome != OutcomeOK || !slices.Equal(e.Names, []string{"a.example.com", "10.0.0.1"}) || deref(e.Issuer) != "CN=Test CA" || deref(e.Expiry) != "2027-03-05" {
		t.Errorf("443 = %+v issuer %s expiry %s", e, deref(e.Issuer), deref(e.Expiry))
	}
	for port, want := range map[int]string{465: OutcomeNoAnswer, 636: OutcomeRefused, 853: OutcomeNotTLS, 993: OutcomeReset, 995: OutcomeOK} {
		if byPort[port].Outcome != want {
			t.Errorf("port %d outcome = %s, want %s", port, byPort[port].Outcome, want)
		}
	}
	if byPort[993].Issuer != nil || byPort[993].Expiry != nil || byPort[995].Issuer != nil || byPort[995].Expiry != nil {
		t.Error("an entry with no certificate has an issuer or an expiry")
	}
	if len(tl.calls) != 6 {
		t.Errorf("handshakes = %v; port 80 is no TLS port", tl.calls)
	}
}

func TestRunProbe_OneHandshakePerHostname(t *testing.T) {
	t.Parallel()
	tcp := &fakeTCP{fn: openOn(map[int]string{443: "", 8443: ""})}
	tl := &fakeTLS{fn: func(int, string) (egress.TLSResult, error) { return egress.TLSCert{}, nil }}
	o := runProbe(context.Background(), egress.Probe{TCP: tcp, TLS: tl}, probeJob{Addr: addr("8.8.4.4"), Hostnames: []string{"b.example.com", "a.example.com"}, Ports: []int{443, 8443}, TLS: true})
	var got []string
	for _, e := range o.TLS {
		got = append(got, fmt.Sprintf("%d/%s", e.Port, deref(e.ServerName)))
	}
	if want := []string{"443/b.example.com", "443/a.example.com", "8443/b.example.com", "8443/a.example.com"}; !slices.Equal(got, want) {
		t.Errorf("entries = %v, want %v", got, want)
	}
	slices.Sort(tl.calls)
	if want := []string{"443/a.example.com", "443/b.example.com", "8443/a.example.com", "8443/b.example.com"}; !slices.Equal(tl.calls, want) {
		t.Errorf("handshakes = %v", tl.calls)
	}
}

func TestRunProbe_WebOutcomes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		result egress.HTTPResult
		want   string
	}{
		{"ok", egress.Response{Status: 200, Header: map[string][]string{"Server": {"nginx"}}, Body: []byte("<html><title> Hi  there </title></html>")}, OutcomeOK},
		{"timeout", egress.NoService{Reason: egress.NoServiceTimeout}, OutcomeNoAnswer},
		{"refused", egress.NoService{Reason: egress.NoServiceRefused}, OutcomeRefused},
		{"tls failed", egress.NoService{Reason: egress.NoServiceTLSFailed}, OutcomeNotTLS},
		{"other", egress.NoService{Reason: egress.NoServiceOther}, OutcomeReset},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tcp := &fakeTCP{fn: openOn(map[int]string{80: ""})}
			get := &fakeGet{fn: func() (egress.HTTPResult, error) { return tc.result, nil }}
			o := runProbe(context.Background(), egress.Probe{TCP: tcp, HTTP: get}, probeJob{Addr: addr("8.8.4.4"), Ports: []int{80, 22}, Web: true})
			if o.Failure != nil || len(o.Web) != 1 {
				t.Fatalf("outcome = %+v", o)
			}
			e := o.Web[0]
			if e.Port != 80 || e.Scheme != "http" || e.Host != "8.8.4.4" || e.Outcome != tc.want {
				t.Errorf("entry = %+v", e)
			}
			if tc.want == OutcomeOK {
				if e.Status == nil || *e.Status != 200 || deref(e.Server) != "nginx" || deref(e.Title) != "Hi there" || e.Location != nil {
					t.Errorf("entry = status %v server %s title %s location %v", e.Status, deref(e.Server), deref(e.Title), e.Location)
				}
			} else if e.Status != nil || e.Server != nil || e.Title != nil || e.Location != nil {
				t.Errorf("an entry with no response has values: %+v", e)
			}
		})
	}
}

func TestRunProbe_ARedirectIsReported(t *testing.T) {
	t.Parallel()
	tcp := &fakeTCP{fn: openOn(map[int]string{80: ""})}
	get := &fakeGet{fn: func() (egress.HTTPResult, error) {
		return egress.Response{Status: 301, Location: "https://x.example.com/login", Header: map[string][]string{"Location": {"https://x.example.com/login"}}}, nil
	}}
	o := runProbe(context.Background(), egress.Probe{TCP: tcp, HTTP: get}, probeJob{Addr: addr("8.8.4.4"), Hostnames: []string{"x.example.com"}, Ports: []int{80}, Web: true})
	e := o.Web[0]
	if *e.Status != 301 || deref(e.Location) != "https://x.example.com/login" || e.Host != "x.example.com" || e.Title != nil {
		t.Errorf("entry = %+v", e)
	}
	if get.calls.Load() != 1 {
		t.Errorf("%d requests: a redirect is not followed", get.calls.Load())
	}
}

func TestRunProbe_WebSchemesFollowTheTLSPorts(t *testing.T) {
	t.Parallel()
	tcp := &fakeTCP{fn: openOn(map[int]string{80: "", 443: "", 8000: "", 8080: "", 8443: "", 8888: "", 9443: "", 22: "", 853: ""})}
	get := &fakeGet{fn: func() (egress.HTTPResult, error) { return egress.NoService{Reason: egress.NoServiceRefused}, nil }}
	o := runProbe(context.Background(), egress.Probe{TCP: tcp, HTTP: get}, probeJob{Addr: addr("8.8.4.4"), Hostnames: []string{"a.example.com", "b.example.com"}, Ports: []int{22, 80, 443, 853, 8000, 8080, 8443, 8888, 9443}, Web: true})
	var got []string
	for _, e := range o.Web {
		got = append(got, fmt.Sprintf("%s://%s:%d", e.Scheme, e.Host, e.Port))
	}
	want := []string{
		"http://a.example.com:80", "http://b.example.com:80", "https://a.example.com:443", "https://b.example.com:443",
		"http://a.example.com:8000", "http://b.example.com:8000", "http://a.example.com:8080", "http://b.example.com:8080",
		"https://a.example.com:8443", "https://b.example.com:8443", "http://a.example.com:8888", "http://b.example.com:8888",
		"https://a.example.com:9443", "https://b.example.com:9443",
	}
	if !slices.Equal(got, want) {
		t.Errorf("requests =\n%v\nwant\n%v", got, want)
	}
}

func TestRunProbe_AnIPv6HostIsTheAddress(t *testing.T) {
	t.Parallel()
	tcp := &fakeTCP{fn: openOn(map[int]string{80: ""})}
	get := &fakeGet{fn: func() (egress.HTTPResult, error) { return egress.NoService{Reason: egress.NoServiceRefused}, nil }}
	o := runProbe(context.Background(), egress.Probe{TCP: tcp, HTTP: get}, probeJob{Addr: addr("2001:db8::1"), Ports: []int{80}, Web: true})
	if o.Web[0].Host != "2001:db8::1" {
		t.Errorf("host = %s", o.Web[0].Host)
	}
}

// --- End to end: Lookup under --active against loopback targets ---

type target struct {
	conns    atomic.Int32
	received atomic.Int64
	addr     string
}

// listenTCP is a plain TCP target that sends banner, then waits for the client to close.
func listenTCP(t *testing.T, banner string) *target {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tg := &target{addr: l.Addr().String()}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			tg.conns.Add(1)
			go func() {
				defer c.Close()
				if banner != "" {
					_, _ = c.Write([]byte(banner))
				}
				buf := make([]byte, 512)
				for {
					n, err := c.Read(buf)
					tg.received.Add(int64(n))
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return tg
}

// closedAddr is a loopback address and port that refuse every connection. The socket is bound but
// never listens, for the whole test: closing a listener instead would free the port for another
// parallel test's server, and the "closed" ports would then answer.
func closedAddr(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(sa.(*syscall.SockaddrInet4).Port))
}

func (w *world) probeOptions(t *testing.T, a string, open map[int]string) {
	t.Helper()
	closed := closedAddr(t)
	dm := map[string]string{}
	for _, p := range probePorts([]int{8081}) {
		dm[net.JoinHostPort(a, strconv.Itoa(p))] = closed
	}
	for p, to := range open {
		dm[net.JoinHostPort(a, strconv.Itoa(p))] = to
	}
	w.cfg.ProbeOptions = egress.Options{
		DialMap: dm, RatePerHost: 1000, DNSTimeout: time.Second, ConnectTimeout: time.Second, BannerWait: 150 * time.Millisecond, HTTPTimeout: 2 * time.Second,
	}
}

type webTarget struct {
	srv   *httptest.Server
	hosts chan string
	snis  chan string
}

func startWeb(t *testing.T, useTLS bool, handler http.HandlerFunc) *webTarget {
	t.Helper()
	wt := &webTarget{hosts: make(chan string, 16), snis: make(chan string, 16)}
	wt.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		wt.hosts <- r.Host
		handler(rw, r)
	}))
	if useTLS {
		wt.srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			wt.snis <- h.ServerName
			return nil, nil
		}}
		wt.srv.StartTLS()
	} else {
		wt.srv.Start()
	}
	t.Cleanup(wt.srv.Close)
	return wt
}

func drain(ch chan string) []string {
	var out []string
	for {
		select {
		case s := <-ch:
			out = append(out, s)
		default:
			slices.Sort(out)
			return out
		}
	}
}

func hostOf(u string) string { return strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://") }

func TestActive_EndToEnd(t *testing.T) {
	t.Parallel()
	w := newWorld(t, true, "all")
	w.populate(pubAddr)
	w.http.on(internetDBURL(pubAddr), 200, `{"ports":[8081,22],"hostnames":[],"tags":[],"cpes":[],"vulns":[]}`)
	ssh := listenTCP(t, "SSH-2.0-nyx\r\n")
	plain := listenTCP(t, "hello\r\n")
	extra := listenTCP(t, "")
	page := startWeb(t, false, func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Server", "nyxd/1")
		_, _ = rw.Write([]byte("<html><head><title>Welcome</title></head></html>"))
	})
	redirect := startWeb(t, false, func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, "https://elsewhere.example/", http.StatusFound)
	})
	secure := startWeb(t, true, func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("<title>Secure</title>"))
	})
	w.probeOptions(t, pubAddr, map[int]string{
		22: ssh.addr, 80: hostOf(page.srv.URL), 8080: hostOf(redirect.srv.URL), 443: hostOf(secure.srv.URL), 8443: plain.addr, 8081: extra.addr,
	})
	res := Lookup(w.ctx(), w.cfg, Resolved{Addresses: []Address{{Addr: addr(pubAddr), Hostnames: []string{"a.example.com", "b.example.com"}, Found: FoundPublicDNS}}})
	r := only(t, res).Record
	if r.NotContacted != nil || len(r.Failures) != 0 {
		t.Fatalf("not contacted %s, failures %+v", deref(r.NotContacted), r.Failures)
	}
	if !slices.Contains(only(t, res).Asked, SourceProbe) {
		t.Errorf("asked = %v, want probe", only(t, res).Asked)
	}
	states := map[int]Port{}
	for _, p := range r.Ports {
		states[p.Port] = p
	}
	if len(r.Ports) != len(probePorts([]int{8081})) {
		t.Errorf("%d ports in the record, want every port probed (%d)", len(r.Ports), len(probePorts([]int{8081})))
	}
	for port, want := range map[int]string{22: PortOpen, 80: PortOpen, 8080: PortOpen, 443: PortOpen, 8443: PortOpen, 8081: PortOpen, 21: PortClosed, 3306: PortClosed} {
		if states[port].State != want {
			t.Errorf("port %d = %s, want %s", port, states[port].State, want)
		}
	}
	if deref(states[22].Banner) != "SSH-2.0-nyx\r\n" || states[80].Banner != nil {
		t.Errorf("banners: 22 %q, 80 %v", deref(states[22].Banner), states[80].Banner)
	}
	if ssh.received.Load() != 0 || extra.received.Load() != 0 {
		t.Error("nyx sent bytes to a port during the scan")
	}
	// TLS: 443 completes for both names, 8443 is not TLS.
	var tlsGot []string
	for _, e := range r.TLS {
		tlsGot = append(tlsGot, fmt.Sprintf("%d/%s/%s", e.Port, deref(e.ServerName), e.Outcome))
		if e.Port == 443 && (!slices.Contains(e.Names, "example.com") || e.Issuer == nil || !regexp.MustCompile(`^\d{4}-\d\d-\d\d$`).MatchString(deref(e.Expiry))) {
			t.Errorf("443 entry = %+v", e)
		}
	}
	if want := []string{"443/a.example.com/ok", "443/b.example.com/ok", "8443/a.example.com/not-tls", "8443/b.example.com/not-tls"}; !slices.Equal(tlsGot, want) {
		t.Errorf("tls = %v, want %v", tlsGot, want)
	}
	if got := drain(secure.snis); !slices.Contains(got, "a.example.com") || !slices.Contains(got, "b.example.com") {
		t.Errorf("server names seen = %v", got)
	}
	checkEndToEndWeb(t, r, page, redirect)
}

func checkEndToEndWeb(t *testing.T, r Record, page, redirect *webTarget) {
	t.Helper()
	var webGot []string
	for _, e := range r.Web {
		webGot = append(webGot, fmt.Sprintf("%s/%d/%s/%s", e.Scheme, e.Port, e.Host, e.Outcome))
	}
	want := []string{
		"http/80/a.example.com/ok", "http/80/b.example.com/ok", "http/8080/a.example.com/ok", "http/8080/b.example.com/ok",
		"https/443/a.example.com/ok", "https/443/b.example.com/ok", "https/8443/a.example.com/not-tls", "https/8443/b.example.com/not-tls",
	}
	slices.Sort(webGot)
	slices.Sort(want)
	if !slices.Equal(webGot, want) {
		t.Errorf("web =\n%v\nwant\n%v", webGot, want)
	}
	for _, e := range r.Web {
		switch {
		case e.Port == 80 && (deref(e.Title) != "Welcome" || deref(e.Server) != "nyxd/1" || *e.Status != 200):
			t.Errorf("80 entry = %+v", e)
		case e.Port == 8080 && (*e.Status != 302 || deref(e.Location) != "https://elsewhere.example/"):
			t.Errorf("8080 entry = %+v status %v location %s", e, e.Status, deref(e.Location))
		case e.Port == 443 && deref(e.Title) != "Secure":
			t.Errorf("443 entry = %+v", e)
		}
	}
	if hosts := drain(page.hosts); len(hosts) != 2 || !strings.HasPrefix(hosts[0], "a.example.com") || !strings.HasPrefix(hosts[1], "b.example.com") {
		t.Errorf("Host headers = %v", hosts)
	}
	if n := len(redirect.hosts); n != 2 {
		t.Errorf("the redirect target saw %d requests, want 2 (not followed)", n)
	}
}

func TestActive_NoHostnameUsesTheAddress(t *testing.T) {
	t.Parallel()
	w := newWorld(t, true, "all")
	w.populate(pubAddr)
	page := startWeb(t, false, func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte("<title>T</title>")) })
	secure := startWeb(t, true, func(rw http.ResponseWriter, _ *http.Request) {})
	w.probeOptions(t, pubAddr, map[int]string{80: hostOf(page.srv.URL), 443: hostOf(secure.srv.URL)})
	r := only(t, w.lookup(pubAddr)).Record
	if len(r.TLS) != 1 || r.TLS[0].ServerName != nil || r.TLS[0].Outcome != OutcomeOK {
		t.Errorf("tls = %+v", r.TLS)
	}
	if hosts := drain(page.hosts); len(hosts) != 1 || hosts[0] != pubAddr {
		t.Errorf("Host headers = %v, want the address", hosts)
	}
	for _, name := range drain(secure.snis) {
		if name != "" {
			t.Errorf("server name %q, want none", name)
		}
	}
	if len(r.Web) != 2 || r.Web[0].Host != pubAddr {
		t.Errorf("web = %+v", r.Web)
	}
}

func TestActive_PortsAloneMakesNoHandshakeOrRequest(t *testing.T) {
	t.Parallel()
	w := newWorld(t, true, "ports")
	w.populate(pubAddr)
	page := startWeb(t, false, func(rw http.ResponseWriter, _ *http.Request) {})
	secure := startWeb(t, true, func(rw http.ResponseWriter, _ *http.Request) {})
	w.probeOptions(t, pubAddr, map[int]string{80: hostOf(page.srv.URL), 443: hostOf(secure.srv.URL)})
	r := only(t, w.lookup(pubAddr)).Record
	if len(r.Ports) == 0 {
		t.Fatal("no ports")
	}
	if len(drain(page.hosts)) != 0 || len(drain(secure.snis)) != 0 || len(drain(secure.hosts)) != 0 {
		t.Error("a GET or a handshake was made for --fields ports")
	}
}

func TestActive_ShareCheckRunsWhateverIsSelectedButNothingIsProbed(t *testing.T) {
	t.Parallel()
	w := newWorld(t, true, "geo_country")
	w.populate(pubAddr)
	srv := listenTCP(t, "x")
	w.probeOptions(t, pubAddr, map[int]string{22: srv.addr})
	res := only(t, w.lookup(pubAddr))
	if w.dns.queried(originName(pubAddr)) != 1 {
		t.Error("the owner was not asked for the shared check")
	}
	if srv.conns.Load() != 0 || len(res.Record.Ports) != 0 || slices.Contains(res.Asked, SourceProbe) {
		t.Errorf("probed with nothing selected: conns %d, ports %v, asked %v", srv.conns.Load(), res.Record.Ports, res.Asked)
	}
	if res.Record.NotContacted != nil {
		t.Errorf("not contacted = %s", deref(res.Record.NotContacted))
	}
}

func TestActive_DefaultModeDialsNothing(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	w.populate(pubAddr)
	srv := listenTCP(t, "x")
	w.probeOptions(t, pubAddr, map[int]string{22: srv.addr, 80: srv.addr, 443: srv.addr})
	w.lookup(pubAddr)
	if srv.conns.Load() != 0 {
		t.Errorf("%d connections in the default mode", srv.conns.Load())
	}
}

func TestActive_NotContactedPublicAddresses(t *testing.T) {
	t.Parallel()
	t.Run("shared", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, true, "all")
		w.ownedBy("1.1.1.1", 13335, "1.1.1.0/24", "CLOUDFLARENET")
		srv := listenTCP(t, "x")
		w.probeOptions(t, "1.1.1.1", map[int]string{22: srv.addr, 80: srv.addr, 443: srv.addr})
		res := only(t, w.lookup("1.1.1.1"))
		r := res.Record
		if deref(r.NotContacted) != "shared provider infrastructure (cloudflare, cdn)" || srv.conns.Load() != 0 {
			t.Errorf("not contacted = %q, conns %d", deref(r.NotContacted), srv.conns.Load())
		}
		if r.Ports == nil || r.TLS == nil || r.Web == nil || len(r.Ports)+len(r.TLS)+len(r.Web) != 0 {
			t.Errorf("probe keys = %#v %#v %#v, want []", r.Ports, r.TLS, r.Web)
		}
		if slices.Contains(res.Asked, SourceProbe) || slices.Contains(res.Asked, SourceHackerTarget) {
			t.Errorf("asked = %v", res.Asked)
		}
	})
	t.Run("owner unknown", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, true, "all")
		w.dns.set(originName(pubAddr), egress.TypeTXT, egress.DNSResult{RCode: egress.RCodeServFail})
		srv := listenTCP(t, "x")
		w.probeOptions(t, pubAddr, map[int]string{22: srv.addr})
		r := only(t, w.lookup(pubAddr)).Record
		if deref(r.NotContacted) != "owner unknown: cymru NETWORK_ERROR" || srv.conns.Load() != 0 {
			t.Errorf("not contacted = %q, conns %d", deref(r.NotContacted), srv.conns.Load())
		}
	})
	t.Run("an owner Cymru does not know is contacted", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, true, "ports,not_contacted")
		srv := listenTCP(t, "x")
		w.probeOptions(t, pubAddr, map[int]string{22: srv.addr})
		r := only(t, w.lookup(pubAddr)).Record
		if r.NotContacted != nil || srv.conns.Load() != 1 {
			t.Errorf("not contacted = %q, conns %d", deref(r.NotContacted), srv.conns.Load())
		}
	})
	t.Run("cloud addresses are contacted", func(t *testing.T) {
		t.Parallel()
		for _, asn := range []int{16509, 14061} {
			w := newWorld(t, true, "ports,not_contacted")
			w.ownedBy(pubAddr, asn, "8.8.4.0/24", "CLOUD")
			srv := listenTCP(t, "x")
			w.probeOptions(t, pubAddr, map[int]string{22: srv.addr})
			r := only(t, w.lookup(pubAddr)).Record
			if r.NotContacted != nil || srv.conns.Load() != 1 {
				t.Errorf("AS%d: not contacted = %q, conns %d", asn, deref(r.NotContacted), srv.conns.Load())
			}
		}
	})
}

func TestActive_NonPublicAddresses(t *testing.T) {
	t.Parallel()
	never := map[string]string{
		"0.0.0.0": "unspecified address", "224.0.0.1": "multicast address", "255.255.255.255": "broadcast address",
		"fe80::1": "IPv6 link-local address (needs a zone", "0.1.2.3": "this-network address",
	}
	for a, reason := range never {
		t.Run("never "+a, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, true, "all")
			srv := listenTCP(t, "x")
			dm := map[string]string{}
			for _, p := range probePorts(nil) {
				dm[net.JoinHostPort(a, strconv.Itoa(p))] = srv.addr
			}
			w.cfg.ProbeOptions = egress.Options{DialMap: dm, RatePerHost: 1000, ConnectTimeout: time.Second, BannerWait: 100 * time.Millisecond, HTTPTimeout: time.Second}
			r := only(t, w.lookup(a)).Record
			if !strings.HasPrefix(deref(r.NotContacted), reason) || srv.conns.Load() != 0 {
				t.Errorf("not contacted = %q, conns %d", deref(r.NotContacted), srv.conns.Load())
			}
		})
	}
	contact := func(t *testing.T, found Found, setup func(w *world)) (Record, int32) {
		t.Helper()
		w := newWorld(t, true, "all")
		if setup != nil {
			setup(w)
		}
		srv := listenTCP(t, "x")
		w.probeOptions(t, "10.0.0.1", map[int]string{22: srv.addr})
		res := Lookup(w.ctx(), w.cfg, Resolved{Addresses: []Address{{Addr: addr("10.0.0.1"), Hostnames: []string{}, Found: found}}})
		if w.http.total() != 0 || len(w.dns.queries()) != 0 {
			t.Errorf("a non-public address reached a third party or a public resolver")
		}
		return only(t, res).Record, srv.conns.Load()
	}
	t.Run("a literal is contacted", func(t *testing.T) {
		t.Parallel()
		r, conns := contact(t, FoundLiteral, nil)
		if r.NotContacted != nil || conns != 1 {
			t.Errorf("not contacted = %q, conns %d", deref(r.NotContacted), conns)
		}
		if states := portStates(probeOutcome{Ports: r.Ports}); states[22] != PortOpen {
			t.Errorf("ports = %v", states)
		}
		if r.InternetDBPorts == nil || len(r.InternetDBPorts) != 0 {
			t.Errorf("internetdb ports = %#v, want []", r.InternetDBPorts)
		}
	})
	t.Run("one the local resolver gave is contacted", func(t *testing.T) {
		t.Parallel()
		r, conns := contact(t, FoundLocalDNS, nil)
		if r.NotContacted != nil || conns != 1 {
			t.Errorf("not contacted = %q, conns %d", deref(r.NotContacted), conns)
		}
	})
	t.Run("one only public DNS gave is not", func(t *testing.T) {
		t.Parallel()
		r, conns := contact(t, FoundPublicDNS, nil)
		if deref(r.NotContacted) != "non-public address from public DNS" || conns != 0 {
			t.Errorf("not contacted = %q, conns %d", deref(r.NotContacted), conns)
		}
	})
}

func TestActive_APortScanIsNotAFailureWhenTheCallEnds(t *testing.T) {
	t.Parallel()
	w := newWorld(t, true, "ports")
	w.populate(pubAddr)
	w.probeOptions(t, pubAddr, nil)
	w.cfg.ProbeOptions.RatePerHost = 5
	ctx, cancel := contextWithTimeout(1200 * time.Millisecond)
	defer cancel()
	res := only(t, w.lookupCtx(ctx, pubAddr))
	states := portStates(probeOutcome{Ports: res.Record.Ports})
	n := 0
	for _, s := range states {
		if s == PortNotProbed {
			n++
		}
	}
	if n == 0 || len(res.Record.Ports) != len(probePorts(nil)) {
		t.Errorf("%d of %d ports not probed", n, len(res.Record.Ports))
	}
	if _, ok := failureOf(res.Record, SourceProbe); ok {
		t.Errorf("failures = %+v", res.Record.Failures)
	}
}
