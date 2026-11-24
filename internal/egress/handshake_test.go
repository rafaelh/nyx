package egress_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/scope"
)

var certExpiry = time.Date(2027, 3, 4, 5, 6, 7, 0, time.UTC)

// selfSignedCert covers requested DNS names and loopback.
func selfSignedCert(t *testing.T, dnsNames ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "Probe Test CA", OrganizationalUnit: []string{"Acme Probes"}},
		NotBefore:    certExpiry.AddDate(-1, 0, 0), NotAfter: certExpiry,
		DNSNames: dnsNames, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// probeTLSServer counts application bytes after completing TLS, making handshake-only behaviour
// observable.
type probeTLSServer struct {
	port  int
	sni   chan string
	sent  chan int // the bytes received after the handshake, one value per connection
	conns atomic.Int32
}

func startProbeTLSServer(t *testing.T, cfg *tls.Config) *probeTLSServer {
	t.Helper()
	s := &probeTLSServer{sni: make(chan string, 16), sent: make(chan int, 16)}
	cfg = cfg.Clone()
	cfg.GetConfigForClient = func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
		s.sni <- hi.ServerName
		return nil, nil
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				n, _ := io.Copy(io.Discard, c)
				s.sent <- int(n)
			}()
		}
	}()
	s.port = portOf(t, ln.Addr().String())
	return s
}

func (s *probeTLSServer) serverName(t *testing.T) string {
	t.Helper()
	select {
	case n := <-s.sni:
		return n
	case <-time.After(2 * time.Second):
		t.Fatal("the server saw no client hello")
		return ""
	}
}

func handshakeOpts() egress.Options {
	return egress.Options{RatePerHost: 1000, ConnectTimeout: time.Second, HTTPTimeout: 2 * time.Second}
}

// handshakeClient builds a probe for the selected policy ports.
func handshakeClient(t *testing.T, opts egress.Options, p *egress.Policy) egress.TargetTLS {
	t.Helper()
	return egress.NewProbe(opts, p).TLS
}

func TestHandshakeReadsCertificate(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "srv.example.com", "*.example.net")}})
	res, err := handshakeClient(t, handshakeOpts(), tcpPolicy(srv.port)).Handshake(context.Background(), addr("127.0.0.1"), srv.port, "srv.example.com")
	if err != nil {
		t.Fatal(err)
	}
	c, ok := res.(egress.TLSCert)
	if !ok {
		t.Fatalf("result = %#v, want a TLSCert", res)
	}
	slices.Sort(c.Names)
	if want := []string{"*.example.net", "127.0.0.1", "srv.example.com"}; !slices.Equal(c.Names, want) {
		t.Errorf("Names = %v, want %v (DNS and IP alternative names)", c.Names, want)
	}
	if !strings.Contains(c.Issuer, "Probe Test CA") || !strings.Contains(c.Issuer, "Acme Probes") {
		t.Errorf("Issuer = %q, want the issuer's name", c.Issuer)
	}
	if !c.NotAfter.Equal(certExpiry) {
		t.Errorf("NotAfter = %v, want %v", c.NotAfter, certExpiry)
	}
	if c.Version != "TLS 1.3" {
		t.Errorf("Version = %q, want TLS 1.3", c.Version)
	}
}

func TestHandshakeReportsAnOlderVersion(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t, "srv.example.com")}, MaxVersion: tls.VersionTLS12,
	})
	res, err := handshakeClient(t, handshakeOpts(), tcpPolicy(srv.port)).Handshake(context.Background(), addr("127.0.0.1"), srv.port, "")
	if c, ok := res.(egress.TLSCert); err != nil || !ok || c.Version != "TLS 1.2" {
		t.Errorf("result = %#v %v, want TLS 1.2", res, err)
	}
}

func TestHandshakeSendsTheServerName(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "a.example.com")}})
	cl := handshakeClient(t, handshakeOpts(), tcpPolicy(srv.port))
	if _, err := cl.Handshake(context.Background(), addr("127.0.0.1"), srv.port, "a.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := srv.serverName(t); got != "a.example.com" {
		t.Errorf("server name = %q, want a.example.com", got)
	}
	if _, err := cl.Handshake(context.Background(), addr("127.0.0.1"), srv.port, "b.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := srv.serverName(t); got != "b.example.com" {
		t.Errorf("server name = %q, want b.example.com", got)
	}
}

// Collect certificates despite trust failures, including expired and wrong-name self-signed
// leaves.
func TestHandshakeDoesNotVerify(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "other.example.org")}})
	opts := handshakeOpts()
	opts.Now = func() time.Time { return certExpiry.AddDate(5, 0, 0) }
	res, err := handshakeClient(t, opts, tcpPolicy(srv.port)).Handshake(context.Background(), addr("127.0.0.1"), srv.port, "not-the-name.example.com")
	if _, ok := res.(egress.TLSCert); err != nil || !ok {
		t.Errorf("result = %#v %v, want the certificate of a service whose name does not match", res, err)
	}
}

func TestHandshakeSendsNoApplicationData(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "srv.example.com")}})
	if _, err := handshakeClient(t, handshakeOpts(), tcpPolicy(srv.port)).Handshake(context.Background(), addr("127.0.0.1"), srv.port, "srv.example.com"); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-srv.sent:
		if n != 0 {
			t.Errorf("the server received %d bytes of application data, want none", n)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the connection was not closed after the handshake")
	}
}

func TestHandshakeDialsThroughDialMap(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "srv.example.com")}})
	opts := handshakeOpts()
	opts.DialMap = map[string]string{"192.0.2.5:8443": "127.0.0.1:" + strconv.Itoa(srv.port)}
	res, err := handshakeClient(t, opts, tcpPolicy(8443)).Handshake(context.Background(), addr("192.0.2.5"), 8443, "srv.example.com")
	if _, ok := res.(egress.TLSCert); err != nil || !ok {
		t.Errorf("result = %#v %v, want the mapped server's certificate", res, err)
	}
}

// Policy refusal is a result without target traffic.
func TestHandshakeRefusals(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "srv.example.com")}})
	good := func() *egress.Policy { return tcpPolicy(srv.port) }

	noAck := good()
	noAck.Ack = false
	passive := good()
	passive.Passive = true
	cases := []struct {
		name   string
		policy *egress.Policy
		addr   string
		port   int
	}{
		{"no policy", nil, "127.0.0.1", srv.port},
		{"no authorisation", noAck, "127.0.0.1", srv.port},
		{"passive", passive, "127.0.0.1", srv.port},
		{"port not in the policy", tcpPolicy(srv.port + 1), "127.0.0.1", srv.port},
		{"address not eligible", good(), "8.8.8.8", srv.port},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := handshakeOpts()
			opts.DialMap = map[string]string{"8.8.8.8:" + strconv.Itoa(srv.port): "127.0.0.1:" + strconv.Itoa(srv.port)}
			res, err := handshakeClient(t, opts, tc.policy).Handshake(context.Background(), addr(tc.addr), tc.port, "srv.example.com")
			if r, ok := res.(egress.Refused); err != nil || !ok || r.Reason == "" {
				t.Errorf("result = %#v %v, want Refused with a reason", res, err)
			}
		})
	}
}

// Connection counters verify refusals occur before dialling.
func TestHandshakeRefusalsOpenNoConnection(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "srv.example.com")}})
	noAck := tcpPolicy(srv.port)
	noAck.Ack = false
	ineligible := tcpPolicy(srv.port) // outside the allowed netblocks
	unlisted := tcpPolicy(srv.port + 1)
	opts := handshakeOpts()
	opts.DialMap = map[string]string{"8.8.8.8:" + strconv.Itoa(srv.port): "127.0.0.1:" + strconv.Itoa(srv.port)}
	for name, c := range map[string]struct {
		p    *egress.Policy
		addr string
	}{"no ack": {noAck, "127.0.0.1"}, "ineligible": {ineligible, "8.8.8.8"}, "unlisted port": {unlisted, "127.0.0.1"}} {
		_, _ = handshakeClient(t, opts, c.p).Handshake(context.Background(), addr(c.addr), srv.port, "srv.example.com")
		time.Sleep(50 * time.Millisecond)
		if n := srv.conns.Load(); n != 0 {
			t.Fatalf("%s: the server accepted %d connections, want none", name, n)
		}
	}
}

func TestHandshakeExcludedAddressIsReported(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "srv.example.com")}})
	p := tcpPolicy(srv.port)
	p.Scope = scope.New(scope.Config{
		Netblocks:  []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Exclusions: mustExcl(t, "127.0.0.9/32"),
	})
	var reported []string
	p.Excluded = func(v, _ string) { reported = append(reported, v) }
	res, err := handshakeClient(t, handshakeOpts(), p).Handshake(context.Background(), addr("127.0.0.9"), srv.port, "")
	if _, ok := res.(egress.Refused); err != nil || !ok || !slices.Equal(reported, []string{"127.0.0.9"}) {
		t.Errorf("result = %#v %v reported=%v, want a refusal that reports the exclusion", res, err, reported)
	}
}

func TestHandshakeClosedPortIsRefused(t *testing.T) {
	t.Parallel()
	port := portOf(t, closedAddr(t))
	res, err := handshakeClient(t, handshakeOpts(), tcpPolicy(port)).Handshake(context.Background(), addr("127.0.0.1"), port, "srv.example.com")
	if ns, ok := res.(egress.NoService); err != nil || !ok || ns.Reason != egress.NoServiceRefused {
		t.Errorf("result = %#v %v, want NoService refused", res, err)
	}
}

func TestHandshakePlainTCPServerIsTLSFailed(t *testing.T) {
	t.Parallel()
	for name, handle := range map[string]func(net.Conn){
		"banner": func(c net.Conn) {
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
			time.Sleep(100 * time.Millisecond)
		},
		"reads then closes": func(c net.Conn) { _, _ = c.Read(make([]byte, 4096)) },
		"http": func(c net.Conn) {
			_, _ = c.Read(make([]byte, 4096))
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			port := serveTCP(t, handle)
			res, err := handshakeClient(t, handshakeOpts(), tcpPolicy(port)).Handshake(context.Background(), addr("127.0.0.1"), port, "srv.example.com")
			if ns, ok := res.(egress.NoService); err != nil || !ok || ns.Reason != egress.NoServiceTLSFailed {
				t.Errorf("result = %#v %v, want NoService tls-failed", res, err)
			}
		})
	}
}

func TestHandshakeResetIsTLSFailed(t *testing.T) {
	t.Parallel()
	port := serveTCP(t, func(c net.Conn) {
		_, _ = c.Read(make([]byte, 4096))
		_ = c.(*net.TCPConn).SetLinger(0) // closing now sends a reset
	})
	res, err := handshakeClient(t, handshakeOpts(), tcpPolicy(port)).Handshake(context.Background(), addr("127.0.0.1"), port, "")
	if ns, ok := res.(egress.NoService); err != nil || !ok || ns.Reason != egress.NoServiceTLSFailed {
		t.Errorf("result = %#v %v, want NoService tls-failed", res, err)
	}
}

// A silent accepted connection times out at the request deadline.
func TestHandshakeDeadlineMidHandshakeIsTimeout(t *testing.T) {
	t.Parallel()
	port := serveTCP(t, func(c net.Conn) { time.Sleep(3 * time.Second) })
	opts := handshakeOpts()
	opts.HTTPTimeout = 200 * time.Millisecond
	start := time.Now()
	res, err := handshakeClient(t, opts, tcpPolicy(port)).Handshake(context.Background(), addr("127.0.0.1"), port, "srv.example.com")
	if ns, ok := res.(egress.NoService); err != nil || !ok || ns.Reason != egress.NoServiceTimeout {
		t.Errorf("result = %#v %v, want NoService timeout", res, err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v; the deadline is 200ms", el)
	}
}

func TestHandshakeCancelIsAnError(t *testing.T) {
	t.Parallel()
	port := serveTCP(t, func(c net.Conn) { time.Sleep(3 * time.Second) })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	res, err := handshakeClient(t, handshakeOpts(), tcpPolicy(port)).Handshake(ctx, addr("127.0.0.1"), port, "")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("result = %#v %v, want the cancellation as an error", res, err)
	}
}

// TLS attempts share per-address pacing.
func TestHandshakeUsesTheHostLimiter(t *testing.T) {
	t.Parallel()
	srv := startProbeTLSServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t, "srv.example.com")}})
	opts := handshakeOpts()
	opts.RatePerHost = 20
	cl := handshakeClient(t, opts, tcpPolicy(srv.port))
	start := time.Now()
	for range 5 {
		if _, err := cl.Handshake(context.Background(), addr("127.0.0.1"), srv.port, ""); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 180*time.Millisecond {
		t.Errorf("5 handshakes at 20/s took %v; want >= 200ms", el)
	}
}

// Only explicit probes expose a TLS client to callers.

func TestClientsHaveNoTLSClient(t *testing.T) {
	t.Parallel()
	var names []string
	for f := range reflect.TypeFor[egress.Clients]().Fields() {
		names = append(names, f.Name)
	}
	if want := []string{"DNS", "ThirdParty", "HTTP", "TCP"}; !slices.Equal(names, want) {
		t.Errorf("Clients fields = %v, want exactly %v", names, want)
	}
	c := egress.New(egress.Options{}).Clients(true, nil)
	for name, v := range map[string]any{"DNS": c.DNS, "ThirdParty": c.ThirdParty, "HTTP": c.HTTP, "TCP": c.TCP} {
		if _, ok := v.(egress.TargetTLS); ok {
			t.Errorf("Clients.%s can complete a TLS handshake", name)
		}
	}
	if tt := reflect.TypeFor[egress.TargetTLS](); tt.NumMethod() != 1 || tt.Method(0).Name != "Handshake" {
		t.Error("TargetTLS must expose only Handshake")
	}
}

func TestProbeCarriesTheClientsOfOneAddress(t *testing.T) {
	t.Parallel()
	p := egress.NewProbe(egress.Options{}, tcpPolicy(443))
	if p.TCP == nil || p.HTTP == nil || p.TLS == nil {
		t.Fatalf("probe = %#v, want all three clients", p)
	}
	// Every target client refuses without installed policy.
	none := egress.NewProbe(egress.Options{}, nil)
	if res, err := none.TCP.Connect(context.Background(), addr("127.0.0.1"), 443); !isRefusedTCP(res) || err != nil {
		t.Errorf("TCP without a policy: %#v %v", res, err)
	}
	if res, err := none.HTTP.Get(context.Background(), egress.Root("127.0.0.1", "http", 80)); !isRefused(res) || err != nil {
		t.Errorf("HTTP without a policy: %#v %v", res, err)
	}
}

func isRefusedTCP(r egress.TCPResult) bool { _, ok := r.(egress.Refused); return ok }
