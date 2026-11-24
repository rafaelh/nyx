package egress_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/scope"
)

var tlsNow = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

// tlsServer uses the supplied TLS config, defaulting to httptest's certificate when none is
// provided.
func tlsServer(t *testing.T, cfg *tls.Config) int {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("secure")) }))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return portOf(t, strings.TrimPrefix(srv.URL, "https://"))
}

// getTLS probes a named HTTPS service routed to loopback by policy.
func getTLS(t *testing.T, host string, port int) egress.HTTPResult {
	t.Helper()
	rs := map[string][]netip.Addr{host: {addr("127.0.0.1")}}
	eg := egress.New(egress.Options{RatePerHost: 1000, HTTPTimeout: 2 * time.Second, Now: func() time.Time { return tlsNow }})
	eg.SetPolicy(&egress.Policy{
		Scope: scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: rs}),
		Ack:   true, Ports: []int{port},
	})
	r, err := eg.Clients(true, nil).HTTP.Get(context.Background(), egress.Root(host, "https", port))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Legacy-only targets remain reachable and report their negotiated version.
func TestTargetHTTPAcceptsTLS10And11(t *testing.T) {
	t.Parallel()
	for want, v := range map[string]uint16{"TLS 1.0": tls.VersionTLS10, "TLS 1.1": tls.VersionTLS11} {
		port := tlsServer(t, &tls.Config{MinVersion: v, MaxVersion: v,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}})
		resp, ok := getTLS(t, "example.com", port).(egress.Response)
		if !ok || resp.Status != 200 || string(resp.Body) != "secure" {
			t.Fatalf("%s: %#v", want, resp)
		}
		if resp.TLSVersion != want || resp.TLSCipher != "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" {
			t.Errorf("%s: version %q cipher %q", want, resp.TLSVersion, resp.TLSCipher)
		}
	}
}

// Offering legacy compatibility does not downgrade a TLS 1.3-capable target.
func TestTargetHTTPReportsModernVersionAndCipher(t *testing.T) {
	t.Parallel()
	port := tlsServer(t, &tls.Config{})
	resp, ok := getTLS(t, "example.com", port).(egress.Response)
	if !ok || resp.TLSVersion != "TLS 1.3" || !strings.HasPrefix(resp.TLSCipher, "TLS_") {
		t.Fatalf("%#v", resp)
	}
	port = tlsServer(t, &tls.Config{MaxVersion: tls.VersionTLS12})
	resp, ok = getTLS(t, "example.com", port).(egress.Response)
	if !ok || resp.TLSVersion != "TLS 1.2" {
		t.Fatalf("%#v", resp)
	}
}

// Older RSA/CBC-only targets remain observable.
func TestTargetHTTPAcceptsRSAKeyExchangeCBC(t *testing.T) {
	t.Parallel()
	port := tlsServer(t, &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}})
	resp, ok := getTLS(t, "example.com", port).(egress.Response)
	if !ok || resp.TLSCipher != "TLS_RSA_WITH_AES_128_CBC_SHA" || resp.TLSVersion != "TLS 1.2" {
		t.Fatalf("%#v", resp)
	}
}

// RC4/3DES-only targets cannot negotiate with the client.
func TestTargetHTTPDoesNotOfferRC4Or3DES(t *testing.T) {
	t.Parallel()
	for name, suite := range map[string]uint16{
		"rc4":  tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		"3des": tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	} {
		port := tlsServer(t, &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite}})
		if ns, ok := getTLS(t, "example.com", port).(egress.NoService); !ok || ns.Reason != egress.NoServiceTLSFailed {
			t.Errorf("%s: %#v", name, ns)
		}
	}
}

// Third-party clients retain modern minimum TLS requirements independently of target probing.
func TestThirdPartyStillRefusesTLS11(t *testing.T) {
	t.Parallel()
	port := tlsServer(t, &tls.Config{MinVersion: tls.VersionTLS11, MaxVersion: tls.VersionTLS11,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}})
	base := "https://127.0.0.1:" + strconv.Itoa(port)
	_, err := thirdPartyEgress(t, map[string]string{"src.example.net": base}, egress.Options{}).Clients(false, []string{"src.example.net"}).ThirdParty.Do(context.Background(),
		egress.ThirdPartyRequest{Method: "GET", URL: "https://src.example.net/"})
	if err == nil || !strings.Contains(err.Error(), "protocol version") {
		t.Errorf("a TLS 1.1 source must be refused on its version: %v", err)
	}
}

// Certificate trust

type certSpec struct {
	dns                 []string
	notBefore, notAfter time.Time
}

func trustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func trustCert(t *testing.T, tpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func leafTemplate(cn string, s certSpec, serial int64) *x509.Certificate {
	nb, na := s.notBefore, s.notAfter
	if nb.IsZero() {
		nb = tlsNow.AddDate(-1, 0, 0)
	}
	if na.IsZero() {
		na = tlsNow.AddDate(0, 3, 0)
	}
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: s.dns,
	}
}

// Crafted chains exercise trust precedence at a fixed time.
func TestCertTrustValues(t *testing.T) {
	t.Parallel()
	caKey := trustKey(t)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: tlsNow.AddDate(-5, 0, 0), NotAfter: tlsNow.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	ca := trustCert(t, caTpl, caTpl, &caKey.PublicKey, caKey)
	trusted := x509.NewCertPool()
	trusted.AddCert(ca)
	elsewhere := x509.NewCertPool() // trust store missing the signing CA

	issued := func(s certSpec) []*x509.Certificate {
		k := trustKey(t)
		return []*x509.Certificate{trustCert(t, leafTemplate("leaf", s, 2), ca, &k.PublicKey, caKey)}
	}
	self := func(s certSpec) []*x509.Certificate {
		k := trustKey(t)
		tpl := leafTemplate("leaf", s, 3)
		return []*x509.Certificate{trustCert(t, tpl, tpl, &k.PublicKey, k)}
	}
	yesterday := tlsNow.AddDate(0, 0, -1)
	www := certSpec{dns: []string{"www.example.com"}}
	other := certSpec{dns: []string{"other.example.com"}}
	for _, tc := range []struct {
		name  string
		certs []*x509.Certificate
		roots *x509.CertPool
		want  string
	}{
		{"trusted", issued(www), trusted, "trusted"},
		{"expired", issued(certSpec{dns: www.dns, notAfter: yesterday}), trusted, "expired"},
		{"not yet valid", issued(certSpec{dns: www.dns, notBefore: tlsNow.AddDate(0, 0, 1), notAfter: tlsNow.AddDate(1, 0, 0)}), trusted, "expired"},
		{"hostname mismatch", issued(other), trusted, "hostname-mismatch"},
		{"self-signed", self(www), trusted, "self-signed"},
		{"untrusted chain", issued(www), elsewhere, "untrusted-chain"},
		// Trust precedence is validity, hostname, self-signing, then chain.
		{"expired beats mismatch", issued(certSpec{dns: other.dns, notAfter: yesterday}), trusted, "expired"},
		{"expired beats self-signed", self(certSpec{dns: www.dns, notAfter: yesterday}), trusted, "expired"},
		{"mismatch beats self-signed", self(other), trusted, "hostname-mismatch"},
		{"self-signed beats untrusted", self(www), elsewhere, "self-signed"},
	} {
		if got := egress.CertTrustWith("www.example.com", tc.certs, tlsNow, tc.roots); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if got := egress.CertTrustWith("198.51.100.7", self(certSpec{}), tlsNow, nil); got != "hostname-mismatch" {
		t.Errorf("an IP literal the certificate does not name: %q", got)
	}
}

// Real HTTPS responses expose trust; HTTP has no certificate state.
func TestResponseCertTrustAndSelfSigned(t *testing.T) {
	t.Parallel()
	port := tlsServer(t, &tls.Config{}) // httptest's self-signed certificate covers example.com, its wildcard and loopback
	byName := getTLS(t, "example.com", port).(egress.Response)
	if byName.CertTrust() != "self-signed" || !byName.SelfSigned() {
		t.Errorf("example.com: %q selfSigned=%v", byName.CertTrust(), byName.SelfSigned())
	}
	other := getTLS(t, "a.b.example.com", port).(egress.Response)
	if other.CertTrust() != "hostname-mismatch" || !other.SelfSigned() {
		t.Errorf("a.b.example.com: %q selfSigned=%v", other.CertTrust(), other.SelfSigned())
	}

	f := newHTTPFixture(t, egress.Options{}, func(http.ResponseWriter, *http.Request) {})
	r, err := f.client().Get(context.Background(), egress.Root("www.example.com", "http", f.port))
	resp, ok := r.(egress.Response)
	if err != nil || !ok || resp.CertTrust() != "" || resp.TLSVersion != "" || resp.TLSCipher != "" || resp.SelfSigned() {
		t.Errorf("plain http: %#v %v", r, err)
	}
}
