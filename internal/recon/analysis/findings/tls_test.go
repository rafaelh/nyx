package findings_test

import (
	"strings"
	"testing"
)

// tlsService seeds probe-style HTTPS evidence.
func (f *fixture) tlsService(host string, kv ...any) {
	f.add(rec("web_service", "https://"+host, append([]any{"host", host, "scheme", "https", "tls_expiry", "2030-01-01",
		"tls_subject", "CN=" + host, "tls_issuer", "CN=Test CA", "tls_trust", "trusted", "tls_self_signed", false}, kv...)...))
}

// Only negotiated TLS 1.0/1.1 produces low legacy-TLS findings.
func TestLegacyTLSFinding(t *testing.T) {
	t.Parallel()
	f := newFixture()
	for _, h := range []string{"v10", "v11", "v12", "v13", "none"} {
		f.host(h+".example.com", "203.0.113.5")
	}
	f.tlsService("v10.example.com", "tls_version", "TLS 1.0")
	f.tlsService("v11.example.com", "tls_version", "TLS 1.1")
	f.tlsService("v12.example.com", "tls_version", "TLS 1.2")
	f.tlsService("v13.example.com", "tls_version", "TLS 1.3")
	f.tlsService("none.example.com") // older observation without negotiated-version data
	got := f.derive(t)
	wantSet(t, got, "certificates/legacy-tls=low", "certificates/legacy-tls=low")
	for _, x := range got {
		if x.Target != "https://v10.example.com" && x.Target != "https://v11.example.com" {
			t.Errorf("unexpected target %s", x.Target)
		}
		if !strings.Contains(x.Detail, "TLS 1.") || x.Attrs["url"] != x.Target {
			t.Errorf("finding = %+v", x)
		}
	}
}

// Hostname mismatch applies only where target-owned hostname configuration can be corrected.
func TestHostnameMismatchFinding(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.host("help.example.com", "203.0.113.6")
	f.host("cdn.example.com", "203.0.113.7")
	f.host("app.example.com", "203.0.113.8")
	f.host("pages.example.com", "185.199.108.153") // shared hosting established by range rather than CNAME
	f.host("ok.example.com", "203.0.113.9")
	f.cname("help.example.com", "acme.zendesk.com")
	f.cname("cdn.example.com", "d1.cloudfront.net")
	f.cname("app.example.com", "acme.herokuapp.com")
	for _, h := range []string{"www", "help", "cdn", "app", "pages"} {
		f.tlsService(h+".example.com", "tls_trust", "hostname-mismatch")
	}
	f.tlsService("ok.example.com")
	// A service addressed by IP literal.
	f.add(rec("web_service", "https://198.51.100.7:8443", "host", "198.51.100.7", "scheme", "https", "tls_trust", "hostname-mismatch",
		"tls_subject", "CN=x", "tls_expiry", "2030-01-01"))
	got := f.derive(t)
	wantSet(t, got, "certificates/hostname-mismatch=low")
	if len(got) != 1 || got[0].Target != "https://www.example.com" {
		t.Errorf("only the unserved host is flagged: %+v", got)
	}
}

// TLS conditions aggregate into one service row with sorted type names.
func TestTLSFindingsCombine(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.host("a.example.com", "203.0.113.5")
	f.host("b.example.com", "203.0.113.6")
	f.tlsService("a.example.com", "tls_version", "TLS 1.0", "tls_trust", "hostname-mismatch", "tls_self_signed", true)
	f.tlsService("b.example.com", "tls_version", "TLS 1.1", "tls_trust", "expired", "tls_expiry", "2020-01-01")
	got := f.derive(t)
	wantSet(t, got, "certificates/hostname-mismatch;legacy-tls;self-signed=low", "certificates/expired;legacy-tls=medium")
}

// Legacy TLS attributes reconstruct trust for older engagements.
func TestHostnameMismatchFromOldRecord(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.add(rec("web_service", "https://www.example.com", "host", "www.example.com", "scheme", "https",
		"tls_subject", "CN=x", "tls_expiry", "2030-01-01", "tls_self_signed", false,
		"tls_error", "x509: certificate is valid for other.example.com, not www.example.com"))
	wantSet(t, f.derive(t), "certificates/hostname-mismatch=low")
}
