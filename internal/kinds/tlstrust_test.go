package kinds

import (
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
)

// The stored tls_trust values are the strings egress reports.
func TestTrustValuesMatchEgress(t *testing.T) {
	t.Parallel()
	for _, p := range [][2]string{
		{TrustExpired, egress.TrustExpired},
		{TrustHostnameMismatch, egress.TrustHostnameMismatch},
		{TrustSelfSigned, egress.TrustSelfSigned},
		{TrustUntrustedChain, egress.TrustUntrustedChain},
		{TrustTrusted, egress.TrustTrusted},
	} {
		if p[0] != p[1] {
			t.Errorf("kinds value %q, egress reports %q", p[0], p[1])
		}
	}
}

// TLSTrust is the stored tls_trust, or the same value worked out from the
// tls_error text and tls_self_signed of a record stored before it existed.
func TestTLSTrust(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	for _, tc := range []struct {
		name string
		a    WebServiceAttrs
		want string
	}{
		{"stored", WebServiceAttrs{TLSTrust: "untrusted-chain", TLSError: "x509: certificate has expired or is not yet valid", TLSSelfSigned: &yes}, "untrusted-chain"},
		{"no TLS", WebServiceAttrs{}, ""},
		{"old trusted", WebServiceAttrs{TLSSubject: "CN=a", TLSSelfSigned: &no}, "trusted"},
		{"old expired", WebServiceAttrs{TLSSelfSigned: &no,
			TLSError: "x509: certificate has expired or is not yet valid: current time 2026-11-01T00:00:00Z is after 2021-01-01T00:00:00Z"}, "expired"},
		{"old not yet valid", WebServiceAttrs{TLSSelfSigned: &no,
			TLSError: "x509: certificate has expired or is not yet valid: current time 2026-11-01T00:00:00Z is before 2027-01-01T00:00:00Z"}, "expired"},
		{"old mismatch", WebServiceAttrs{TLSSelfSigned: &no, TLSError: "x509: certificate is valid for a.example.com, not b.example.com"}, "hostname-mismatch"},
		{"old no names", WebServiceAttrs{TLSSelfSigned: &no, TLSError: "x509: certificate is not valid for any names, but wanted to match b.example.com"}, "hostname-mismatch"},
		{"old IP", WebServiceAttrs{TLSSelfSigned: &no, TLSError: "x509: cannot validate certificate for 192.0.2.1 because it doesn't contain any IP SANs"}, "hostname-mismatch"},
		{"old common name only", WebServiceAttrs{TLSSelfSigned: &yes, TLSError: "x509: certificate relies on legacy Common Name field, use SANs instead"}, "hostname-mismatch"},
		{"old self-signed", WebServiceAttrs{TLSSelfSigned: &yes, TLSError: "x509: certificate signed by unknown authority"}, "self-signed"},
		{"old untrusted", WebServiceAttrs{TLSSelfSigned: &no, TLSError: "x509: certificate signed by unknown authority"}, "untrusted-chain"},
		{"old expired and self-signed", WebServiceAttrs{TLSSelfSigned: &yes, TLSError: "x509: certificate has expired or is not yet valid: current time"}, "expired"},
	} {
		if got := TLSTrust(tc.a); got != tc.want {
			t.Errorf("%s: TLSTrust = %q, want %q", tc.name, got, tc.want)
		}
	}
}
