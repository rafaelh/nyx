package egress

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync"
	"time"
)

// Trust states of a presented certificate chain, as CertTrust reports them.
// They are stored as tls_trust, and kinds holds the same values (a test there
// pins them) so the record layer need not import egress.
const (
	TrustExpired          = "expired" // including not yet valid
	TrustHostnameMismatch = "hostname-mismatch"
	TrustSelfSigned       = "self-signed"
	TrustUntrustedChain   = "untrusted-chain"
	TrustTrusted          = "trusted"
)

// targetCipherSuites is what requests to target services offer: every suite
// Go considers secure, plus the CBC-mode and RSA key-exchange suites it
// considers insecure, so a service that has not moved on from them can still
// be seen. RC4 and 3DES are left out: no service is worth reaching with those.
// Built once, because the lists are fixed for the life of the process.
var targetCipherSuites = sync.OnceValue(func() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		if !strings.Contains(s.Name, "RC4") && !strings.Contains(s.Name, "3DES") {
			ids = append(ids, s.ID)
		}
	}
	return ids
})

// targetTLSConfig is the client TLS configuration for every request to a
// target service. Verification is skipped for the connection itself (the
// chain is judged afterwards, by CertTrust) so an expired or self-signed
// service is still reached. The minimum version is TLS 1.0, so a service that
// offers nothing newer is recorded with the version it negotiated instead of
// failing. SSL 3.0 is not supported by Go at all. Only the version actually
// negotiated is seen: an old version offered alongside a new one is not.
func targetTLSConfig(host string) *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS10, CipherSuites: targetCipherSuites()}
}

// CertTrust is the first state that applies to the certificate the service
// presented, as of when the response arrived: TrustExpired (including not yet
// valid), TrustHostnameMismatch, TrustSelfSigned, TrustUntrustedChain or
// TrustTrusted. It is "" for plain HTTP. Whether a chain is trusted depends on
// the root store of the machine running the check. It is computed on each call:
// most callers never ask.
func (r Response) CertTrust() string {
	if r.tlsAt.IsZero() {
		return ""
	}
	return certTrust(r.origin.host, r.PeerCerts, r.tlsAt, nil)
}

// SelfSigned reports whether the leaf certificate the service presented was
// issued and signed by itself, whatever else CertTrust finds wrong with it.
func (r Response) SelfSigned() bool {
	return len(r.PeerCerts) > 0 && selfSigned(r.PeerCerts[0])
}

// certTrust judges the presented chain separately from the connection (which
// skips verification), against roots or, if nil, the system's. Validity and
// hostname are checked here, not left to Verify, because on macOS and Windows
// Verify defers to the platform verifier. That verifier reports a different
// error for the same certificate (an expired leaf reads as "unknown authority"
// on macOS), so the answer would otherwise depend on the operator's OS.
func certTrust(host string, certs []*x509.Certificate, now time.Time, roots *x509.CertPool) string {
	if len(certs) == 0 {
		return ""
	}
	leaf := certs[0]
	switch {
	case now.Before(leaf.NotBefore) || now.After(leaf.NotAfter):
		return TrustExpired
	case leaf.VerifyHostname(host) != nil:
		return TrustHostnameMismatch
	case selfSigned(leaf):
		return TrustSelfSigned
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter, CurrentTime: now}); err != nil {
		return TrustUntrustedChain
	}
	return TrustTrusted
}

// selfSigned reports whether the certificate was issued and signed by itself.
// Checking the signature directly, not CheckSignatureFrom, also covers a
// self-signed leaf that is not marked as a CA.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}
