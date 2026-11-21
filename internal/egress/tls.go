package egress

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rafaelh/nyx/internal/scope"
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

// TLSResult is the outcome of a TLS handshake: a TLSCert, NoService or Refused.
type TLSResult interface{ tlsResult() }

// TLSCert is what a service presented when a handshake completed. Nothing was sent after it.
type TLSCert struct {
	Names    []string // the DNS and IP subject alternative names; an address is in its text form
	Issuer   string   // the issuer's distinguished name
	NotAfter time.Time
	Version  string // the negotiated version, such as "TLS 1.3"
}

func (TLSCert) tlsResult()   {}
func (NoService) tlsResult() {}
func (Refused) tlsResult()   {}

// TargetTLS completes TLS handshakes with target-owned addresses and reads the certificate.
type TargetTLS interface {
	Handshake(ctx context.Context, addr netip.Addr, port int, serverName string) (TLSResult, error)
}

type targetTLS struct{ e *Egress }

func (t *targetTLS) Handshake(ctx context.Context, addr netip.Addr, port int, serverName string) (TLSResult, error) {
	p := t.e.policy()
	if r, ok := p.targetRefusal(); ok {
		return r, nil
	}
	if !p.portAllowed(port, false) {
		return Refused{"port " + strconv.Itoa(port) + " not in the configured list"}, nil
	}
	addr = addr.Unmap()
	if r, refused := p.portIneligible(addr); refused {
		return r, nil
	}
	if err := wait(ctx, t.e.hostLimiter(addr)); err != nil {
		return nil, err
	}
	return t.e.handshake(ctx, addr, port, serverName)
}

// handshake dials addr, completes a TLS handshake offering serverName and closes the connection
// without sending anything else. The dial is bounded by ConnectTimeout, and the dial and handshake
// together by HTTPTimeout. A refused connection, a service that is not TLS, and one that
// does not answer in time are results; a failure of this machine, and a cancelled ctx, are errors.
func (e *Egress) handshake(ctx context.Context, addr netip.Addr, port int, serverName string) (TLSResult, error) {
	hctx, cancel := context.WithTimeout(ctx, e.opts.HTTPTimeout)
	defer cancel()
	d := net.Dialer{Timeout: e.opts.ConnectTimeout}
	raw, err := d.DialContext(hctx, "tcp", e.dialAddr(addr, port))
	if err != nil {
		return handshakeFailure(ctx, hctx, localRoute(err, addr, e.routeLookup()), classify)
	}
	conn := tls.Client(raw, targetTLSConfig(serverName))
	defer conn.Close()
	if err := conn.HandshakeContext(hctx); err != nil {
		return handshakeFailure(ctx, hctx, err, func(err error) string {
			if timedOut(err) {
				return NoServiceTimeout
			}
			return NoServiceTLSFailed // not TLS, or reset or closed during the handshake
		})
	}
	state := conn.ConnectionState()
	out := TLSCert{Version: tls.VersionName(state.Version)}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		out.Names = append(slices.Clone(leaf.DNSNames), ipNames(leaf.IPAddresses)...)
		out.Issuer, out.NotAfter = leaf.Issuer.String(), leaf.NotAfter
	}
	return out, nil
}

// handshakeFailure classifies a dial or handshake that failed, as requestFailure does a request.
// Cancelling the run, and a failure on this side, are errors; the deadline is a timeout; anything
// else is the reason the classifier gives.
func handshakeFailure(parent, ctx context.Context, err error, reason func(error) string) (TLSResult, error) {
	switch perr := parent.Err(); {
	case perr != nil && !errors.Is(perr, context.DeadlineExceeded):
		return nil, perr
	case ctx.Err() != nil:
		return NoService{NoServiceTimeout}, nil //nolint:nilerr // the deadline passing is the result, not a failure
	case localFailure(err):
		return nil, err
	}
	return NoService{reason(err)}, nil
}

// timedOut reports whether err is a network timeout.
func timedOut(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}

func ipNames(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// Probe is the set of target clients for one address, built with NewProbe. Clients, which the
// stages get, has no TLS client.
type Probe struct {
	TCP  TargetTCP
	HTTP TargetHTTP
	TLS  TargetTLS
}

// ProbePolicy is the Policy of the probe of one address: the address is the only netblock, the
// hostnames that gave it are the roots and resolve to it, the ports are the only ports, the
// contact is acknowledged and nothing is shared.
func ProbePolicy(addr netip.Addr, hostnames []string, ports []int) *Policy {
	res := map[string][]netip.Addr{}
	for _, h := range hostnames {
		res[h] = []netip.Addr{addr}
	}
	return &Policy{
		Scope: scope.New(scope.Config{
			Roots:       hostnames,
			Netblocks:   []netip.Prefix{netip.PrefixFrom(addr, addr.BitLen())},
			Resolutions: res,
		}),
		Resolutions: res,
		Ack:         true,
		Ports:       ports,
	}
}

// NewProbe returns the target clients of a new Egress that enforces only p (ProbePolicy, for
// one address), whatever the run.
func NewProbe(o Options, p *Policy) Probe {
	e := New(o)
	e.SetPolicy(p)
	return Probe{TCP: &targetTCP{e: e}, HTTP: &targetHTTP{e: e}, TLS: &targetTLS{e: e}}
}
