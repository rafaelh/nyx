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

// Certificate trust values are stored as tls_trust. kinds mirrors them to avoid importing
// egress; tests keep the values aligned.
const (
	TrustExpired          = "expired" // including not yet valid
	TrustHostnameMismatch = "hostname-mismatch"
	TrustSelfSigned       = "self-signed"
	TrustUntrustedChain   = "untrusted-chain"
	TrustTrusted          = "trusted"
)

// targetCipherSuites includes Go's secure suites plus CBC and RSA key-exchange suites to reach
// older services. RC4 and 3DES remain excluded. The fixed list is built once per process.
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

// targetTLSConfig permits TLS 1.0 and skips connection-time verification so old, expired and
// self-signed services can be observed. CertTrust evaluates the chain afterwards. Only the
// negotiated version is recorded, not every supported version. Go does not support SSL 3.0.
func targetTLSConfig(host string) *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS10, CipherSuites: targetCipherSuites()}
}

// CertTrust checks certificate validity, hostname, self-signing and chain trust in that order.
// Plain HTTP returns "". Chain trust uses the operator's root store. The result is calculated
// on demand.
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

// certTrust evaluates chains separately from the unverified connection. It checks dates and
// hostname before Verify because platform verifiers can otherwise classify the same certificate
// differently across operating systems. Nil roots uses the system store.
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

// selfSigned checks issuer identity and the certificate's own signature directly, covering
// leaves without the CA flag as well as CA certificates.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// TLSResult is the outcome of a TLS handshake: a TLSCert, NoService or Refused.
type TLSResult interface{ tlsResult() }

// TLSCert captures the certificate after handshake without sending application data.
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

// handshake connects, negotiates TLS with serverName and closes without application data.
// ConnectTimeout bounds the dial; HTTPTimeout bounds the whole operation. Refusal, non-TLS and
// timeout are probe results; cancellation and local failures are errors.
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

// handshakeFailure distinguishes cancellation/local errors, request timeout and other
// classified handshake results, following requestFailure's rules.
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
// procedures get, has no TLS client.
type Probe struct {
	TCP  TargetTCP
	HTTP TargetHTTP
	TLS  TargetTLS
}

// ProbePolicy permits one address, the hostnames resolving to it and only the selected ports.
// It acknowledges contact and treats the address as dedicated.
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
