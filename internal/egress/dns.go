package egress

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"github.com/rafaelh/nyx/internal/dnsname"
)

// Expose query types without leaking the DNS library into procedures.
const (
	TypeA     = dns.TypeA
	TypeAAAA  = dns.TypeAAAA
	TypeCNAME = dns.TypeCNAME
	TypePTR   = dns.TypePTR
	TypeTXT   = dns.TypeTXT
	TypeMX    = dns.TypeMX
	TypeNS    = dns.TypeNS
	TypeSOA   = dns.TypeSOA
	TypeCAA   = dns.TypeCAA
	TypeSRV   = dns.TypeSRV
)

// DNS response codes returned in DNSResult.RCode.
const (
	RCodeSuccess  = dns.RcodeSuccess
	RCodeServFail = dns.RcodeServerFailure
	RCodeNXDomain = dns.RcodeNameError
)

// Answer is one record of a DNS answer.
type Answer struct {
	Name, Type, Value string
	TTL               uint32
}

// CNAME links an alias Name to Target.
type CNAME struct{ Name, Target string }

// DNSResult preserves NXDOMAIN/NODATA/SERVFAIL as DNS responses. Only failure to receive a
// response returns an error.
type DNSResult struct {
	RCode   int
	Answers []Answer // CNAME records are reported in CNAMEs, not here (unless CNAME was queried)
	// CNAMEs retains the answer chain even for NXDOMAIN/NODATA, exposing dangling aliases.
	CNAMEs []CNAME
}

// Addrs extracts unmapped A/AAAA answers and ignores invalid address values.
func (r DNSResult) Addrs() []netip.Addr {
	var out []netip.Addr
	for _, a := range r.Answers {
		if a.Type != "A" && a.Type != "AAAA" {
			continue
		}
		if addr, err := netip.ParseAddr(a.Value); err == nil {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

// Resolver exposes fixed public DNS queries without zone transfers.
type Resolver interface {
	Query(ctx context.Context, name string, qtype uint16) (DNSResult, error)
}

type resolver struct{ e *Egress }

func (r *resolver) Query(ctx context.Context, name string, qtype uint16) (DNSResult, error) {
	if qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
		return DNSResult{}, errors.New("zone transfers are not permitted")
	}
	if err := wait(ctx, r.e.dnsLim); err != nil {
		return DNSResult{}, err
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	addrs := r.e.opts.ResolverAddrs
	start := int(r.e.rr.Add(1)) % len(addrs)
	var last *dns.Msg
	var lastErr error
	for i := range addrs {
		addr := addrs[(start+i)%len(addrs)]
		resp, err := exchange(ctx, &dns.Client{Timeout: r.e.opts.DNSTimeout}, m, addr)
		if err == nil && resp.Truncated {
			resp, err = exchange(ctx, &dns.Client{Net: "tcp", Timeout: r.e.opts.DNSTimeout}, m, addr)
		}
		if err != nil {
			if ctx.Err() != nil {
				return DNSResult{}, ctx.Err()
			}
			lastErr = err
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			last = resp
			continue
		}
		return toResult(resp, qtype), nil
	}
	if last != nil {
		return toResult(last, qtype), nil
	}
	return DNSResult{}, fmt.Errorf("dns query %s %s: %w", name, dns.TypeToString[qtype], lastErr)
}

// exchange closes the connection on cancellation to interrupt blocked DNS reads immediately.
// The library otherwise uses context only to shorten deadlines and would wait until its
// timeout.
func exchange(ctx context.Context, c *dns.Client, m *dns.Msg, addr string) (*dns.Msg, error) {
	conn, err := c.DialContext(ctx, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	resp, _, err := c.ExchangeWithConnContext(ctx, m, conn)
	return resp, err
}

func toResult(m *dns.Msg, qtype uint16) DNSResult {
	res := DNSResult{RCode: m.Rcode}
	if m.Rcode == dns.RcodeRefused {
		res.RCode = dns.RcodeServerFailure
	}
	for _, rr := range m.Answer {
		h := rr.Header()
		if cn, ok := rr.(*dns.CNAME); ok {
			res.CNAMEs = append(res.CNAMEs, CNAME{Name: dnsname.Normalise(h.Name), Target: dnsname.Normalise(cn.Target)})
			if qtype != dns.TypeCNAME {
				continue
			}
		}
		res.Answers = append(res.Answers, Answer{
			Name: dnsname.Normalise(h.Name), Type: dns.TypeToString[h.Rrtype], Value: rdata(rr), TTL: h.Ttl,
		})
	}
	return res
}

func rdata(rr dns.RR) string {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		return dnsname.Normalise(v.Target)
	case *dns.NS:
		return dnsname.Normalise(v.Ns)
	case *dns.PTR:
		return dnsname.Normalise(v.Ptr)
	case *dns.TXT:
		return strings.Join(v.Txt, "")
	case *dns.SOA:
		return dnsname.Normalise(v.Ns) + " " + mailbox(v.Mbox)
	case *dns.MX:
		host := "."
		if v.Mx != "." {
			host = dnsname.Normalise(v.Mx)
		}
		return fmt.Sprintf("%d %s", v.Preference, host)
	case *dns.SRV:
		host := "."
		if v.Target != "." {
			host = dnsname.Normalise(v.Target)
		}
		return fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, host)
	}
	parts := strings.SplitN(rr.String(), "\t", 5)
	if len(parts) == 5 {
		return parts[4]
	}
	return rr.String()
}

// mailbox converts an SOA responsible-person name to email form. The first unescaped dot
// becomes @; escaped local-part dots stay dots, as in john.doe@example.com.
func mailbox(mbox string) string {
	mbox = strings.TrimSuffix(mbox, ".")
	i, end := dns.NextLabel(mbox, 0)
	if end {
		return strings.ReplaceAll(mbox, `\.`, ".")
	}
	return strings.ReplaceAll(mbox[:i-1], `\.`, ".") + "@" + strings.ToLower(mbox[i:])
}
