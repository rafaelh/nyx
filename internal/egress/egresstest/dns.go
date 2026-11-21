// Package egresstest is a fake DNS server for tests. It lives under
// internal/egress so the passive-boundary test allows its use of net and miekg/dns.
package egresstest

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/nyx/internal/dnsname"
)

// DNS is a scriptable authoritative-for-everything DNS server on loopback.
type DNS struct {
	Addr string

	mu       sync.Mutex
	addrs    map[string][]netip.Addr
	cnames   map[string]string
	rcodes   map[string]int
	sufRcode map[string]int
	drop     map[string]bool
	wild     map[string]wildcard
	ptr      map[string][]string
	txt      map[string][]string
	mx       map[string][]mxRecord
	ns       map[string][]string
	soa      map[string]soaRecord
	caa      map[string][]caaRecord
	srv      map[string][]srvRecord
	typeRC   map[string]int // "name|TYPE" -> rcode
	queries  map[string]int
}

type soaRecord struct{ mname, rname string }

type caaRecord struct {
	flags      uint8
	tag, value string
}

type srvRecord struct {
	priority, weight, port uint16
	target                 string
}

type mxRecord struct {
	pref uint16
	host string
}

type wildcard struct {
	addrs []netip.Addr
	cname string
}

// NewDNS starts a server that is shut down when the test ends.
func NewDNS(tb testing.TB) *DNS {
	tb.Helper()
	d := &DNS{
		addrs: map[string][]netip.Addr{}, cnames: map[string]string{}, rcodes: map[string]int{},
		sufRcode: map[string]int{}, drop: map[string]bool{}, wild: map[string]wildcard{},
		ptr: map[string][]string{}, txt: map[string][]string{}, mx: map[string][]mxRecord{}, queries: map[string]int{},
		ns: map[string][]string{}, soa: map[string]soaRecord{}, caa: map[string][]caaRecord{}, srv: map[string][]srvRecord{}, typeRC: map[string]int{},
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	srv := &mdns.Server{PacketConn: pc, Handler: mdns.HandlerFunc(d.serve)}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	tb.Cleanup(func() { _ = srv.Shutdown() })
	d.Addr = pc.LocalAddr().String()
	return d
}

// A makes name resolve to the addresses (IPv4 answer A queries, IPv6 answer AAAA).
func (d *DNS) A(name string, addrs ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, a := range addrs {
		d.addrs[dnsname.Normalise(name)] = append(d.addrs[dnsname.Normalise(name)], netip.MustParseAddr(a))
	}
}

// CNAME makes name an alias of target.
func (d *DNS) CNAME(name, target string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cnames[dnsname.Normalise(name)] = dnsname.Normalise(target)
}

// Rcode forces a response code for every query for name.
func (d *DNS) Rcode(name string, rcode int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rcodes[dnsname.Normalise(name)] = rcode
}

// ClearRcode removes the response code forced for name by Rcode.
func (d *DNS) ClearRcode(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.rcodes, dnsname.Normalise(name))
}

// RcodeSuffix forces a response code for every name under suffix.
func (d *DNS) RcodeSuffix(suffix string, rcode int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sufRcode[dnsname.Normalise(suffix)] = rcode
}

// Drop makes the server not answer queries for name (a client timeout).
func (d *DNS) Drop(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drop[dnsname.Normalise(name)] = true
}

// Undrop makes the server answer queries for name again.
func (d *DNS) Undrop(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.drop, dnsname.Normalise(name))
}

// Wildcard makes every otherwise-unknown direct child of zone resolve to the addresses.
func (d *DNS) Wildcard(zone string, addrs ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	w := wildcard{}
	for _, a := range addrs {
		w.addrs = append(w.addrs, netip.MustParseAddr(a))
	}
	d.wild[dnsname.Normalise(zone)] = w
}

// WildcardCNAME makes every otherwise-unknown direct child of zone an alias of target.
func (d *DNS) WildcardCNAME(zone, target string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.wild[dnsname.Normalise(zone)] = wildcard{cname: dnsname.Normalise(target)}
}

// PTR makes the reverse name of addr answer with hostname.
func (d *DNS) PTR(addr, hostname string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rev, _ := mdns.ReverseAddr(addr)
	d.ptr[dnsname.Normalise(rev)] = append(d.ptr[dnsname.Normalise(rev)], dnsname.Normalise(hostname))
}

// TXT makes name answer TXT queries with text.
func (d *DNS) TXT(name, text string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.txt[dnsname.Normalise(name)] = append(d.txt[dnsname.Normalise(name)], text)
}

// MX makes name answer MX queries with a mail exchanger. host "." is a null MX.
func (d *DNS) MX(name string, pref int, host string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.mx[dnsname.Normalise(name)] = append(d.mx[dnsname.Normalise(name)], mxRecord{uint16(pref), host})
}

// NS makes name answer NS queries with a name server.
func (d *DNS) NS(name, host string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ns[dnsname.Normalise(name)] = append(d.ns[dnsname.Normalise(name)], dnsname.Normalise(host))
}

// SOA makes name answer SOA queries. rname is in DNS form, so an escaped dot in
// the local part is written `john\.doe.example.com`.
func (d *DNS) SOA(name, mname, rname string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.soa[dnsname.Normalise(name)] = soaRecord{dnsname.Normalise(mname), rname}
}

// CAA makes name answer CAA queries with a record.
func (d *DNS) CAA(name string, flags int, tag, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.caa[dnsname.Normalise(name)] = append(d.caa[dnsname.Normalise(name)], caaRecord{uint8(flags), tag, value})
}

// SRV makes name answer SRV queries with a service record. target "." is the
// null target, meaning the service is not offered.
func (d *DNS) SRV(name string, priority, weight, port int, target string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.srv[dnsname.Normalise(name)] = append(d.srv[dnsname.Normalise(name)], srvRecord{uint16(priority), uint16(weight), uint16(port), target})
}

// RcodeType forces a response code for queries of one type ("TXT", "NS", ...)
// for name, leaving its other types alone.
func (d *DNS) RcodeType(name, qtype string, rcode int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.typeRC[dnsname.Normalise(name)+"|"+qtype] = rcode
}

// ClearRcodeType removes the response code forced by RcodeType.
func (d *DNS) ClearRcodeType(name, qtype string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.typeRC, dnsname.Normalise(name)+"|"+qtype)
}

// ClearRoot removes the NS, SOA, TXT and CAA records of name.
func (d *DNS) ClearRoot(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := dnsname.Normalise(name)
	delete(d.ns, n)
	delete(d.soa, n)
	delete(d.txt, n)
	delete(d.caa, n)
}

// Count is how many queries of the type ("A", "AAAA", "PTR", "TXT", "MX", "NS", "SOA", "CAA", "SRV") were made for name.
func (d *DNS) Count(name, qtype string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.queries[dnsname.Normalise(name)+"|"+qtype]
}

// Queried lists the names queried with the type, sorted.
func (d *DNS) Queried(qtype string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for k := range d.queries {
		if n, ty, _ := strings.Cut(k, "|"); ty == qtype {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// Total is the number of queries received.
func (d *DNS) Total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, c := range d.queries {
		n += c
	}
	return n
}

func (d *DNS) known(name string) bool {
	_, a := d.addrs[name]
	_, c := d.cnames[name]
	_, p := d.ptr[name]
	_, x := d.txt[name]
	_, m := d.mx[name]
	_, n := d.ns[name]
	_, s := d.soa[name]
	_, k := d.caa[name]
	_, v := d.srv[name]
	return a || c || p || x || m || n || s || k || v
}

func (d *DNS) serve(w mdns.ResponseWriter, r *mdns.Msg) {
	q := r.Question[0]
	name := dnsname.Normalise(q.Name)
	ty := mdns.TypeToString[q.Qtype]

	d.mu.Lock()
	d.queries[name+"|"+ty]++
	dropped := d.drop[name]
	m := new(mdns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true // a recursive resolver says so; Go's resolver reads an empty answer without it as a lame referral
	if !dropped {
		d.answer(m, name, q.Qtype)
	}
	d.mu.Unlock()
	if dropped {
		return
	}
	_ = w.WriteMsg(m)
}

// rrHeader is the header of an answer record for name.
func rrHeader(name string, t uint16) mdns.RR_Header {
	return mdns.RR_Header{Name: mdns.Fqdn(name), Rrtype: t, Class: mdns.ClassINET, Ttl: 60}
}

// answer fills m. The caller holds d.mu.
func (d *DNS) answer(m *mdns.Msg, name string, qtype uint16) {
	if rc, ok := d.forcedRcode(name, qtype); ok {
		m.Rcode = rc
		return
	}
	cur := d.followCNAMEs(m, name)
	known := d.known(cur)
	var wild *wildcard
	if !known {
		if w, ok := d.wildTarget(cur); ok && w.cname == "" {
			wild, known = &w, true
		}
	}
	if !known {
		m.Rcode = mdns.RcodeNameError // no such name, or a dangling chain
		return
	}
	m.Answer = append(m.Answer, d.records(cur, qtype, wild)...)
}

// forcedRcode is the rcode set for name, for name and qtype, or for a suffix name is under,
// checked in that order.
func (d *DNS) forcedRcode(name string, qtype uint16) (int, bool) {
	if rc, ok := d.rcodes[name]; ok {
		return rc, true
	}
	if rc, ok := d.typeRC[name+"|"+mdns.TypeToString[qtype]]; ok {
		return rc, true
	}
	for suf, rc := range d.sufRcode {
		if dnsname.Under(name, suf) {
			return rc, true
		}
	}
	return 0, false
}

// followCNAMEs appends the CNAME chain from name (explicit or from a wildcard), at most 8 hops,
// to m and returns the name the chain ends at.
func (d *DNS) followCNAMEs(m *mdns.Msg, name string) string {
	cur := name
	for range 8 {
		target, ok := d.cnames[cur]
		if !ok {
			if w, wok := d.wildTarget(cur); wok && w.cname != "" {
				target, ok = w.cname, true
			}
		}
		if !ok {
			break
		}
		m.Answer = append(m.Answer, &mdns.CNAME{Hdr: rrHeader(cur, mdns.TypeCNAME), Target: mdns.Fqdn(target)})
		cur = target
	}
	return cur
}

// records are the qtype records of the known name cur. A non-nil wild gives its addresses.
func (d *DNS) records(cur string, qtype uint16, wild *wildcard) []mdns.RR {
	h := rrHeader(cur, qtype)
	var rrs []mdns.RR
	switch qtype {
	case mdns.TypeA, mdns.TypeAAAA:
		addrs := d.addrs[cur]
		if wild != nil {
			addrs = wild.addrs
		}
		rrs = addrRecords(h, qtype, addrs)
	case mdns.TypePTR:
		for _, p := range d.ptr[cur] {
			rrs = append(rrs, &mdns.PTR{Hdr: h, Ptr: mdns.Fqdn(p)})
		}
	case mdns.TypeTXT:
		for _, t := range d.txt[cur] {
			rrs = append(rrs, &mdns.TXT{Hdr: h, Txt: []string{t}})
		}
	case mdns.TypeMX:
		for _, x := range d.mx[cur] {
			rrs = append(rrs, &mdns.MX{Hdr: h, Preference: x.pref, Mx: rootOrFqdn(x.host)})
		}
	case mdns.TypeNS:
		for _, n := range d.ns[cur] {
			rrs = append(rrs, &mdns.NS{Hdr: h, Ns: mdns.Fqdn(n)})
		}
	case mdns.TypeSOA:
		if s, ok := d.soa[cur]; ok {
			rrs = append(rrs, &mdns.SOA{Hdr: h, Ns: mdns.Fqdn(s.mname), Mbox: mdns.Fqdn(s.rname),
				Serial: 1, Refresh: 7200, Retry: 3600, Expire: 1209600, Minttl: 300})
		}
	case mdns.TypeCAA:
		for _, c := range d.caa[cur] {
			rrs = append(rrs, &mdns.CAA{Hdr: h, Flag: c.flags, Tag: c.tag, Value: c.value})
		}
	case mdns.TypeSRV:
		for _, v := range d.srv[cur] {
			rrs = append(rrs, &mdns.SRV{Hdr: h, Priority: v.priority, Weight: v.weight, Port: v.port, Target: rootOrFqdn(v.target)})
		}
	}
	return rrs
}

// addrRecords are the A (or AAAA) records for the IPv4 (or IPv6) addresses among addrs.
func addrRecords(h mdns.RR_Header, qtype uint16, addrs []netip.Addr) []mdns.RR {
	var rrs []mdns.RR
	for _, a := range addrs {
		if a.Is4() && qtype == mdns.TypeA {
			rrs = append(rrs, &mdns.A{Hdr: h, A: net.IP(a.AsSlice())})
		} else if a.Is6() && qtype == mdns.TypeAAAA {
			rrs = append(rrs, &mdns.AAAA{Hdr: h, AAAA: net.IP(a.AsSlice())})
		}
	}
	return rrs
}

// rootOrFqdn is host as a fully qualified name, leaving the root "." (a null MX or SRV target) alone.
func rootOrFqdn(host string) string {
	if host == "." {
		return host
	}
	return mdns.Fqdn(host)
}

func (d *DNS) wildTarget(name string) (wildcard, bool) {
	if d.known(name) {
		return wildcard{}, false
	}
	_, parent, ok := strings.Cut(name, ".")
	if !ok {
		return wildcard{}, false
	}
	w, ok := d.wild[parent]
	return w, ok
}
