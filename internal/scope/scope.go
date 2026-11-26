// Package scope classifies names and addresses using engagement inputs. Scope values are
// immutable and classification performs no I/O.
package scope

import (
	"cmp"
	"fmt"
	"iter"
	"net/netip"
	"slices"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/knowledge/orgname"
)

// Class is the scope classification of a hostname.
type Class int

const (
	InScope Class = iota
	Candidate
	Excluded
)

func (c Class) String() string { return [...]string{"in-scope", "candidate", "excluded"}[c] }

// Classification is a Class with the reason for an exclusion.
type Classification struct {
	Class  Class
	Reason string
}

// Config supplies inputs and DNS results for scope classification.
type Config struct {
	Roots       []string                // in-scope root domains
	Netblocks   []netip.Prefix          // CIDR inputs and ASN netblocks
	Exclusions  []input.Exclusion       // hostnames, wildcards and CIDRs
	Resolutions map[string][]netip.Addr // hostname -> addresses
	// WildcardOnly names do not establish address ownership for port checks because
	// arbitrary names could resolve there.
	WildcardOnly map[string]bool
	// ASNs and Orgs identify --asn and --org inputs so those entities are not candidates.
	// ASN values use the canonical "AS123" form; expansion into netblocks happens
	// separately.
	ASNs, Orgs []string
}

// Scope classifies names and addresses.
type Scope struct {
	roots     []string
	netblocks []netip.Prefix
	blockSet  map[netip.Prefix]bool
	blockBits []int // the prefix lengths of the netblocks, sorted, once each
	exclHosts []input.Exclusion
	exclCIDRs []input.Exclusion
	resolved  map[string][]netip.Addr
	exclAddrs map[netip.Addr]string // addresses of hosts excluded by name
	hostAddrs map[netip.Addr]bool   // addresses of in-scope, non-wildcard-only hostnames
	asns      map[string]bool
	orgs      []orgname.Org
}

func New(c Config) *Scope {
	s := &Scope{roots: normaliseAll(c.Roots), netblocks: c.Netblocks, blockSet: map[netip.Prefix]bool{},
		resolved: map[string][]netip.Addr{}, exclAddrs: map[netip.Addr]string{}, hostAddrs: map[netip.Addr]bool{},
		asns: map[string]bool{}}
	for _, a := range c.ASNs {
		s.asns[a] = true
	}
	for _, o := range c.Orgs {
		s.orgs = append(s.orgs, orgname.New(o))
	}
	for _, p := range c.Netblocks {
		s.blockSet[p] = true
		s.blockBits = append(s.blockBits, p.Bits())
	}
	slices.Sort(s.blockBits)
	s.blockBits = slices.Compact(s.blockBits)
	for _, e := range c.Exclusions {
		if _, ok := e.Prefix(); ok {
			s.exclCIDRs = append(s.exclCIDRs, e)
		} else {
			s.exclHosts = append(s.exclHosts, e)
		}
	}
	for h, addrs := range c.Resolutions {
		h = dnsname.Normalise(h)
		s.resolved[h] = addrs
		if e, ok := s.matchName(h); ok {
			for _, a := range addrs {
				s.exclAddrs[a] = fmt.Sprintf("address %s of excluded host %s (matched %s)", a, h, e.Entry)
			}
		}
	}
	for h, addrs := range s.resolved {
		if c.WildcardOnly[h] || s.ClassifyHost(h).Class != InScope {
			continue
		}
		for _, a := range addrs {
			s.hostAddrs[a] = true
		}
	}
	return s
}

func normaliseAll(in []string) []string {
	out := make([]string, len(in))
	for i, h := range in {
		out[i] = dnsname.Normalise(h)
	}
	return out
}

func (s *Scope) matchName(h string) (input.Exclusion, bool) {
	for _, e := range s.exclHosts {
		if e.MatchesHost(h) {
			return e, true
		}
	}
	return input.Exclusion{}, false
}

func (s *Scope) cidrOf(a netip.Addr) (input.Exclusion, bool) {
	for _, e := range s.exclCIDRs {
		if p, _ := e.Prefix(); p.Contains(a) {
			return e, true
		}
	}
	return input.Exclusion{}, false
}

func (s *Scope) HostInScope(host string) bool { return s.ClassifyHost(host).Class == InScope }

// Addrs returns the addresses a hostname resolves to, by its normalised name.
func (s *Scope) Addrs(host string) []netip.Addr { return s.resolved[dnsname.Normalise(host)] }

// ClassifyHost applies name exclusions and excluded resolved CIDRs before classifying a name as
// in scope or a candidate.
func (s *Scope) ClassifyHost(host string) Classification {
	h := dnsname.Normalise(host)
	if e, ok := s.matchName(h); ok {
		return Classification{Excluded, "matched exclusion " + e.Entry}
	}
	for _, a := range s.resolved[h] {
		if e, ok := s.cidrOf(a); ok {
			return Classification{Excluded, fmt.Sprintf("resolves to %s in excluded %s", a, e.Entry)}
		}
	}
	for _, r := range s.roots {
		if dnsname.Under(h, r) {
			return Classification{InScope, ""}
		}
	}
	return Classification{Candidate, ""}
}

// RootOf returns the most specific input root containing host, or "". It ignores exclusions;
// ClassifyHost applies them.
func (s *Scope) RootOf(host string) string {
	h, best := dnsname.Normalise(host), ""
	for _, r := range s.roots {
		if dnsname.Under(h, r) && len(r) > len(best) {
			best = r
		}
	}
	return best
}

// InScopeIP reports whether the address is inside an in-scope netblock.
func (s *Scope) InScopeIP(a netip.Addr) bool {
	for _, p := range s.netblocks {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// WebHostInScope controls web-record visibility for reports and counts. Names must be in scope;
// IP literals must belong to an in-scope netblock and pass exclusions.
func (s *Scope) WebHostInScope(host string) bool {
	h := dnsname.Normalise(host)
	if a, ok := input.IPLiteral(h); ok {
		_, _, excluded := s.exclusion(a)
		return s.InScopeIP(a) && !excluded
	}
	return h != "" && s.ClassifyHost(h).Class == InScope
}

// exclusion checks excluded CIDRs and addresses of name-excluded hosts. It returns the reason
// and whether a CIDR matched, since CIDR exclusions also apply to shared infrastructure.
func (s *Scope) exclusion(a netip.Addr) (why string, cidr, ok bool) {
	if e, ok := s.cidrOf(a); ok {
		return fmt.Sprintf("address %s in excluded %s", a, e.Entry), true, true
	}
	why, ok = s.exclAddrs[a]
	return why, false, ok
}

// excluded is exclusion without its reason.
func (s *Scope) excluded(a netip.Addr) (cidr, ok bool) {
	if _, ok := s.cidrOf(a); ok {
		return true, true
	}
	_, ok = s.exclAddrs[a]
	return false, ok
}

// ExcludedFor always blocks excluded CIDRs. An address belonging to a name-excluded host is
// blocked unless it is known shared infrastructure. Unknown ownership does not count as shared.
func (s *Scope) ExcludedFor(a netip.Addr, shared bool) (bool, string) {
	why, cidr, ok := s.exclusion(a)
	return ok && (!shared || cidr), why
}

// Owner supplies shared-hosting and ownership status for an address. Unknown ownership fails
// closed and does not imply shared infrastructure.
type Owner func(netip.Addr) (shared, known bool)

// PortEligible applies the same rules for egress and ips.csv. Exclusions take priority. An
// address then qualifies if it belongs to an in-scope netblock, or is known, dedicated and used
// by an in-scope non-wildcard-only hostname. owner is called only when needed. excluded
// distinguishes an exclusion from other refusals.
func (s *Scope) PortEligible(a netip.Addr, owner Owner) (ok bool, why string, excluded bool) {
	a = a.Unmap()
	switch s.portVerdict(a, owner) {
	case portEligible:
		return true, "", false
	case portExcluded:
		why, _, _ := s.exclusion(a)
		return false, why, true
	case portShared:
		return false, "address " + a.String() + " is shared provider infrastructure or its owner is unknown", false
	case portOutside: // refused below
	}
	return false, "address " + a.String() + " is not in scope", false
}

// PortAllowed is PortEligible's verdict alone, for callers that discard the reason it would
// build.
func (s *Scope) PortAllowed(a netip.Addr, owner Owner) bool {
	return s.portVerdict(a.Unmap(), owner) == portEligible
}

// portVerdict is PortEligible's decision for an unmapped address.
type portVerdict uint8

const (
	portEligible portVerdict = iota
	portExcluded             // an exclusion applies
	portShared               // shared provider infrastructure, or an unknown owner
	portOutside              // not in scope
)

func (s *Scope) portVerdict(a netip.Addr, owner Owner) portVerdict {
	if cidr, ex := s.excluded(a); ex {
		if cidr {
			return portExcluded
		}
		if shared, _ := owner(a); !shared {
			return portExcluded
		}
	}
	if s.InScopeIP(a) {
		return portEligible
	}
	if shared, known := owner(a); shared || !known {
		return portShared
	}
	if s.hostAddrs[a] {
		return portEligible
	}
	return portOutside
}

// Netblocks returns the in-scope netblocks.
func (s *Scope) Netblocks() []netip.Prefix { return slices.Clone(s.netblocks) }

// HasASN checks whether a canonical ASN such as "AS123" is an --asn input.
func (s *Scope) HasASN(key string) bool { return s.asns[key] }

// MatchesOrg applies orgname's word matching to the --org inputs.
func (s *Scope) MatchesOrg(name string) bool {
	return slices.ContainsFunc(s.orgs, func(org orgname.Org) bool { return org.Matches(name) })
}

// HasNetblock reports whether key, a CIDR, is one of the in-scope netblocks.
func (s *Scope) HasNetblock(key string) bool {
	p, err := netip.ParsePrefix(key)
	return err == nil && s.blockSet[p.Masked()]
}

// InsideNetblock reports whether an in-scope netblock other than p itself contains p.
func (s *Scope) InsideNetblock(p netip.Prefix) bool {
	for _, bits := range s.blockBits {
		if bits >= p.Bits() {
			return false
		}
		if w, err := p.Addr().Prefix(bits); err == nil && s.blockSet[w] {
			return true
		}
	}
	return false
}

// ipv4Range is an inclusive range of IPv4 addresses held as integers.
type ipv4Range struct{ lo, hi uint64 }

// ipv4Ranges merges overlapping and adjacent netblocks into sorted, disjoint IPv4 ranges.
func (s *Scope) ipv4Ranges() []ipv4Range {
	var ivs []ipv4Range
	for _, p := range s.netblocks {
		if !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		b := p.Addr().As4()
		lo := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		ivs = append(ivs, ipv4Range{lo, lo + (1 << (32 - p.Bits())) - 1})
	}
	slices.SortFunc(ivs, func(a, b ipv4Range) int { return cmp.Compare(a.lo, b.lo) })
	var out []ipv4Range
	for _, r := range ivs {
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

// IPv4AddressCount counts unique in-scope IPv4 addresses, including overlapping netblocks only
// once.
func (s *Scope) IPv4AddressCount() uint64 {
	var total uint64
	for _, r := range s.ipv4Ranges() {
		total += r.hi - r.lo + 1
	}
	return total
}

// IPv4Addrs yields the addresses counted by IPv4AddressCount in ascending order.
func (s *Scope) IPv4Addrs() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		for _, r := range s.ipv4Ranges() {
			for v := r.lo; v <= r.hi; v++ {
				if !yield(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})) {
					return
				}
			}
		}
	}
}

// OwnerUnit groups origin-AS lookups by /24 for IPv4 and /48 for IPv6, since longer prefixes
// are filtered from global routing. A narrower in-scope netblock takes precedence. Addresses
// outside all in-scope netblocks return ok=false.
func (s *Scope) OwnerUnit(a netip.Addr) (unit netip.Prefix, ok bool) {
	a = a.Unmap()
	var holder netip.Prefix // the smallest in-scope netblock holding the address
	for _, p := range s.netblocks {
		if p.Contains(a) && (!ok || p.Bits() > holder.Bits()) {
			holder, ok = p, true
		}
	}
	if !ok {
		return netip.Prefix{}, false
	}
	widest := 24
	if a.Is6() {
		widest = 48
	}
	if holder.Bits() > widest {
		return holder.Masked(), true
	}
	return netip.PrefixFrom(a, widest).Masked(), true
}
