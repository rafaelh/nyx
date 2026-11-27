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
	// Lookups holds the addresses of each candidate name's lookup, by name; nil when promotion
	// by address is off.
	Lookups map[string][]netip.Addr
	// MaxNamesPerAddress is the shared-hosting guard: an in-scope address listed by more of
	// the Lookups names than this brings none of them into scope.
	MaxNamesPerAddress int
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
	byAddr    map[string]byAddress // names in scope by address
	promotes  bool                 // Config.Lookups was given: promotion by address is on
	shared    []netip.Addr         // in-netblock addresses over the shared-hosting guard, sorted
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
		s.blockSet[p.Masked()] = true
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
	s.promote(c.Lookups, c.MaxNamesPerAddress)
	for h, addrs := range s.resolved {
		if c.WildcardOnly[h] || !s.NameInScope(h) {
			continue
		}
		for _, a := range addrs {
			s.hostAddrs[a] = true
		}
	}
	return s
}

// byAddress is the address that brings a name into scope, and the narrowest in-scope netblock
// holding it.
type byAddress struct {
	addr  netip.Addr
	block netip.Prefix
}

// promote works out the names in scope by address: of the looked-up names under no root and
// matching no name exclusion, each with an address inside an in-scope netblock that at most max
// of them list, none of whose addresses is in an excluded CIDR and that is not generic for any of
// its IPv4 addresses. A generic or CIDR-excluded name is still counted against the guard.
func (s *Scope) promote(lookups map[string][]netip.Addr, max int) {
	s.byAddr = map[string]byAddress{}
	s.promotes = lookups != nil
	if len(s.netblocks) == 0 {
		return
	}
	names := map[string][]netip.Addr{}
	listed := map[netip.Addr]int{} // the looked-up names of each in-netblock address
	for h, addrs := range lookups {
		h = dnsname.Normalise(h)
		if _, ok := s.matchName(h); ok || s.RootOf(h) != "" {
			continue
		}
		names[h] = addrs
		for _, a := range addrs {
			if s.InScopeIP(a) {
				listed[a]++
			}
		}
	}
	for a, n := range listed {
		if n > max {
			s.shared = append(s.shared, a)
		}
	}
	slices.SortFunc(s.shared, netip.Addr.Compare)
	for h, addrs := range names {
		var best netip.Addr
		for _, a := range addrs {
			if n, ok := listed[a]; ok && n <= max && (!best.IsValid() || a.Less(best)) {
				best = a
			}
		}
		if !best.IsValid() || slices.ContainsFunc(addrs, func(a netip.Addr) bool {
			_, excl := s.cidrOf(a)
			return excl || dnsname.Generic(h, a)
		}) {
			continue
		}
		block, _ := s.holder(best)
		s.byAddr[h] = byAddress{best, block.Masked()}
	}
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
// in scope (under an input root, or by an address of its candidate lookup) or a candidate.
func (s *Scope) ClassifyHost(host string) Classification {
	c := s.ClassifyName(host)
	if c.Class == Candidate && s.InScopeByAddress(host) {
		return Classification{InScope, ""}
	}
	return c
}

// NameInScope reports whether host is in scope by its name: under an input root and not
// excluded. A name in scope only by its address is not.
func (s *Scope) NameInScope(host string) bool { return s.ClassifyName(host).Class == InScope }

// ClassifyName classifies host by name exclusions, resolved addresses in excluded CIDRs and the
// input roots alone: a name in scope by address is a candidate here.
func (s *Scope) ClassifyName(host string) Classification {
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
	for _, bits := range s.blockBits {
		if p, err := a.Prefix(bits); err == nil && s.blockSet[p] {
			return true
		}
	}
	return false
}

// holder returns the narrowest in-scope netblock holding the address.
func (s *Scope) holder(a netip.Addr) (holder netip.Prefix, ok bool) {
	for _, p := range s.netblocks {
		if p.Contains(a) && (!ok || p.Bits() > holder.Bits()) {
			holder, ok = p, true
		}
	}
	return holder, ok
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

// ByAddress reports whether host is in scope by an address of its candidate lookup, with the
// lowest such address and the narrowest in-scope netblock holding it.
func (s *Scope) ByAddress(host string) (addr netip.Addr, block netip.Prefix, ok bool) {
	b, ok := s.byAddr[dnsname.Normalise(host)]
	return b.addr, b.block, ok
}

// PromotesByAddress reports whether names can enter scope by address: promotion is on and there
// is an in-scope netblock.
func (s *Scope) PromotesByAddress() bool { return s.promotes && len(s.netblocks) > 0 }

// InScopeByAddress reports whether host is in scope by an address of its candidate lookup.
func (s *Scope) InScopeByAddress(host string) bool {
	_, ok := s.byAddr[dnsname.Normalise(host)]
	return ok
}

// SharedHosting returns, sorted, the in-scope addresses listed by more lookup names than the
// shared-hosting guard allows.
func (s *Scope) SharedHosting() []netip.Addr { return slices.Clone(s.shared) }

// DialAddrs returns the addresses host may be dialled at: for a name in scope by address, its
// resolved addresses inside an in-scope netblock; for any other name, Addrs.
func (s *Scope) DialAddrs(host string) []netip.Addr {
	addrs := s.Addrs(host)
	if !s.InScopeByAddress(host) {
		return addrs
	}
	return slices.DeleteFunc(slices.Clone(addrs), func(a netip.Addr) bool { return !s.InScopeIP(a) })
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
	holder, ok := s.holder(a)
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
