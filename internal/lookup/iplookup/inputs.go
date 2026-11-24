package iplookup

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/input"
)

// MaxAddresses is the most distinct addresses one call holds.
const MaxAddresses = 256

// Class identifies an input's parsed category.
type Class int

// The classes of an input.
const (
	ClassInvalid  Class = iota // not an address, CIDR or hostname: Err says why
	ClassAddress               // an IPv4 or IPv6 address
	ClassCIDR                  // a range of addresses
	ClassHostname              // a name that stands for the addresses it resolves to
)

// Input holds one classified argument or stdin line.
type Input struct {
	// Raw preserves the input text after trimming outer whitespace.
	Raw   string
	Class Class
	// Addr is the address of a ClassAddress input, unmapped and without a zone.
	Addr netip.Addr
	// Prefix is the range of a ClassCIDR input, its host bits masked.
	Prefix netip.Prefix
	// Hostname is the name of a ClassHostname input: lower case, punycode, with no trailing dot.
	Hostname string
	// SingleLabel restricts this hostname to local resolution.
	SingleLabel bool
	// Err is why a ClassInvalid input is: INVALID_INPUT, with a hint.
	Err *clierr.Error
}

// Plan preserves classified inputs in invocation order.
type Plan struct {
	Inputs []Input
}

// ParseInputs trims and classifies inputs in order. Active mode permits single-label hostnames.
// Addresses are unmapped and stripped of zones; zoned non-public addresses are reported without
// contact. CIDRs have host bits masked.
func ParseInputs(raw []string, active bool) Plan {
	p := Plan{Inputs: make([]Input, len(raw))}
	for i, r := range raw {
		p.Inputs[i] = classify(r, active)
	}
	return p
}

// guide explains accepted input forms for invalid values.
const guide = "give an address, a hostname or a CIDR, such as 192.0.2.1, example.com or 192.0.2.0/30"

// invalid is an invalid input.
func invalid(raw, message, hint string) Input {
	return Input{Raw: raw, Class: ClassInvalid, Err: &clierr.Error{Code: clierr.InvalidInput, Message: message, Hint: hint}}
}

func classify(raw string, active bool) Input {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return invalid(raw, "an input is empty", guide)
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		return Input{Raw: raw, Class: ClassAddress, Addr: a.Unmap().WithZone("")}
	}
	var cidrErr error
	if strings.Contains(raw, "/") {
		pfx, err := input.ParseCIDR(raw)
		if err == nil {
			if pfx.Addr().Is4In6() && pfx.Bits() >= 96 { // ::ffff:a.b.c.d/n is the IPv4 range
				pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96).Masked()
			}
			return Input{Raw: raw, Class: ClassCIDR, Prefix: pfx}
		}
		cidrErr = err
	}
	if host, ok := input.BareHost(raw); ok {
		return invalid(raw, fmt.Sprintf("invalid input %q: it has a scheme, a port or a path", raw), "use the bare host: "+host)
	}
	if cidrErr != nil {
		return invalid(raw, cidrErr.Error(), guide)
	}
	host, err := input.ParseHostname(raw, active)
	if err != nil {
		if _, single := input.ParseHostname(raw, true); single == nil && !active {
			return invalid(raw, err.Error(), "add --active to resolve single-label names through this machine's resolver")
		}
		return invalid(raw, err.Error(), guide)
	}
	return Input{Raw: raw, Class: ClassHostname, Hostname: host, SingleLabel: !strings.Contains(host, ".")}
}

// Problems returns ordered invalid-input details for combined usage errors.
func (p Plan) Problems() clierr.Problems {
	var out clierr.Problems
	for _, in := range p.Inputs {
		if in.Class == ClassInvalid {
			out.Add("input", in.Raw, in.Err.Message, in.Err.Hint)
		}
	}
	return out
}

// AllInvalid reports whether the plan has inputs and every one of them is invalid.
func (p Plan) AllInvalid() bool {
	return len(p.Inputs) > 0 && !slices.ContainsFunc(p.Inputs, func(in Input) bool { return in.Class != ClassInvalid })
}

// Hostnames returns distinct lookup names in input order.
func (p Plan) Hostnames() []Input {
	var out []Input
	seen := map[string]bool{}
	for _, in := range p.Inputs {
		if in.Class == ClassHostname && !seen[in.Hostname] {
			seen[in.Hostname] = true
			out = append(out, in)
		}
	}
	return out
}

// maxCount saturates address counts well beyond the cap but below possible overflow.
const maxCount = 1 << 40

// size counts prefix addresses, saturating at maxCount.
func size(p netip.Prefix) int {
	host := p.Addr().BitLen() - p.Bits()
	if host >= 40 {
		return maxCount
	}
	return 1 << host
}

// LiteralCount counts distinct literal/CIDR addresses without expanding ranges. It saturates
// once the count is large enough to exceed the cap, so even /0 needs no address list.
func (p Plan) LiteralCount() int {
	var prefixes []netip.Prefix
	var literals []netip.Addr
	for _, in := range p.Inputs {
		switch in.Class {
		case ClassCIDR:
			prefixes = append(prefixes, in.Prefix)
		case ClassAddress:
			literals = append(literals, in.Addr)
		case ClassInvalid, ClassHostname:
		}
	}
	// Sorted prefixes either nest or are disjoint, so only the last retained prefix can
	// cover the next.
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	var kept []netip.Prefix
	total := 0
	for _, pfx := range prefixes {
		if len(kept) > 0 && kept[len(kept)-1].Bits() <= pfx.Bits() && kept[len(kept)-1].Contains(pfx.Addr()) {
			continue
		}
		kept = append(kept, pfx)
		total = min(total+size(pfx), maxCount)
	}
	seen := map[netip.Addr]bool{}
	for _, a := range literals {
		if seen[a] || slices.ContainsFunc(kept, func(k netip.Prefix) bool { return k.Contains(a) }) {
			continue
		}
		seen[a] = true
		total = min(total+1, maxCount)
	}
	return total
}

// ProvisionalCount estimates the deadline before DNS: each literal or hostname counts once per
// occurrence; each CIDR contributes its size. Invalid inputs contribute zero.
func (p Plan) ProvisionalCount() int {
	total := 0
	for _, in := range p.Inputs {
		switch in.Class {
		case ClassAddress, ClassHostname:
			total++
		case ClassCIDR:
			total += size(in.Prefix)
		case ClassInvalid:
		}
		total = min(total, maxCount)
	}
	return total
}

// Found is how an address came to be in the call.
type Found uint8

// Discovery flags accumulate when several input forms produce the same address.
const (
	FoundLiteral   Found = 1 << iota // given as an address
	FoundCIDR                        // inside a CIDR
	FoundPublicDNS                   // a hostname's answer from the public resolvers
	FoundLocalDNS                    // a hostname's answer from this machine's resolver
)

// OnlyPublicDNS identifies addresses obtained solely through public resolvers. Active probing
// rejects non-public addresses found only this way to prevent hostile DNS pointing at the
// operator's machine.
func (f Found) OnlyPublicDNS() bool { return f == FoundPublicDNS }

// Address is one distinct address of the call.
type Address struct {
	Addr netip.Addr
	// Hostnames are the input hostnames that gave the address, in the order given; empty when
	// none did.
	Hostnames []string
	Found     Found
}

// Resolution is a hostname's addresses and where they came from.
type Resolution struct {
	Addrs []netip.Addr
	// Found is FoundPublicDNS or FoundLocalDNS.
	Found Found
}

// Addresses deduplicates in input order. CIDRs expand in address order including endpoints;
// hostname results replace their input position, sorted IPv4 before IPv6. Repeated addresses
// accumulate hostnames and discovery flags. resolved is keyed by Input.Hostname; missing
// entries contribute nothing.
//
// CapError returns no list if literal/CIDR counts exceed MaxAddresses before expansion, or
// resolved results exceed it afterwards.
func (p Plan) Addresses(resolved map[string]Resolution) ([]Address, error) {
	if n := p.LiteralCount(); n > MaxAddresses {
		return nil, p.capError(n, false)
	}
	var out []Address
	index := map[netip.Addr]int{}
	add := func(a netip.Addr, f Found, host string) {
		i, ok := index[a]
		if !ok {
			i = len(out)
			index[a] = i
			out = append(out, Address{Addr: a, Hostnames: []string{}})
		}
		out[i].Found |= f
		if host != "" && !slices.Contains(out[i].Hostnames, host) {
			out[i].Hostnames = append(out[i].Hostnames, host)
		}
	}
	for _, in := range p.Inputs {
		switch in.Class {
		case ClassAddress:
			add(in.Addr, FoundLiteral, "")
		case ClassCIDR:
			for a := in.Prefix.Addr(); in.Prefix.Contains(a); a = a.Next() {
				add(a.Unmap(), FoundCIDR, "")
			}
		case ClassInvalid:
		case ClassHostname:
			res := resolved[in.Hostname]
			for _, a := range canonical(res.Addrs) {
				add(a, res.Found, in.Hostname)
			}
		}
	}
	if len(out) > MaxAddresses {
		return nil, p.capError(len(out), true)
	}
	return out, nil
}

// capError combines invalid inputs before the cap problem so usage errors report all issues
// together.
func (p Plan) capError(count int, resolved bool) *clierr.Error {
	return append(p.Problems(), CapProblem(count, resolved)).Usage("")
}

// canonical copies, unmaps and deduplicates addresses, removing zones and sorting IPv4 before
// IPv6.
func canonical(addrs []netip.Addr) []netip.Addr {
	as := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		as[i] = a.Unmap().WithZone("")
	}
	slices.SortFunc(as, netip.Addr.Compare)
	return as
}

// CapProblem reports count exceeding MaxAddresses, distinguishing DNS-expanded totals when
// resolved is true.
func CapProblem(count int, resolved bool) clierr.Problem {
	shown := fmt.Sprintf("%d addresses", count)
	if count > 1<<20 {
		shown = "over a million addresses"
	}
	msg := fmt.Sprintf("the inputs give %s, and a call holds at most %d", shown, MaxAddresses)
	if resolved {
		msg = fmt.Sprintf("the inputs give %s once the hostnames resolve, and a call holds at most %d", shown, MaxAddresses)
	}
	return clierr.Problem{Name: "input", Message: msg, Hint: "split the inputs into calls of at most 256 addresses, or use a smaller CIDR"}
}

// CapError carries cap-validation problems for a usage failure.
func CapError(count int, resolved bool) *clierr.Error {
	return clierr.Problems{CapProblem(count, resolved)}.Usage("")
}
