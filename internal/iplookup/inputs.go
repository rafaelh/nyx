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

// Class is what an input is.
type Class int

// The classes of an input.
const (
	ClassInvalid  Class = iota // not an address, CIDR or hostname: Err says why
	ClassAddress               // an IPv4 or IPv6 address
	ClassCIDR                  // a range of addresses
	ClassHostname              // a name that stands for the addresses it resolves to
)

// Input is one argument, or one line of stdin, as it was classified.
type Input struct {
	// Raw is the input as given, trimmed of surrounding space.
	Raw   string
	Class Class
	// Addr is the address of a ClassAddress input, unmapped and without a zone.
	Addr netip.Addr
	// Prefix is the range of a ClassCIDR input, its host bits masked.
	Prefix netip.Prefix
	// Hostname is the name of a ClassHostname input: lower case, punycode, with no trailing dot.
	Hostname string
	// SingleLabel is true for a ClassHostname input of one label, which only this machine's
	// resolver may resolve.
	SingleLabel bool
	// Err is why a ClassInvalid input is: INVALID_INPUT, with a hint.
	Err *clierr.Error
}

// Plan is the inputs of a call, classified, in the order given.
type Plan struct {
	Inputs []Input
}

// ParseInputs classifies each of the raw inputs, in the order given. active says whether a
// single-label name is a hostname. Surrounding space is trimmed. An address is unmapped (an
// IPv4-mapped IPv6 address is the IPv4 address) and loses its zone: a zoned link-local address is
// reported but never contacted, so the zone is no use to it. A CIDR has its host bits masked.
func ParseInputs(raw []string, active bool) Plan {
	p := Plan{Inputs: make([]Input, len(raw))}
	for i, r := range raw {
		p.Inputs[i] = classify(r, active)
	}
	return p
}

// guide is the hint of an input that is none of an address, a CIDR or a hostname.
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

// Problems are the invalid inputs as problems of the "input" argument, in the order given, for a
// call that exits 2 with every one of them.
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

// Hostnames are the distinct hostnames to resolve, in the order they were given.
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

// maxCount is where a count of addresses stops growing: far past the cap, and far short of an
// overflow however many ranges are added.
const maxCount = 1 << 40

// size is how many addresses the prefix holds, as a count that stops at maxCount.
func size(p netip.Prefix) int {
	host := p.Addr().BitLen() - p.Bits()
	if host >= 40 {
		return maxCount
	}
	return 1 << host
}

// LiteralCount is how many distinct addresses the literal addresses and the CIDRs give, counted
// without expanding any CIDR, so a /8 or a /0 is a number and never a list. The count stops at a
// large number (it only has to say whether the cap is passed).
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
	// Prefixes nest or are apart. Sorted by address, then by size, a prefix is covered exactly
	// when the last one kept holds it.
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

// ProvisionalCount is the number of addresses the deadline is first worked out from, before the
// hostnames resolve: each hostname and each address counts as one and each CIDR as its size,
// whether or not they repeat. Invalid inputs count nothing.
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

// The ways an address is found. An address found more than one way has each flag.
const (
	FoundLiteral   Found = 1 << iota // given as an address
	FoundCIDR                        // inside a CIDR
	FoundPublicDNS                   // a hostname's answer from the public resolvers
	FoundLocalDNS                    // a hostname's answer from this machine's resolver
)

// OnlyPublicDNS reports whether only the public resolvers gave the address: a hostile name could
// otherwise point --active at the operator's own machine, so a non-public address found only this
// way is not contacted.
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

// Addresses is every distinct address of the plan, once each, at its first appearance as the
// inputs are read in order: a literal is one address, a CIDR gives its addresses in address order
// (its first and last included), and a hostname gives its resolved addresses in resolved at the
// place of the hostname, IPv4 first then IPv6, each in address order. A later appearance adds its
// flag and its hostname to the address. A hostname with no entry in resolved gives none, and the
// map is keyed by Input.Hostname.
//
// It fails with CapError, and gives no list, when the literal addresses and CIDRs alone pass
// MaxAddresses (decided by size before any CIDR is expanded) or when the whole list does.
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

// capError is CapError with the plan's invalid inputs listed before the cap, so that a call that
// exits 2 reports every one of its problems together.
func (p Plan) capError(count int, resolved bool) *clierr.Error {
	return append(p.Problems(), CapProblem(count, resolved)).Usage("")
}

// canonical is a hostname's addresses unmapped and without a zone, in address order (IPv4 sorts
// before IPv6), in a new slice.
func canonical(addrs []netip.Addr) []netip.Addr {
	as := make([]netip.Addr, len(addrs))
	for i, a := range addrs {
		as[i] = a.Unmap().WithZone("")
	}
	slices.SortFunc(as, netip.Addr.Compare)
	return as
}

// CapProblem is the problem of a call that holds count addresses, which is more than MaxAddresses.
// resolved says the count includes what the hostnames resolved to.
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

// CapError is CapProblem as the error of a call, which exits 2.
func CapError(count int, resolved bool) *clierr.Error {
	return clierr.Problems{CapProblem(count, resolved)}.Usage("")
}
