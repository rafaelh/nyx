package dns

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"slices"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/ipsource"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
)

// NetblockOwner finds the origin AS of the addresses inside the in-scope netblocks, from Team
// Cymru through the public resolvers, once for each covering /24 (IPv4) or /48 (IPv6), or once
// for an in-scope netblock that is smaller (see scope.OwnerUnit). Prefixes longer than those are
// filtered from the global routing table, so one answer is the origin of the whole unit.
//
// The AS is kept in its own kind, netblock_owner, which the scope build never reads: it is used
// only to flag an address in an abusive AS, and changes nothing about whether an address is shared
// provider infrastructure, contacted, excluded or a candidate. ipowner does the same for addresses
// outside the netblocks, one lookup each, and records them as ip_owner.
type NetblockOwner struct{ base }

// NewNetblockOwner returns the netblockowner stage.
func NewNetblockOwner() *NetblockOwner { return &NetblockOwner{base{"netblockowner"}} }

// Checks yields one check per unit that holds a current ip record, in address order. An address
// that only DNS history names is not left out: the answer applies to the whole unit, and ipowner
// asks about such addresses too.
func (*NetblockOwner) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		sc := v.Scope()
		set := map[netip.Prefix]bool{}
		for _, a := range v.IPs(func(netip.Addr) bool { return true }) {
			if unit, ok := sc.OwnerUnit(a); ok { // ok only inside an in-scope netblock
				set[unit] = true
			}
		}
		units := slices.SortedFunc(maps.Keys(set), func(a, b netip.Prefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})
		for _, u := range units {
			if !yield(run.Check{Key: u.String(), Input: u}, nil) {
				return
			}
		}
	}
}

// Run asks for the origin AS of the unit's first address. A unit Team Cymru does not know
// (NXDOMAIN, AS0) is a completed check with no record; any other failure is transient.
func (*NetblockOwner) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	unit := c.Input.(netip.Prefix)
	owner, found, err := ipsource.Origin(ctx, e.DNS, unit.Addr())
	if err != nil {
		return nil, fmt.Errorf("owner of %s: %w", unit, err)
	}
	if !found {
		return nil, nil
	}
	return []run.Observation{kinds.NetblockOwner.Obs(unit.String(), kinds.NetblockOwnerAttrs{ASN: owner.ASN, Prefix: owner.Prefix})}, nil
}
