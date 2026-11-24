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

// NetblockOwner queries Cymru once per occupied /24 (IPv4), /48 (IPv6), or narrower in-scope
// netblock. These units reflect global routing prefix limits.
//
// Results use netblock_owner solely for abuse findings. Scope and contact decisions do not read
// them. ipowner separately records per-address ownership outside these blocks as ip_owner.
type NetblockOwner struct{ base }

// NewNetblockOwner returns the netblockowner procedure.
func NewNetblockOwner() *NetblockOwner { return &NetblockOwner{base{"netblockowner"}} }

// Jobs lists occupied ownership units in address order, including history-only IPs because
// the answer describes the entire unit.
func (*NetblockOwner) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
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
			if !yield(run.Job{Key: u.String(), Input: u}, nil) {
				return
			}
		}
	}
}

// Run queries the unit's first address. NXDOMAIN and AS0 complete without a record; other
// failures are retried later.
func (*NetblockOwner) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
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
