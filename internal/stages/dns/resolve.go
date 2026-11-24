package dns

import (
	"context"
	"iter"
	"net/netip"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
)

// Resolve queries A/AAAA for input roots and in-scope/excluded names. Address answers stay
// associated with the queried name even when CNAMEs change the answer owner.
type Resolve struct{ base }

// NewResolve returns the resolve stage.
func NewResolve() *Resolve { return &Resolve{base{"resolve"}} }

// Checks yields one check per resolvable hostname.
func (*Resolve) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, h := range v.ResolvableHostnames() {
			if !yield(run.Check{Key: h, Input: h}, nil) {
				return
			}
		}
	}
}

// Run resolves the name. NXDOMAIN, NODATA and SERVFAIL are results recorded as
// kind unresolved; a timeout is an error.
func (*Resolve) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	name := c.Key
	a, err := lookup(ctx, e, name, egress.TypeA)
	if err != nil {
		return nil, err
	}
	aaaa, err := lookup(ctx, e, name, egress.TypeAAAA)
	if err != nil {
		return nil, err
	}
	var obs []run.Observation
	links := map[egress.CNAME]bool{}
	for _, res := range []egress.DNSResult{a, aaaa} {
		for _, l := range res.CNAMEs {
			if !links[l] {
				links[l] = true
				obs = append(obs, kinds.Resolution.Obs(kinds.ResolutionAttrs{Name: l.Name, Type: "CNAME", Value: l.Target}))
			}
		}
	}
	seen := map[netip.Addr]bool{}
	for _, res := range []egress.DNSResult{a, aaaa} {
		for _, addr := range res.Addrs() {
			if seen[addr] {
				continue
			}
			seen[addr] = true
			typ := "AAAA"
			if addr.Is4() {
				typ = "A"
			}
			obs = append(obs,
				kinds.Resolution.Obs(kinds.ResolutionAttrs{Name: name, Type: typ, Value: addr.String()}),
				kinds.IP.Obs(addr.String()))
		}
	}
	if len(seen) == 0 {
		obs = append(obs, kinds.Unresolved.Obs(name, kinds.UnresolvedAttrs{RCode: rcodeName(a, aaaa)}))
	}
	return obs, nil
}

// rcodeName prioritises NXDOMAIN, then either query's SERVFAIL, otherwise NODATA when no
// address exists.
func rcodeName(a, aaaa egress.DNSResult) string {
	switch {
	case a.RCode == egress.RCodeNXDomain:
		return "NXDOMAIN"
	case a.RCode == egress.RCodeServFail || aaaa.RCode == egress.RCodeServFail:
		return "SERVFAIL"
	}
	return "NODATA"
}
