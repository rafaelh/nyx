// Package serveraddr looks up the addresses of the name servers and mail hosts
// that dnsroot and email find, so that inventory.SelfHosted can tell whether the
// organisation runs them itself. The public resolvers are asked, never the host,
// and the answers are kept as server_address records that nothing deciding
// contact reads.
package serveraddr

import (
	"context"
	"slices"

	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
)

// KeyToken ends the key of every check that looks up server addresses: a check
// made before they were looked up does not have it, so an engagement from before
// makes it again, once.
const KeyToken = "|addrs"

// Observations returns a server_address observation for each A and AAAA record
// of a name server or mail host whose addresses inventory.AddressDecides; nothing
// is looked up for any other host, or for an address. The lookup is best-effort:
// a SERVFAIL or a timeout gives no addresses, so a server whose domain is broken
// cannot fail the check that found it. The only error is a cancelled context.
func Observations(ctx context.Context, e egress.Clients, sc *scope.Scope, host string) ([]run.Observation, error) {
	host = dnsname.Normalise(host)
	if host == "" {
		return nil, nil
	}
	if _, ok := input.IPLiteral(host); ok || !inventory.AddressDecides(host, sc, provider.Default()) {
		return nil, nil
	}
	var addrs []string
	for _, qtype := range []uint16{egress.TypeA, egress.TypeAAAA} {
		res, err := e.DNS.Query(ctx, host, qtype)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if res.RCode == egress.RCodeServFail {
			continue
		}
		for _, a := range res.Addrs() {
			addrs = append(addrs, a.String())
		}
	}
	slices.Sort(addrs)
	obs := make([]run.Observation, 0, len(addrs))
	for _, a := range slices.Compact(addrs) {
		obs = append(obs, kinds.ServerAddress.Obs(kinds.ServerAddressKey(host, a), kinds.ServerAddressAttrs{Host: host, Addr: a}))
	}
	return obs, nil
}
