// Package serveraddr resolves DNS/mail servers for SelfHosted attribution through public DNS.
// Its server_address records cannot grant target contact or probe eligibility.
package serveraddr

import (
	"context"
	"slices"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
)

// KeyToken versions parent jobs so older engagements collect server addresses once after
// upgrading.
const KeyToken = "|addrs"

// Observations resolves only servers whose addresses can affect inventory.AddressDecides.
// Timeout/SERVFAIL produces no addresses without failing the parent job. Context cancellation
// is the only returned error.
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
		obs = append(obs, kinds.ServerAddress.Obs(kinds.ServerAddressAttrs{Host: host, Addr: a}))
	}
	return obs, nil
}
