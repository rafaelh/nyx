// Package serveraddr resolves DNS/mail servers for SelfHosted attribution through public DNS.
// Its server_address records cannot grant target contact or probe eligibility.
package serveraddr

import (
	"context"
	"net/netip"
	"slices"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/scope"
)

// KeyToken versions parent jobs so older engagements collect server addresses once after
// upgrading.
const KeyToken = "|addrs"

// Observations resolves only servers for which inventory.AddressDecides holds, as only their
// addresses can change inventory.SelfHosted. Only addresses owned by the server's name or its
// alias chain are kept. Timeout/SERVFAIL produces no addresses
// without failing the parent job. Context cancellation is the only returned error.
func Observations(ctx context.Context, e egress.Clients, sc *scope.Scope, host string) ([]run.Observation, error) {
	host = dnsname.Normalise(host)
	if host == "" {
		return nil, nil
	}
	if _, err := netip.ParseAddr(host); err == nil || !inventory.AddressDecides(host, sc, provider.Default()) {
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
		addrs = append(addrs, owned(host, res)...)
	}
	slices.Sort(addrs)
	obs := make([]run.Observation, 0, len(addrs))
	for _, a := range slices.Compact(addrs) {
		obs = append(obs, kinds.ServerAddress.Obs(kinds.ServerAddressAttrs{Host: host, Addr: a}))
	}
	return obs, nil
}

// owned returns the A/AAAA values whose owner is the host or a name its alias chain reaches,
// ignoring any other address an answer carries.
func owned(host string, res egress.DNSResult) []string {
	chain := map[string]bool{host: true}
	for _, c := range res.CNAMEs {
		if chain[c.Name] {
			chain[c.Target] = true
		}
	}
	var out []string
	for _, a := range res.Answers {
		if a.Type != "A" && a.Type != "AAAA" || !chain[a.Name] {
			continue
		}
		if addr, err := netip.ParseAddr(a.Value); err == nil {
			out = append(out, addr.Unmap().String())
		}
	}
	return out
}
