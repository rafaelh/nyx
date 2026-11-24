// Package dns implements public-resolver procedures for resolution, wildcards, name generation,
// reverse DNS, ownership and root records. They are ThirdParty procedures and run in passive mode.
package dns

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// base is the contract shared by the DNS procedures: no third-party hosts, always configured.
type base struct{ name string }

func (b base) Name() string                    { return b.name }
func (base) Contact() run.Contact              { return run.ThirdParty }
func (base) Sources() []string                 { return nil }
func (base) Configured(run.Env) (bool, string) { return true, "" }

// lookup runs one query. Anything that is not a DNS answer is an error: a
// timeout is a transient failure, never a result.
func lookup(ctx context.Context, e egress.Clients, name string, qtype uint16) (egress.DNSResult, error) {
	res, err := e.DNS.Query(ctx, name, qtype)
	if err != nil {
		return res, fmt.Errorf("%s: %w", name, err)
	}
	return res, nil
}

func sortedStrings(addrs []netip.Addr) []string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	slices.Sort(out)
	return slices.Compact(out)
}
