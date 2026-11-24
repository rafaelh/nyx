// Package asn expands input ASNs into announced netblocks using RIPEstat.
package asn

import (
	"context"
	"fmt"
	"iter"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/procedures/httpsrc"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// Procedure expands input ASNs; observed blocks enter scope through that relationship.
type Procedure struct{}

// New returns the asn procedure.
func New() *Procedure { return &Procedure{} }

func (*Procedure) Name() string                      { return "asn" }
func (*Procedure) Contact() run.Contact              { return run.ThirdParty }
func (*Procedure) Sources() []string                 { return []string{"stat.ripe.net"} }
func (*Procedure) Configured(run.Env) (bool, string) { return true, "" }

// ExpandsInputASNs declares netblock observations as input-ASN scope expansion.
func (*Procedure) ExpandsInputASNs() {}

// Jobs yields one job per input ASN, keyed "AS<n>".
func (*Procedure) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return run.JobsOf(v.Inputs().ASNs, func(a string) run.Job { return run.Job{Key: a, Input: a} })
}

// Run fetches the prefixes announced by the ASN. Anything but a well-formed
// "ok" answer is a transient failure.
func (*Procedure) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	asn := c.Key
	prefixes, err := httpsrc.Announced(ctx, e, asn)
	if err != nil {
		return nil, fmt.Errorf("asn %s: %w", asn, err)
	}
	obs := make([]run.Observation, 0, len(prefixes))
	for _, p := range prefixes {
		obs = append(obs, kinds.Netblock.Obs(p, kinds.NetblockAttrs{ASN: asn}))
	}
	return obs, nil
}
