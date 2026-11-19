// Package asn expands input ASNs into announced netblocks using RIPEstat.
package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/url"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

// Stage is the asn stage. A netblock it observes under a check for an input
// ASN is in scope.
type Stage struct{}

// New returns the asn stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string                      { return "asn" }
func (*Stage) Contact() run.Contact              { return run.ThirdParty }
func (*Stage) Sources() []string                 { return []string{"stat.ripe.net"} }
func (*Stage) Configured(run.Env) (bool, string) { return true, "" }

// Checks yields one check per input ASN, keyed "AS<n>".
func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, a := range v.Inputs().ASNs {
			if !yield(run.Check{Key: a, Input: a}, nil) {
				return
			}
		}
	}
}

// Announced returns the prefixes RIPEstat says asn announces. Anything but a
// well-formed "ok" answer is an error.
func Announced(ctx context.Context, e egress.Clients, asn string) ([]string, error) {
	q := url.Values{"resource": {asn}, "sourceapp": {"nyx"}}
	raw, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{
		Method: "GET", URL: "https://stat.ripe.net/data/announced-prefixes/data.json?" + q.Encode(),
	})
	if err != nil {
		return nil, fmt.Errorf("RIPEstat: %w", err)
	}
	var body struct {
		Status string `json:"status"`
		Data   struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("unreadable RIPEstat response: %w", err)
	}
	if body.Status != "ok" {
		return nil, fmt.Errorf("RIPEstat status %q", body.Status)
	}
	var out []string
	for _, p := range body.Data.Prefixes {
		if p := strings.TrimSpace(p.Prefix); p != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

// Run fetches the prefixes announced by the ASN. Anything but a well-formed
// "ok" answer is a transient failure.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	asn := c.Key
	prefixes, err := Announced(ctx, e, asn)
	if err != nil {
		return nil, fmt.Errorf("asn %s: %w", asn, err)
	}
	obs := make([]run.Observation, 0, len(prefixes))
	for _, p := range prefixes {
		obs = append(obs, kinds.Netblock.Obs(p, kinds.NetblockAttrs{ASN: asn}))
	}
	return obs, nil
}
