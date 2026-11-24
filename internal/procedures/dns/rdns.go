package dns

import (
	"context"
	"iter"
	"net/netip"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/run"
)

// RDNS sweeps guarded in-scope IPv4 netblocks and looks up other discovered in-scope-netblock
// addresses individually, covering IPv6 without expanding it.
type RDNS struct{ base }

// NewRDNS returns the rdns procedure.
func NewRDNS() *RDNS { return &RDNS{base{"rdns"}} }

// CandidateSources: reverse DNS is a family of its own.
func (*RDNS) CandidateSources() map[string]string { return map[string]string{"rdns": "rdns"} }

// Jobs yields one job per address.
func (*RDNS) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		sc := v.Scope()
		for a := range sc.IPv4Addrs() {
			if !yield(run.Job{Key: a.String(), Input: a}, nil) {
				return
			}
		}
		// IPv4 netblock addresses were all yielded above.
		for _, a := range v.IPs(func(a netip.Addr) bool { return !a.Is4() && sc.InScopeIP(a) }) {
			if !yield(run.Job{Key: a.String(), Input: a}, nil) {
				return
			}
		}
	}
}

// Run queries the PTR record. No answer is a completed job.
func (*RDNS) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	addr := c.Input.(netip.Addr)
	res, err := lookup(ctx, e, dnsname.ReverseName(addr), egress.TypePTR)
	if err != nil {
		return nil, err
	}
	var obs []run.Observation
	seen := map[string]bool{}
	for _, a := range res.Answers {
		if a.Type != "PTR" {
			continue
		}
		host := dnsname.Normalise(a.Value)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		obs = append(obs,
			kinds.Hostname.Obs(host, kinds.HostnameAttrs{}),
			kinds.IP.Obs(addr.String()),
			kinds.IPHostname.Obs(kinds.IPHostnameAttrs{IP: addr.String(), Hostname: host, Source: "rdns"}))
	}
	return obs, nil
}
