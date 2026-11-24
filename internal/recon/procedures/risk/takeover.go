package risk

import (
	"context"
	"fmt"
	"iter"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// Takeover checks live provider-backed services against unclaimed-resource HTTP fingerprints.
// Findings derives DNS-only evidence without another request.
type Takeover struct{}

// NewTakeover returns the takeover procedure.
func NewTakeover() *Takeover { return &Takeover{} }

func (*Takeover) Name() string                      { return "takeover" }
func (*Takeover) Contact() run.Contact              { return run.Target }
func (*Takeover) Sources() []string                 { return nil }
func (*Takeover) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedJobs replaces evidence from edited provider fingerprints.
func (*Takeover) RetiresUnlistedJobs() {}

type takeoverInput struct {
	service string // the web_service key
	svc     egress.Service
	ph      inventory.ProviderHost
}

// Jobs versions each visible service/fingerprint pair with the entry hash, limiting reruns to
// edited fingerprints.
func (*Takeover) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		byHost := map[string][]inventory.ProviderHost{}
		for _, ph := range v.ProviderHosts() {
			if ph.Entry.Body != "" {
				byHost[ph.Hostname] = append(byHost[ph.Hostname], ph)
			}
		}
		for _, ws := range v.WebServices() {
			for _, ph := range byHost[ws.Svc.Host] {
				in := takeoverInput{service: ws.Key, svc: ws.Svc, ph: ph}
				if !yield(run.Job{Key: fmt.Sprintf("%s|fp=%s", ws.Key, ph.Entry.Hash()), Input: in}, nil) {
					return
				}
			}
		}
	}
}

// Run records takeover_http for a matching root response. Nonmatches/refusals complete empty;
// transport failures remain retryable.
func (*Takeover) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(takeoverInput)
	res, err := e.HTTP.Get(ctx, egress.Root(in.svc.Host, in.svc.Scheme, in.svc.Port))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Key, err)
	}
	r, ok := res.(egress.Response)
	if !ok || !in.ph.Entry.BodyMatches(r.Body) {
		return nil, nil
	}
	return []run.Observation{kinds.TakeoverHTTP.Obs(in.service, kinds.TakeoverHTTPAttrs{
		Host: in.svc.Host, URL: in.service + "/", Status: r.Status, Service: in.service,
		Provider: in.ph.Provider, ProviderService: in.ph.Service, CNAME: in.ph.CNAME,
	})}, nil
}
