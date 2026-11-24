package risk

import (
	"context"
	"fmt"
	"iter"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
)

// Takeover checks live provider-backed services against unclaimed-resource HTTP fingerprints.
// Findings derives DNS-only evidence without another request.
type Takeover struct{}

// NewTakeover returns the takeover stage.
func NewTakeover() *Takeover { return &Takeover{} }

func (*Takeover) Name() string                      { return "takeover" }
func (*Takeover) Contact() run.Contact              { return run.Target }
func (*Takeover) Sources() []string                 { return nil }
func (*Takeover) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedChecks replaces evidence from edited provider fingerprints.
func (*Takeover) RetiresUnlistedChecks() {}

type takeoverInput struct {
	service string // the web_service key
	svc     egress.Service
	ph      inventory.ProviderHost
}

// Checks versions each visible service/fingerprint pair with the entry hash, limiting reruns to
// edited fingerprints.
func (*Takeover) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		byHost := map[string][]inventory.ProviderHost{}
		for _, ph := range v.ProviderHosts() {
			if ph.Entry.Body != "" {
				byHost[ph.Hostname] = append(byHost[ph.Hostname], ph)
			}
		}
		for _, ws := range v.WebServices() {
			for _, ph := range byHost[ws.Svc.Host] {
				in := takeoverInput{service: ws.Key, svc: ws.Svc, ph: ph}
				if !yield(run.Check{Key: fmt.Sprintf("%s|fp=%s", ws.Key, ph.Entry.Hash()), Input: in}, nil) {
					return
				}
			}
		}
	}
}

// Run records takeover_http for a matching root response. Nonmatches/refusals complete empty;
// transport failures remain retryable.
func (*Takeover) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
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
