package web

import (
	"context"
	"fmt"
	"iter"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/origin"
	"github.com/rafaelh/nyx/internal/run"
)

// OriginCheck requests a candidate address using the fronted hostname's SNI and Host header. It
// shares pairs with origin findings and jobs only contactable candidates with a successful
// HTTPS baseline. Title/certificate hashes version jobs; obsolete jobs retire so changed
// baselines cannot keep old confirmation evidence.
type OriginCheck struct{}

// NewOriginCheck returns the origincheck procedure.
func NewOriginCheck() *OriginCheck { return &OriginCheck{} }

func (*OriginCheck) Name() string                      { return "origincheck" }
func (*OriginCheck) Contact() run.Contact              { return run.Target }
func (*OriginCheck) Sources() []string                 { return nil }
func (*OriginCheck) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedJobs removes evidence from completed pairs no longer yielded.
func (*OriginCheck) RetiresUnlistedJobs() {}

// Jobs requires a contactable pair and a successful fronted-host HTTPS baseline.
func (*OriginCheck) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		for _, p := range v.OriginPairs() {
			if ctx.Err() != nil {
				return
			}
			if !p.Contactable || !p.Probed() {
				continue
			}
			if !yield(run.Job{Key: p.JobKey(), Input: p}, nil) {
				return
			}
		}
	}
}

// Run tries HTTPS, falling back to HTTP only when 443 gives no answer. TLS failure counts as an
// answer, so it does not trigger fallback. Responses are recorded; no answer completes without
// evidence.
func (*OriginCheck) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	p := c.Input.(origin.Pair)
	for _, scheme := range []string{"https", "http"} {
		res, err := e.HTTP.Get(ctx, egress.OriginCheck(p.Host, scheme, p.Addr))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Key, err)
		}
		switch r := res.(type) {
		case egress.Response:
			a := kinds.OriginCheckAttrs{Host: p.Host, Addr: p.Addr.String(), Scheme: scheme, Status: r.Status, BodyLen: len(r.Body)}
			if pg, ok := newHop(r).page(); ok {
				a.Title = pg.title()
			}
			if len(r.PeerCerts) > 0 {
				a.CertNamesHost = r.PeerCerts[0].VerifyHostname(p.Host) == nil
			}
			return []run.Observation{kinds.OriginCheck.Obs(a)}, nil
		case egress.NoService:
			if scheme == "https" && r.Reason != egress.NoServiceTLSFailed {
				continue
			}
			return nil, nil
		default:
			// Enumeration and egress share policy. Retry a disagreement rather than
			// permanently completing the pair without evidence.
			return nil, fmt.Errorf("%s refused: %v", c.Key, res)
		}
	}
	return nil, nil
}
