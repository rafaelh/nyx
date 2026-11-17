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

// OriginCheck is the origincheck stage: for a hostname behind a CDN or WAF and an address that may
// be its origin, one GET of "/" to that address with the hostname as the TLS server name and the
// Host header, to see whether the address serves the site. The same pairs are the origin-exposure
// findings, which decide from the answer whether the exposure is confirmed.
//
// A pair is checked only when the candidate may be contacted (see origin.Candidate) and the probe
// has a 2xx status for the hostname's HTTPS service. The check key carries a hash of the probe's
// title and certificate subject, and the stage retires the checks it no longer yields, so a changed
// title or certificate checks the pair again and the old answer stops being evidence.
type OriginCheck struct{}

// NewOriginCheck returns the origincheck stage.
func NewOriginCheck() *OriginCheck { return &OriginCheck{} }

func (*OriginCheck) Name() string                      { return "origincheck" }
func (*OriginCheck) Contact() run.Contact              { return run.Target }
func (*OriginCheck) Sources() []string                 { return nil }
func (*OriginCheck) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedChecks makes the runner retire a completed check the stage no longer yields.
func (*OriginCheck) RetiresUnlistedChecks() {}

// Checks yields each contactable pair whose fronted host the probe saw answer 2xx.
func (*OriginCheck) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, p := range v.OriginPairs() {
			if ctx.Err() != nil {
				return
			}
			if !p.Contactable || !p.Probed() {
				continue
			}
			if !yield(run.Check{Key: p.CheckKey(), Input: p}, nil) {
				return
			}
		}
	}
}

// Run sends one GET over HTTPS, and one over HTTP only if nothing answered on 443 (a TLS failure
// is an answer of a kind: the address speaks something else on 443, and asking on 80 would be a
// different question). Any response is recorded; no answer is a completed check with nothing.
func (*OriginCheck) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
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
			return []run.Observation{kinds.OriginCheck.Obs(p.Key(), a)}, nil
		case egress.NoService:
			if scheme == "https" && r.Reason != egress.NoServiceTLSFailed {
				continue
			}
			return nil, nil
		default:
			// The policy that yielded the check is the one that refuses it, so this is a fault to
			// retry, not a result that would skip the pair for good.
			return nil, fmt.Errorf("%s refused: %v", c.Key, res)
		}
	}
	return nil, nil
}
