// Package ports checks configured TCP ports on eligible target addresses through ordinary
// connections.
package ports

import (
	"context"
	"fmt"
	"iter"
	"net/netip"
	"slices"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
)

// Ports completes a TCP handshake to every port-eligible address on every
// configured port and records the open ones with any banner sent unprompted.
type Ports struct{}

// New returns the ports procedure.
func New() *Ports { return &Ports{} }

func (*Ports) Name() string         { return "ports" }
func (*Ports) Contact() run.Contact { return run.Target }
func (*Ports) Sources() []string    { return nil }

// Configured is false with no ports to check. Passive mode and the
// authorisation are gated by the runner for every Target procedure.
func (*Ports) Configured(e run.Env) (bool, string) {
	if len(e.Settings.Ports) == 0 {
		return false, "no ports"
	}
	return true, ""
}

// Workers is --port-concurrency: a silent port costs the whole connect
// timeout, so the sweep needs far more workers than other procedures.
func (*Ports) Workers(s config.Settings) int { return s.PortConcurrency }

// portCheck preserves whether a third party reported the port so closed or silent outcomes can
// qualify that report.
type portCheck struct {
	ap       netip.AddrPort
	reported bool
}

// recheckSuffix marks the job that settles a port a third party reported after
// the plain job of it had already completed.
const recheckSuffix = "|reported"

// Jobs walks ports before addresses to spread workers across per-host rate limits. Only
// configured ports on eligible addresses are checked.
//
// Reported ports carry that context into execution. If a job completed before the report
// existed, one "|reported" job can record its outcome, unless nyx already opened or checked
// the reported port. Reports therefore cannot cause a third connection attempt.
func (*Ports) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		addrs := eligible(ctx, v)
		reported := map[netip.AddrPort]bool{}
		for _, rec := range v.Records(kinds.ReportedPort) {
			if ap, ok := kinds.ParsePortKey(rec.Key); ok {
				reported[ap] = true
			}
		}
		settled := map[netip.AddrPort]bool{} // opened, or a port_check made
		for _, rec := range slices.Concat(v.Records(kinds.OpenPort), v.Records(kinds.PortCheck)) {
			if ap, ok := kinds.ParsePortKey(rec.Key); ok {
				settled[ap] = true
			}
		}
		for _, port := range v.Settings().Ports {
			for _, a := range addrs {
				if ctx.Err() != nil {
					return
				}
				ap := netip.AddrPortFrom(a, uint16(port))
				key := ap.String()
				if !yield(run.Job{Key: key, Input: portCheck{ap, reported[ap]}}, nil) {
					return
				}
				if reported[ap] && !settled[ap] && v.Done(key) &&
					!yield(run.Job{Key: key + recheckSuffix, Input: portCheck{ap, true}}, nil) {
					return
				}
			}
		}
	}
}

// eligible combines the IPv4 netblock sweep with other discovered addresses, deduplicating and
// applying the shared port-eligibility decision.
func eligible(ctx context.Context, v run.View) []netip.Addr {
	sc := v.Scope()
	var out []netip.Addr
	for a := range sc.IPv4Addrs() {
		if ctx.Err() != nil {
			return nil
		}
		if v.PortEligible(a) {
			out = append(out, a)
		}
	}
	// IPv4 netblock addresses were all decided above.
	found := v.IPs(func(a netip.Addr) bool { return !a.Is4() || !sc.InScopeIP(a) })
	unknown := 0
	for _, a := range found {
		switch {
		case v.PortEligible(a):
			out = append(out, a)
		case !v.OwnerKnown(a):
			// Held back, not refused, if it would be eligible with a known,
			// dedicated owner: it is checked once its owner is known.
			if ok, _, _ := sc.PortEligible(a, func(netip.Addr) (bool, bool) { return false, true }); ok {
				unknown++
			}
		}
	}
	if unknown > 0 {
		v.Warn("ports: %d address(es) skipped because their owner is unknown", unknown)
	}
	return out
}

// Run records open ports. Closed/silent jobs normally complete empty; reported ports
// additionally store port_check evidence, hiding rejected reports while leaving silent ones
// unconfirmed. Policy refusal is retryable because enumeration and egress should agree, and
// completing it would prevent a later eligible retry.
func (*Ports) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(portCheck)
	ap := in.ap
	res, err := e.TCP.Connect(ctx, ap.Addr(), int(ap.Port()))
	if err != nil {
		return nil, err
	}
	// The key of a port record is the address and port, whichever job made it.
	key := ap.String()
	outcome := func(result string) []run.Observation {
		if !in.reported {
			return nil
		}
		return []run.Observation{kinds.PortCheck.Obs(key, kinds.PortCheckAttrs{Result: result})}
	}
	switch r := res.(type) {
	case egress.Open:
		return []run.Observation{kinds.OpenPort.Obs(kinds.OpenPortAttrs{
			IP: ap.Addr().String(), Port: int(ap.Port()), Banner: kinds.EncodeBanner(string(r.Banner)),
		})}, nil
	case egress.Closed:
		return outcome(kinds.PortClosed), nil
	case egress.Filtered:
		return outcome(kinds.PortSilent), nil
	case egress.Refused:
		return nil, fmt.Errorf("%s refused: %s", c.Key, r.Reason)
	}
	return nil, fmt.Errorf("%s: unexpected result %T", c.Key, res)
}
