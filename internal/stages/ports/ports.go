// Package ports is the ports stage: it finds which of the configured TCP ports
// the target's own addresses accept connections on, connecting only as any
// client would.
package ports

import (
	"context"
	"fmt"
	"iter"
	"net/netip"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
)

// Ports completes a TCP handshake to every port-eligible address on every
// configured port and records the open ones with any banner sent unprompted.
type Ports struct{}

// New returns the ports stage.
func New() *Ports { return &Ports{} }

func (*Ports) Name() string         { return "ports" }
func (*Ports) Contact() run.Contact { return run.Target }
func (*Ports) Sources() []string    { return nil }

// Configured is false with no ports to check. Passive mode and the
// authorisation are gated by the runner for every Target stage.
func (*Ports) Configured(e run.Env) (bool, string) {
	if len(e.Settings.Ports) == 0 {
		return false, "no ports"
	}
	return true, ""
}

// Workers is --port-concurrency: a silent port costs the whole connect
// timeout, so the sweep needs far more workers than other stages.
func (*Ports) Workers(s config.Settings) int { return s.PortConcurrency }

// portCheck is a check's input: the address and port, and whether a third party
// reported the port, so that the outcome is recorded when nyx does not open it.
type portCheck struct {
	ap       netip.AddrPort
	reported bool
}

// recheckSuffix marks the check that settles a port a third party reported after
// the plain check of it had already completed.
const recheckSuffix = "|reported"

// Checks yields one check per eligible address and port, port by port. The
// transport rate-limits each address, so the order keeps every worker off the
// same host.
//
// A port a third party reported carries that in its check, so a check that has
// not run yet records what nyx found (closed or silent) as it connects. A
// check that completed before the report existed is run once more under the key
// "<address:port>|reported", but only while nyx has neither opened the port nor
// recorded what it found: a port is never connected to a third time on account
// of a report. Only the ports of the configured list, on eligible addresses, are
// ever yielded, whatever a third party reports.
func (*Ports) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		addrs := eligible(ctx, v)
		reported := map[netip.AddrPort]bool{}
		for _, rec := range v.Records(kinds.ReportedPort) {
			if ap, ok := kinds.ParsePortKey(rec.Key); ok {
				reported[ap] = true
			}
		}
		settled := map[netip.AddrPort]bool{} // opened, or a port_check made
		for _, op := range v.OpenPorts() {
			settled[op.Addr] = true
		}
		for _, rec := range v.Records(kinds.PortCheck) {
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
				if !yield(run.Check{Key: key, Input: portCheck{ap, reported[ap]}}, nil) {
					return
				}
				if reported[ap] && !settled[ap] && v.Done(key) &&
					!yield(run.Check{Key: key + recheckSuffix, Input: portCheck{ap, true}}, nil) {
					return
				}
			}
		}
	}
}

// eligible lists the addresses to check, built once per Checks call: every
// distinct address of the in-scope IPv4 netblocks, then the other found
// addresses (hostname-resolved, or IPv6 inside an in-scope netblock), keeping
// those the single eligibility decision allows.
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

// Run connects. Open is an open_port observation. Closed and Filtered are
// completed checks with nothing found, except for a port a third party reported,
// where the outcome is a port_check: closed (rejected) takes the report out of
// what is shown, and silent leaves it unconfirmed. Refused cannot happen for a
// check the stage yielded (the policy is built from the same scope and
// inventory), so it is a failure rather than a result that would permanently
// skip an address that later becomes eligible.
func (*Ports) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(portCheck)
	ap := in.ap
	res, err := e.TCP.Connect(ctx, ap.Addr(), int(ap.Port()))
	if err != nil {
		return nil, err
	}
	// The key of a port record is the address and port, whichever check made it.
	key := ap.String()
	outcome := func(result string) []run.Observation {
		if !in.reported {
			return nil
		}
		return []run.Observation{kinds.PortCheck.Obs(key, kinds.PortCheckAttrs{Result: result})}
	}
	switch r := res.(type) {
	case egress.Open:
		return []run.Observation{kinds.OpenPort.Obs(key, kinds.OpenPortAttrs{
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
