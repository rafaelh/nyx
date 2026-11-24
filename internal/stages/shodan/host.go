package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"

	"github.com/rafaelh/nyx/internal/candidates"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

// Host retrieves services/names for eligible addresses outside netblock-search coverage,
// including addresses missed by capped searches. Checks use address-only keys and refresh
// through --redo shodan-host. Newly promoted hostname roots need redo for reclassification.
// shodan.max_hosts defers excess addresses in sorted order to later runs.
type Host struct{ shodanAPI }

// NewHost returns the shodan-host stage.
func NewHost() *Host { return &Host{} }

func (*Host) Name() string { return "shodan-host" }

// CandidateSources classifies Shodan evidence as passive DNS.
func (*Host) CandidateSources() map[string]string {
	return map[string]string{"shodan-host": candidates.PassiveDNS}
}

// Budget is shodan.max_hosts: each check is one address.
func (*Host) Budget(s config.Settings) int { return s.Shodan.MaxHosts }

// hostInput carries scope to classify returned names under input roots.
type hostInput struct {
	addr netip.Addr
	sc   *scope.Scope
}

// Checks selects sorted eligible addresses outside completed search coverage.
func (*Host) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		sc := v.Scope()
		cut := truncated(v)
		// Keep every address returned by netblock search, including UDP-only results,
		// to avoid redundant host lookups.
		returned := map[netip.Addr]bool{}
		for _, rec := range v.Records(kinds.IP) {
			if a, err := netip.ParseAddr(rec.Key); err == nil && slices.Contains(rec.Stages, "shodan") {
				returned[a.Unmap()] = true
			}
		}
		for _, a := range v.KnownAddrs() {
			if ctx.Err() != nil {
				return
			}
			if !v.PortEligible(a) {
				continue
			}
			if sc.InScopeIP(a) {
				inCut := slices.ContainsFunc(cut, func(p netip.Prefix) bool { return p.Contains(a) })
				if !inCut || returned[a] {
					continue // a complete search would have returned it, or it did
				}
			}
			if !yield(run.Check{Key: a.String(), Input: hostInput{a, sc}, Cost: 1}, nil) {
				return
			}
		}
	}
}

// hostAnswer is Shodan's answer for an address.
type hostAnswer struct {
	Hostnames []string `json:"hostnames"`
	Data      []struct {
		Port      int      `json:"port"`
		Transport string   `json:"transport"`
		Data      string   `json:"data"`
		Timestamp string   `json:"timestamp"`
		Hostnames []string `json:"hostnames"`
	} `json:"data"`
}

// Run completes empty for unknown addresses. TCP services become reports; in-scope names are
// tied to the address, while other names contribute candidate registrable roots. UDP is
// ignored.
func (*Host) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(hostInput)
	body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{
		Method: "GET", URL: "https://api.shodan.io/shodan/host/" + in.addr.String(), KeySource: "shodan", KeyParam: "key",
	})
	if errors.Is(err, httpsrc.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("shodan-host %s: %w", in.addr, err)
	}
	var r hostAnswer
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("shodan-host %s: unreadable response: %w", in.addr, err)
	}
	var obs []run.Observation
	seen := map[string]bool{}
	names := slices.Clone(r.Hostnames)
	for _, d := range r.Data {
		// Keep the first report when several Shodan modules describe one service.
		if o, ok := reportedPort(in.addr.String(), d.Port, d.Transport, d.Data, d.Timestamp); ok && !seen[o.Key] {
			seen[o.Key] = true
			obs = append(obs, o)
		}
		if isTCP(d.Transport) {
			names = append(names, d.Hostnames...)
		}
	}
	obs = append(obs, nameObs(in.sc, seen, names, in.addr.String())...)
	return obs, nil
}

// nameObs cleans and deduplicates returned names/roots. In-scope hostnames get optional address
// pairings; external names contribute candidate roots. seen uses type-prefixed keys to keep
// both distinct.
func nameObs(sc *scope.Scope, seen map[string]bool, names []string, addr string) []run.Observation {
	var obs []run.Observation
	for _, n := range names {
		if n = input.CleanName(n); n == "" || seen["name|"+n] {
			continue
		}
		seen["name|"+n] = true
		if sc.HostInScope(n) {
			obs = append(obs, kinds.Hostname.Obs(n, kinds.HostnameAttrs{}))
			if addr != "" {
				obs = append(obs, kinds.IPHostname.Obs(kinds.IPHostnameAttrs{IP: addr, Hostname: n, Source: "shodan"}))
			}
		} else if root, ok := dnsname.ETLDPlusOne(n); ok && !seen["root|"+root] {
			seen["root|"+root] = true
			obs = append(obs, kinds.Root.Obs(root))
		}
	}
	return obs
}
