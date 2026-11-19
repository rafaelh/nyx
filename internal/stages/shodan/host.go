package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

// Host is the shodan-host stage: the TCP ports, banners and hostnames Shodan
// holds for one address, asked of every address that may be port-checked and that
// the netblock search did not cover: one outside every in-scope netblock, or
// inside one whose search stopped at its page cap without returning it.
//
// The check key is the address, so Shodan's data for an address is refreshed
// only by --redo shodan-host. The key carries no scope: a hostname under a root
// promoted later was recorded only as a candidate root until the redo. The stage
// is budgeted by shodan.max_hosts; an address past the budget waits for the next
// run, in address order.
type Host struct{ shodanAPI }

// NewHost returns the shodan-host stage.
func NewHost() *Host { return &Host{} }

func (*Host) Name() string { return "shodan-host" }

// Budget is shodan.max_hosts: each check is one address.
func (*Host) Budget(s config.Settings) int { return s.Shodan.MaxHosts }

// hostInput is the Check.Input. The scope travels in it so that Run can tell a
// hostname under an in-scope root from one that is not.
type hostInput struct {
	addr netip.Addr
	sc   *scope.Scope
}

// Checks yields, in address order, each known address that may be port-checked
// and that no complete netblock search covered.
func (*Host) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		sc := v.Scope()
		cut := truncated(v)
		// The addresses the shodan stage returned, whether or not it returned a
		// TCP port for them (a match may be a UDP service only).
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

// Run asks for one address. A 404 is an address Shodan knows nothing about, a
// completed check with nothing found. Each TCP service is a reported_port (UDP
// is not recorded); a hostname under an in-scope root becomes a hostname and is
// tied to the address, and any other gives its registrable domain as a
// candidate root.
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
		return nil, fmt.Errorf("shodan-host %s: unreadable response: %v", in.addr, err)
	}
	var obs []run.Observation
	seen := map[string]bool{}
	names := slices.Clone(r.Hostnames)
	for _, d := range r.Data {
		// A service listed twice (two modules saw the port) keeps its first entry.
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

// nameObs are the observations of hostnames Shodan reported, each cleaned and
// taken once (seen holds them as "name|<name>", and their roots as
// "root|<root>"): a name under an in-scope root is a hostname, followed by
// its ip_hostname pairing with addr if addr is not "", and any other name gives
// its registrable domain as a candidate root.
func nameObs(sc *scope.Scope, seen map[string]bool, names []string, addr string) []run.Observation {
	var obs []run.Observation
	for _, n := range names {
		if n = httpsrc.CleanName(n); n == "" || seen["name|"+n] {
			continue
		}
		seen["name|"+n] = true
		if sc.HostInScope(n) {
			obs = append(obs, kinds.Hostname.Obs(n, kinds.HostnameAttrs{}))
			if addr != "" {
				obs = append(obs, kinds.IPHostnameObs(addr, n, "shodan"))
			}
		} else if root, ok := dnsname.ETLDPlusOne(n); ok && !seen["root|"+root] {
			seen["root|"+root] = true
			obs = append(obs, kinds.Root.Obs(root))
		}
	}
	return obs
}
