package iplookup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/batch"
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/spamhaus"
)

// Config supplies lookup dependencies and selected output fields.
type Config struct {
	// Fields selects record keys and required sources. Fields.Active additionally enables
	// shared-host checks, local resolution and target probes.
	Fields Fields
	// ThirdParty must permit every source host required by the lookup.
	ThirdParty egress.ThirdPartyHTTP
	// DNS is the public resolver set; Local is this machine's resolver.
	DNS   egress.Resolver
	Local egress.LocalResolver
	// ProbeOptions builds per-address active clients with a policy limited to that address.
	ProbeOptions egress.Options
	// Abusive supplies local matching data; nil uses the embedded snapshot without
	// requests.
	Abusive *abusive.Snapshot
	// Drop supplies local DROP matching data; nil uses embedded lists without requests.
	Drop *spamhaus.Lists
	// Warn receives deduplicated source/referral warnings.
	Warn func(string)
	// Debug, when set, receives diagnostic lines.
	Debug func(string)
}

// Resolved is the inputs after their hostnames have resolved.
type Resolved struct {
	// Inputs preserves each original input's result and resolved addresses.
	Inputs []InputResult
	// Addresses are the distinct addresses to look up, in record order.
	Addresses []Address
}

// resolveConcurrency is how many hostnames resolve at once.
const resolveConcurrency = 8

// hostResolution is how one hostname resolved.
type hostResolution struct {
	addrs []netip.Addr
	found Found
	err   *clierr.Error
}

// Resolve uses public A/AAAA lookups, adding local resolution in Active mode for unknown or
// single-label names. It returns deduplicated addresses, a cap error or context error.
func Resolve(ctx context.Context, cfg Config, plan Plan) (Resolved, error) {
	if n := plan.LiteralCount(); n > MaxAddresses {
		return Resolved{}, plan.capError(n, false) // before any request
	}
	hosts := plan.Hostnames()
	results := make([]hostResolution, len(hosts))
	batch.Each(len(hosts), resolveConcurrency, func(i int) { results[i] = resolveHost(ctx, cfg, hosts[i]) })
	if errors.Is(ctx.Err(), context.Canceled) {
		return Resolved{}, ctx.Err()
	}
	byName := map[string]hostResolution{}
	resolved := map[string]Resolution{}
	for i, h := range hosts {
		byName[h.Hostname] = results[i]
		if results[i].err == nil {
			resolved[h.Hostname] = Resolution{Addrs: results[i].addrs, Found: results[i].found}
		}
	}
	addrs, err := plan.Addresses(resolved)
	if err != nil {
		return Resolved{}, err
	}
	out := Resolved{Addresses: addrs, Inputs: make([]InputResult, len(plan.Inputs))}
	for i, in := range plan.Inputs {
		out.Inputs[i] = InputResult{Input: in.Raw}
		switch in.Class {
		case ClassInvalid:
			out.Inputs[i].Err = in.Err
		case ClassAddress:
			out.Inputs[i].Addresses = []string{in.Addr.String()}
		case ClassCIDR:
			for a := in.Prefix.Addr(); in.Prefix.Contains(a); a = a.Next() {
				out.Inputs[i].Addresses = append(out.Inputs[i].Addresses, a.Unmap().String())
			}
		case ClassHostname:
			if r := byName[in.Hostname]; r.err != nil {
				out.Inputs[i].Err = r.err
			} else {
				out.Inputs[i].Addresses = hostAddresses(r.addrs)
			}
		}
	}
	return out, nil
}

// hostAddresses formats unique resolved addresses in sorted IPv4/IPv6 order.
func hostAddresses(addrs []netip.Addr) []string {
	as := slices.Compact(canonical(addrs))
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}

// resolveHost resolves one hostname as Resolve describes.
func resolveHost(ctx context.Context, cfg Config, in Input) hostResolution {
	if in.SingleLabel {
		return resolveLocal(ctx, cfg, in.Hostname)
	}
	r := resolvePublic(ctx, cfg, in.Hostname)
	if len(r.addrs) > 0 || !cfg.Fields.Active() || r.err != nil && r.err.Code != clierr.NotFound {
		return r
	}
	if l := resolveLocal(ctx, cfg, in.Hostname); l.err == nil || l.err.Code != clierr.NotFound {
		return l
	}
	return r
}

// notFound distinguishes nonexistent names from names without address records.
func notFound(name string, nxdomain, active bool) *clierr.Error {
	msg := name + " has no A or AAAA records"
	if nxdomain {
		msg = name + " does not exist (NXDOMAIN)"
	}
	hint := "check the spelling of the name"
	if !active {
		hint += ", or add --active to also ask this machine's resolver"
	}
	return &clierr.Error{Code: clierr.NotFound, Message: msg, Hint: hint}
}

// resolverFailure classifies unanswered DNS queries, including deadline timeouts.
func resolverFailure(ctx context.Context, name string, err error) *clierr.Error {
	if timedOut(ctx, err) {
		return &clierr.Error{Code: clierr.Timeout, Message: fmt.Sprintf("resolving %s timed out", name), Hint: "raise --timeout, or retry", Transient: true}
	}
	return &clierr.Error{Code: clierr.NetworkError, Message: fmt.Sprintf("resolving %s: %v", name, err), Hint: "check the network connection and retry", Transient: true}
}

// resolvePublic accepts addresses from either A or AAAA lookup. If both return no addresses,
// any lookup failure wins; otherwise the name has no address.
func resolvePublic(ctx context.Context, cfg Config, name string) hostResolution {
	type answer struct {
		addrs    []netip.Addr
		nxdomain bool
		err      error
	}
	var ans [2]answer
	var wg sync.WaitGroup
	for i, qtype := range []uint16{egress.TypeA, egress.TypeAAAA} {
		wg.Go(func() {
			res, err := cfg.DNS.Query(ctx, name, qtype)
			switch {
			case err != nil:
				ans[i].err = err
			case res.RCode == egress.RCodeSuccess:
				ans[i].addrs = res.Addrs()
			case res.RCode == egress.RCodeNXDomain:
				ans[i].nxdomain = true
			default:
				ans[i].err = fmt.Errorf("resolver answered rcode %d", res.RCode)
			}
		})
	}
	wg.Wait()
	out := hostResolution{found: FoundPublicDNS}
	for _, a := range ans {
		out.addrs = append(out.addrs, a.addrs...)
	}
	if len(out.addrs) > 0 {
		return out
	}
	for _, a := range ans {
		if a.err != nil {
			out.err = resolverFailure(ctx, name, a.err)
			return out
		}
	}
	out.err = notFound(name, ans[0].nxdomain && ans[1].nxdomain, cfg.Fields.Active())
	return out
}

// resolveLocal asks this machine's resolver.
func resolveLocal(ctx context.Context, cfg Config, name string) hostResolution {
	out := hostResolution{found: FoundLocalDNS}
	if cfg.Local == nil {
		out.err = notFound(name, false, cfg.Fields.Active())
		return out
	}
	addrs, err := cfg.Local.Addrs(ctx, name)
	switch {
	case err != nil:
		out.err = resolverFailure(ctx, name, err)
	case len(addrs) == 0:
		out.err = notFound(name, false, cfg.Fields.Active())
	default:
		out.addrs = addrs
	}
	return out
}

// lookupConcurrency bounds simultaneous addresses, each of which may open several active-probe
// connections.
func lookupConcurrency(active bool) int {
	if active {
		return 16
	}
	return 32
}

// Lookup processes addresses concurrently and returns results in r.Addresses order. Active mode
// also probes eligible addresses. Cancellation returns completed work early; deadline expiry
// instead becomes a timeout for each unanswered source.
func Lookup(ctx context.Context, cfg Config, r Resolved) []AddressResult {
	st := newState(cfg)
	out := make([]AddressResult, len(r.Addresses))
	for i, a := range r.Addresses {
		out[i] = AddressResult{Record: NewRecord(a)}
	}
	batch.Each(len(out), lookupConcurrency(cfg.Fields.Active()), func(i int) {
		if !errors.Is(ctx.Err(), context.Canceled) {
			out[i] = st.lookupAddress(ctx, r.Addresses[i])
		}
	})
	return out
}

// contact applies active-mode contact rules and probes only when selected fields need probe
// results. in describes the address and record.
func (s *state) contact(ctx context.Context, a Address, rec *Record, in contactInput, runs *sourceRuns) {
	addr := in.Addr
	rec.Ports, rec.TLS, rec.Web = []Port{}, []TLSEntry{}, []WebEntry{}
	if reason := notContacted(in); reason != "" {
		rec.NotContacted = &reason
		return
	}
	f := s.cfg.Fields
	if !f.NeedsProbe() {
		return
	}
	var extra []int
	if rec.Kind == addrkind.Public {
		extra = rec.InternetDBPorts // from InternetDB; a non-public address is sent to no third party
	}
	ports := probePorts(extra)
	probe := egress.NewProbe(s.cfg.ProbeOptions, egress.ProbePolicy(addr, a.Hostnames, ports))
	out := runProbe(ctx, probe, probeJob{Addr: addr, Hostnames: a.Hostnames, Ports: ports, TLS: f.NeedsTLS(), Web: f.NeedsWeb()})
	rec.Ports = nonNil(out.Ports)
	rec.TLS = nonNil(out.TLS)
	rec.Web = nonNil(out.Web)
	runs.set(SourceProbe, out.Failure)
	s.debugf("probed %s: %d ports", addr, len(rec.Ports))
}
