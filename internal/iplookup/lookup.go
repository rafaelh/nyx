package iplookup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/egress"
)

// Config is what a lookup needs from its caller.
type Config struct {
	// Fields are the keys the caller selected; only the sources they need are asked. Its mode
	// (Fields.Active) is whether --active was given: the shared check, the local resolver and the
	// probes.
	Fields Fields
	// ThirdParty reaches the sources. It must be built for every source host the lookup asks.
	ThirdParty egress.ThirdPartyHTTP
	// DNS is the public resolver set; Local is this machine's resolver.
	DNS   egress.Resolver
	Local egress.LocalResolver
	// ProbeOptions are what the target clients for one contacted address are built from, under a
	// Policy that holds that address alone. Only used under --active.
	ProbeOptions egress.Options
	// Warn receives each warning once (a latched source, an RDAP referral problem).
	Warn func(string)
	// Debug, when set, receives diagnostic lines.
	Debug func(string)
}

// Resolved is the inputs after their hostnames have resolved.
type Resolved struct {
	// Inputs holds one result per input, in input order, with the addresses each gave.
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

// Resolve resolves the plan's hostnames (A and AAAA through the public resolvers; under Active a
// name they do not know, and a single-label name, through this machine's resolver) and builds the
// distinct address list. The error is a cap error (exit 2) or the context's.
func Resolve(ctx context.Context, cfg Config, plan Plan) (Resolved, error) {
	if n := plan.LiteralCount(); n > MaxAddresses {
		return Resolved{}, plan.capError(n, false) // before any request
	}
	hosts := plan.Hostnames()
	results := make([]hostResolution, len(hosts))
	sem := make(chan struct{}, resolveConcurrency)
	var wg sync.WaitGroup
	for i, h := range hosts {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			results[i] = resolveHost(ctx, cfg, h)
		})
	}
	wg.Wait()
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

// hostAddresses are a hostname's addresses as text, IPv4 first, each in address order, once each.
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

// notFound is the error of a name with no address. nxdomain says the name does not exist.
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

// resolverFailure is the error of a resolver that did not answer. A deadline is TIMEOUT.
func resolverFailure(ctx context.Context, name string, err error) *clierr.Error {
	if timedOut(ctx, err) {
		return &clierr.Error{Code: clierr.Timeout, Message: fmt.Sprintf("resolving %s timed out", name), Hint: "raise --timeout, or retry", Transient: true}
	}
	return &clierr.Error{Code: clierr.NetworkError, Message: fmt.Sprintf("resolving %s: %v", name, err), Hint: "check the network connection and retry", Transient: true}
}

// resolvePublic asks the public resolvers for A and AAAA. One of them answering with addresses is
// enough; when neither does, a failure of either is the failure, else the name has no address.
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

// lookupConcurrency is how many addresses are looked up at once: the sources are paced, and an
// address probed under --active opens a connection for each of its ports.
func lookupConcurrency(active bool) int {
	if active {
		return 16
	}
	return 32
}

// Lookup asks every source each address needs, and probes the contacted ones under Active, with
// the addresses a few at a time. It returns one result per address, in the order of r.Addresses.
// It returns early, with whatever finished, when ctx is cancelled; the caller reports the cause.
// A deadline is not an early end: each source that has not answered is a timed-out failure.
func Lookup(ctx context.Context, cfg Config, r Resolved) []AddressResult {
	st := newState(cfg)
	out := make([]AddressResult, len(r.Addresses))
	sem := make(chan struct{}, lookupConcurrency(cfg.Fields.Active()))
	var wg sync.WaitGroup
	for i, a := range r.Addresses {
		out[i] = AddressResult{Record: NewRecord(a)}
		if errors.Is(ctx.Err(), context.Canceled) {
			continue
		}
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			out[i] = st.lookupAddress(ctx, a)
		})
	}
	wg.Wait()
	return out
}

// contact decides whether --active contacts the address, and probes it when it does and the
// selection shows what a probe finds. in describes a and rec.
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
