package dns

import (
	"context"
	"iter"
	"net/netip"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/scope"
)

// Resolve queries A/AAAA for input roots and in-scope/excluded names. Address answers stay
// associated with the queried name even when CNAMEs change the answer owner.
type Resolve struct{ base }

// NewResolve returns the resolve procedure.
func NewResolve() *Resolve { return &Resolve{base{"resolve"}} }

// Required: resolution decides which names are real, so it cannot be skipped.
func (*Resolve) Required() {}

// parentPrefix marks the key of a parent job: one for a name between a found hostname and its
// input root, which no source found. The separate key gives such a name a normal job once a
// source does find it.
const parentPrefix = "parent|"

// Jobs yields one job per resolvable hostname and per in-scope CNAME target only resolve has
// found, then one per parent name that has no job of its own.
func (r *Resolve) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		sc := v.Scope()
		hosts := v.ResolvableHostnames(r.Name())
		asked := map[string]bool{}
		for _, h := range hosts {
			asked[h] = true
		}
		for _, h := range append(hosts, cnameTargets(v, asked)...) {
			if !yield(run.Job{Key: h, Input: resolveInput{sc: sc}}, nil) {
				return
			}
		}
		parents := v.ParentNames(r.Name())
		if len(parents) == 0 {
			return
		}
		zones := wildcardZones(v)
		wild := map[string]kinds.WildcardAttrs{}
		for _, rec := range v.Records(kinds.Wildcard) {
			wild[rec.Key] = kinds.Wildcard.Attrs(rec)
		}
		for _, p := range parents {
			_, zone, _ := strings.Cut(p, ".")
			if asked[p] || wildcardPending(v, zones, zone) {
				continue // asked as a name, or its answer can be told from the wildcard's only once the check is done
			}
			in := resolveInput{sc: sc}
			if w, ok := wild[zone]; ok {
				in.wildcard = &w
			}
			if !yield(run.Job{Key: parentPrefix + p, Input: in}, nil) {
				return
			}
		}
	}
}

// cnameTargets returns, sorted, the targets of current CNAME rows that are hostnames and are not
// asked yet, adding each to asked: ResolvableHostnames leaves out a name only resolve produced,
// which a CNAME target is.
func cnameTargets(v run.View, asked map[string]bool) []string {
	var out []string
	for _, rec := range v.Records(kinds.Resolution) {
		a := kinds.Resolution.Attrs(rec)
		if a.Type != "CNAME" {
			continue
		}
		if t := dnsname.Normalise(a.Value); !asked[t] && cnameHost(v.Scope(), a.Name, t) {
			asked[t] = true
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}

// resolveInput is a job's input: the scope snapshot, and for a parent job its zone's wildcard,
// if the zone has one.
type resolveInput struct {
	sc       *scope.Scope
	wildcard *kinds.WildcardAttrs
}

// cnameHost reports whether the target of an alias's CNAME is a hostname: the alias is in scope
// and the target passes the rule for names a record points at.
func cnameHost(sc *scope.Scope, alias, target string) bool {
	return sc.HostInScope(alias) && recordHost(sc, target)
}

// Run resolves the name. NXDOMAIN, NODATA and SERVFAIL are results recorded as
// kind unresolved; a timeout is an error. A parent name that has an address or a CNAME is
// recorded as a hostname too; one that has neither, or whose answer only its zone's wildcard
// gives, records nothing, so it is listed nowhere. The in-scope target of an in-scope alias's
// CNAME is a hostname.
func (*Resolve) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	name, parent := strings.CutPrefix(c.Key, parentPrefix)
	in := c.Input.(resolveInput)
	obs, ans, err := resolve(ctx, e, name, in.sc)
	if err != nil || !parent {
		return obs, err
	}
	if !ans.found() || in.wildcard != nil && ans.matches(*in.wildcard) {
		return nil, nil
	}
	return append(obs, kinds.Hostname.Obs(name, kinds.HostnameAttrs{})), nil
}

// answer is what the A and AAAA lookups of a name gave: its addresses and the targets of its own
// CNAMEs.
type answer struct {
	addrs, cnames []string
	chained       bool // any CNAME in the chain
}

func (a answer) found() bool { return len(a.addrs) > 0 || a.chained }

// matches reports whether the answer is its zone's wildcard's, by the rule inventory uses to mark
// a name wildcard-only: one of its addresses is a wildcard address, or its CNAME is the wildcard's
// target.
func (a answer) matches(w kinds.WildcardAttrs) bool {
	return w.CNAME != "" && slices.Contains(a.cnames, w.CNAME) ||
		slices.ContainsFunc(a.addrs, func(s string) bool { return slices.Contains(w.Addrs, s) })
}

// resolve asks A and AAAA for the name and returns its observations and the answer. The in-scope
// target of each in-scope alias in the chain is observed as a hostname.
func resolve(ctx context.Context, e egress.Clients, name string, sc *scope.Scope) (obs []run.Observation, ans answer, err error) {
	a, err := lookup(ctx, e, name, egress.TypeA)
	if err != nil {
		return nil, ans, err
	}
	aaaa, err := lookup(ctx, e, name, egress.TypeAAAA)
	if err != nil {
		return nil, ans, err
	}
	links := map[egress.CNAME]bool{}
	for _, res := range []egress.DNSResult{a, aaaa} {
		for _, l := range res.CNAMEs {
			if !links[l] {
				links[l] = true
				if dnsname.Normalise(l.Name) == name {
					ans.cnames = append(ans.cnames, l.Target)
				}
				obs = append(obs, kinds.Resolution.Obs(kinds.ResolutionAttrs{Name: l.Name, Type: "CNAME", Value: l.Target}))
				if cnameHost(sc, l.Name, l.Target) {
					obs = append(obs, kinds.Hostname.Obs(l.Target, kinds.HostnameAttrs{}))
				}
			}
		}
	}
	seen := map[netip.Addr]bool{}
	for _, res := range []egress.DNSResult{a, aaaa} {
		for _, addr := range res.Addrs() {
			if seen[addr] {
				continue
			}
			seen[addr] = true
			typ := "AAAA"
			if addr.Is4() {
				typ = "A"
			}
			ans.addrs = append(ans.addrs, addr.String())
			obs = append(obs,
				kinds.Resolution.Obs(kinds.ResolutionAttrs{Name: name, Type: typ, Value: addr.String()}),
				kinds.IP.Obs(addr.String()))
		}
	}
	if len(seen) == 0 {
		obs = append(obs, kinds.Unresolved.Obs(name, kinds.UnresolvedAttrs{RCode: rcodeName(a, aaaa)}))
	}
	ans.chained = len(links) > 0
	return obs, ans, nil
}

// rcodeName prioritises NXDOMAIN, then either query's SERVFAIL, otherwise NODATA when no
// address exists.
func rcodeName(a, aaaa egress.DNSResult) string {
	switch {
	case a.RCode == egress.RCodeNXDomain:
		return "NXDOMAIN"
	case a.RCode == egress.RCodeServFail || aaaa.RCode == egress.RCodeServFail:
		return "SERVFAIL"
	}
	return "NODATA"
}
