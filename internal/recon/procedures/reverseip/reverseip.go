// Package reverseip is the reverseip procedure: the other hostnames that point at
// each port-eligible address nyx has recorded (one inside an in-scope netblock, or a
// dedicated one an in-scope hostname uses).
package reverseip

import (
	"context"
	"fmt"
	"iter"
	"net/netip"
	"net/url"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	scopeinput "github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/ipsource"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/recon/analysis/candidates"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/procedures/httpsrc"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/scope"
)

// maxSecurityTrailsPages bounds credits per reverse-IP lookup; larger result sets already imply
// shared hosting beyond useful domain caps.
const maxSecurityTrailsPages = 10

// Procedure looks up recorded port-eligible addresses using HackerTarget for IPv4 and optionally
// SecurityTrails for A/AAAA data. It does not expand netblocks.
//
// Results exceeding reverseip.max_domains are discarded as shared hosting. The cap is part of
// job keys, and so is whether the address is inside an in-scope netblock: there, a name under no
// root is kept as a candidate hostname as well as its registrable domain as a candidate root, so
// an address asked before its netblock came into scope is asked once more. Other scope changes are
// not in the key, so names beneath newly promoted roots need --redo reverseip for
// reclassification. Shodan is queried separately.
type Procedure struct{}

// New returns the reverseip procedure.
func New() *Procedure { return &Procedure{} }

func (*Procedure) Name() string         { return "reverseip" }
func (*Procedure) Contact() run.Contact { return run.ThirdParty }
func (*Procedure) Sources() []string {
	return []string{ipsource.HackerTargetHost, "api.securitytrails.com"}
}

// Configured: HackerTarget needs no key, so the procedure always runs; a SecurityTrails
// key adds a source.
func (*Procedure) Configured(run.Env) (bool, string) { return true, "" }

// input carries scope so Run can distinguish in-scope hostnames from external candidate roots.
type input struct {
	addr  netip.Addr
	sc    *scope.Scope
	max   int
	keyed bool // keys.securitytrails was set when the job was made
	names bool // the address is inside an in-scope netblock, so names under no root are kept
}

// Jobs lists eligible recorded addresses in order. IPv6 requires a SecurityTrails key and
// becomes eligible for a job when one is added.
func (*Procedure) Jobs(_ context.Context, v run.View) iter.Seq2[run.Job, error] {
	set := v.Settings()
	_, keyed := set.Key("securitytrails")
	sc := v.Scope()
	addrs := v.IPs(func(a netip.Addr) bool { return (a.Is4() || keyed) && v.PortEligible(a) })
	return run.JobsOf(addrs, func(a netip.Addr) run.Job {
		key := fmt.Sprintf("%s|max=%d", a, set.ReverseIP.MaxDomains)
		names := sc.InScopeIP(a)
		if names {
			key += "|names"
		}
		return run.Job{Key: key, Input: input{a, sc, set.ReverseIP.MaxDomains, keyed, names}}
	})
}

// CandidateSources: the procedure is the reverse IP family.
func (*Procedure) CandidateSources() map[string]string {
	return map[string]string{"reverseip": candidates.ReverseIP}
}

// Evidence uses the address without the cap so cap changes cannot duplicate support, while two
// addresses still count as two items.
func (*Procedure) Evidence(jobKey string) (source, item string) {
	addr, _, _ := strings.Cut(jobKey, "|")
	return "reverseip", addr
}

// Run merges source names. Names under an input root and excluded names remain hostname records;
// other names contribute their registrable domain as a candidate root and, for an address inside
// an in-scope netblock, are kept as candidate hostnames too. Empty results complete normally.
func (*Procedure) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(input)
	f := found{seen: map[string]bool{}, domains: map[string]bool{}}
	if err := gather(ctx, e, in, &f); err != nil {
		return nil, fmt.Errorf("reverseip %s: %w", in.addr, err)
	}
	if f.over(in.max) {
		run.Warnf(ctx, "reverseip %s: at least %d registrable domains, more than reverseip.max_domains (%d): treated as shared hosting, nothing recorded",
			in.addr, len(f.domains), in.max)
		return nil, nil
	}
	var obs []run.Observation
	roots := map[string]bool{}
	for _, n := range f.names {
		class := in.sc.ClassifyName(n.name).Class
		if class != scope.Candidate || in.names {
			obs = append(obs, kinds.Hostname.Obs(n.name, kinds.HostnameAttrs{}))
		}
		if class == scope.Candidate && n.root != "" && !roots[n.root] {
			roots[n.root] = true
			obs = append(obs, kinds.Root.Obs(n.root))
		}
	}
	return obs, nil
}

// found deduplicates cleaned names and tracks their registrable domains for shared-hosting
// limits.
type found struct {
	names   []struct{ name, root string }
	seen    map[string]bool
	domains map[string]bool
}

func (f *found) add(names []string) {
	for _, n := range names {
		if n = scopeinput.CleanName(n); n == "" || f.seen[n] {
			continue
		}
		f.seen[n] = true
		root, _ := dnsname.ETLDPlusOne(n)
		if root != "" {
			f.domains[root] = true
		}
		f.names = append(f.names, struct{ name, root string }{n, root})
	}
}

// over detects shared hosting from too many distinct registrable domains.
func (f *found) over(limit int) bool { return len(f.domains) > limit }

// gather asks HackerTarget first for IPv4, then keyed SecurityTrails. Results already proving
// shared hosting skip the credit-consuming second source.
func gather(ctx context.Context, e egress.Clients, in input, f *found) error {
	if in.addr.Is4() {
		names, err := httpsrc.GetNames(ctx, e, "https://"+ipsource.HackerTargetHost+"/reverseiplookup/?"+url.Values{"q": {in.addr.String()}}.Encode(), reverseLines)
		if err != nil {
			return err
		}
		f.add(names)
	}
	if !in.keyed || f.over(in.max) {
		return nil
	}
	return securityTrails(ctx, e, in, f)
}

// reverseLines validates HackerTarget's name list. Quota replies map to run.ErrQuota even with
// status 200. Invalid name lines fail the job rather than completing an empty result.
func reverseLines(body []byte) ([]string, error) {
	lines, quota, err := ipsource.ReverseLines(body)
	if quota {
		return nil, fmt.Errorf("HackerTarget API count exceeded: %w", run.ErrQuota)
	}
	return lines, err
}

// securityTrails reads until exhaustion, the domain cap or maxSecurityTrailsPages. Passing the
// cap stops credit use. Keyed 401/403/429 aborts the whole procedure, including later HackerTarget
// jobs.
func securityTrails(ctx context.Context, e egress.Clients, in input, f *found) error {
	field := "ipv4"
	if in.addr.Is6() {
		field = "ipv6"
	}
	return httpsrc.SecurityTrailsDomains(ctx, e, field, in.addr.String(), maxSecurityTrailsPages, "reverseip "+in.addr.String(),
		func(_ int, names []string) bool {
			f.add(names)
			return f.over(in.max)
		})
}
