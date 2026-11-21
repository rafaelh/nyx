// Package nsreverse is the nsreverse stage: the domains hosted on each name server
// and mail host the organisation runs itself, which are strong signs of common
// ownership.
package nsreverse

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/candidates"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

// maxPages caps the result pages read for one server (one query credit each). A
// server that needs more has more domains than any sensible nsreverse.max_domains.
const maxPages = 100

// The roles of a server, and the evidence source each gives its candidates.
const (
	roleNS = "ns"
	roleMX = "mx"
)

// Stage asks SecurityTrails which domains are hosted on each name server of the
// in-scope roots, and which have each mail host as their MX, for every one of
// them that is self-hosted (inventory.SelfHosted). A name server or mail host on a
// known provider, or on a shared or unknown-owner address, is never asked: it says
// nothing about who else uses it. Each domain is recorded as a candidate root, its
// source "shared-ns" or "shared-mx". Candidate roots are never resolved or
// contacted, so this lookup is the only way they are found.
//
// A server with more domains than nsreverse.max_domains is shared hosting after
// all: nothing is recorded for it and a warning names it. The total is read from the
// first page, so such a server costs one query. The cap is in the check key, so
// changing it asks again. The key carries no scope: a server that a root added later
// brings into scope is asked once it is self-hosted by either test, and a changed
// self-hosted result does not repeat a check already made (--redo nsreverse).
type Stage struct{}

// New returns the nsreverse stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string         { return "nsreverse" }
func (*Stage) Contact() run.Contact { return run.ThirdParty }
func (*Stage) Sources() []string    { return []string{"api.securitytrails.com"} }

// Configured: it needs keys.securitytrails.
func (*Stage) Configured(e run.Env) (bool, string) {
	return httpsrc.Configured(e, "securitytrails", true)
}

// server is the Check.Input.
type server struct {
	role, host string
	max        int
}

// Checks yields, in key order, one check for each self-hosted name server of an
// in-scope root and one for each self-hosted mail host of one, keyed
// "ns|<host>|max=<n>" and "mx|<host>|max=<n>".
func (*Stage) Checks(_ context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		limit := v.Settings().NSReverse.MaxDomains
		sc := v.Scope()
		var servers []server
		seen := map[string]bool{}
		add := func(role, host string) {
			host = dnsname.Normalise(host)
			if k := role + "|" + host; host != "" && !seen[k] && v.SelfHosted(host) {
				seen[k] = true
				servers = append(servers, server{role, host, limit})
			}
		}
		for _, rec := range v.Records(kinds.Resolution) {
			if a := kinds.Resolution.Attrs(rec); a.Type == "NS" && sc.HostInScope(a.Name) {
				add(roleNS, a.Value)
			}
		}
		for _, rec := range v.Records(kinds.EmailPosture) {
			if !sc.HostInScope(rec.Key) {
				continue
			}
			for h := range strings.SplitSeq(kinds.EmailPosture.Attrs(rec).MX, ";") {
				add(roleMX, h)
			}
		}
		slices.SortFunc(servers, func(a, b server) int { return strings.Compare(a.key(), b.key()) })
		for _, s := range servers {
			if !yield(run.Check{Key: s.key(), Input: s}, nil) {
				return
			}
		}
	}
}

func (s server) key() string { return fmt.Sprintf("%s|%s|max=%d", s.role, s.host, s.max) }

// CandidateSources: a self-hosted name server or mail host shared with another
// domain is shared infrastructure.
func (*Stage) CandidateSources() map[string]string {
	return map[string]string{"shared-ns": candidates.SharedInfra, "shared-mx": candidates.SharedInfra}
}

// Evidence is the server, under the source "shared-ns" or "shared-mx". The item leaves out the cap, so changing it does
// not count a server twice.
func (*Stage) Evidence(checkKey string) (source, item string) {
	role, rest, _ := strings.Cut(checkKey, "|")
	host, _, _ := strings.Cut(rest, "|")
	return "shared-" + role, host
}

// Run asks for the domains of one server. A server SecurityTrails does not know
// (404), or one with no domains, is a completed check with nothing found. A 401,
// 403 or 429 aborts the stage (httpsrc.Get), which is the quota rule.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	s := c.Input.(server)
	var obs []run.Observation
	roots := map[string]bool{}
	seen := 0 // domains listed so far
	err := httpsrc.SecurityTrailsDomains(ctx, e, s.role, s.host, maxPages, "nsreverse "+s.host, func(total int, names []string) bool {
		// The total is read first, from the first page: a server over the cap costs one
		// query, and nothing it lists is recorded. The domains listed are counted too,
		// so a reply whose total is missing or short still cannot pass the cap.
		seen += len(names)
		if n := max(total, seen); n > s.max {
			run.Warnf(ctx, "nsreverse %s: %d domains, more than nsreverse.max_domains (%d): treated as shared hosting, nothing recorded",
				s.host, n, s.max)
			obs = nil
			return true
		}
		for _, n := range names {
			if root, ok := dnsname.ETLDPlusOne(input.CleanName(n)); ok && !roots[root] {
				roots[root] = true
				obs = append(obs, kinds.Root.Obs(root))
			}
		}
		return false
	})
	if err != nil {
		return nil, fmt.Errorf("nsreverse %s: %w", s.host, err)
	}
	return obs, nil
}
