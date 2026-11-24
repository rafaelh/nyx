// Package nsreverse discovers candidate domains sharing self-hosted DNS/mail infrastructure
// with the organisation.
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

// maxPages bounds per-server credits; results beyond it already exceed useful shared-hosting
// limits.
const maxPages = 100

// The roles of a server, and the evidence source each gives its candidates.
const (
	roleNS = "ns"
	roleMX = "mx"
)

// Stage searches SecurityTrails for domains sharing self-hosted name servers or MX hosts with
// in-scope roots. Managed providers and shared/unknown-owner addresses provide no ownership
// signal. Results are candidate roots with shared-ns/shared-mx evidence; they are not resolved
// or contacted.
//
// Servers exceeding nsreverse.max_domains are discarded as shared hosting. The first-page total
// avoids extra requests. The cap is in check keys; scope and later self-hosting changes do not
// repeat completed checks without --redo nsreverse.
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

// Checks emits sorted NS/MX server checks only for self-hosted servers of in-scope roots. Keys
// include host, mechanism and max-domain cap.
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

// Evidence uses server identity under shared-ns/shared-mx without the cap, avoiding duplicate
// support after limit changes.
func (*Stage) Evidence(checkKey string) (source, item string) {
	role, rest, _ := strings.Cut(checkKey, "|")
	host, _, _ := strings.Cut(rest, "|")
	return "shared-" + role, host
}

// Run completes empty for unknown or domainless servers. Keyed refusals/rate limits abort
// through httpsrc.Get.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	s := c.Input.(server)
	var obs []run.Observation
	roots := map[string]bool{}
	seen := 0 // domains listed so far
	err := httpsrc.SecurityTrailsDomains(ctx, e, s.role, s.host, maxPages, "nsreverse "+s.host, func(total int, names []string) bool {
		// Check first-page totals before recording anything, then count actual domains
		// too. This enforces the cap even when reported totals are missing or too
		// small.
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
