package risk

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strconv"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/knowledge/weburl"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// SensitivePaths checks configured paths on live non-SaaS services, once for a host whose HTTP
// service only redirects to its HTTPS one. It stores matching exposure evidence without response
// bodies.
type SensitivePaths struct{}

// NewSensitivePaths returns the sensitive-paths procedure.
func NewSensitivePaths() *SensitivePaths { return &SensitivePaths{} }

func (*SensitivePaths) Name() string                      { return "sensitive-paths" }
func (*SensitivePaths) Contact() run.Contact              { return run.Target }
func (*SensitivePaths) Sources() []string                 { return nil }
func (*SensitivePaths) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedJobs replaces evidence from edited path entries.
func (*SensitivePaths) RetiresUnlistedJobs() {}

type pathInput struct {
	service string // the web_service key
	svc     egress.Service
	index   int
	entry   config.SensitivePath
}

// Budget is the most requests the procedure sends in one run.
func (*SensitivePaths) Budget(s config.Settings) int { return s.SensitivePathMaxRequests }

// Jobs visits paths by severity then list order, cycling services for each path. This
// prioritises high-risk coverage and spreads requests across hosts. Keys hash response
// matchers; egress indexes the original list position.
func (*SensitivePaths) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		var svcs []pathInput
		all := v.WebServices()
		upgraded := upgradedServices(v, all)
		for _, ws := range all {
			if !v.SaaSServed(ws.Svc.Host) && !upgraded[ws.Key] {
				svcs = append(svcs, pathInput{service: ws.Key, svc: ws.Svc})
			}
		}
		entries := v.Settings().SensitivePathEntries
		order := make([]int, len(entries))
		for i := range order {
			order[i] = i
		}
		slices.SortStableFunc(order, func(a, b int) int { return entries[a].SeverityRank() - entries[b].SeverityRank() })
		for _, i := range order {
			entry := entries[i]
			hash := entry.Hash()
			for _, in := range svcs {
				in.index, in.entry = i, entry
				key := fmt.Sprintf("%s|%s|%s", in.service, entry.Path, hash)
				if !yield(run.Job{Key: key, Input: in}, nil) {
					return
				}
			}
		}
	}
}

// upgradedServices are the HTTP services whose own answer redirects to an HTTPS service of the
// same host that is itself listed: the paths are asked of that service, so asking this one too
// would send every request twice.
func upgradedServices(v run.View, all []run.WebService) map[string]bool {
	listed := map[string]bool{}
	for _, ws := range all {
		listed[ws.Key] = true
	}
	out := map[string]bool{}
	for _, rec := range v.Records(kinds.WebService) {
		svc, ok := egress.ParseService(rec.Key)
		if !ok || svc.Scheme != "http" || !listed[rec.Key] {
			continue
		}
		to, ok := egress.ParseService(kinds.WebService.Attrs(rec).Redirect)
		if ok && to.Scheme == "https" && to.Host == svc.Host && listed[weburl.Origin(to.Scheme, to.Host, to.Port)] {
			out[rec.Key] = true
		}
	}
	return out
}

// Run stores sensitive_hit only for the expected status and matcher. Nonmatches, missing
// services and policy refusals complete without evidence.
func (*SensitivePaths) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(pathInput)
	res, err := e.HTTP.Get(ctx, egress.SensitivePath(in.svc, in.index))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", c.Key, err)
	}
	r, ok := res.(egress.Response)
	if !ok {
		return nil, nil
	}
	sig, ok := in.entry.Match(r.Status, r.Body)
	if !ok {
		return nil, nil
	}
	hash := in.entry.Hash()
	return []run.Observation{kinds.SensitiveHit.Obs(in.service+"|"+in.entry.Path+"|"+hash, kinds.SensitiveHitAttrs{
		Service: in.service, Host: in.svc.Host, URL: in.service + in.entry.Path, Path: in.entry.Path,
		Status: r.Status, Size: bodySize(r), Signature: sig, Hash: hash,
	})}, nil
}

// bodySize prefers Content-Length for capped bodies when valid, otherwise reports the read
// length with "+" for unknown totals.
func bodySize(r egress.Response) kinds.Size {
	if !r.Truncated {
		return kinds.SizeOf(int64(len(r.Body)))
	}
	if n, err := strconv.ParseInt(r.HeaderValue("Content-Length"), 10, 64); err == nil && n >= int64(len(r.Body)) {
		return kinds.SizeOf(n)
	}
	return kinds.Size(fmt.Sprintf("%d+", len(r.Body)))
}
