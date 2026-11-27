package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/recon/analysis/candidates"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/procedures/httpsrc"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/scope"
)

// maxPivotHosts rejects widely shared identifiers as likely template, plugin or framework
// defaults rather than ownership evidence.
const maxPivotHosts = 200

// defaultFavicons excludes the empty file and common framework icons, which unrelated
// installations share.
var defaultFavicons = map[string]string{
	"0":          "the empty file",
	"116323821":  "Spring Boot",
	"81586312":   "Jenkins",
	"-297069493": "Apache Tomcat",
}

// Pivot searches Shodan once per non-SaaS analytics ID, pixel ID or non-default favicon.
// Copyright is not searched. It reads one result page, recording in-scope names, external
// candidate roots and addresses without granting contact permission.
//
// Keys contain the identifier, not scope, to avoid spending credits on every scope change.
// Reclassification after root promotion requires --redo identifier-pivot.
// identifier_pivot.max_queries budgets searches; passive runs can search identifiers saved
// earlier.
type Pivot struct{ shodanAPI }

// NewPivot returns the identifier-pivot procedure.
func NewPivot() *Pivot { return &Pivot{} }

func (*Pivot) Name() string { return "identifier-pivot" }

// Paid: Shodan searches spend query credits, which a free account lacks.
func (*Pivot) Paid() {}

// CandidateSources groups all identifier-pivot:<id> sources into one evidence family.
func (*Pivot) CandidateSources() map[string]string {
	return map[string]string{"identifier-pivot": candidates.WebIdentifier}
}

// Budget is identifier_pivot.max_queries: each job is one search.
func (*Pivot) Budget(s config.Settings) int { return s.IdentifierPivot.MaxQueries }

// Evidence includes the identifier in its source label for display. CandidateSources groups all
// such suffixes into one family so multiple identifiers do not appear independent.
func (*Pivot) Evidence(jobKey string) (source, item string) {
	_, id, _ := strings.Cut(jobKey, "|")
	return "identifier-pivot:" + id, id
}

// pivotInput carries the identifier, search query and scope used to classify returned names.
type pivotInput struct {
	id, query string
	sc        *scope.Scope
}

// Jobs emits one sorted job per identifier on a visible, non-SaaS service whose host is not in
// scope by address. SaaS identifiers belong to the platform, so they cannot support organisation
// pivots, and a name its address brought in is not the organisation's own. The hosting test matches
// web-posture findings.
func (*Pivot) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	sc := v.Scope()
	pivotable := map[string]bool{} // the service keys
	for _, ws := range v.WebServices() {
		if !sc.InScopeByAddress(ws.Svc.Host) && !v.SaaSServed(ws.Svc.Host) {
			pivotable[ws.Key] = true
		}
	}
	keys := map[string]pivotInput{}
	for _, rec := range v.Records(kinds.WebIdentifier) {
		a := kinds.WebIdentifier.Attrs(rec)
		if !pivotable[a.Service] || a.Value == "" {
			continue
		}
		switch a.Type {
		case kinds.IdentifierAnalytics, kinds.IdentifierPixel:
			keys["html|"+a.Value] = pivotInput{id: a.Value, query: `http.html:"` + a.Value + `"`, sc: sc}
		case kinds.IdentifierFavicon:
			if _, isDefault := defaultFavicons[a.Value]; !isDefault {
				keys["favicon|"+a.Value] = pivotInput{id: a.Value, query: "http.favicon.hash:" + a.Value, sc: sc}
			}
		}
	}
	return run.JobsOf(slices.Sorted(maps.Keys(keys)), func(key string) run.Job {
		return run.Job{Key: key, Input: keys[key], Cost: 1}
	})
}

// Run checks the first search page, discarding oversized results with a warning. Key
// refusal/rate limits and exhausted-credit 402 responses abort the procedure for later retry.
func (*Pivot) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(pivotInput)
	q := url.Values{"query": {in.query}, "page": {"1"}}
	body, err := httpsrc.GetCredits(ctx, e, egress.ThirdPartyRequest{
		Method: "GET", URL: "https://api.shodan.io/shodan/host/search?" + q.Encode(), KeySource: "shodan", KeyParam: "key",
	})
	if err != nil {
		return nil, fmt.Errorf("identifier-pivot %s: %w", in.id, err)
	}
	var r search
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("identifier-pivot %s: unreadable response: %w", in.id, err)
	}
	if r.Total > maxPivotHosts {
		run.Warnf(ctx, "identifier-pivot %s: %s matches %d hosts, more than %d: a shared identifier, so nothing is recorded",
			in.id, in.query, r.Total, maxPivotHosts)
		return nil, nil
	}
	var obs []run.Observation
	seen := map[string]bool{}
	for _, m := range r.Matches {
		a, ok := input.IPLiteral(m.IPStr)
		if ok && !seen["ip|"+a.String()] {
			seen["ip|"+a.String()] = true
			obs = append(obs, kinds.IP.Obs(a.String()))
		}
		// The match's address only tells nameObs which names are its network's reverse names:
		// they are not paired with it, as it is not the organisation's.
		obs = append(obs, nameObs(in.sc, seen, m.Hostnames, a, false)...)
	}
	return obs, nil
}
