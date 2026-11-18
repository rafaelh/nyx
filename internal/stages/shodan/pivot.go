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
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

// maxPivotHosts is the most hosts a search may return for its result to be
// recorded. An identifier that more hosts share is a template, a plugin or a
// framework default, and says nothing about who runs them.
const maxPivotHosts = 200

// defaultFavicons are the favicon hashes that are not pivoted: the empty file,
// which a server with no icon may answer with, and the default icons of common
// frameworks, which every installation that has not changed them shares. The
// README lists them.
var defaultFavicons = map[string]string{
	"0":          "the empty file",
	"116323821":  "Spring Boot",
	"81586312":   "Jenkins",
	"-297069493": "Apache Tomcat",
}

// Pivot is the identifier-pivot stage: for each analytics ID, pixel ID or favicon
// hash seen on an in-scope web service that no SaaS platform serves, one Shodan
// search for the hosts that show the same identifier. Copyright lines are never
// searched, and neither are the favicon hashes in defaultFavicons.
//
// A hostname on a returned host is recorded when it is under an in-scope root,
// and otherwise gives its registrable domain as a candidate root. A returned
// address is recorded as an ip and classified like any other; it is never
// contacted unless the scope says it may be. Only the first page of results is
// read.
//
// The check key is the identifier alone: it carries no scope, so a hostname
// under a root promoted later is recorded only as that candidate root until
// --redo identifier-pivot (a search spends a query credit, and a key with the
// scope in it would spend one per identifier on every change). The stage is
// budgeted by identifier_pivot.max_queries. It is third-party contact, so it runs
// under --passive, over the identifiers earlier runs recorded.
type Pivot struct{ shodanAPI }

// NewPivot returns the identifier-pivot stage.
func NewPivot() *Pivot { return &Pivot{} }

func (*Pivot) Name() string { return "identifier-pivot" }

// Budget is identifier_pivot.max_queries: each check is one search.
func (*Pivot) Budget(s config.Settings) int { return s.IdentifierPivot.MaxQueries }

// Evidence is what a candidate a search found rests on: the identifier it was
// found by, in the source ("identifier-pivot:G-ABC123"), so that the sources column
// says which. The candidate family table holds the part before the colon, so every
// identifier is one family however many found the candidate.
func (*Pivot) Evidence(checkKey string) (source, item string) {
	_, id, _ := strings.Cut(checkKey, "|")
	return "identifier-pivot:" + id, id
}

// pivotInput is the Check.Input: the identifier and its Shodan search. The scope
// travels in it so that Run can tell a hostname under an in-scope root from any
// other name.
type pivotInput struct {
	id, query string
	sc        *scope.Scope
}

// Checks yields, in key order, one check per distinct identifier on a shown web
// service that no SaaS platform serves. A SaaS platform's identifier is the
// platform's, not the organisation's. The test is the one the web posture
// findings use, so the two cannot disagree.
func (*Pivot) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		pivotable := map[string]bool{} // the service keys
		for _, ws := range v.WebServices() {
			if !v.SaaSServed(ws.Svc.Host) {
				pivotable[ws.Key] = true
			}
		}
		sc := v.Scope()
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
		for _, key := range slices.Sorted(maps.Keys(keys)) {
			if !yield(run.Check{Key: key, Input: keys[key], Cost: 1}, nil) {
				return
			}
		}
	}
}

// Run reads the first page of the search. More than maxPivotHosts hosts records
// nothing and warns. A 401, 403 or 429 aborts the stage (httpsrc), and so does a
// 402: no credits are left, and the searches not yet sent wait for the next run.
func (*Pivot) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
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
		return nil, fmt.Errorf("identifier-pivot %s: unreadable response: %v", in.id, err)
	}
	if r.Total > maxPivotHosts {
		run.Warnf(ctx, "identifier-pivot %s: %s matches %d hosts, more than %d: a shared identifier, so nothing is recorded",
			in.id, in.query, r.Total, maxPivotHosts)
		return nil, nil
	}
	var obs []run.Observation
	seen := map[string]bool{}
	for _, m := range r.Matches {
		if a, ok := input.IPLiteral(m.IPStr); ok && !seen["ip|"+a.String()] {
			seen["ip|"+a.String()] = true
			obs = append(obs, kinds.IP.Obs(a.String()))
		}
		obs = append(obs, nameObs(in.sc, seen, m.Hostnames, "")...)
	}
	return obs, nil
}
