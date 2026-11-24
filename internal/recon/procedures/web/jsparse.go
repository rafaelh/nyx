package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"maps"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/weburl"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/term/layout"
)

const (
	// maxEndpointsPerScript caps the URLs recorded from one script.
	maxEndpointsPerScript = 500
	// parserVersion versions extraction changes not represented by patterns or caps.
	parserVersion = 1
)

// parserHash versions job keys when extraction rules change.
var parserHash = func() string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d|%s|%d|%d", parserVersion, endpointPattern, maxEndpointsPerScript, egress.MaxScriptBody))
	return hex.EncodeToString(sum[:4])
}()

// JSParse fetches recorded in-scope scripts and extracts URLs/hostnames. Extracted endpoints
// are recorded without requests. Egress permits only crawl-recorded script URLs; the crawl
// follows page links rather than parsed script endpoints.
type JSParse struct{}

// NewJSParse returns the jsparse procedure.
func NewJSParse() *JSParse { return &JSParse{} }

func (*JSParse) Name() string                      { return "jsparse" }
func (*JSParse) Contact() run.Contact              { return run.Target }
func (*JSParse) Sources() []string                 { return nil }
func (*JSParse) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedJobs removes evidence from scripts no longer referenced by crawling. Parser
// changes create new jobs for remaining scripts.
func (*JSParse) RetiresUnlistedJobs() {}

// Evidence uses the script URL independently of parser-version job keys, avoiding duplicate
// support after parser changes.
func (*JSParse) Evidence(jobKey string) (source, item string) {
	item, _, _ = strings.Cut(jobKey, "|p=")
	return "jsparse", item
}

type scriptInput struct {
	url string
	sc  *scope.Scope
}

// Jobs selects current scripts on eligible probe hosts or in-scope IPs, excluding SaaS.
// Per-origin caps prefer already-read scripts so newly sorted URLs cannot evict existing work.
// Parser version is keyed; scope is not, so extracting names under newly added roots needs
// --redo jsparse.
func (*JSParse) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		parsed := map[string]bool{}
		for _, rec := range v.Records(kinds.ScriptParsed) {
			parsed[rec.Key] = true
		}
		byOrigin := scriptsByOrigin(v)
		limit := v.Settings().JSParse.MaxScripts
		for _, origin := range slices.Sorted(maps.Keys(byOrigin)) {
			urls, skipped := capScripts(byOrigin[origin], parsed, limit)
			if skipped > 0 {
				v.Warn("jsparse: %d %s of %s not read: at most %d are read per origin (jsparse.max_scripts)",
					skipped, layout.Plural(skipped, "script", "scripts"), origin, limit)
			}
			for _, u := range urls {
				if !yield(run.Job{Key: u + "|p=" + parserHash, Input: scriptInput{url: u, sc: v.Scope()}}, nil) {
					return
				}
			}
		}
	}
}

// scriptsByOrigin groups eligible non-SaaS scripts by origin.
func scriptsByOrigin(v run.View) map[string][]string {
	probe := map[string]bool{}
	for _, h := range v.ProbeHostnames() {
		probe[h] = true
	}
	byOrigin := map[string][]string{}
	for _, rec := range v.Records(kinds.Script) {
		host := weburl.HostOfURL(rec.Key)
		if !fetchableHost(v, probe, host) || v.SaaSServed(host) {
			continue
		}
		o := originOf(rec.Key)
		byOrigin[o] = append(byOrigin[o], rec.Key)
	}
	return byOrigin
}

// capScripts prioritises already-read scripts, fills remaining slots in URL order, then returns
// sorted selections and the omitted count.
func capScripts(urls []string, parsed map[string]bool, limit int) ([]string, int) {
	slices.Sort(urls)
	skipped := len(urls) - limit
	if skipped <= 0 {
		return urls, 0
	}
	var read, unread []string
	for _, u := range urls {
		if parsed[u] {
			read = append(read, u)
		} else {
			unread = append(unread, u)
		}
	}
	urls = append(read, unread...)[:limit]
	slices.Sort(urls)
	return urls, skipped
}

// fetchableHost accepts probe hostnames or non-excluded in-scope IP literals.
func fetchableHost(v run.View, probe map[string]bool, host string) bool {
	if _, isIP := input.IPLiteral(host); isIP {
		return v.Scope().WebHostInScope(host)
	}
	return probe[host]
}

// Run marks completed script jobs with script_parsed even for empty/unusable responses.
// Timeouts remain transient and uncompleted.
func (*JSParse) Run(ctx context.Context, chk run.Job, e egress.Clients) ([]run.Observation, error) {
	in := chk.Input.(scriptInput)
	obs := []run.Observation{kinds.ScriptParsed.Obs(in.url)}
	scriptHost := weburl.HostOfURL(in.url)
	resp, ok, err := fetchScript(ctx, e, in.url, scriptHost)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", chk.Key, err)
	}
	if !ok || isMarkup(resp) {
		return obs, nil
	}
	if resp.Truncated {
		run.Warnf(ctx, "jsparse: %s is longer than %d MiB: truncated, only the first %d MiB was read", in.url, egress.MaxScriptBody>>20, egress.MaxScriptBody>>20)
	}
	found := ExtractEndpoints(resp.Body, originOf(resp.URL()))
	hosts := map[string]bool{}
	recorded, more := 0, false
	for _, u := range found {
		host := weburl.HostOfURL(u)
		if !in.sc.WebHostInScope(host) {
			continue
		}
		if d, ok := otherHost(host, scriptHost); ok {
			hosts[d] = true
		}
		if recorded == maxEndpointsPerScript {
			more = true
			continue
		}
		recorded++
		obs = append(obs, kinds.URL.Obs(u, kinds.URLAttrs{URL: u, Host: host}))
	}
	if more {
		run.Warnf(ctx, "jsparse: %s names more than %d URLs in scope: only the first %d are recorded", in.url, maxEndpointsPerScript, maxEndpointsPerScript)
	}
	for _, h := range slices.Sorted(maps.Keys(hosts)) {
		obs = append(obs, kinds.Hostname.Obs(h, kinds.HostnameAttrs{}))
	}
	return obs, nil
}

var errScriptTimeout = errors.New("no complete response within the HTTP timeout")

// fetchScript follows same-host redirects. Non-2xx, external redirects and policy refusals
// return ok=false.
func fetchScript(ctx context.Context, e egress.Clients, scriptURL, host string) (egress.Response, bool, error) {
	req := egress.Script(scriptURL)
	visited := map[string]bool{scriptURL: true}
	for hop := 0; ; hop++ {
		res, err := e.HTTP.Get(ctx, req)
		if err != nil {
			return egress.Response{}, false, err
		}
		switch r := res.(type) {
		case egress.NoService:
			if r.Reason == egress.NoServiceTimeout {
				return egress.Response{}, false, errScriptTimeout
			}
			return egress.Response{}, false, nil
		case egress.Response:
			if !isRedirect(r.Status) {
				return r, r.Status >= 200 && r.Status < 300, nil
			}
			target, _ := redirectTarget(r) // "", which has no host, when it cannot be resolved
			if r.Location == "" || weburl.HostOfURL(target) != host || visited[target] || hop >= maxHops {
				return egress.Response{}, false, nil
			}
			visited[target] = true
			if req, err = egress.Redirect(r); err != nil {
				return egress.Response{}, false, nil //nolint:nilerr // a redirect that cannot be followed means there is no script to parse
			}
		default: // refused
			return egress.Response{}, false, nil
		}
	}
}

// isMarkup rejects script responses declaring HTML or starting with markup.
func isMarkup(r egress.Response) bool {
	if r.ContentType() == "text/html" {
		return true
	}
	body := bytes.TrimPrefix(r.Body, []byte("\xef\xbb\xbf")) // a UTF-8 byte order mark
	body = bytes.TrimLeft(body, " \t\r\n")
	return len(body) > 0 && body[0] == '<'
}
