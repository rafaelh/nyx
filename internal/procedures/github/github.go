// Package github is the github procedure: public repositories that mention an
// in-scope root domain.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/httpsrc"
	scopeinput "github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/sanitize"
	"github.com/rafaelh/nyx/internal/scope"
)

const (
	// maxWait bounds waitable rate limits. Later resets abort this procedure for the run.
	maxWait = 60 * time.Second
	// maxWaits bounds repeated waits so a persistent limit cannot stall one page
	// indefinitely.
	maxWaits = 5
	perPage  = 100
	// lastPage enforces GitHub's 1,000-result ceiling even when pages contain fewer than
	// perPage results.
	lastPage = 1000 / perPage
)

// Procedure searches GitHub code for each quoted in-scope input root. It stores repository/file
// locations and matching in-scope hostnames, never fragments or inferred secrets.
//
// Jobs include root and result cap, so cap changes rerun searches. Other refreshes, including
// extracting names under roots added later, require --redo github because scope is not in the
// key.
type Procedure struct{}

// New returns the github procedure.
func New() *Procedure { return &Procedure{} }

func (*Procedure) Name() string         { return "github" }
func (*Procedure) Contact() run.Contact { return run.ThirdParty }
func (*Procedure) Sources() []string    { return []string{"api.github.com"} }

// Configured needs keys.github, a personal access token: GitHub's code search
// does not answer unauthenticated requests.
func (*Procedure) Configured(e run.Env) (bool, string) { return httpsrc.Configured(e, "github", true) }

// Evidence is the root searched. The item leaves out the cap, so changing
// github.max_results does not count a name twice.
func (*Procedure) Evidence(jobKey string) (source, item string) {
	root, _, _ := strings.Cut(jobKey, "|")
	return "github", root
}

// input carries scope and roots so Run can extract in-scope subdomains while excluding root
// names themselves.
type input struct {
	root  string
	max   int
	roots []string
	sc    *scope.Scope
}

// Jobs yields one job per in-scope input root, keyed "<root>|max=<n>".
func (*Procedure) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		limit := v.Settings().GitHub.MaxResults
		roots := v.InScopeRoots()
		for _, r := range roots {
			if !yield(run.Job{Key: fmt.Sprintf("%s|max=%d", r, limit), Input: input{root: r, max: limit, roots: roots, sc: v.Scope()}}, nil) {
				return
			}
		}
	}
}

// searchResult is the part of a code search page that the procedure reads.
type searchResult struct {
	Total int `json:"total_count"`
	// Items is nil when the answer has no "items" array, which is unreadable.
	Items []match `json:"items"`
}

// match is one file that matched.
type match struct {
	Path       string `json:"path"`
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	TextMatches []struct {
		Fragment string `json:"fragment"`
	} `json:"text_matches"`
}

// Run reads the root's result pages until the cap, the total, an empty page or
// the last page GitHub serves.
func (s *Procedure) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(input)
	var obs []run.Observation
	seen := map[string]bool{}  // match URLs
	named := map[string]bool{} // hostnames already observed
	for read, page := 0, 1; read < in.max && page <= lastPage; page++ {
		res, err := search(ctx, e, in.root, page)
		if err != nil {
			return nil, fmt.Errorf("github %s: %w", in.root, err)
		}
		items := res.Items[:min(len(res.Items), in.max-read)]
		if len(items) == 0 {
			break
		}
		read += len(items)
		for _, it := range items {
			u := sanitize.Text(it.HTMLURL)
			if u == "" || seen[u] {
				continue
			}
			seen[u] = true
			names := in.hostnames(it)
			obs = append(obs, kinds.CodeMention.Obs(u, kinds.CodeMentionAttrs{
				Root: in.root, Repository: sanitize.Text(it.Repository.FullName), Path: sanitize.Text(it.Path),
				Hostnames: strings.Join(names, ";"),
			}))
			for _, n := range names {
				if !named[n] {
					named[n] = true
					obs = append(obs, kinds.Hostname.Obs(n, kinds.HostnameAttrs{}))
				}
			}
		}
		if read >= res.Total {
			break
		}
	}
	return obs, nil
}

// search retries the same page for rate limits lifting within maxWait. A 401 or unhandled
// 403/429 aborts the procedure. Other statuses, truncation and invalid responses remain retryable
// job failures.
func search(ctx context.Context, e egress.Clients, root string, page int) (searchResult, error) {
	q := url.Values{"q": {`"` + root + `"`}, "per_page": {strconv.Itoa(perPage)}, "page": {strconv.Itoa(page)}}
	req := egress.ThirdPartyRequest{
		Method: "GET", URL: "https://api.github.com/search/code?" + q.Encode(),
		KeySource: "github", KeyHeader: "Authorization", KeyPrefix: "Bearer ",
		Accept: "application/vnd.github.text-match+json",
	}
	for waits := 0; ; waits++ {
		resp, err := e.ThirdParty.Do(ctx, req)
		if err != nil {
			return searchResult{}, err
		}
		switch {
		case resp.Status == 401:
			return searchResult{}, fmt.Errorf("HTTP 401 (key rejected): %w", run.ErrKeyRejected)
		case resp.Status == 403 || resp.Status == 429:
			wait, ok := resetWait(resp, time.Now())
			if !ok || wait > maxWait || waits == maxWaits {
				return searchResult{}, fmt.Errorf("HTTP %d (key rejected, or rate limit not lifting within %v): %w", resp.Status, maxWait, run.ErrAbortProcedure)
			}
			if err := httpsrc.Sleep(ctx, wait); err != nil {
				return searchResult{}, err
			}
			continue
		case resp.Status != 200:
			return searchResult{}, fmt.Errorf("HTTP %d", resp.Status)
		case resp.Truncated:
			return searchResult{}, errors.New("response was larger than the 10 MiB limit")
		}
		var res searchResult
		if err := json.Unmarshal(resp.Body, &res); err != nil || res.Items == nil {
			return searchResult{}, errors.New("unreadable response")
		}
		return res, nil
	}
}

// resetWait reads Retry-After or an exhausted quota's reset timestamp, with a one-second
// minimum. Without either signal, the refusal is not treated as a waitable limit.
func resetWait(resp egress.ThirdPartyResponse, now time.Time) (wait time.Duration, ok bool) {
	if v := resp.HeaderValue("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return max(time.Duration(secs)*time.Second, time.Second), true
		}
	}
	if resp.HeaderValue("X-RateLimit-Remaining") != "0" {
		return 0, false
	}
	reset, err := strconv.ParseInt(resp.HeaderValue("X-RateLimit-Reset"), 10, 64)
	if err != nil {
		return 0, false
	}
	return max(time.Unix(reset, 0).Sub(now), time.Second), true
}

// tokens includes underscores/wildcards so invalid names are rejected as a whole instead of
// yielding a misleading valid suffix.
var tokens = regexp.MustCompile(`[A-Za-z0-9_*.-]+`)

// hostnames extracts sorted in-scope subdomains from response fragments without retaining the
// fragments. Root names are omitted because the search already implies them.
func (in input) hostnames(it match) []string {
	set := map[string]bool{}
	for _, m := range it.TextMatches {
		for _, loc := range tokens.FindAllStringIndex(m.Fragment, -1) {
			tok := unescaped(m.Fragment, loc[0], m.Fragment[loc[0]:loc[1]])
			if !strings.Contains(tok, ".") { // a plain word; no name under a root
				continue
			}
			n := scopeinput.CleanName(strings.Trim(tok, ".-"))
			if n != "" && !slices.Contains(in.roots, n) && in.sc.HostInScope(n) {
				set[n] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// unescaped removes escape tails accidentally included at the start of a hostname token, such
// as "2F" in "%2Fapi.example.com" or the letter after a backslash. Escaped backslashes do not
// escape the following hostname.
func unescaped(s string, i int, tok string) string {
	if i == 0 {
		return tok
	}
	switch s[i-1] {
	case '%':
		if hexRun(tok, 0, 2) {
			return tok[2:]
		}
	case '\\':
		slashes := 0
		for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
			slashes++
		}
		switch {
		case slashes%2 == 0:
		case tok[0] == 'x' && hexRun(tok, 1, 2):
			return tok[3:]
		case tok[0] == 'u' && hexRun(tok, 1, 4):
			return tok[5:]
		case tok[0] == 'n' || tok[0] == 'r' || tok[0] == 't':
			return tok[1:]
		}
	}
	return tok
}

// hexRun reports whether tok[from:from+n] exists and is all hex digits.
func hexRun(tok string, from, n int) bool {
	if len(tok) < from+n {
		return false
	}
	return strings.Trim(tok[from:from+n], "0123456789abcdefABCDEF") == ""
}
