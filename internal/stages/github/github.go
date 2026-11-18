// Package github is the github stage: public repositories that mention an
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
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/sanitize"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

const (
	// maxWait is the longest rate-limit wait the stage sits out. A reset further
	// away stops the stage for the run, as for any other keyed source.
	maxWait = 60 * time.Second
	// maxWaits is how many times in a row one page is waited for. A limit that is
	// still in force after that many waits is not going to lift.
	maxWaits = 5
	perPage  = 100
	// lastPage is the last page GitHub serves: a search returns at most 1,000
	// results, and asking past them is refused. A page can hold fewer than
	// perPage results, so the cap alone does not keep the stage within it.
	lastPage = 1000 / perPage
)

// Stage searches GitHub's code for the quoted text of each in-scope input root
// and records where it is mentioned: the repository, the file path and the
// match's URL, with the hostnames under an in-scope root that the returned
// fragment names. The stage queries GitHub about the domain, never the target,
// and never stores a fragment, so nothing about secrets is recorded or inferred.
//
// A root is searched once. The check is keyed by the root and the cap, so
// github.max_results changes search again; new mentions appear only after
// --redo github. The key carries no scope: a hostname under a root added later
// was ignored and is recorded only after --redo github.
type Stage struct{}

// New returns the github stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string         { return "github" }
func (*Stage) Contact() run.Contact { return run.ThirdParty }
func (*Stage) Sources() []string    { return []string{"api.github.com"} }

// Configured needs keys.github, a personal access token: GitHub's code search
// does not answer unauthenticated requests.
func (*Stage) Configured(e run.Env) (bool, string) { return httpsrc.Configured(e, "github", true) }

// Evidence is the root searched. The item leaves out the cap, so changing
// github.max_results does not count a name twice.
func (*Stage) Evidence(checkKey string) (source, item string) {
	root, _, _ := strings.Cut(checkKey, "|")
	return "github", root
}

// input is the Check.Input. The scope and the input roots travel in it so that
// Run can tell a hostname under an in-scope root, other than the root itself,
// from any other name.
type input struct {
	root  string
	max   int
	roots []string
	sc    *scope.Scope
}

// Checks yields one check per in-scope input root, keyed "<root>|max=<n>".
func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		limit := v.Settings().GitHub.MaxResults
		roots := v.InScopeRoots()
		for _, r := range roots {
			if !yield(run.Check{Key: fmt.Sprintf("%s|max=%d", r, limit), Input: input{root: r, max: limit, roots: roots, sc: v.Scope()}}, nil) {
				return
			}
		}
	}
}

// searchResult is the part of a code search page that the stage reads.
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
func (s *Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
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

// search asks for one page of the root's results. A rate limit that lifts within
// maxWait is waited out and the same page asked again; a 401 and any other 403 or
// 429 abort the stage. Any other status, a truncated body and an unreadable
// answer are transient errors, as for httpsrc.Get.
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
				return searchResult{}, fmt.Errorf("HTTP %d (key rejected, or rate limit not lifting within %v): %w", resp.Status, maxWait, run.ErrAbortStage)
			}
			if err := sleep(ctx, wait); err != nil {
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

// sleep waits for d or the context, whichever ends first.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// resetWait is how long GitHub asks to wait, at least a second: retry-after, or
// else the time until x-ratelimit-reset when x-ratelimit-remaining is 0. ok is
// false when the response says neither, which is a refusal and no rate limit.
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

// tokens are the runs of characters a hostname is made of, plus the underscore
// and the wildcard, so that a name such as "a_b.example.com" is one token that
// fails to validate and not a shorter name that it merely ends with.
var tokens = regexp.MustCompile(`[A-Za-z0-9_*.-]+`)

// hostnames are the names in the fragments of a match that are under an
// in-scope root, sorted. The roots themselves are not listed: every match
// mentions the root it was searched for. The fragments are read here and kept
// nowhere.
func (in input) hostnames(it match) []string {
	set := map[string]bool{}
	for _, m := range it.TextMatches {
		for _, loc := range tokens.FindAllStringIndex(m.Fragment, -1) {
			tok := unescaped(m.Fragment, loc[0], m.Fragment[loc[0]:loc[1]])
			if !strings.Contains(tok, ".") { // a plain word; no name under a root
				continue
			}
			n := httpsrc.CleanName(strings.Trim(tok, ".-"))
			if n != "" && !slices.Contains(in.roots, n) && in.sc.ClassifyHost(n).Class == scope.InScope {
				set[n] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(set))
}

// unescaped is tok, which starts at s[i:], without the tail of an escape that
// runs into it: the hex digits of a percent-encoding ("%2Fapi.example.com") or
// of a backslash escape ("\x2f", "/"), or the letter of "\n", "\r" or "\t".
// Left on, they would make a name such as "2fapi.example.com" that the text never
// named. An escaped backslash ("\\server.example.com") escapes nothing.
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
