package cli_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The github stage: code search for mentions of an in-scope root. The tests drive
// cli.Execute with the real stage; api.github.com is a loopback fake that answers
// /search/code as GitHub does, with text matches when asked for them.

const githubKey = "gh-token-SECRET-0017"

// ghFile is one search result: a file in a repository that mentions the root.
// An empty url is ghURL(repo, path).
type ghFile struct {
	repo, path, url string
	fragments       []string
}

func ghURL(repo, path string) string { return "https://github.com/" + repo + "/blob/main/" + path }

// ghPage is the JSON GitHub answers a code search page with.
func ghPage(total int, files []ghFile) []byte {
	type textMatch struct {
		Fragment string `json:"fragment"`
		Matches  []any  `json:"matches"`
	}
	type item struct {
		Name       string `json:"name"`
		Path       string `json:"path"`
		HTMLURL    string `json:"html_url"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		TextMatches []textMatch `json:"text_matches"`
	}
	out := struct {
		Total      int    `json:"total_count"`
		Incomplete bool   `json:"incomplete_results"`
		Items      []item `json:"items"`
	}{Total: total, Items: []item{}}
	for _, f := range files {
		var it item
		it.Name = f.path[strings.LastIndex(f.path, "/")+1:]
		it.Path, it.HTMLURL, it.Repository.FullName = f.path, f.url, f.repo
		if it.HTMLURL == "" {
			it.HTMLURL = ghURL(f.repo, f.path)
		}
		for _, fr := range f.fragments {
			it.TextMatches = append(it.TextMatches, textMatch{Fragment: fr, Matches: []any{}})
		}
		out.Items = append(out.Items, it)
	}
	b, _ := json.Marshal(out)
	return b
}

// ghFake is api.github.com's code search.
type ghFake struct {
	mu    sync.Mutex
	files map[string][]ghFile // by root
	// total, when set for a root, is the total_count reported instead of the number of files.
	total map[string]int
	// before may answer a request itself (it returns true); n counts the requests
	// made so far for the same root and page, this one included.
	before func(rw http.ResponseWriter, root string, page, n int) bool
	seen   map[string]int
}

func newGH(files map[string][]ghFile) *ghFake {
	return &ghFake{files: files, total: map[string]int{}, seen: map[string]int{}}
}

func (g *ghFake) set(root string, files []ghFile) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.files[root] = files
}

func (g *ghFake) serve(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/search/code" || r.Method != "GET" || r.Header.Get("Authorization") != "Bearer "+githubKey {
		http.Error(rw, "bad credentials", 401)
		return
	}
	q := r.URL.Query()
	root := strings.Trim(q.Get("q"), `"`)
	page, _ := strconv.Atoi(q.Get("page"))
	per, _ := strconv.Atoi(q.Get("per_page"))
	g.mu.Lock()
	g.seen[root+"|"+strconv.Itoa(page)]++
	n := g.seen[root+"|"+strconv.Itoa(page)]
	before := g.before
	all := g.files[root]
	total, ok := g.total[root]
	g.mu.Unlock()
	if before != nil && before(rw, root, page, n) {
		return
	}
	if !ok {
		total = len(all)
	}
	lo := min((page-1)*per, len(all))
	hi := min(lo+per, len(all))
	_, _ = rw.Write(ghPage(total, all[lo:hi]))
}

// ghWorld is a world with api.github.com served by g and the key set.
func ghWorld(t *testing.T, g *ghFake) *world {
	t.Helper()
	w := newWorld(t)
	w.h.setenv("NYX_KEYS_GITHUB", githubKey)
	w.handle("api.github.com", g.serve)
	return w
}

// ghQueries are the queries the fake received, in order.
func ghQueries(w *world) []url.Values {
	var out []url.Values
	for _, r := range w.requests("api.github.com") {
		u, _ := url.Parse(r.URI)
		out = append(out, u.Query())
	}
	return out
}

// ghAsked lists "<root>#<page>" for each request, in order.
func ghAsked(w *world) []string {
	var out []string
	for _, q := range ghQueries(w) {
		out = append(out, strings.Trim(q.Get("q"), `"`)+"#"+q.Get("page"))
	}
	return out
}

// ghMany makes n files for a root, named by their index. A URL belongs to one
// match, so the files of two roots never share one.
func ghMany(root string, n int) []ghFile {
	var out []ghFile
	for i := range n {
		p := fmt.Sprintf("conf/%s-f%03d.yml", root, i)
		out = append(out, ghFile{repo: "acme/infra", path: p})
	}
	return out
}

// ghFailed is how many checks of the github stage failed in the last run: a stage
// is "failed" only when every check was, so a stop partway shows as done with a count.
func ghFailed(w *world) int { return lastState(w.h.events(), "github").num("failed") }

func ghCheckKey(root string, max int) string { return fmt.Sprintf("%s|max=%d", root, max) }

func TestGitHub_NotConfiguredWithoutKey(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if st, reason := stateOf(w, "github"); st != "not-configured" || reason != "no key" {
		t.Errorf("github = %s (%s), want not-configured (no key)", st, reason)
	}
	if n := len(w.requests("api.github.com")); n != 0 {
		t.Errorf("sent %d requests without a key", n)
	}
}

// A match is a row with its location and the in-scope names of its fragment. No
// fragment text is kept, nothing is inferred from it, and the stage runs passively.
func TestGitHub_RowsHostnamesAndNoFragmentText(t *testing.T) {
	t.Parallel()
	const (
		secretA = "password=hunter2-SECRETWORD"
		secretB = "A_FRAGMENT_PHRASE_NEVER_STORED"
	)
	u1, u2 := ghURL("octocat/infra", "deploy/hosts.yml"), ghURL("someone/dotfiles", "notes.txt")
	g := newGH(map[string][]ghFile{"example.com": {
		{repo: "octocat/infra", path: "deploy/hosts.yml", fragments: []string{
			"ci: internal-jenkins.example.com:8080\n" + secretA,
			"also vpn.example.com and cdn.example.org and example.com " + secretB,
			// Escapes that run into a name do not make a longer one.
			`next=https%3A%2F%2Fsso.example.com%2Fin "a\nwiki.example.com" \\files.example.com\share`,
		}},
		{repo: "someone/dotfiles", path: "notes.txt", fragments: []string{
			"see staging.example.com.attacker.net and mail admin@example.com or config.json",
		}},
	}})
	w := ghWorld(t, g)
	w.dns.A("internal-jenkins.example.com", "203.0.113.5")
	w.dns.A("vpn.example.com", "203.0.113.6")
	w.dns.A("cdn.example.org", "203.0.113.7")
	if code := w.run("--passive", "--no-permutations", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if st, _ := stateOf(w, "github"); st != "done" {
		t.Errorf("github state = %s, want done: --passive runs the stage", st)
	}
	rows := w.table(eng, "code-mentions.csv")
	if len(rows) != 2 {
		t.Fatalf("code-mentions.csv = %s, want 2 rows", w.file(eng, "code-mentions.csv"))
	}
	if r := find(rows, "url", u1); r == nil || r["repository"] != "octocat/infra" || r["path"] != "deploy/hosts.yml" ||
		r["hostnames"] != "files.example.com;internal-jenkins.example.com;sso.example.com;vpn.example.com;wiki.example.com" || r["root"] != "example.com" || r["current"] != "true" {
		t.Errorf("row for %s = %v", u1, r)
	}
	// A personal account is recorded like any other. Names that are not under an
	// in-scope root, and the root itself, are not hostnames of the row.
	if r := find(rows, "url", u2); r == nil || r["repository"] != "someone/dotfiles" || r["hostnames"] != "" || r["root"] != "example.com" {
		t.Errorf("row for %s = %v", u2, r)
	}
	if got := strings.Split(strings.SplitN(w.file(eng, "code-mentions.csv"), "\n", 2)[0], ","); !slices.Equal(got[:5], []string{"repository", "path", "url", "hostnames", "root"}) {
		t.Errorf("columns = %v", got)
	}
	subs := w.lines(eng, "subdomains.txt")
	for _, na := range [][2]string{{"internal-jenkins.example.com", "203.0.113.5"}, {"vpn.example.com", "203.0.113.6"}} {
		n := na[0]
		if !slices.Contains(subs, n) {
			t.Errorf("subdomains.txt missing %s: %v", n, subs)
		}
		if resolutionSource(w, n, "A", na[1]) == "<no row>" {
			t.Errorf("%s was recorded but not resolved", n)
		}
	}
	recorded := w.obsAttrs(eng, "hostname")
	for _, n := range []string{"cdn.example.org", "staging.example.com.attacker.net", "config.json", "attacker.net", "2fsso.example.com", "nwiki.example.com", "iles.example.com"} {
		if _, ok := recorded[n]; ok {
			t.Errorf("%s must not be recorded as a hostname", n)
		}
	}
	if cands := w.table(eng, "candidates.csv"); find(cands, "value", "cdn.example.org") != nil || find(cands, "value", "attacker.net") != nil {
		t.Errorf("a name outside scope is not even a candidate: %s", w.file(eng, "candidates.csv"))
	}
	// Locations only: nothing of the fragments is kept anywhere, and nothing is a finding.
	for _, text := range []string{secretA, "hunter2", secretB, "8080"} {
		if hits := w.anywhere(eng, text); len(hits) > 0 {
			t.Errorf("fragment text %q written to %v", text, hits)
		}
	}
	if fs, _ := w.h.summaryEvent()["findings"].([]any); len(fs) != 0 {
		t.Errorf("findings = %v, want none", fs)
	}
	if n := countOf(w, "code mentions"); n != 2 {
		t.Errorf("summary counts %d code mentions, want 2", n)
	}
	if hits := leaks(w); len(hits) > 0 {
		t.Errorf("key leaked into %v", hits)
	}
}

func countOf(w *world, category string) int {
	totals, _ := w.h.summaryEvent()["totals"].(map[string]any)
	n, _ := totals[category].(float64)
	return int(n)
}

// Repository, path and URL are target-influenced text and are written sanitised.
func TestGitHub_TextIsSanitised(t *testing.T) {
	t.Parallel()
	u := ghURL("evil/repo", "a/b.txt")
	g := newGH(map[string][]ghFile{"example.com": {
		{repo: "evil/\x1b[31mrepo\x1b[0m", path: "a/\x1b]0;owned\x07b.txt‮", url: u, fragments: []string{"x"}},
	}})
	w := ghWorld(t, g)
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	rows := w.table(eng, "code-mentions.csv")
	if len(rows) != 1 || rows[0]["repository"] != "evil/repo" || rows[0]["path"] != "a/b.txt" {
		t.Fatalf("rows = %v", rows)
	}
	// The database is binary and holds the odd 0x1b or 0x07 as structure, so the
	// escape sequences are looked for by their text.
	for _, s := range []string{"[31m", ";owned", "‮"} {
		if hits := w.anywhere(eng, s); len(hits) > 0 {
			t.Errorf("unsanitised %q written to %v", s, hits)
		}
	}
}

// The request is the documented code search for the quoted root, with the key as
// a bearer token and the text-match media type; roots out of scope are not searched.
func TestGitHub_RequestShape(t *testing.T) {
	t.Parallel()
	g := newGH(map[string][]ghFile{"example.com": ghMany("example.com", 1), "example.net": ghMany("example.net", 1), "example.org": ghMany("example.org", 1)})
	w := ghWorld(t, g)
	if code := w.run("--passive", "--concurrency", "1", "-e", eng, "--exclude", "example.net", "example.org", "example.net", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	// In order of the roots, whatever order the inputs were given in.
	if got := ghAsked(w); !slices.Equal(got, []string{"example.com#1", "example.org#1"}) {
		t.Fatalf("asked = %v, want the in-scope roots only, sorted", got)
	}
	r := w.requests("api.github.com")[0]
	q := ghQueries(w)[0]
	if r.Method != "GET" || !strings.HasPrefix(r.URI, "/search/code?") || q.Get("q") != `"example.com"` || q.Get("per_page") != "100" {
		t.Errorf("request = %s %s", r.Method, r.URI)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+githubKey {
		t.Errorf("Authorization = %q", got)
	}
	if got := r.Header.Get("Accept"); got != "application/vnd.github.text-match+json" {
		t.Errorf("Accept = %q", got)
	}
	if done := w.h.completed(eng, "github"); !slices.Equal(done, []string{ghCheckKey("example.com", 500), ghCheckKey("example.org", 500)}) {
		t.Errorf("completed = %v", done)
	}
}

// Paging ends at github.max_results, the total or an empty page. The cap is part
// of the check, so changing it searches again.
func TestGitHub_CapStopsPaging(t *testing.T) {
	t.Parallel()
	g := newGH(map[string][]ghFile{"example.com": ghMany("example.com", 250)})
	w := ghWorld(t, g)
	if code := w.run("--passive", "--github-max-results", "150", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := ghAsked(w); !slices.Equal(got, []string{"example.com#1", "example.com#2"}) {
		t.Errorf("asked = %v, want two pages for a cap of 150", got)
	}
	if n := len(w.table(eng, "code-mentions.csv")); n != 150 {
		t.Errorf("%d rows, want 150: a page is read only as far as the cap", n)
	}
	if done := w.h.completed(eng, "github"); !slices.Equal(done, []string{ghCheckKey("example.com", 150)}) {
		t.Errorf("completed = %v", done)
	}

	// The default cap is 500, and it is a new check.
	if code := w.run("--passive", "-e", eng); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := ghAsked(w)[2:]; !slices.Equal(got, []string{"example.com#1", "example.com#2", "example.com#3"}) {
		t.Errorf("after raising the cap, asked = %v, want pages 1 to 3 (the total is 250)", got)
	}
	if done := w.h.completed(eng, "github"); !slices.Equal(done, []string{ghCheckKey("example.com", 150), ghCheckKey("example.com", 500)}) {
		t.Errorf("completed = %v", done)
	}
	if n := len(w.table(eng, "code-mentions.csv")); n != 250 {
		t.Errorf("%d rows, want 250", n)
	}
}

func TestGitHub_StopsAtTheTotalOrAnEmptyPage(t *testing.T) {
	t.Parallel()
	g := newGH(map[string][]ghFile{"example.com": ghMany("example.com", 130), "example.org": ghMany("example.org", 100)})
	g.total["example.org"] = 400 // GitHub reports more than it will serve
	w := ghWorld(t, g)
	if code := w.run("--passive", "--concurrency", "1", "example.com", "example.org"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := []string{"example.com#1", "example.com#2", "example.org#1", "example.org#2"}
	if got := ghAsked(w); !slices.Equal(got, want) {
		t.Errorf("asked = %v, want %v (the total ends one root, an empty page the other)", got, want)
	}
}

// GitHub serves the first 1,000 results only, in ten pages of 100, and refuses a
// page after them. A short page leaves the cap unreached, so paging also ends at
// the tenth page, and what was read completes the root.
func TestGitHub_StopsAtGitHubsLastPage(t *testing.T) {
	t.Parallel()
	g := newGH(map[string][]ghFile{})
	all := ghMany("example.com", 500)
	g.before = func(rw http.ResponseWriter, root string, page, n int) bool {
		if page > 10 {
			http.Error(rw, `{"message":"Cannot access beyond the first 1000 results"}`, 422)
			return true
		}
		_, _ = rw.Write(ghPage(5000, all[(page-1)*50:page*50])) // short pages
		return true
	}
	w := ghWorld(t, g)
	if code := w.run("--passive", "--github-max-results", "1000", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := ghAsked(w); len(got) != 10 || got[9] != "example.com#10" {
		t.Errorf("asked = %v, want pages 1 to 10 only", got)
	}
	if done := w.h.completed(eng, "github"); !slices.Equal(done, []string{ghCheckKey("example.com", 1000)}) {
		t.Errorf("completed = %v", done)
	}
	if n := len(w.table(eng, "code-mentions.csv")); n != 500 {
		t.Errorf("%d rows, want 500", n)
	}
}

func TestGitHub_MaxResultsIsBounded(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		val  string
		code int
	}{{"0", 2}, {"-5", 2}, {"1001", 2}, {"1", 0}, {"1000", 0}} {
		t.Run(tc.val, func(t *testing.T) {
			w := newWorld(t)
			if code := w.run("--passive", "--github-max-results", tc.val, "example.com"); code != tc.code {
				t.Errorf("exit %d, want %d", code, tc.code)
			}
		})
	}
	w := newWorld(t)
	w.h.setenv("NYX_GITHUB_MAX_RESULTS", "2000")
	if code := w.run("--passive", "example.com"); code != 2 {
		t.Errorf("an environment value above 1000: exit %d, want 2", code)
	}
}

// A root's search completes once: a later run does not ask again, a root added
// later is searched, and --redo github asks again.
func TestGitHub_RootsAreSearchedOnce(t *testing.T) {
	t.Parallel()
	g := newGH(map[string][]ghFile{"example.com": ghMany("example.com", 1), "example.org": ghMany("example.org", 2)})
	w := ghWorld(t, g)
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if code := w.run("--passive", "-e", eng); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := ghAsked(w); !slices.Equal(got, []string{"example.com#1"}) {
		t.Fatalf("asked = %v: a completed root is not searched again", got)
	}
	if code := w.run("--passive", "-e", eng, "example.org"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := ghAsked(w); !slices.Equal(got, []string{"example.com#1", "example.org#1"}) {
		t.Errorf("asked = %v: only the root added later is searched", got)
	}
	if n := len(w.table(eng, "code-mentions.csv")); n != 3 {
		t.Errorf("%d rows, want 3", n)
	}
	if code := w.run("--passive", "-e", eng, "--redo", "github"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := ghAsked(w)[2:]; !slices.Equal(slices.Sorted(slices.Values(got)), []string{"example.com#1", "example.org#1"}) {
		t.Errorf("--redo github asked %v, want both roots again", got)
	}
}

// A match that is gone after --redo github is marked not current; its row keeps
// only the URL, which names the repository and the path.
func TestGitHub_RedoMarksVanishedMatchesNotCurrent(t *testing.T) {
	t.Parallel()
	keep, gone := ghURL("acme/infra", "keep.yml"), ghURL("acme/old", "gone.yml")
	g := newGH(map[string][]ghFile{"example.com": {
		{repo: "acme/infra", path: "keep.yml", fragments: []string{"a.example.com"}},
		{repo: "acme/old", path: "gone.yml", fragments: []string{"b.example.com"}},
	}})
	w := ghWorld(t, g)
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if n := countOf(w, "code mentions"); n != 2 {
		t.Fatalf("code mentions = %d, want 2", n)
	}
	g.set("example.com", g.files["example.com"][:1])
	if code := w.run("--passive", "-e", eng, "--redo", "github"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	rows := w.table(eng, "code-mentions.csv")
	if len(rows) != 2 {
		t.Fatalf("code-mentions.csv = %s, want both rows", w.file(eng, "code-mentions.csv"))
	}
	if r := find(rows, "url", keep); r == nil || r["current"] != "true" || r["repository"] != "acme/infra" {
		t.Errorf("kept row = %v", r)
	}
	r := find(rows, "url", gone)
	if r == nil || r["current"] != "false" {
		t.Fatalf("vanished row = %v, want one marked not current", r)
	}
	for _, col := range []string{"repository", "path", "hostnames", "root"} {
		if r[col] != "" {
			t.Errorf("a not-current row keeps only its URL, but %s = %q", col, r[col])
		}
	}
	if n := countOf(w, "code mentions"); n != 1 {
		t.Errorf("code mentions = %d, want 1: a match that is gone is not counted", n)
	}
}

// A mention is shown while its root is in scope.
func TestGitHub_MentionsAreShownWhileTheRootIsInScope(t *testing.T) {
	t.Parallel()
	g := newGH(map[string][]ghFile{"example.com": ghMany("example.com", 1), "example.org": ghMany("example.org", 2)})
	w := ghWorld(t, g)
	if code := w.run("--passive", "example.com", "example.org"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if n := len(w.table(eng, "code-mentions.csv")); n != 3 {
		t.Fatalf("%d rows, want 3", n)
	}
	if code := w.run("--passive", "-e", eng, "--exclude", "example.org"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	rows := w.table(eng, "code-mentions.csv")
	if len(rows) != 1 || rows[0]["root"] != "example.com" {
		t.Errorf("code-mentions.csv = %v, want only the mention of the root still in scope", rows)
	}
	if n := countOf(w, "code mentions"); n != 1 {
		t.Errorf("code mentions = %d, want 1", n)
	}
}

// --- rate limits and failures ---

// ghRefuse answers the first request for a root's page with status and hdr, then
// serves it; then, if set, runs after the refusal. An empty root matches any root.
func ghRefuse(g *ghFake, root string, page, status int, hdr map[string]string, then func()) {
	g.before = func(rw http.ResponseWriter, r string, p, n int) bool {
		if (root != "" && r != root) || p != page || n > 1 {
			return false
		}
		for k, v := range hdr {
			rw.Header().Set(k, v)
		}
		http.Error(rw, `{"message":"rate limit"}`, status)
		if then != nil {
			then()
		}
		return true
	}
}

// A reset within 60 seconds is waited for and the same page is asked again.
func TestGitHub_WaitsForAShortReset(t *testing.T) {
	t.Parallel()
	soon := func() string { return strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10) }
	for name, tc := range map[string]struct {
		status int
		hdr    func() map[string]string
	}{
		"retry-after on a 403": {403, func() map[string]string { return map[string]string{"Retry-After": "1"} }},
		"retry-after on a 429": {429, func() map[string]string { return map[string]string{"Retry-After": "1"} }},
		"reset on a 403": {403, func() map[string]string {
			return map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": soon()}
		}},
		"reset on a 429": {429, func() map[string]string {
			return map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": soon()}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := newGH(map[string][]ghFile{"example.com": ghMany("example.com", 150)})
			ghRefuse(g, "", 2, tc.status, tc.hdr(), nil)
			w := ghWorld(t, g)
			start := time.Now()
			if code := w.run("--passive", "example.com"); code != 0 {
				t.Fatalf("exit %d", code)
			}
			if took := time.Since(start); took < 900*time.Millisecond {
				t.Errorf("run took %v: the stage did not wait for the reset", took)
			}
			// Page 2 is asked again; page 1 is not read again.
			if got := ghAsked(w); !slices.Equal(got, []string{"example.com#1", "example.com#2", "example.com#2"}) {
				t.Errorf("asked = %v", got)
			}
			if st, _ := stateOf(w, "github"); st != "done" {
				t.Errorf("github state = %s, want done", st)
			}
			if n := len(w.table(eng, "code-mentions.csv")); n != 150 {
				t.Errorf("%d rows, want 150", n)
			}
			if hits := leaks(w); len(hits) > 0 {
				t.Errorf("key leaked into %v", hits)
			}
		})
	}
}

// An interrupt during the wait exits 130 at once; the roots completed before it are kept.
func TestGitHub_InterruptDuringTheWait(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g := newGH(map[string][]ghFile{"example.com": ghMany("example.com", 2), "example.org": ghMany("example.org", 3)})
	ghRefuse(g, "example.org", 1, 403, map[string]string{"Retry-After": "30"}, func() {
		go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	})
	w := ghWorld(t, g)
	start := time.Now()
	code := w.h.execCtx(ctx, "--json", "--rate-per-source", "1000", "--rate-dns", "100000", "--passive", "--concurrency", "1", "example.com", "example.org")
	if code != 130 {
		t.Fatalf("exit %d, want 130", code)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("exit took %v: the wait must end at the interrupt", took)
	}
	if done := w.h.completed(eng, "github"); !slices.Equal(done, []string{ghCheckKey("example.com", 500)}) {
		t.Errorf("completed = %v, want only the root searched before the interrupt", done)
	}
	if n := len(w.table(eng, "code-mentions.csv")); n != 2 {
		t.Errorf("%d rows, want the 2 of the completed root", n)
	}

	// The next run searches only the root that was waiting.
	if code := w.run("--passive", "-e", eng); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := ghAsked(w); !slices.Equal(got, []string{"example.com#1", "example.org#1", "example.org#1"}) {
		t.Errorf("asked = %v", got)
	}
	if n := len(w.table(eng, "code-mentions.csv")); n != 5 {
		t.Errorf("%d rows, want 5", n)
	}
}

// A reset further away, a 401, any other 403 and a 429 without a reset stop the
// stage for the run: the roots completed before are kept and the rest are not asked.
func TestGitHub_StopsTheStage(t *testing.T) {
	t.Parallel()
	far := func() string { return strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) }
	for name, tc := range map[string]struct {
		status int
		hdr    func() map[string]string
	}{
		"retry-after over 60s": {403, func() map[string]string { return map[string]string{"Retry-After": "61"} }},
		"reset in an hour": {403, func() map[string]string {
			return map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": far()}
		}},
		"429 reset in an hour": {429, func() map[string]string {
			return map[string]string{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": far()}
		}},
		"unauthorised":        {401, func() map[string]string { return nil }},
		"plain 403":           {403, func() map[string]string { return nil }},
		"403 with quota left": {403, func() map[string]string { return map[string]string{"X-RateLimit-Remaining": "4"} }},
		"plain 429":           {429, func() map[string]string { return nil }},
		"reset without remaining": {403, func() map[string]string {
			return map[string]string{"X-RateLimit-Reset": strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10)}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := newGH(map[string][]ghFile{"example.com": ghMany("example.com", 1), "example.net": ghMany("example.net", 1), "example.org": ghMany("example.org", 1)})
			ghRefuse(g, "example.net", 1, tc.status, tc.hdr(), nil)
			w := ghWorld(t, g)
			start := time.Now()
			f := w.h.partial(w.run("--passive", "--concurrency", "1", "example.com", "example.net", "example.org"), true)
			// A 401 is a refused key and waiting does not cure it; GitHub answers 403 and 429 for a
			// limit that has not lifted, which does.
			if want := tc.status != 401; f.transient != want || f.msg != "2 checks failed: github 2" {
				t.Errorf("transient = %v, want %v: %+v", f.transient, want, f)
			}
			if took := time.Since(start); took > 8*time.Second {
				t.Errorf("run took %v: the stage must stop and not wait", took)
			}
			if n := ghFailed(w); n != 2 {
				t.Errorf("%d checks failed, want 2: the refused root and the one never asked", n)
			}
			if got := ghAsked(w); !slices.Equal(got, []string{"example.com#1", "example.net#1"}) {
				t.Errorf("asked = %v: the stage stops after the refusal", got)
			}
			if done := w.h.completed(eng, "github"); !slices.Equal(done, []string{ghCheckKey("example.com", 500)}) {
				t.Errorf("completed = %v, want the root completed before the stop", done)
			}
			if n := len(w.table(eng, "code-mentions.csv")); n != 1 {
				t.Errorf("%d rows, want 1", n)
			}
			if hits := leaks(w); len(hits) > 0 {
				t.Errorf("key leaked into %v", hits)
			}
		})
	}
}

// Any other failure is a failed check for that root alone: not completed, retried
// on a later run, and the other roots are still searched.
func TestGitHub_OtherFailuresAreTransient(t *testing.T) {
	t.Parallel()
	for name, serve := range map[string]func(rw http.ResponseWriter){
		"server error": func(rw http.ResponseWriter) { http.Error(rw, "oops", 500) },
		"not json":     func(rw http.ResponseWriter) { _, _ = rw.Write([]byte("<html>")) },
		"wrong shape":  func(rw http.ResponseWriter) { _, _ = rw.Write([]byte(`{"message":"nope"}`)) },
		"truncated body": func(rw http.ResponseWriter) {
			_, _ = rw.Write([]byte(strings.Repeat(" ", 10<<20+10))) // over egress's 10 MiB cap
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := newGH(map[string][]ghFile{"example.com": ghMany("example.com", 1), "example.net": ghMany("example.net", 1)})
			var bad = true
			g.before = func(rw http.ResponseWriter, root string, page, n int) bool {
				if root != "example.com" || !bad {
					return false
				}
				serve(rw)
				return true
			}
			w := ghWorld(t, g)
			if f := w.h.partial(w.run("--passive", "--concurrency", "1", "example.com", "example.net"), true); !f.transient || f.msg != "1 checks failed: github 1" {
				t.Errorf("%+v", f)
			}
			if n := ghFailed(w); n != 1 {
				t.Errorf("%d checks failed, want 1", n)
			}
			if done := w.h.completed(eng, "github"); !slices.Equal(done, []string{ghCheckKey("example.net", 500)}) {
				t.Errorf("completed = %v: only the root that answered", done)
			}
			bad = false
			if code := w.run("--passive", "-e", eng); code != 0 {
				t.Fatalf("exit %d", code)
			}
			if done := w.h.completed(eng, "github"); !slices.Equal(done, []string{ghCheckKey("example.com", 500), ghCheckKey("example.net", 500)}) {
				t.Errorf("completed = %v: the failed root is retried", done)
			}
		})
	}
}

// --- registry, help and README ---

func TestGitHub_RegistryHelpAndSkip(t *testing.T) {
	t.Parallel()
	var names []string
	for _, s := range defaultStageList() {
		names = append(names, s.Name())
	}
	idx := func(n string) int { return slices.Index(names, n) }
	if !(idx("chaos") >= 0 && idx("chaos") < idx("github") && idx("github") < idx("shodan")) {
		t.Errorf("stage order = %v, want github after the subdomain sources and before shodan", names)
	}
	h := newHarness(t, defaultStageList()...)
	if code := h.exec("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stdout.String(), "--github-max-results") {
		t.Error("help missing --github-max-results")
	}
	if row := stageRow(h.stagesHelp(), "github"); !strings.Contains(row, " github ") {
		t.Errorf("help stages does not list github with its key: %q", row)
	}

	g := newGH(map[string][]ghFile{"example.com": ghMany("example.com", 1)})
	w := ghWorld(t, g)
	if code := w.run("--passive", "--skip", "github", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if n := len(w.requests("api.github.com")); n != 0 {
		t.Errorf("--skip github sent %d requests", n)
	}
}

func TestGitHub_ReadmeStatesWhatIsAndIsNotRecorded(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	// Phrases wrap across lines and start sentences, so they are matched on words.
	flat := strings.ToLower(strings.Join(strings.Fields(readme), " "))
	if keyed := keyedSourcesBullet(readme); !strings.Contains(keyed, "`github`") || !strings.Contains(keyed, "github.max_results") {
		t.Errorf("the keyed-sources entry does not name github and github.max_results: %q", keyed)
	}
	for _, want := range []string{
		"code-mentions.csv",
		"personal-account repositories",
		"queries GitHub about the domain, not the target",
		"only locations",
		"keeps only its URL",
		"--redo github",
	} {
		if !strings.Contains(flat, strings.ToLower(want)) {
			t.Errorf("README does not say %q", want)
		}
	}
	// The passive-boundary list of third parties names GitHub.
	i := strings.Index(readme, "Everything else comes from third parties:")
	if i < 0 || !strings.Contains(readme[i:min(len(readme), i+900)], "GitHub") {
		t.Error("the list of third parties in the passive boundary does not name GitHub")
	}
}
