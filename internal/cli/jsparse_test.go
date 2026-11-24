package cli_test

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- The jsparse procedure ---

// js serves a script.
func js(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(body))
	}
}

// scriptPage is an HTML page that loads the scripts at the given URLs.
func scriptPage(srcs ...string) string {
	var b strings.Builder
	b.WriteString("<html><head>")
	for _, s := range srcs {
		fmt.Fprintf(&b, `<script src="%s"></script>`, s)
	}
	b.WriteString("</head><body>hello</body></html>")
	return b.String()
}

// jsFixture serves a root loading supplied scripts, returning 404 for missing script bodies.
func jsFixture(t *testing.T, srcs []string, scripts map[string]http.HandlerFunc) (*web, *site) {
	t.Helper()
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	m := map[string]http.HandlerFunc{"/": page(scriptPage(srcs...))}
	maps.Copy(m, scripts)
	return x, x.plain("203.0.113.5", 80, routes(m))
}

// jsparseURLs are the URLs jsparse observed, sorted.
func (x *web) jsparseURLs() []string {
	x.t.Helper()
	got := x.observedBy("url", "jsparse")
	slices.Sort(got)
	return got
}

// JS parsing fetches a script once; crawling records the reference without fetching it.
func TestJSParse_FetchesSameHostScriptsOnce(t *testing.T) {
	t.Parallel()
	x, s := jsFixture(t, []string{"/app.js", "/vendor/lib.js?v=2", "/app.js"}, map[string]http.HandlerFunc{
		"/app.js":        js(`fetch("/api/v1/users")`),
		"/vendor/lib.js": js(`x("/api/lib")`),
	})
	x.mustRun()
	x.mustRun()
	x.mustRun("--crawl-pages", "50")
	if got := x.jsparseURLs(); !slices.Equal(got, []string{"http://a.example.com/api/lib", "http://a.example.com/api/v1/users"}) {
		t.Errorf("recorded %v", got)
	}

	if n := s.count("/app.js"); n != 1 {
		t.Errorf("/app.js fetched %d times, want once: %v", n, s.uris())
	}
	if n := s.count("/vendor/lib.js?v=2"); n != 1 { // the query is part of the request
		t.Errorf("/vendor/lib.js?v=2 fetched %d times, want once: %v", n, s.uris())
	}
	if !s.onlyGET() {
		t.Errorf("non-GET request: %+v", s.requests())
	}
	keys := x.completedKeys("jsparse")
	slices.Sort(keys)
	if len(keys) != 2 || !strings.HasPrefix(keys[0], "http://a.example.com/app.js|p=") {
		t.Errorf("jsparse jobs = %v, want one per script URL, keyed by URL and parser", keys)
	}
}

// Only eligible in-scope script hosts are fetched; CDN/SaaS/excluded hosts are skipped.
func TestJSParse_NeverFetchesCDNOrSaaSScripts(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("a.example.com", "b.example.com", "help.example.com", "bad.example.com")
	x.dns.CNAME("help.example.com", "acme.zendesk.com")
	x.host("acme.zendesk.com", "203.0.113.13")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.6")
	x.host("bad.example.com", "203.0.113.8")
	x.host("cdn.example.net", "203.0.113.7")
	root := scriptPage("/own.js", "//b.example.com/b.js", "http://help.example.com/saas.js",
		"https://cdn.example.net/lib.js", "http://bad.example.com/x.js", "http://203.0.113.99/ip.js")
	a := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{"/": page(root), "/own.js": js("1")}))
	b := x.plain("203.0.113.6", 80, routes(map[string]http.HandlerFunc{"/b.js": js("1")}))
	saas := x.plain("203.0.113.13", 80, routes(map[string]http.HandlerFunc{"/saas.js": js("1")}))
	cdn := x.plain("203.0.113.7", 80, routes(map[string]http.HandlerFunc{"/lib.js": js("1")}))
	bad := x.plain("203.0.113.8", 80, routes(map[string]http.HandlerFunc{"/x.js": js("1")}))
	x.mustRun("--exclude", "bad.example.com")

	if a.count("/own.js") != 1 || b.count("/b.js") != 1 {
		t.Errorf("in-scope scripts: /own.js %d, /b.js %d, want 1 each", a.count("/own.js"), b.count("/b.js"))
	}
	for name, n := range map[string]int{"SaaS-hosted": saas.count("/saas.js"), "CDN": cdn.count("/lib.js"), "excluded": bad.count("/x.js")} {
		if n != 0 {
			t.Errorf("a %s script was requested %d times", name, n)
		}
	}
	for _, k := range x.completedKeys("jsparse") {
		if !strings.HasPrefix(k, "http://a.example.com/own.js|") && !strings.HasPrefix(k, "http://b.example.com/b.js|") {
			t.Errorf("unexpected jsparse job %q", k)
		}
	}
}

// Script redirects stay on-host. Non-2xx completes empty; timeout retries later.
func TestJSParse_RedirectsAndFailures(t *testing.T) {
	t.Parallel()
	var slow atomic.Int32
	x := newWeb(t)
	x.names("a.example.com", "b.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.6")
	x.h.eopts.HTTPTimeout = 300 * time.Millisecond
	root := scriptPage("/old.js", "/away.js", "/gone.js", "/boom.js", "/slow.js", "/loop.js")
	a := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":        page(root),
		"/old.js":  redirectTo(301, "/new.js"),
		"/new.js":  js(`x("/api/from-new")`),
		"/away.js": redirectTo(302, "http://b.example.com/target.js"),
		"/gone.js": func(w http.ResponseWriter, r *http.Request) { http.Error(w, `x("/api/gone")`, http.StatusNotFound) },
		"/boom.js": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `x("/api/boom")`, http.StatusInternalServerError)
		},
		"/slow.js": func(w http.ResponseWriter, r *http.Request) {
			slow.Add(1)
			// Answer only after the client has given up, without holding the server's Close.
			select {
			case <-r.Context().Done():
			case <-time.After(time.Second):
			}
			_, _ = w.Write([]byte(`x("/api/slow")`))
		},
		"/loop.js": redirectTo(302, "/loop.js"),
	}))
	b := x.plain("203.0.113.6", 80, routes(map[string]http.HandlerFunc{"/target.js": js(`x("/api/from-target")`)}))
	// The script that times out fails its job on both runs, and only that one.
	for range 2 {
		x.partialRun("jsparse", 1)
	}

	if a.count("/new.js") != 1 {
		t.Errorf("a same-host redirect was followed %d times, want once", a.count("/new.js"))
	}
	if b.count("/target.js") != 0 {
		t.Error("a redirect to another host was followed")
	}
	if got := x.jsparseURLs(); !slices.Equal(got, []string{"http://a.example.com/api/from-new"}) {
		t.Errorf("recorded %v, want only what /new.js named", got)
	}
	for _, p := range []string{"/gone.js", "/boom.js", "/away.js", "/old.js"} {
		if a.count(p) != 1 {
			t.Errorf("%s fetched %d times over two runs, want once (a completed job is not repeated)", p, a.count(p))
		}
	}
	if slow.Load() != 2 {
		t.Errorf("a timed-out script was fetched %d times over two runs, want 2 (a failed job is retried)", slow.Load())
	}
	done := strings.Join(x.completedKeys("jsparse"), " ")
	if strings.Contains(done, "/slow.js") {
		t.Errorf("a timeout must not complete its job: %s", done)
	}
	if !strings.Contains(done, "/gone.js") || !strings.Contains(done, "/boom.js") || !strings.Contains(done, "/away.js") {
		t.Errorf("a non-2xx answer or a refused redirect completes with nothing: %s", done)
	}
	if a.count("/loop.js") > 12 {
		t.Errorf("a redirect loop was followed %d times", a.count("/loop.js"))
	}
}

// URLs are recorded without a status and found by jsparse; in-scope hosts become
// hostnames; out-of-scope hosts and non-paths are ignored.
func TestJSParse_RecordsURLsAndHostnames(t *testing.T) {
	t.Parallel()
	body := `var a="/api/v1/users",b="//api.example.com/v2",c="https://c.example.com/x?y=1",
d="https://evil.example.net/steal",e="/.js",f=s.match(/\d+/g),g="/ ",h="//comment",
i="/api/${id}",j='/static/app.css',k="https://c.example.com/again",
l="https://p.example.com/v1/${id}",m="https:\/\/q.example.com\/w";`
	x, _ := jsFixture(t, []string{"/app.js"}, map[string]http.HandlerFunc{"/app.js": js(body)})
	x.mustRun()

	rows := x.urls()
	for _, u := range []string{"http://a.example.com/api/v1/users", "http://api.example.com/v2", "https://c.example.com/x?y=1", "http://a.example.com/static/app.css",
		"https://p.example.com/v1/", "https://q.example.com/w"} {
		r := find(rows, "url", u)
		if r == nil || !strings.Contains(r["found_by"], "jsparse") || r["status"] != "" || r["current"] != "true" {
			t.Errorf("%s = %v, want a current row found by jsparse with no status", u, r)
		}
	}
	for _, r := range rows {
		for _, bad := range []string{"evil.example.net", "/.js", "comment", "${", "%24%7B"} {
			if strings.Contains(r["url"], bad) {
				t.Errorf("recorded %s (matches %q)", r["url"], bad)
			}
		}
	}
	if got := x.observedBy("hostname", "jsparse"); !slices.Equal(got, []string{"api.example.com", "c.example.com", "p.example.com", "q.example.com"}) {
		t.Errorf("jsparse hostnames = %v, want the in-scope hosts other than the script's own", got)
	}
	if hosts := x.lines(eng, "subdomains.txt"); !slices.Contains(hosts, "api.example.com") || !slices.Contains(hosts, "c.example.com") {
		t.Errorf("subdomains.txt = %v", hosts)
	}
	for _, c := range x.table(eng, "candidates.csv") {
		if strings.Contains(c["value"], "evil.example.net") {
			t.Errorf("an out-of-scope host in a script became a candidate: %v", c)
		}
	}
}

// At most jsparse.max_scripts scripts are fetched per origin, in URL order, and a
// warning says how many were left.
func TestJSParse_PerOriginCapAndWarning(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("a.example.com", "b.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.6")
	var srcs []string
	aRoutes := map[string]http.HandlerFunc{}
	for _, n := range []string{"s5", "s1", "s4", "s2", "s3"} {
		srcs = append(srcs, "/"+n+".js")
		aRoutes["/"+n+".js"] = js(`x("/api/` + n + `")`)
	}
	srcs = append(srcs, "//b.example.com/b1.js", "//b.example.com/b2.js")
	aRoutes["/"] = page(scriptPage(srcs...))
	a := x.plain("203.0.113.5", 80, routes(aRoutes))
	b := x.plain("203.0.113.6", 80, routes(map[string]http.HandlerFunc{"/b1.js": js("1"), "/b2.js": js("1")}))
	x.mustRun("--jsparse-max-scripts", "3")

	if got := a.uris(); !slices.Contains(got, "/s1.js") || !slices.Contains(got, "/s2.js") || !slices.Contains(got, "/s3.js") || slices.Contains(got, "/s4.js") || slices.Contains(got, "/s5.js") {
		t.Errorf("a.example.com fetched %v, want /s1.js /s2.js /s3.js and not /s4.js or /s5.js", got)
	}
	if b.count("/b1.js") != 1 || b.count("/b2.js") != 1 {
		t.Errorf("the cap is per origin: b.example.com fetched %v", b.uris())
	}
	w := x.warnings()
	if !strings.Contains(w, "2 scripts") || !strings.Contains(w, "http://a.example.com") || strings.Contains(w, "http://b.example.com") || !strings.Contains(w, "jsparse.max_scripts") {
		t.Errorf("warnings = %q, want one saying 2 scripts of http://a.example.com were not fetched, naming jsparse.max_scripts", w)
	}
}

// The default is 50, and the setting must be at least 1.
func TestJSParse_DefaultCapIsFifty(t *testing.T) {
	t.Parallel()
	var srcs []string
	routesMap := map[string]http.HandlerFunc{}
	for i := range 55 {
		p := fmt.Sprintf("/s%02d.js", i)
		srcs = append(srcs, p)
		routesMap[p] = js("1")
	}
	x, s := jsFixture(t, srcs, routesMap)
	x.mustRun()
	n := 0
	for _, u := range s.uris() {
		if strings.HasSuffix(u, ".js") {
			n++
		}
	}
	if n != 50 {
		t.Errorf("%d scripts fetched, want 50", n)
	}
	if !strings.Contains(x.warnings(), "5 scripts") {
		t.Errorf("warnings = %q", x.warnings())
	}
	if code := x.run("--jsparse-max-scripts", "0"); code != 2 {
		t.Errorf("--jsparse-max-scripts 0 exits %d, want 2", code)
	}
}

// Previously fetched scripts retain cap slots and evidence when new URLs sort earlier.
func TestJSParse_ParsedScriptStaysWithinTheCap(t *testing.T) {
	t.Parallel()
	var body atomic.Value
	body.Store(scriptPage("/s1.js", "/s2.js"))
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	s := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":      func(w http.ResponseWriter, r *http.Request) { page(body.Load().(string))(w, r) },
		"/s1.js": js(`x("/api/one")`), "/s2.js": js(`x("/api/two")`), "/a0.js": js(`x("/api/zero")`), "/a1.js": js(`x("/api/first")`),
	}))
	x.mustRun("--jsparse-max-scripts", "2")
	if s.count("/s1.js") != 1 || s.count("/s2.js") != 1 {
		t.Fatalf("first run fetched %v", s.uris())
	}

	body.Store(scriptPage("/a0.js", "/a1.js", "/s1.js", "/s2.js"))
	x.mustRun("--jsparse-max-scripts", "2", "--redo", "crawl")

	if s.count("/a0.js") != 0 || s.count("/a1.js") != 0 {
		t.Errorf("new scripts pushed parsed ones out of the cap: %v", s.uris())
	}
	if s.count("/s1.js") != 1 || s.count("/s2.js") != 1 {
		t.Errorf("parsed scripts were fetched again: %v", s.uris())
	}
	for _, u := range []string{"http://a.example.com/api/one", "http://a.example.com/api/two"} {
		if r := find(x.urls(), "url", u); r == nil || r["current"] != "true" {
			t.Errorf("%s = %v, want it still current", u, r)
		}
	}
	if !strings.Contains(x.warnings(), "2 scripts") {
		t.Errorf("warnings = %q, want the two new scripts counted as skipped", x.warnings())
	}

	// Raising the cap then fetches them.
	x.mustRun("--jsparse-max-scripts", "4")
	if s.count("/a0.js") != 1 || s.count("/a1.js") != 1 {
		t.Errorf("with room under the cap the new scripts are fetched: %v", s.uris())
	}
}

// An HTML answer, or a body that starts with "<", records nothing.
func TestJSParse_HTMLAnswerRecordsNothing(t *testing.T) {
	t.Parallel()
	x, _ := jsFixture(t, []string{"/spa.js", "/fallback.js", "/ok.js"}, map[string]http.HandlerFunc{
		"/spa.js":      page(`<html><script>x("/api/in-html")</script></html>`),
		"/fallback.js": js("  \n<!doctype html><title>x</title>\"/api/behind-markup\""),
		"/ok.js":       js(`x("/api/ok")`),
	})
	x.mustRun()
	if got := x.jsparseURLs(); !slices.Equal(got, []string{"http://a.example.com/api/ok"}) {
		t.Errorf("recorded %v, want only /api/ok", got)
	}
}

// Truncated scripts retain discoveries from the first 4 MiB and produce a warning.
func TestJSParse_TruncatedBundle(t *testing.T) {
	t.Parallel()
	const limit = 4 << 20
	bundle := `x("/api/early");` + strings.Repeat(" ", limit) + `x("/api/late");`
	x, _ := jsFixture(t, []string{"/big.js"}, map[string]http.HandlerFunc{"/big.js": js(bundle)})
	x.mustRun()
	if got := x.jsparseURLs(); !slices.Equal(got, []string{"http://a.example.com/api/early"}) {
		t.Errorf("recorded %v, want the part that was read", got)
	}
	if w := x.warnings(); !strings.Contains(w, "truncated") || !strings.Contains(w, "/big.js") {
		t.Errorf("warnings = %q, want one saying /big.js was truncated", w)
	}
	// A script that fits is not warned about.
	x2, _ := jsFixture(t, []string{"/fits.js"}, map[string]http.HandlerFunc{"/fits.js": js(`x("/api/a");` + strings.Repeat(" ", 3<<20))})
	x2.mustRun()
	if w := x2.warnings(); strings.Contains(w, "truncated") {
		t.Errorf("unexpected warning: %q", w)
	}
}

// At most 500 URLs are recorded per script, in order of appearance, with a warning.
func TestJSParse_URLCap(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := range 600 {
		fmt.Fprintf(&b, "x(\"/api/%03d\");", i)
	}
	x, _ := jsFixture(t, []string{"/many.js", "/few.js"}, map[string]http.HandlerFunc{
		"/many.js": js(b.String()), "/few.js": js(`x("/api/few")`),
	})
	x.mustRun()
	got := x.jsparseURLs()
	if len(got) != 501 { // 500 from the first script, one from the second
		t.Errorf("recorded %d URLs, want 501", len(got))
	}
	for _, i := range []int{0, 1, 499} {
		if u := fmt.Sprintf("http://a.example.com/api/%03d", i); !slices.Contains(got, u) {
			t.Errorf("%s not recorded", u)
		}
	}
	for _, i := range []int{500, 599} {
		if u := fmt.Sprintf("http://a.example.com/api/%03d", i); slices.Contains(got, u) {
			t.Errorf("%s recorded past the cap", u)
		}
	}
	w := x.warnings()
	if !strings.Contains(w, "/many.js") || !strings.Contains(w, "500") || strings.Contains(w, "/few.js") {
		t.Errorf("warnings = %q, want one for /many.js only", w)
	}
}

// Removing a script reference retires only evidence unsupported by remaining scripts.
func TestJSParse_ReCrawlThatDropsAScriptRetiresItsURLs(t *testing.T) {
	t.Parallel()
	var body atomic.Value
	body.Store(scriptPage("/app.js", "/keep.js"))
	x := newWeb(t)
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":        func(w http.ResponseWriter, r *http.Request) { page(body.Load().(string))(w, r) },
		"/app.js":  js(`x("/api/only-app");x("/api/shared")`),
		"/keep.js": js(`x("/api/only-keep");x("/api/shared")`),
	}))
	x.mustRun()
	for _, u := range []string{"http://a.example.com/api/only-app", "http://a.example.com/api/only-keep", "http://a.example.com/api/shared"} {
		if cur := x.urlSet(); !slices.Contains(cur, u) {
			t.Fatalf("%s is not current after the first run: %v", u, cur)
		}
	}

	body.Store(scriptPage("/keep.js"))
	x.mustRun("--redo", "crawl")
	now := x.urlSet()
	if slices.Contains(now, "http://a.example.com/api/only-app") {
		t.Errorf("a URL only a dropped script found is still current: %v", now)
	}
	if r := find(x.urls(), "url", "http://a.example.com/api/only-app"); r == nil || r["current"] != "false" {
		t.Errorf("the dropped script's URL should stay on record, not current: %v", r)
	}
	for _, u := range []string{"http://a.example.com/api/only-keep", "http://a.example.com/api/shared"} {
		if !slices.Contains(now, u) {
			t.Errorf("%s should still be current: %v", u, now)
		}
	}
}

// Nothing found in a script is ever requested, however many runs and passes follow.
func TestJSParse_CanaryNothingFoundInAScriptIsRequested(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("a.example.com", "b.example.com", "api.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.6")
	x.host("api.example.com", "203.0.113.7")
	x.host("evil.example.net", "203.0.113.9")
	body := `x("/api/v1/users");x("/admin/panel");x("http://b.example.com/found-b");x("//api.example.com/v2");
x("https://api.example.com/v1/items");x("http://evil.example.net/off");x("/static/app.css");x("/data.json")`
	a := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{"/": page(scriptPage("/app.js")), "/app.js": js(body)}))
	b := x.plain("203.0.113.6", 80, routes(map[string]http.HandlerFunc{"/": page("b")}))
	api := x.plain("203.0.113.7", 80, routes(map[string]http.HandlerFunc{"/": page("api")}))
	evil := x.plain("203.0.113.9", 80, routes(map[string]http.HandlerFunc{}))
	x.mustRun()
	x.mustRun("--redo", "jsparse")
	x.mustRun("--redo", "crawl")

	for _, u := range a.uris() {
		if u != "/" && u != "/app.js" && u != "/robots.txt" && u != "/sitemap.xml" && u != "/favicon.ico" {
			t.Errorf("a.example.com received a request for %s", u)
		}
	}
	if b.count("/found-b") != 0 {
		t.Error("a URL on another in-scope host, found in a script, was requested")
	}
	for _, u := range api.uris() {
		if u != "/" && u != "/robots.txt" && u != "/sitemap.xml" && u != "/favicon.ico" {
			t.Errorf("api.example.com received a request for %s", u)
		}
	}
	if evil.hits() != 0 {
		t.Errorf("an out-of-scope host named in a script was contacted: %v", evil.uris())
	}
	if n := x.h.network(); n != 0 {
		t.Errorf("%d requests reached the canaries", n)
	}
}

// Passive runs skip script fetching and mark the procedure unconfigured.
func TestJSParse_NotUnderPassive(t *testing.T) {
	t.Parallel()
	x, s := jsFixture(t, []string{"/app.js"}, map[string]http.HandlerFunc{"/app.js": js(`x("/api/a")`)})
	x.mustRun("--passive")
	if s.hits() != 0 {
		t.Errorf("a passive run sent %d requests to the target", s.hits())
	}
	if got := x.completedKeys("jsparse"); len(got) != 0 {
		t.Errorf("jsparse jobs completed under --passive: %v", got)
	}
	if st := lastState(x.h.events(), "jsparse"); st == nil || st.str("state") != "not-configured" || st.str("reason") != "passive-only" {
		t.Errorf("jsparse state = %v, want not-configured (passive-only)", st)
	}
}

// The crawl keeps its own behaviour: it records the script URL and never fetches it.
func TestJSParse_CrawlRecordsScriptsForAllHosts(t *testing.T) {
	t.Parallel()
	x, _ := jsFixture(t, []string{"/app.js", "https://cdn.example.net/lib.js"}, map[string]http.HandlerFunc{"/app.js": js("1")})
	x.mustRun("--crawl-depth", "0")
	got := queryStrings(x.t, x.h.openDB(eng), "SELECT key FROM records WHERE kind='script' ORDER BY key")
	want := []string{"http://a.example.com/app.js", "https://cdn.example.net/lib.js"}
	if !slices.Equal(got, want) {
		t.Errorf("script records = %v, want %v", got, want)
	}
}
