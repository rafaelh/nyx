package cli_test

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- Hostnames read from the text of web responses ---
//
// The names these tests plant in text have no address unless a test gives one, so that probing a
// name found this way changes no request count being asserted.

// tnOrigin is the service origin of www.example.com on port 80.
const tnOrigin = "http://www.example.com"

// tnWorld is the web world with www.example.com, known from crt.sh, on 203.0.113.5.
func tnWorld(t *testing.T) *web {
	t.Helper()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	return x
}

// tnNames are n distinct names under example.com: prefix00000.example.com and on.
func tnNames(prefix string, n int) []string {
	out := make([]string, n)
	for i := range n {
		out[i] = fmt.Sprintf("%s%05d.example.com", prefix, i)
	}
	return out
}

// spaced writes names as running text.
func spaced(names []string) string { return strings.Join(names, " ") }

// hostnameSet is the key of every hostname record, current or not, whoever observed it.
func (x *web) hostnameSet() map[string]bool {
	x.t.Helper()
	set := map[string]bool{}
	for _, k := range queryStrings(x.t, x.h.openDB(eng), "SELECT key FROM records WHERE kind='hostname'") {
		set[k] = true
	}
	return set
}

// taken is how many of names are hostname records.
func (x *web) taken(names []string) int {
	x.t.Helper()
	set := x.hostnameSet()
	n := 0
	for _, name := range names {
		if set[name] {
			n++
		}
	}
	return n
}

// textNames are the names of the text_hostname records, current or not, kept for one service.
func (x *web) textNames(origin string) []string {
	x.t.Helper()
	prefix := origin + "|"
	keys := queryStrings(x.t, x.h.openDB(eng), "SELECT key FROM records WHERE kind='text_hostname' AND substr(key, 1, ?) = ?", len(prefix), prefix)
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = strings.TrimPrefix(k, prefix)
	}
	return out
}

// wantTaken fails unless name is listed as a hostname, was observed by procedure and was resolved.
func (x *web) wantTaken(name, procedure string) {
	x.t.Helper()
	if subs := x.lines(eng, "subdomains.txt"); !slices.Contains(subs, name) {
		x.t.Errorf("%s is not in subdomains.txt: %v", name, subs)
	}
	if got := x.observedBy("hostname", procedure); !slices.Contains(got, name) {
		x.t.Errorf("%s was not observed as a hostname by %s, which observed %v", name, procedure, got)
	}
	if !slices.Contains(x.completedKeys("resolve"), name) {
		x.t.Errorf("%s has no completed resolve job", name)
	}
}

// wantNoHostname fails if name is a hostname record or is listed in subdomains.txt.
func (x *web) wantNoHostname(name, why string) {
	x.t.Helper()
	if x.hostnameSet()[name] {
		x.t.Errorf("%s is a hostname record: %s", name, why)
	}
	if slices.Contains(x.lines(eng, "subdomains.txt"), name) {
		x.t.Errorf("%s is in subdomains.txt: %s", name, why)
	}
}

// capWarnings are the last run's warnings about the most hostnames taken from one web service.
func (x *web) capWarnings() []string { return x.h.messages("warning", "1,000") }

// wantCapWarning fails unless the last run printed one cap warning, naming origin and the number
// of names left out (or "more than 10,000").
func (x *web) wantCapWarning(origin, leftOut string) {
	x.t.Helper()
	ws := x.capWarnings()
	if len(ws) != 1 {
		x.t.Errorf("cap warnings = %q, want one for %s (all warnings: %q)", ws, origin, x.warnings())
		return
	}
	w := ws[0]
	if !strings.Contains(w, origin) {
		x.t.Errorf("cap warning %q does not name the service %s", w, origin)
	}
	if strings.HasPrefix(leftOut, "more than") {
		if !strings.Contains(w, leftOut) {
			x.t.Errorf("cap warning %q does not say %q", w, leftOut)
		}
		return
	}
	if !regexp.MustCompile(`(^|[^0-9,])` + regexp.QuoteMeta(leftOut) + `([^0-9,]|$)`).MatchString(w) {
		x.t.Errorf("cap warning %q does not give %s names left out", w, leftOut)
	}
}

// wantNoCapWarning fails if the last run printed a cap warning.
func (x *web) wantNoCapWarning(why string) {
	x.t.Helper()
	if ws := x.capWarnings(); len(ws) != 0 {
		x.t.Errorf("cap warnings = %q, want none: %s", ws, why)
	}
}

// plainText serves body as text/plain with the given status.
func plainText(code int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
}

// xmlBody serves body as application/xml.
func xmlBody(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(body))
	}
}

// abortAfter writes part of a longer body, then breaks the connection.
func abortAfter(part string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Length", "100000")
		_, _ = w.Write([]byte(part))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
}

// --- Where names are read ---

func TestTextNames_CommentOnACrawledPage(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":      page(`<a href="/about">about</a>`),
		"/about": page(`<html><!-- staging moved to comment-host.example.com --><p>about</p></html>`),
	}))
	x.mustRun()
	x.wantTaken("comment-host.example.com", "crawl")
}

func TestTextNames_EscapedJSONStringInAScript(t *testing.T) {
	t.Parallel()
	x, _ := jsFixture(t, []string{"/app.js"}, map[string]http.HandlerFunc{
		"/app.js": js(`window.cfg = JSON.parse("{\"apiHost\":\"json-host.example.com\",\"v\":2}");`),
	})
	x.mustRun()
	x.wantTaken("json-host.example.com", "jsparse")
}

func TestTextNames_WildcardInAContentSecurityPolicyHeader(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": posturePage("<p>home</p>", map[string]string{
			"Content-Security-Policy": "default-src 'self'; script-src 'self' *.cdn.example.com",
		}),
	}))
	x.mustRun("--crawl-pages", "0")
	x.wantTaken("cdn.example.com", "httpprobe")
	for k := range x.hostnameSet() {
		if strings.Contains(k, "*") {
			t.Errorf("a wildcard was recorded as is: %s", k)
		}
	}
}

func TestTextNames_RedirectHopBody(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/home")
			plainText(http.StatusFound, "Moved to /home; the old site was hop-body.example.com")(w, r)
		},
		"/home": page("<p>home</p>"),
	}))
	x.mustRun("--crawl-pages", "0")
	x.wantTaken("hop-body.example.com", "httpprobe")
}

func TestTextNames_CommentInRobotsTxt(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":           page("<p>home</p>"),
		"/robots.txt": plainText(http.StatusOK, "# mirrored at robots-host.example.com\nUser-agent: *\nDisallow:\n"),
	}))
	x.mustRun()
	x.wantTaken("robots-host.example.com", "crawl")
}

func TestTextNames_LocInSitemap(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": page("<p>home</p>"),
		"/sitemap.xml": xmlBody(`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
			`<url><loc>http://sitemap-host.example.com/page</loc></url></urlset>`),
	}))
	x.mustRun()
	x.wantTaken("sitemap-host.example.com", "crawl")
}

func TestTextNames_BodyOfA404Page(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":     page(`<a href="/gone">gone</a>`),
		"/gone": plainText(http.StatusNotFound, "Not here. Try notfound-host.example.com instead."),
	}))
	x.mustRun()
	x.wantTaken("notfound-host.example.com", "crawl")
}

func TestTextNames_NonSuccessAnswerToAScript(t *testing.T) {
	t.Parallel()
	x, _ := jsFixture(t, []string{"/missing.js"}, map[string]http.HandlerFunc{
		"/missing.js": plainText(http.StatusNotFound, `no such script; see nonok-host.example.com`),
	})
	x.mustRun()
	x.wantTaken("nonok-host.example.com", "jsparse")
}

func TestTextNames_MarkupAnswerToAScript(t *testing.T) {
	t.Parallel()
	x, _ := jsFixture(t, []string{"/spa.js"}, map[string]http.HandlerFunc{
		"/spa.js": page(`<!doctype html><html><body>App served by markup-host.example.com</body></html>`),
	})
	x.mustRun()
	x.wantTaken("markup-host.example.com", "jsparse")
}

// A service found on a port the probe detected takes names, and counts them against its own origin.
func TestTextNames_ServiceOnADetectedPort(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.secure("203.0.113.5", 8443, selfSigned(t, leafSpec{cn: "www.example.com", dns: []string{"www.example.com"}}),
		page("<p>admin console for port-host.example.com</p>"))
	x.open("203.0.113.5:8443", "")
	x.mustRun("--crawl-pages", "0")
	x.wantServices("https://www.example.com:8443")
	x.wantTaken("port-host.example.com", "httpprobe")
	if got := x.textNames("https://www.example.com:8443"); !slices.Equal(got, []string{"port-host.example.com"}) {
		t.Errorf("names kept for https://www.example.com:8443 = %v, want port-host.example.com", got)
	}
}

// --- Reading sends nothing ---

// placeNames are the names placesWorld plants, one for each place a web procedure reads.
var placeNames = []string{
	"csp-place.example.com", "hop-place.example.com", "comment-place.example.com", "notfound-place.example.com",
	"robots-place.example.com", "sitemap-place.example.com", "json-place.example.com", "nonok-place.example.com",
	"markup-place.example.com", "port-place.example.com",
}

// placesWorld serves www.example.com on ports 80 and 8443 with placeNames planted in every place
// the web procedures read, or, without plant, the same responses with no names in them.
func placesWorld(t *testing.T, plant bool) (x *web, www, port *site) {
	t.Helper()
	x = tnWorld(t)
	n := func(name string) string {
		if plant {
			return name
		}
		return "nothing"
	}
	csp, loc := "default-src 'self'", "http://www.example.com/home"
	if plant {
		csp, loc = "default-src 'self'; img-src *.csp-place.example.com", "http://sitemap-place.example.com/page"
	}
	www = x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Security-Policy", csp)
			w.Header().Set("Location", "/home")
			plainText(http.StatusFound, "moved; was "+n("hop-place.example.com"))(w, r)
		},
		"/home": page(`<html><!-- ` + n("comment-place.example.com") + ` --><a href="/gone">g</a>` +
			scriptPage("/app.js", "/missing.js", "/spa.js") + `</html>`),
		"/gone":        plainText(http.StatusNotFound, "not here: "+n("notfound-place.example.com")),
		"/robots.txt":  plainText(http.StatusOK, "# "+n("robots-place.example.com")+"\nUser-agent: *\nDisallow:\n"),
		"/sitemap.xml": xmlBody(`<urlset><url><loc>` + loc + `</loc></url></urlset>`),
		"/app.js":      js(`JSON.parse("{\"apiHost\":\"` + n("json-place.example.com") + `\"}")`),
		"/missing.js":  plainText(http.StatusNotFound, "no script: "+n("nonok-place.example.com")),
		"/spa.js":      page(`<html>` + n("markup-place.example.com") + `</html>`),
	}))
	port = x.secure("203.0.113.5", 8443, selfSigned(t, leafSpec{cn: "www.example.com", dns: []string{"www.example.com"}}),
		page("<p>"+n("port-place.example.com")+"</p>"))
	x.open("203.0.113.5:8443", "")
	return x, www, port
}

func TestTextNames_ReadingSendsNothing(t *testing.T) {
	t.Parallel()
	with, wwwWith, portWith := placesWorld(t, true)
	with.mustRun()
	without, wwwWithout, portWithout := placesWorld(t, false)
	without.mustRun()

	subs := with.lines(eng, "subdomains.txt")
	for _, n := range placeNames {
		if !slices.Contains(subs, n) {
			t.Errorf("precondition: %s, planted in a response, is not in subdomains.txt: %v", n, subs)
		}
	}
	for name, pair := range map[string][2]*site{"www.example.com:80": {wwwWith, wwwWithout}, "www.example.com:8443": {portWith, portWithout}} {
		w, wo := pair[0], pair[1]
		if w.hits() != wo.hits() {
			t.Errorf("%s received %d requests with names in its responses, %d without", name, w.hits(), wo.hits())
		}
		if !slices.Equal(w.uris(), wo.uris()) {
			t.Errorf("%s was asked for %v with names in its responses, %v without", name, w.uris(), wo.uris())
		}
		if !w.onlyGET() {
			t.Errorf("%s received a request that is not a GET: %+v", name, w.requests())
		}
	}
	if n := with.h.network(); n != 0 {
		t.Errorf("%d requests reached the canaries", n)
	}
}

// A name found in text that resolves to an in-scope service is probed and crawled like any other.
func TestTextNames_FoundNameIsProbedAndCrawled(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, page(`<html><!-- the new portal is found-host.example.com --></html>`))
	x.host("found-host.example.com", "203.0.113.6")
	found := x.plain("203.0.113.6", 80, page("<title>Found</title>"))
	x.mustRun()

	if r := find(current(x.services()), "url", "http://found-host.example.com"); r == nil || r["title"] != "Found" {
		t.Errorf("found-host.example.com was not probed: %v", x.serviceURLs())
	}
	if got := found.hostHeaders(); !slices.Equal(got, []string{"found-host.example.com"}) {
		t.Errorf("found-host.example.com was asked as %v", got)
	}
	if found.count("/robots.txt") != 1 {
		t.Errorf("found-host.example.com was not crawled: %v", found.uris())
	}
	if !slices.Contains(x.completedKeys("crawl"), "http://found-host.example.com|depth=2|pages=100") {
		t.Errorf("crawl jobs = %v, want one for http://found-host.example.com", x.completedKeys("crawl"))
	}
}

// --- What is read: only what the size limits let through ---

func TestTextNames_PageBodyCap(t *testing.T) {
	t.Parallel()
	const limit = 1 << 20
	head := "<html><body><p>before-cut.example.com</p><p>"
	edge := "straddle.example.com" // the cut falls here; the full name is straddle.example.company.net
	body := head + strings.Repeat(" ", limit-len(head)-len(edge)) + edge + "pany.net after-cut.example.com</p></body></html>"
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{"/": page(body)}))
	x.mustRun()

	x.wantTaken("before-cut.example.com", "httpprobe")
	x.wantNoHostname("straddle.example.com", "it runs up to the body cap, so it may be cut short")
	x.wantNoHostname("after-cut.example.com", "it is past the body cap")
}

func TestTextNames_ScriptBodyCap(t *testing.T) {
	t.Parallel()
	const limit = 4 << 20
	head := `var a = "before-js-cut.example.com"; var b = "`
	edge := "straddle-js.example.com"
	body := head + strings.Repeat(" ", limit-len(head)-len(edge)) + edge + `pany.net"; var c = "after-js-cut.example.com";`
	x, _ := jsFixture(t, []string{"/big.js"}, map[string]http.HandlerFunc{"/big.js": js(body)})
	x.mustRun()

	x.wantTaken("before-js-cut.example.com", "jsparse")
	x.wantNoHostname("straddle-js.example.com", "it runs up to the script cap, so it may be cut short")
	x.wantNoHostname("after-js-cut.example.com", "it is past the script cap")
}

// --- What is left out ---

// A name under no in-scope root is neither a hostname, a candidate nor a third party. The same name
// as a redirect target or a certificate SAN still gives a candidate:
// TestRedirect_OutOfScopeRedirectIsACandidateAndNotRequested and
// TestCertificateSANsFlowThroughOrBecomeCandidates.
func TestTextNames_NameUnderNoRootIsIgnored(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":       page(`<html><p>Our API is api.other.net; status at ctl-other.example.com.</p>` + scriptPage("/app.js") + `</html>`),
		"/app.js": js(`var api = "api.other.net";`),
	}))
	x.mustRun()

	x.wantTaken("ctl-other.example.com", "httpprobe")
	x.wantNoHostname("api.other.net", "it is under no in-scope root and appears only in text")
	if r := find(x.table(eng, "candidates.csv"), "value", "api.other.net"); r != nil {
		t.Errorf("a name only in text became a candidate: %v", r)
	}
	for _, r := range x.table(eng, "third-parties.csv") {
		for _, v := range r {
			if strings.Contains(v, "other.net") {
				t.Errorf("a name only in text became a third party: %v", r)
			}
		}
	}
}

// The responding host's own name and an input root add nothing.
func TestTextNames_OwnNameAndInputRootAddNothing(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": page(`<html><p>Welcome to www.example.com and WWW.Example.COM, part of example.com; see ctl-own.example.com.</p>` +
			scriptPage("/app.js") + `</html>`),
		"/app.js": js(`var self = "https://www.example.com/api", root = "example.com", other = "ctl-own-js.example.com";`),
	}))
	x.mustRun()

	x.wantTaken("ctl-own.example.com", "httpprobe")
	x.wantTaken("ctl-own-js.example.com", "jsparse")
	for _, p := range []string{"httpprobe", "crawl", "jsparse"} {
		got := x.observedBy("hostname", p)
		for _, n := range []string{"www.example.com", "example.com"} {
			if slices.Contains(got, n) {
				t.Errorf("%s observed %s from text: %v", p, n, got)
			}
		}
	}
}

// An excluded name in text is recorded as excluded, as any hostname is, and is never contacted.
func TestTextNames_ExcludedNameIsListedAndNotProbed(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, page(`<p>Staff: db.internal.example.com; public: ctl-ex.example.com</p>`))
	x.host("db.internal.example.com", "203.0.113.31")
	blocked := x.plain("203.0.113.31", 80, page("internal"))
	x.mustRun("-x", "*.internal.example.com")

	x.wantTaken("ctl-ex.example.com", "httpprobe")
	if find(x.table(eng, "excluded.csv"), "value", "db.internal.example.com") == nil {
		t.Errorf("excluded.csv does not list the excluded name found in text:\n%s", x.file(eng, "excluded.csv"))
	}
	if slices.Contains(x.lines(eng, "subdomains.txt"), "db.internal.example.com") {
		t.Error("an excluded name is in subdomains.txt")
	}
	if blocked.hits() != 0 {
		t.Errorf("an excluded name found in text was requested %d times", blocked.hits())
	}
}

// The sensitive-path responses and the favicon are not searched.
func TestTextNames_SensitivePathsAndFaviconAreNotRead(t *testing.T) {
	t.Parallel()
	x := newWebWith(t, "sensitive-paths")
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	s := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":            page("<p>see ctl-fav.example.com</p>"),
		"/.env":        plainText(http.StatusOK, "SECRET_KEY=x\nAPI_HOST=envleak.example.com\nDB=env-db.example.com\n"),
		"/favicon.ico": icon("image/x-icon", []byte("\x00\x00\x01\x00favleak.example.com fav-two.example.com")),
	}))
	paths := writeFile(t, t.TempDir(), "paths.yaml", "- path: /.env\n  signature: '(?m)^SECRET_KEY='\n")
	x.mustRun("--sensitive-paths", paths)

	if s.count("/.env") != 1 || s.count("/favicon.ico") != 1 {
		t.Fatalf("precondition: /.env and /favicon.ico must be fetched once each: %v", s.uris())
	}
	x.wantTaken("ctl-fav.example.com", "httpprobe")
	if got := x.observedBy("hostname", "sensitive-paths"); len(got) != 0 {
		t.Errorf("sensitive-paths observed hostnames %v", got)
	}
	for _, n := range []string{"envleak.example.com", "env-db.example.com"} {
		x.wantNoHostname(n, "the sensitive-path responses are not searched")
	}
	for _, n := range []string{"favleak.example.com", "fav-two.example.com"} {
		x.wantNoHostname(n, "the favicon response is not searched")
	}
}

// --- The cap on names from one web service ---

// The probe, the crawl's pages and two scripts of one service name 1,500 hosts between them: 1,000
// are taken and one warning gives the 500 left out. A plain re-run sends nothing and warns of
// nothing; a re-crawl whose pages name 300 more adds none and warns again with the new number.
func TestTextNames_CapPerService(t *testing.T) {
	t.Parallel()
	names := tnNames("cap", 1500)
	more := tnNames("more", 300)
	var p1 atomic.Value
	p1.Store(page(spaced(names[400:800])))
	x := tnWorld(t)
	s := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": page(`<html><a href="/p1">p1</a>` + scriptPage("/s1.js", "/s2.js") + `<p>` + spaced(names[:400]) + `</p></html>`),
		"/p1": func(w http.ResponseWriter, r *http.Request) {
			p1.Load().(http.HandlerFunc)(w, r)
		},
		"/s1.js": js(`var hosts = "` + spaced(names[800:1150]) + `";`),
		"/s2.js": js(`var hosts = ["` + strings.Join(names[1150:], `","`) + `"];`),
	}))
	x.mustRun()

	if n := x.taken(names); n != 1000 {
		t.Errorf("%d of the 1,500 names are hostnames, want 1,000", n)
	}
	if n := len(x.textNames(tnOrigin)); n != 1000 {
		t.Errorf("%d names are kept for %s, want 1,000", n, tnOrigin)
	}
	x.wantCapWarning(tnOrigin, "500")

	// A plain re-run.
	subs, hits := x.lines(eng, "subdomains.txt"), s.hits()
	x.mustRun()
	if s.hits() != hits {
		t.Errorf("a plain re-run sent %d requests", s.hits()-hits)
	}
	x.wantNoCapWarning("a plain re-run reads nothing")
	if got := x.lines(eng, "subdomains.txt"); !slices.Equal(got, subs) {
		t.Errorf("a plain re-run changed subdomains.txt from %d to %d names", len(subs), len(got))
	}

	// A re-crawl whose pages name 300 more.
	p1.Store(page(spaced(names[400:800]) + " " + spaced(more)))
	x.mustRun("--redo", "crawl")
	if n := x.taken(more); n != 0 {
		t.Errorf("%d of the 300 new names were taken by a service at its cap", n)
	}
	if n := x.taken(names); n != 1000 {
		t.Errorf("after the re-crawl %d of the 1,500 names are hostnames, want 1,000", n)
	}
	if n := len(x.textNames(tnOrigin)); n != 1000 {
		t.Errorf("after the re-crawl %d names are kept for %s, want 1,000", n, tnOrigin)
	}
	x.wantCapWarning(tnOrigin, "300")
}

// The names of links count against the cap: crawl and jsparse take hostnames only by reading, and
// still record the URLs.
func TestTextNames_LinkNamesCount(t *testing.T) {
	t.Parallel()
	links := tnNames("link", 1200)
	scripted := tnNames("jsurl", 10)
	var b strings.Builder
	b.WriteString("<html>")
	for _, n := range links {
		fmt.Fprintf(&b, `<a href="http://%s/">%s</a>`, n, strings.TrimSuffix(n, ".example.com"))
	}
	b.WriteString(scriptPage("/app.js") + "</html>")
	var js1 strings.Builder
	for _, n := range scripted {
		fmt.Fprintf(&js1, "fetch(\"https://%s/v1\");", n)
	}
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{"/": page(b.String()), "/app.js": js(js1.String())}))
	x.mustRun()

	if n := x.taken(slices.Concat(links, scripted)); n != 1000 {
		t.Errorf("%d of the 1,210 linked hosts are hostnames, want 1,000", n)
	}
	if n := len(x.textNames(tnOrigin)); n != 1000 {
		t.Errorf("%d names are kept for %s, want 1,000", n, tnOrigin)
	}
	x.wantCapWarning(tnOrigin, "210")
	crawled, parsed := map[string]bool{}, map[string]bool{}
	for _, r := range current(x.urls()) {
		if strings.Contains(r["found_by"], "crawl") {
			crawled[r["url"]] = true
		}
		if strings.Contains(r["found_by"], "jsparse") {
			parsed[r["url"]] = true
		}
	}
	for _, n := range links {
		if u := "http://" + n + "/"; !crawled[u] {
			t.Errorf("the crawl did not record the link %s (%d links recorded)", u, len(crawled))
			break
		}
	}
	for _, n := range scripted {
		if u := "https://" + n + "/v1"; !parsed[u] {
			t.Errorf("jsparse did not record %s: %v", u, slices.Sorted(maps.Keys(parsed)))
		}
	}
}

// A name nyx already knew from another source uses a place when the service names it.
func TestTextNames_KnownNameUsesAPlace(t *testing.T) {
	t.Parallel()
	fresh := tnNames("fresh", 1000)
	x := newWeb(t)
	x.names("www.example.com", "known.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, page(`<p>known.example.com `+spaced(fresh)+`</p>`))
	x.mustRun("--crawl-pages", "0")

	// 1,001 distinct names: had the known name used no place, all 1,000 new ones would be taken and
	// none left out.
	if n := len(x.textNames(tnOrigin)); n != 1000 {
		t.Errorf("%d names are kept for %s, want 1,000", n, tnOrigin)
	}
	x.wantCapWarning(tnOrigin, "1")
}

// A redirect target and a certificate SAN are taken as before, outside the cap, even when the page
// names them too.
func TestTextNames_RedirectTargetAndSANUseNoPlace(t *testing.T) {
	t.Parallel()
	fresh := tnNames("fresh", 1000)
	x := tnWorld(t)
	cert := selfSigned(t, leafSpec{cn: "www.example.com", dns: []string{"www.example.com", "san-host.example.com"}})
	x.secure("203.0.113.5", 443, cert, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://redir-host.example.com/landing")
		plainText(http.StatusFound, "Moved to redir-host.example.com (also san-host.example.com). "+spaced(fresh))(w, r)
	})
	x.mustRun("--crawl-pages", "0")

	const origin = "https://www.example.com"
	got := x.observedBy("hostname", "httpprobe")
	for _, n := range []string{"redir-host.example.com", "san-host.example.com"} {
		if !slices.Contains(got, n) {
			t.Errorf("httpprobe did not observe %s", n)
		}
	}
	if n := x.taken(fresh); n != 1000 {
		t.Errorf("%d of the 1,000 names in the page were taken, want all: the redirect target and the SAN use no place", n)
	}
	kept := x.textNames(origin)
	if len(kept) != 1000 {
		t.Errorf("%d names are kept for %s, want 1,000", len(kept), origin)
	}
	for _, n := range []string{"redir-host.example.com", "san-host.example.com"} {
		if slices.Contains(kept, n) {
			t.Errorf("%s uses a place in the cap", n)
		}
	}
	x.wantNoCapWarning("the redirect target and the SAN use no place")
}

// A script counts against the origin that serves it, whichever page loads it.
func TestTextNames_ScriptCountsAgainstItsOwnOrigin(t *testing.T) {
	t.Parallel()
	wwwNames := tnNames("www", 999) // with cdn.example.com, the page names 1,000: www is at its cap
	cdnNames := tnNames("cdn", 50)
	x := newWeb(t)
	x.names("www.example.com", "cdn.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.host("cdn.example.com", "203.0.113.6")
	x.plain("203.0.113.5", 80, page(scriptPage("https://cdn.example.com/lib.js")+"<p>"+spaced(wwwNames)+"</p>"))
	cdn := x.secure("203.0.113.6", 443, selfSigned(t, leafSpec{cn: "cdn.example.com", dns: []string{"cdn.example.com"}}),
		routes(map[string]http.HandlerFunc{"/": page("<p>cdn</p>"), "/lib.js": js(`var h = "` + spaced(cdnNames) + `";`)}))
	x.mustRun()

	if cdn.count("/lib.js") != 1 {
		t.Fatalf("precondition: https://cdn.example.com/lib.js must be fetched once: %v", cdn.uris())
	}
	if n := x.taken(cdnNames); n != 50 {
		t.Errorf("%d of the script's 50 names were taken, want all: they count against https://cdn.example.com", n)
	}
	if n := len(x.textNames("https://cdn.example.com")); n != 50 {
		t.Errorf("%d names are kept for https://cdn.example.com, want 50", n)
	}
	if n := len(x.textNames(tnOrigin)); n != 1000 {
		t.Errorf("%d names are kept for %s, want 1,000", n, tnOrigin)
	}
	x.wantNoCapWarning("no service names more than 1,000")
}

// Past 10,000 names left out, the warning says "more than 10,000".
func TestTextNames_MoreThanTenThousandLeftOut(t *testing.T) {
	t.Parallel()
	names := tnNames("many", 13000)
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, page("<p>"+spaced(names)+"</p>"))
	x.mustRun("--crawl-pages", "0")

	if n := len(x.textNames(tnOrigin)); n != 1000 {
		t.Errorf("%d names are kept for %s, want 1,000", n, tnOrigin)
	}
	if n := x.taken(names); n != 1000 {
		t.Errorf("%d of the 13,000 names are hostnames, want 1,000", n)
	}
	x.wantCapWarning(tnOrigin, "more than 10,000")
}

// --- Failures and re-runs ---

// A script that times out fails its job only; the next run retries it and takes its names.
func TestTextNames_ScriptTimeoutIsRetried(t *testing.T) {
	t.Parallel()
	var stall atomic.Bool
	stall.Store(true)
	x, _ := jsFixture(t, []string{"/ok.js", "/slow.js"}, map[string]http.HandlerFunc{
		"/ok.js": js(`var h = "ok-js.example.com";`),
		"/slow.js": func(w http.ResponseWriter, r *http.Request) {
			if stall.Load() {
				select {
				case <-r.Context().Done():
				case <-time.After(time.Second):
				}
			}
			js(`var h = "slow-js.example.com";`)(w, r)
		},
	})
	x.h.eopts.HTTPTimeout = 300 * time.Millisecond
	x.partialRun("jsparse", 1)
	x.wantTaken("ok-js.example.com", "jsparse")
	x.wantNoHostname("slow-js.example.com", "its script timed out")

	stall.Store(false)
	x.mustRun()
	x.wantTaken("slow-js.example.com", "jsparse")
}

// A crawl whose root fetch fails records nothing and keeps no places: a later job of the service in
// the same run still has all of them. The root first redirects within the origin, so the crawl has
// read a response full of names before the fetch fails.
func TestTextNames_FailedCrawlReservesNothing(t *testing.T) {
	t.Parallel()
	rootNames := tnNames("root", 1000)
	jsNames := tnNames("script", 1000)
	var fail atomic.Bool
	var app atomic.Value
	app.Store(js("1"))
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": func(w http.ResponseWriter, r *http.Request) {
			if fail.Load() {
				w.Header().Set("Location", "/start")
				plainText(http.StatusFound, "moving: "+spaced(rootNames))(w, r)
				return
			}
			page(scriptPage("/app.js"))(w, r)
		},
		"/start":  abortAfter("<p>start-page.example.com</p>"),
		"/app.js": func(w http.ResponseWriter, r *http.Request) { app.Load().(http.HandlerFunc)(w, r) },
	}))
	x.mustRun()

	// The probe's job is done; the crawl's new job fails fetching its root, then jsparse reads the
	// script again.
	fail.Store(true)
	app.Store(js(`var h = "` + spaced(jsNames) + `";`))
	x.partialRun("crawl", 1, "--crawl-depth", "1", "--redo", "jsparse")

	if n := x.taken(rootNames); n != 0 {
		t.Errorf("%d names from the failed crawl's root were taken", n)
	}
	if got := x.observedBy("hostname", "crawl"); len(got) != 0 {
		t.Errorf("the failed crawl observed hostnames: %d of them", len(got))
	}
	if n := x.taken(jsNames); n != 1000 {
		t.Errorf("%d of the script's 1,000 names were taken, want all: the failed crawl must keep no places", n)
	}
	x.wantNoCapWarning("the failed crawl's names are not counted")
}

// An undecodable or binary body gives no names and no error.
func TestTextNames_BinaryAndUndecodableBodies(t *testing.T) {
	t.Parallel()
	bin := make([]byte, 4096)
	v := uint32(2463534242)
	for i := range bin { // xorshift: bytes of every value, deterministic
		v ^= v << 13
		v ^= v >> 17
		v ^= v << 5
		bin[i] = byte(v)
	}
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": page(`<a href="/bin">b</a><a href="/latin">l</a><p>ctl-bin.example.com</p>`),
		"/bin": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(bin)
		},
		"/latin": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=iso-8859-1")
			_, _ = w.Write([]byte("<p>Visit b\xfccher.example.com today</p>"))
		},
	}))
	x.mustRun()

	if st, _ := stateOf(x.world, "crawl"); st != "done" {
		t.Errorf("crawl = %s, want done", st)
	}
	if got := x.observedBy("hostname", "crawl"); !slices.Equal(got, []string{"ctl-bin.example.com"}) {
		t.Errorf("crawl hostnames = %v, want only ctl-bin.example.com", got)
	}
	x.wantNoHostname("cher.example.com", "a Latin-1 letter touching a name rejects it")
}

// A page that fails mid-crawl is skipped, and the pages after it are still read.
func TestTextNames_PageFailingMidCrawlIsSkipped(t *testing.T) {
	t.Parallel()
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":     page(`<a href="/bad">bad</a><a href="/good">good</a>`),
		"/bad":  abortAfter("<p>bad-page.example.com</p>"),
		"/good": page("<p>good-page.example.com</p>"),
	}))
	x.mustRun()

	if got := x.completedKeys("crawl"); !slices.Equal(got, []string{"http://www.example.com|depth=2|pages=100"}) {
		t.Errorf("crawl jobs = %v", got)
	}
	x.wantTaken("good-page.example.com", "crawl")
	x.wantNoHostname("bad-page.example.com", "its page failed mid-body")
}

// A run interrupted during a slow crawl stores nothing from that job, keeps what earlier jobs
// stored, and still warns of a service already over its cap.
func TestTextNames_InterruptedCrawl(t *testing.T) {
	t.Parallel()
	names := tnNames("probe", 1200)
	arrived := make(chan struct{}, 1)
	x := tnWorld(t)
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/":   page(`<a href="/p1">1</a><a href="/slow">s</a><p>` + spaced(names) + `</p>`),
		"/p1": page("<p>crawl-only.example.com</p>"),
		"/slow": func(w http.ResponseWriter, r *http.Request) {
			select {
			case arrived <- struct{}{}:
			default:
			}
			<-r.Context().Done()
		},
	}))
	x.fill()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-arrived:
			cancel()
		case <-ctx.Done():
		}
	}()
	code := x.h.execCtx(ctx, "--json", "--rate-per-source", "1000", "--rate-dns", "100000",
		"--authorised", "--rate-per-host", "1000", "--no-permutations", "example.com")
	if code != 130 {
		t.Fatalf("exit %d, want 130 (interrupted during the crawl)\n%s", code, x.h.stderr.String())
	}

	if got := x.completedKeys("crawl"); len(got) != 0 {
		t.Errorf("the interrupted crawl completed %v", got)
	}
	x.wantNoHostname("crawl-only.example.com", "the crawl that read it was interrupted")
	if n := x.taken(names); n != 1000 {
		t.Errorf("%d of the probe's 1,200 names are hostnames, want the 1,000 it stored", n)
	}
	if n := len(x.textNames(tnOrigin)); n != 1000 {
		t.Errorf("%d names are kept for %s, want 1,000", n, tnOrigin)
	}
	x.wantCapWarning(tnOrigin, "200")
}

// A re-run after a successful one sends nothing and leaves every file as it was.
func TestTextNames_RerunAfterSuccess(t *testing.T) {
	t.Parallel()
	x, www, port := placesWorld(t, true)
	x.mustRun()
	if subs := x.lines(eng, "subdomains.txt"); !slices.Contains(subs, "comment-place.example.com") {
		t.Fatalf("precondition: a name in a comment must be taken: %v", subs)
	}
	files := func() map[string]string {
		all := snapshotDir(t, x.h.eng(eng))
		maps.DeleteFunc(all, func(k, _ string) bool { return strings.HasPrefix(k, ".nyx") })
		return all
	}
	before, hits := files(), www.hits()+port.hits()
	x.mustRun()
	if n := www.hits() + port.hits() - hits; n != 0 {
		t.Errorf("the re-run sent %d requests", n)
	}
	after := files()
	for name, body := range before {
		if after[name] != body {
			t.Errorf("%s changed on a re-run", name)
		}
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			t.Errorf("%s appeared on a re-run", name)
		}
	}
}

// After a run with a failed job, the retry still respects the cap: the names kept by the first run
// count against it.
func TestTextNames_CapHoldsAcrossAPartialRun(t *testing.T) {
	t.Parallel()
	first := tnNames("first", 900)
	late := tnNames("late", 300)
	var stall atomic.Bool
	stall.Store(true)
	x := tnWorld(t)
	x.h.eopts.HTTPTimeout = 300 * time.Millisecond
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": page(scriptPage("/slow.js") + "<p>" + spaced(first) + "</p>"),
		"/slow.js": func(w http.ResponseWriter, r *http.Request) {
			if stall.Load() {
				select {
				case <-r.Context().Done():
				case <-time.After(time.Second):
				}
			}
			js(`var h = "`+spaced(late)+`";`)(w, r)
		},
	}))
	x.partialRun("jsparse", 1)
	if n := x.taken(first); n != 900 {
		t.Fatalf("precondition: %d of the page's 900 names were taken, want all", n)
	}

	stall.Store(false)
	x.mustRun()
	if n := x.taken(late); n != 100 {
		t.Errorf("%d of the retried script's 300 names were taken, want the 100 places left", n)
	}
	if n := len(x.textNames(tnOrigin)); n != 1000 {
		t.Errorf("%d names are kept for %s, want 1,000", n, tnOrigin)
	}
	x.wantCapWarning(tnOrigin, "200")
}
