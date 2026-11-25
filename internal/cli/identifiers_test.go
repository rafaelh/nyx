package cli_test

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Identifier tests use loopback web/Shodan fakes to check extraction and pivot searches.

// iconHashOf uses independently computed Python/base64/MurmurHash fixtures rather than the
// implementation under test.
func iconOf(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

const (
	hash100 = "-1165240594"
	hash50  = "-1267721240"
	hash30  = "-378021985"
)

// icon serves a favicon with the given content type; "" sends none.
func icon(contentType string, body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if contentType == "" {
			w.Header()["Content-Type"] = nil // stop net/http choosing one
		} else {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write(body)
	}
}

// ids removes CSV's spreadsheet-protection quote from negative favicon hashes before comparing
// values.
func (x *web) ids(url string) (analytics, pixels, favicon, copyright string) {
	x.t.Helper()
	r := x.service(url)
	return r["analytics_ids"], r["pixel_ids"], strings.TrimPrefix(r["favicon_hash"], "'"), r["copyright"]
}

const homePage = `<html><head><title>Home</title>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-AAAAAA1"></script>
<script>gtag('config', 'G-AAAAAA1');</script>
</head><body><a href="/about">About</a><footer>© 2026 Acme Pty Ltd</footer></body></html>`

const aboutPage = `<html><body><script>fbq('init', '111111111');</script>
<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABCD123"></iframe></noscript></body></html>`

// --- Collection ---

// The columns follow the posture columns, and the cells are the union over the
// pages the probe and the crawl fetched.
func TestIdentifiers_ProbeAndCrawlUnion(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": page(homePage), "/about": page(aboutPage), "/favicon.ico": icon("image/x-icon", iconOf(100)),
	}))
	x.mustRun()

	wantHeader := "version_disclosure,analytics_ids,pixel_ids,favicon_hash,copyright,current,first_seen,last_seen"
	if hdr, _, _ := strings.Cut(x.file(eng, "web-services.csv"), "\n"); !strings.Contains(hdr, wantHeader) {
		t.Errorf("web-services.csv header = %q, want it to contain %q", hdr, wantHeader)
	}
	a, p, f, c := x.ids("http://www.example.com")
	if a != "G-AAAAAA1;GTM-ABCD123" || p != "111111111" || f != hash100 || c != "© 2026 Acme Pty Ltd" {
		t.Errorf("analytics = %q, pixels = %q, favicon = %q, copyright = %q", a, p, f, c)
	}
	// Each procedure recorded what it saw: the probe the root page, the crawl both.
	if got := x.observedBy("web_identifier", "httpprobe"); !slices.Equal(got, []string{
		"http://www.example.com|analytics|G-AAAAAA1", "http://www.example.com|copyright|© 2026 Acme Pty Ltd", "http://www.example.com|favicon|" + hash100}) {
		t.Errorf("httpprobe observed %v", got)
	}
	got := x.observedBy("web_identifier", "crawl")
	for _, want := range []string{"http://www.example.com|analytics|GTM-ABCD123", "http://www.example.com|pixel|111111111", "http://www.example.com|analytics|G-AAAAAA1"} {
		if !slices.Contains(got, want) {
			t.Errorf("crawl observed %v, want %s", got, want)
		}
	}
	if slices.ContainsFunc(got, func(k string) bool { return strings.Contains(k, "|favicon|") }) {
		t.Errorf("the crawl recorded a favicon: %v", got)
	}
}

// A negative hash is written with the quote every cell starting with "-" gets.
func TestIdentifiers_NegativeHashCellIsQuoted(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{"/": page("<p>home</p>"), "/favicon.ico": icon("image/x-icon", iconOf(100))}))
	x.mustRun("--crawl-pages", "0")
	if got := x.service("http://www.example.com")["favicon_hash"]; got != "'"+hash100 {
		t.Errorf("favicon_hash cell = %q, want %q", got, "'"+hash100)
	}
}

// With the crawl off, only the root page's identifiers are known.
func TestIdentifiers_ProbeOnlySeesTheRootPage(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{"/": page(homePage), "/about": page(aboutPage)}))
	x.mustRun("--crawl-pages", "0")
	a, p, f, c := x.ids("http://www.example.com")
	if a != "G-AAAAAA1" || p != "" || f != "" || c != "© 2026 Acme Pty Ltd" {
		t.Errorf("analytics = %q, pixels = %q, favicon = %q, copyright = %q", a, p, f, c)
	}
}

// Read identifiers only from the service's own pages in the redirect chain.
func TestIdentifiers_OnlyThePagesOfTheServiceItself(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com", "other.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.host("other.example.com", "203.0.113.6")
	x.plain("203.0.113.5", 80, redirectTo(302, "http://other.example.com/"))
	x.plain("203.0.113.6", 80, page(`<script>gtag('config','G-OTHER001')</script><p>© 2025 Other Ltd</p>`))
	x.mustRun("--crawl-pages", "0")
	if a, _, _, c := x.ids("http://www.example.com"); a != "" || c != "" {
		t.Errorf("www took identifiers from the page its redirect led to: %q, %q", a, c)
	}
	if a, _, _, c := x.ids("http://other.example.com"); a != "G-OTHER001" || c != "© 2025 Other Ltd" {
		t.Errorf("other = %q, %q", a, c)
	}
}

// favicon cases: each serves www.example.com on one address.
func faviconCase(t *testing.T, root http.HandlerFunc, routesOf map[string]http.HandlerFunc) (*web, *site) {
	t.Helper()
	x := newWeb(t)
	x.names("www.example.com", "other.example.com")
	x.host("www.example.com", "203.0.113.5")
	m := map[string]http.HandlerFunc{"/": root}
	maps.Copy(m, routesOf)
	return x, x.plain("203.0.113.5", 80, routes(m))
}

// otherSite serves other.example.com, which faviconCase names, with an icon of its own.
func (x *web) otherSite() *site {
	x.t.Helper()
	x.host("other.example.com", "203.0.113.6")
	return x.plain("203.0.113.6", 80, routes(map[string]http.HandlerFunc{"/": page("<p>other</p>"), "/favicon.ico": icon("image/x-icon", iconOf(50))}))
}

func TestFavicon_FromTheSameHostLink(t *testing.T) {
	t.Parallel()
	x, s := faviconCase(t, page(`<head><link rel="stylesheet" href="/s.css"><link rel="apple-touch-icon" href="/apple.png"><link rel="shortcut icon" href="/static/fav.png"></head>`),
		map[string]http.HandlerFunc{"/static/fav.png": icon("image/png", iconOf(100)), "/favicon.ico": icon("image/x-icon", iconOf(50)), "/apple.png": icon("image/png", iconOf(30))})
	x.mustRun("--crawl-pages", "0")
	if _, _, f, _ := x.ids("http://www.example.com"); f != hash100 {
		t.Errorf("favicon = %q, want %s from the linked icon", f, hash100)
	}
	if n := s.count("/static/fav.png"); n != 1 {
		t.Errorf("the linked icon was requested %d times, want 1", n)
	}
	if s.count("/favicon.ico") != 0 || s.count("/apple.png") != 0 {
		t.Errorf("requests = %v, want no /favicon.ico and no apple-touch-icon", s.uris())
	}
}

// A relative icon link resolves against the page's <base href>, as a browser does.
func TestFavicon_LinkUnderBaseHref(t *testing.T) {
	t.Parallel()
	x, s := faviconCase(t, page(`<head><base href="/static/"><link rel="icon" href="fav.png"></head>`),
		map[string]http.HandlerFunc{"/static/fav.png": icon("image/png", iconOf(100)), "/fav.png": icon("image/png", iconOf(50))})
	x.mustRun("--crawl-pages", "0")
	if _, _, f, _ := x.ids("http://www.example.com"); f != hash100 {
		t.Errorf("favicon = %q, want %s from /static/fav.png", f, hash100)
	}
	if s.count("/fav.png") != 0 {
		t.Errorf("requests = %v, want the link resolved against <base href>", s.uris())
	}
}

func TestFavicon_FallsBackToFaviconIco(t *testing.T) {
	t.Parallel()
	x, s := faviconCase(t, page(`<head><title>x</title><link rel="apple-touch-icon" href="/apple.png"></head>`),
		map[string]http.HandlerFunc{"/favicon.ico": icon("image/x-icon", iconOf(100))})
	x.mustRun("--crawl-pages", "0")
	if _, _, f, _ := x.ids("http://www.example.com"); f != hash100 {
		t.Errorf("favicon = %q, want %s", f, hash100)
	}
	if n := s.count("/favicon.ico"); n != 1 {
		t.Errorf("/favicon.ico was requested %d times, want 1", n)
	}
}

// An icon link on another host is not followed, even to an in-scope host: the
// service's own /favicon.ico is used.
func TestFavicon_OffHostLinkFallsBack(t *testing.T) {
	t.Parallel()
	x, s := faviconCase(t, page(`<head><link rel="icon" href="http://cdn.elsewhere.test/fav.png"></head>`),
		map[string]http.HandlerFunc{"/favicon.ico": icon("image/x-icon", iconOf(100))})
	other := x.otherSite()
	x.mustRun("--crawl-pages", "0")
	if _, _, f, _ := x.ids("http://www.example.com"); f != hash100 {
		t.Errorf("favicon = %q, want %s from /favicon.ico", f, hash100)
	}
	if n := s.count("/favicon.ico"); n != 1 {
		t.Errorf("/favicon.ico was requested %d times, want 1", n)
	}
	if n := other.count("/favicon.ico"); n != 1 { // its own probe's, and nobody else's
		t.Errorf("other.example.com was asked for /favicon.ico %d times, want 1 (its own)", n)
	}
}

// When the probe's chain ends on another host, that host's page and its icon
// link are not used for this service.
func TestFavicon_ChainEndingOnAnotherHost(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com", "other.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.host("other.example.com", "203.0.113.6")
	www := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": redirectTo(302, "http://other.example.com/"), "/favicon.ico": icon("image/x-icon", iconOf(100))}))
	other := x.plain("203.0.113.6", 80, routes(map[string]http.HandlerFunc{
		"/": page(`<link rel="icon" href="/other.png">`), "/other.png": icon("image/png", iconOf(50))}))
	x.mustRun("--crawl-pages", "0")
	if _, _, f, _ := x.ids("http://www.example.com"); f != hash100 {
		t.Errorf("www favicon = %q, want %s from its own /favicon.ico", f, hash100)
	}
	if n := www.count("/favicon.ico"); n != 1 {
		t.Errorf("www /favicon.ico requested %d times, want 1", n)
	}
	if _, _, f, _ := x.ids("http://other.example.com"); f != hash50 {
		t.Errorf("other favicon = %q, want %s from its own link", f, hash50)
	}
	if n := other.count("/other.png"); n != 1 {
		t.Errorf("/other.png requested %d times, want 1", n)
	}
}

// A redirect of the icon is followed once, and only to the same host.
func TestFavicon_Redirects(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		routes map[string]http.HandlerFunc
		want   string
	}{
		"one redirect on the host is followed": {map[string]http.HandlerFunc{
			"/favicon.ico": redirectTo(301, "/icons/f.ico"), "/icons/f.ico": icon("image/x-icon", iconOf(100))}, hash100},
		"a second redirect is not": {map[string]http.HandlerFunc{
			"/favicon.ico": redirectTo(301, "/a"), "/a": redirectTo(301, "/b"), "/b": icon("image/x-icon", iconOf(100))}, ""},
		"a redirect to another host is not": {map[string]http.HandlerFunc{
			"/favicon.ico": redirectTo(301, "http://other.example.com/favicon.ico")}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			x, _ := faviconCase(t, page("<p>home</p>"), c.routes)
			other := x.otherSite()
			x.mustRun("--crawl-pages", "0")
			if _, _, f, _ := x.ids("http://www.example.com"); f != c.want {
				t.Errorf("favicon = %q, want %q", f, c.want)
			}
			if n := other.count("/favicon.ico"); n != 1 { // its own probe's
				t.Errorf("other.example.com was asked for /favicon.ico %d times, want 1 (its own)", n)
			}
		})
	}
}

// No hash from a missing file, a web page, or something that is not an image.
func TestFavicon_NoHashFromAnAnswerThatIsNotAnIcon(t *testing.T) {
	t.Parallel()
	for name, h := range map[string]http.HandlerFunc{
		"404":              http.NotFound,
		"html page":        page("<html><body>Not found, honest</body></html>"),
		"html as an image": icon("image/x-icon", []byte("  <html>soft 404</html>")),
		"text":             icon("text/plain", iconOf(100)),
		"server error":     func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
	} {
		t.Run(name, func(t *testing.T) {
			x, s := faviconCase(t, page("<p>home</p>"), map[string]http.HandlerFunc{"/favicon.ico": h})
			x.mustRun("--crawl-pages", "0")
			if _, _, f, _ := x.ids("http://www.example.com"); f != "" {
				t.Errorf("favicon = %q, want none", f)
			}
			if n := s.count("/favicon.ico"); n != 1 {
				t.Errorf("/favicon.ico requested %d times, want 1", n)
			}
		})
	}
}

// An interrupted icon body does not invalidate the service or fail its probe.
func TestFavicon_FailedRequestDoesNotLoseTheService(t *testing.T) {
	t.Parallel()
	x, s := faviconCase(t, page("<title>home</title>"), map[string]http.HandlerFunc{"/favicon.ico": func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte("short"))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}})
	x.mustRun("--crawl-pages", "0")
	if r := x.service("http://www.example.com"); r["title"] != "home" || r["favicon_hash"] != "" {
		t.Errorf("service = %v, want it recorded without a favicon", r)
	}
	if st, _ := x.procedureState("httpprobe"); st != "done" {
		t.Errorf("httpprobe = %s, want done", st)
	}
	if n := s.count("/favicon.ico"); n != 1 {
		t.Errorf("/favicon.ico requested %d times, want 1", n)
	}
}

// A response with no content type is hashed (an icon often has none), and so is
// an empty file, whose hash is 0.
func TestFavicon_NoContentTypeAndEmptyFile(t *testing.T) {
	t.Parallel()
	x, _ := faviconCase(t, page("<p>home</p>"), map[string]http.HandlerFunc{"/favicon.ico": icon("", iconOf(100))})
	x.mustRun("--crawl-pages", "0")
	if _, _, f, _ := x.ids("http://www.example.com"); f != hash100 {
		t.Errorf("favicon without a content type = %q, want %s", f, hash100)
	}
	x, _ = faviconCase(t, page("<p>home</p>"), map[string]http.HandlerFunc{"/favicon.ico": icon("image/x-icon", nil)})
	x.mustRun("--crawl-pages", "0")
	if _, _, f, _ := x.ids("http://www.example.com"); f != "0" {
		t.Errorf("favicon of an empty file = %q, want 0", f)
	}
}

// Exactly one favicon GET per web service, and never one to a service that does not answer.
func TestFavicon_OneGetPerService(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("a.example.com", "b.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.6")
	mk := func() map[string]http.HandlerFunc {
		return map[string]http.HandlerFunc{"/": page("<p>home</p>"), "/favicon.ico": icon("image/x-icon", iconOf(100))}
	}
	a := x.plain("203.0.113.5", 80, routes(mk()))
	b := x.plain("203.0.113.6", 80, routes(mk()))
	x.mustRun()
	x.mustRun("--redo", "crawl") // the crawl must not ask for icons either
	if a.count("/favicon.ico") != 1 || b.count("/favicon.ico") != 1 {
		t.Errorf("favicon GETs: a %d, b %d, want 1 each", a.count("/favicon.ico"), b.count("/favicon.ico"))
	}
	if !a.onlyGET() || !b.onlyGET() {
		t.Error("something other than GET was sent")
	}
}

// --- The pivot ---

// pivotFake is api.shodan.io's host search: an answer per query, and a status per query or for all.
type pivotFake struct {
	mu      sync.Mutex
	answers map[string]string
	status  map[string]int
	all     int
}

func (f *pivotFake) serve(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("key") != shodanKey {
		http.Error(rw, "bad key", http.StatusUnauthorized)
		return
	}
	if r.URL.Path != "/shodan/host/search" {
		http.NotFound(rw, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	q := r.URL.Query().Get("query")
	if f.all != 0 {
		http.Error(rw, "no", f.all)
		return
	}
	if code := f.status[q]; code != 0 {
		http.Error(rw, "no", code)
		return
	}
	if body, ok := f.answers[q]; ok {
		_, _ = rw.Write([]byte(body))
		return
	}
	_, _ = rw.Write([]byte(searchJSON(0)))
}

func (f *pivotFake) set(q, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[q] = body
}

func (f *pivotFake) fail(q string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[q] = code // 0 is no status
}

func (f *pivotFake) failAll(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.all = code
}

// hit is one match of a search: an address and the hostnames Shodan holds for it.
func hit(ip string, hostnames ...string) map[string]any {
	return map[string]any{"ip_str": ip, "port": 443, "transport": "tcp", "hostnames": hostnames}
}

// pivot installs the fake and the key.
func (x *web) pivot() *pivotFake {
	x.t.Helper()
	x.h.setKey("shodan", shodanKey)
	f := &pivotFake{answers: map[string]string{}, status: map[string]int{}}
	x.handle("api.shodan.io", f.serve)
	return f
}

// searches are the queries sent to the host search, in order, with the page asked for.
func (x *web) searches() (queries, pages []string) {
	for _, r := range x.requests("api.shodan.io") {
		if r.path() != "/shodan/host/search" {
			continue
		}
		v, _ := url.ParseQuery(r.query())
		queries = append(queries, v.Get("query"))
		pages = append(pages, v.Get("page"))
	}
	return queries, pages
}

func (x *web) queries() []string { q, _ := x.searches(); return q }

func (x *web) procedureState(name string) (string, string) { return stateOf(x.world, name) }

const (
	qFavicon = "http.favicon.hash:" + hash100
	qPixel   = `http.html:"111111111"`
	qGA      = `http.html:"G-AAAAAA1"`
)

// pivotWorld combines shared identifiers, a SaaS service and an empty favicon; returned
// addresses are canaries.
func pivotWorld(t *testing.T) (x *web, f *pivotFake, canaries, sites []*site) {
	t.Helper()
	x = newWeb(t)
	f = x.pivot()
	x.names("www.example.com", "app.example.com", "help.example.com", "plain.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.host("app.example.com", "203.0.113.6")
	x.host("help.example.com", "203.0.113.20")
	x.dns.CNAME("help.example.com", "acme.zendesk.com")
	x.dns.A("acme.zendesk.com", "203.0.113.20")
	x.host("plain.example.com", "203.0.113.7")
	sites = append(sites, x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": page(homePage + `<script>fbq('init','111111111')</script>`), "/favicon.ico": icon("image/x-icon", iconOf(100))})))
	sites = append(sites, x.plain("203.0.113.6", 80, routes(map[string]http.HandlerFunc{
		"/": page(`<script>gtag('config','G-AAAAAA1')</script><p>© 2026 Acme Pty Ltd</p>`), "/favicon.ico": icon("image/x-icon", iconOf(100))})))
	sites = append(sites, x.plain("203.0.113.20", 80, routes(map[string]http.HandlerFunc{
		"/": page(`<script>gtag('config','G-SAAS0001')</script><p>© 2026 Help</p>`), "/favicon.ico": icon("image/x-icon", iconOf(50))})))
	sites = append(sites, x.plain("203.0.113.7", 80, routes(map[string]http.HandlerFunc{
		"/": page(`<p>plain</p><p>© 2026 Plain Ltd</p>`), "/favicon.ico": icon("image/x-icon", nil)})))
	for _, ip := range []string{"198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"} {
		for _, port := range []int{80, 443} {
			canaries = append(canaries, x.silent(ip, port))
		}
		// Open, as the port sweep would find them if these addresses were in scope: the
		// probe would then connect. It must not.
		x.open(ip+":80", "")
	}
	f.set(qGA, searchJSON(2, hit("198.51.100.10", "sister.example.com", "brand.other-brand.co.uk"), hit("198.51.100.11")))
	f.set(qPixel, searchJSON(1, hit("198.51.100.12", "shop.pixel-friend.org")))
	f.set(qFavicon, searchJSON(1, hit("198.51.100.13")))
	return x, f, canaries, sites
}

func TestIdentifierPivot_OneSearchPerDistinctIdentifier(t *testing.T) {
	t.Parallel()
	x, _, canaries, _ := pivotWorld(t)
	x.mustRun()

	// Search distinct useful identifiers only. Parallel execution means request order need
	// not match enumeration order.
	want := sorted([]string{qFavicon, qPixel, qGA})
	queries, pages := x.searches()
	if !slices.Equal(sorted(queries), want) {
		t.Errorf("searches = %v, want %v", queries, want)
	}
	for _, p := range pages {
		if p != "" && p != "1" {
			t.Errorf("a search asked for page %q, want the first only", p)
		}
	}
	if st, _ := x.procedureState("identifier-pivot"); st != "done" {
		t.Errorf("identifier-pivot = %s, want done", st)
	}
	// What the pivot found: an in-scope name, and the registrable domains of the others.
	if !slices.Contains(x.observedBy("hostname", "identifier-pivot"), "sister.example.com") {
		t.Errorf("hostnames from the pivot = %v, want sister.example.com", x.observedBy("hostname", "identifier-pivot"))
	}
	if got := x.observedBy("hostname", "identifier-pivot"); slices.Contains(got, "brand.other-brand.co.uk") || slices.Contains(got, "shop.pixel-friend.org") {
		t.Errorf("a name outside the scope's roots was recorded as a hostname: %v", got)
	}
	if got, want := x.candidate("other-brand.co.uk"), "identifier-pivot:G-AAAAAA1"; got == nil || got["sources"] != want || got["type"] != "root" {
		t.Errorf("other-brand.co.uk = %v, want a root whose sources are %s", got, want)
	}
	if got := x.candidate("pixel-friend.org"); got == nil || got["sources"] != "identifier-pivot:111111111" {
		t.Errorf("pixel-friend.org = %v", got)
	}
	if got := x.candidate("brand.other-brand.co.uk"); got != nil {
		t.Errorf("a hostname outside the scope is a candidate: %v", got)
	}
	// The addresses are listed, classified by the normal rules, and never contacted.
	for _, ip := range []string{"198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"} {
		row := find(x.table(eng, "ips.csv"), "ip", ip)
		if row == nil {
			t.Errorf("ips.csv has no %s:\n%s", ip, x.file(eng, "ips.csv"))
			continue
		}
		if row["in_scope"] == "yes" || row["port_eligible"] == "yes" {
			t.Errorf("%s = %v, want out of scope", ip, row)
		}
	}
	for i, c := range canaries {
		if c.conns.Load() != 0 {
			t.Errorf("canary %d: an out-of-scope address returned by Shodan was contacted", i)
		}
	}
}

// Identifiers are recorded even where nothing can be searched. Shodan searches need paid credits,
// so the procedure is left out of the output without the key.
func TestIdentifierPivot_UnlistedWithoutKey(t *testing.T) {
	t.Parallel()
	x, _, _, _ := pivotWorld(t)
	x.h.setKey("shodan", "")
	x.mustRun()
	assertUnlisted(t, x.world, "identifier-pivot")
	if n := len(x.queries()); n != 0 {
		t.Errorf("%d searches without a key", n)
	}
	if a, _, f, _ := x.ids("http://www.example.com"); a != "G-AAAAAA1" || f != hash100 {
		t.Errorf("analytics = %q, favicon = %q: identifiers must still be recorded", a, f)
	}
}

// The cap is in searches. The rest wait for later runs, which never repeat one.
func TestIdentifierPivot_PerRunCapDefersTheRest(t *testing.T) {
	t.Parallel()
	x, _, _, _ := pivotWorld(t)
	x.mustRun("--identifier-pivot-max-queries", "1")
	if got := x.queries(); !slices.Equal(got, []string{qFavicon}) {
		t.Fatalf("first run searches = %v, want only %s", got, qFavicon)
	}
	if n := deferredOf(t, x.h, "identifier-pivot"); n != 2 {
		t.Errorf("deferred = %d, want 2", n)
	}
	x.mustRun("--identifier-pivot-max-queries", "1")
	x.mustRun("--identifier-pivot-max-queries", "1")
	if got := x.queries(); !slices.Equal(got, []string{qFavicon, qPixel, qGA}) {
		t.Errorf("searches over three runs = %v, want each once, in order", got)
	}
	if n := deferredOf(t, x.h, "identifier-pivot"); n != 0 {
		t.Errorf("deferred after the last = %d, want 0", n)
	}
}

// A search with more than 200 hosts is a shared or common identifier: nothing is recorded.
func TestIdentifierPivot_TooManyHostsRecordsNothing(t *testing.T) {
	t.Parallel()
	x, f, _, _ := pivotWorld(t)
	f.set(qGA, searchJSON(201, hit("198.51.100.10", "sister.example.com", "brand.other-brand.co.uk")))
	x.mustRun()
	if got := sorted(x.queries()); !slices.Equal(got, sorted([]string{qFavicon, qPixel, qGA})) {
		t.Errorf("searches = %v", got)
	}
	if row := find(x.table(eng, "ips.csv"), "ip", "198.51.100.10"); row != nil {
		t.Errorf("an address from a search of 201 hosts was recorded: %v", row)
	}
	if got := x.candidate("other-brand.co.uk"); got != nil {
		t.Errorf("a candidate came from a search of 201 hosts: %v", got)
	}
	if slices.Contains(x.observedBy("hostname", "identifier-pivot"), "sister.example.com") {
		t.Error("a hostname came from a search of 201 hosts")
	}
	if w := x.warnings(); !strings.Contains(w, "identifier-pivot") || !strings.Contains(w, "G-AAAAAA1") || !strings.Contains(w, "201") {
		t.Errorf("warnings = %q, want one naming the identifier and 201", w)
	}
	// Exactly 200 is fine.
	x2, f2, _, _ := pivotWorld(t)
	f2.set(qGA, searchJSON(200, hit("198.51.100.10", "sister.example.com")))
	x2.mustRun()
	if row := find(x2.table(eng, "ips.csv"), "ip", "198.51.100.10"); row == nil {
		t.Error("an address from a search of exactly 200 hosts was not recorded")
	}
}

// A key without search access fails the procedure once, with one warning.
func TestIdentifierPivot_KeyWithoutSearchAccess(t *testing.T) {
	t.Parallel()
	x, f, _, _ := pivotWorld(t)
	f.failAll(403)
	// A key that is refused (or not entitled to the search) is not cured by waiting.
	if e := x.h.partial(x.run("--concurrency", "1"), true); e.transient || !strings.Contains(e.msg, "identifier-pivot") {
		t.Errorf("error = %+v, want a failure of identifier-pivot that is not transient", e)
	}
	if got := x.queries(); len(got) != 1 {
		t.Errorf("searches after a 403 = %v, want the procedure aborted after the first", got)
	}
	if st, _ := x.procedureState("identifier-pivot"); st != "failed" {
		t.Errorf("identifier-pivot = %s, want failed", st)
	}
	if got := x.completedKeys("identifier-pivot"); len(got) != 0 {
		t.Errorf("completed = %v, want nothing", got)
	}
	n := 0
	for _, m := range x.h.messages("warning", "") {
		if strings.Contains(m, "identifier-pivot") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d warnings name identifier-pivot, want exactly one: %q", n, x.warnings())
	}
}

// Credit exhaustion preserves completed searches and defers refused/unsent searches to the next
// run.
func TestIdentifierPivot_NoCreditsStopsTheProcedure(t *testing.T) {
	t.Parallel()
	x, f, _, _ := pivotWorld(t)
	f.fail(qPixel, 402)
	// Spent credits come back with time: the error is transient.
	if e := x.h.partial(x.run("--concurrency", "1"), true); !e.transient || !strings.Contains(e.msg, "identifier-pivot") {
		t.Errorf("error = %+v, want a transient failure of identifier-pivot", e)
	}
	if got := x.queries(); !slices.Equal(got, []string{qFavicon, qPixel}) {
		t.Fatalf("searches = %v, want the procedure stopped at the refused one", got)
	}
	// One search finished, so the procedure is done with a failure, not failed.
	if ev := lastState(x.h.events(), "identifier-pivot"); ev.num("failed") == 0 {
		t.Errorf("identifier-pivot event = %v, want failed jobs", ev)
	}
	if got := x.completedKeys("identifier-pivot"); !slices.Equal(got, []string{"favicon|" + hash100}) {
		t.Errorf("completed = %v, want only the favicon search", got)
	}

	f.fail(qPixel, 0)
	x.mustRun("--concurrency", "1")
	if got := x.queries(); !slices.Equal(got, []string{qFavicon, qPixel, qPixel, qGA}) {
		t.Errorf("searches over both runs = %v, want the refused one repeated and the last one sent", got)
	}
	if st, _ := x.procedureState("identifier-pivot"); st != "done" {
		t.Errorf("identifier-pivot = %s, want done", st)
	}
}

// Under --passive nothing is collected, but identifiers kept from an earlier run are searched.
func TestIdentifierPivot_PassivePivotsStoredIdentifiers(t *testing.T) {
	t.Parallel()
	x, _, _, sites := pivotWorld(t)
	x.h.setKey("shodan", "")
	x.mustRun() // records the identifiers; nothing to search with
	hits := func() (n int) {
		for _, s := range sites {
			n += s.hits()
		}
		return n
	}
	before := hits()
	x.h.setKey("shodan", shodanKey)
	if code := x.passive(); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := sorted(x.queries()); !slices.Equal(got, sorted([]string{qFavicon, qPixel, qGA})) {
		t.Errorf("a passive run searched %v, want every stored identifier", got)
	}
	if st, _ := x.procedureState("identifier-pivot"); st != "done" {
		t.Errorf("identifier-pivot = %s, want done under --passive", st)
	}
	if hits() != before {
		t.Errorf("a passive run sent %d requests to the web services", hits()-before)
	}
	if a, _, f, _ := x.ids("http://www.example.com"); a != "G-AAAAAA1" || f != hash100 {
		t.Errorf("the stored identifiers were lost: %q, %q", a, f)
	}
}

// A passive run of a fresh engagement collects no identifiers: the probe and the crawl do not run.
func TestIdentifierPivot_PassiveCollectsNothing(t *testing.T) {
	t.Parallel()
	x, _, _, _ := pivotWorld(t)
	x.mustPassive()
	if got := x.queries(); len(got) != 0 {
		t.Errorf("searches = %v, want none with nothing recorded", got)
	}
	if got := x.observedBy("web_identifier", "httpprobe"); len(got) != 0 {
		t.Errorf("--passive collected identifiers: %v", got)
	}
}

// An engagement probed before identifiers existed has none until httpprobe and
// crawl are redone, and a plain re-run sends nothing.
func TestIdentifiers_ExistingEngagementGainsThemOnlyAfterRedo(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	s := x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": page(homePage), "/about": page(aboutPage), "/favicon.ico": icon("image/x-icon", iconOf(100))}))
	x.mustRun()
	db := x.h.openDB(eng)
	for _, q := range []string{"DELETE FROM observations WHERE kind='web_identifier'", "DELETE FROM records WHERE kind='web_identifier'"} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	before := s.hits()
	x.mustRun()
	if s.hits() != before {
		t.Errorf("a plain re-run sent %d requests", s.hits()-before)
	}
	if a, p, f, c := x.ids("http://www.example.com"); a != "" || p != "" || f != "" || c != "" {
		t.Errorf("identifiers without a redo = %q %q %q %q, want blank", a, p, f, c)
	}
	x.mustRun("--redo", "httpprobe")
	if a, p, f, c := x.ids("http://www.example.com"); a != "G-AAAAAA1" || p != "" || f != hash100 || c != "© 2026 Acme Pty Ltd" {
		t.Errorf("after redoing httpprobe = %q %q %q %q, want what the root page and icon give", a, p, f, c)
	}
	x.mustRun("--redo", "crawl")
	if a, p, _, _ := x.ids("http://www.example.com"); a != "G-AAAAAA1;GTM-ABCD123" || p != "111111111" {
		t.Errorf("after redoing crawl = %q %q, want the identifiers of the other pages too", a, p)
	}
}
