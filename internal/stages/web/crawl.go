package web

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/cloudstorage"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/weburl"
)

// urlsPerPage bounds recorded URLs relative to page budget, preventing calendars/faceted search
// from flooding output.
const urlsPerPage = 20

// Crawl performs a breadth-first GET-only walk within one service origin. It reads robots.txt
// and sitemaps as URL sources without applying robots exclusion rules or submitting forms.
type Crawl struct{}

// NewCrawl returns the crawl stage.
func NewCrawl() *Crawl { return &Crawl{} }

func (*Crawl) Name() string { return "crawl" }

// CandidateSources: the crawl is a family of its own.
func (*Crawl) CandidateSources() map[string]string { return map[string]string{"crawl": "crawl"} }
func (*Crawl) Contact() run.Contact                { return run.Target }
func (*Crawl) Sources() []string                   { return nil }

// Configured: crawl.max_pages 0 turns the crawl off.
func (*Crawl) Configured(e run.Env) (bool, string) {
	if e.Settings.Crawl.MaxPages == 0 {
		return false, "disabled"
	}
	return true, ""
}

// Evidence identifies the crawled service independently of limit-bearing check keys, so limit
// changes do not count as new candidate support.
func (*Crawl) Evidence(checkKey string) (source, item string) {
	item, _, _ = strings.Cut(checkKey, "|")
	return "crawl", item
}

type crawlInput struct {
	sc            *scope.Scope
	host, scheme  string
	port          int
	depth, pages  int
	origin, start string
}

// Checks versions each in-scope current service by crawl limits so changing limits creates new
// work.
func (*Crawl) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		set := v.Settings().Crawl
		for _, ws := range v.WebServices() { // in key order
			svc := ws.Svc
			in := crawlInput{sc: v.Scope(), host: svc.Host, scheme: svc.Scheme, port: svc.Port, depth: set.MaxDepth, pages: set.MaxPages, origin: ws.Key}
			in.start, _ = weburl.NormaliseURL(ws.Key + "/")
			key := fmt.Sprintf("%s|depth=%d|pages=%d", ws.Key, set.MaxDepth, set.MaxPages)
			if !yield(run.Check{Key: key, Input: in}, nil) {
				return
			}
		}
	}
}

type recordedURL struct {
	url, host string
	status    int
}

type queued struct {
	url   string
	depth int
}

type crawler struct {
	ctx context.Context
	in  crawlInput
	e   egress.Clients

	gets     int
	visited  map[string]bool
	recorded map[string]int
	urls     []recordedURL
	hosts    map[string]bool
	queue    []queued
	anchor   egress.Response // a same-origin response, the base egress.Link resolves from

	storage     map[string]*storageRef // "page|url" -> reference, for the cloud-storage checks
	storageKeys []string               // in first-seen order

	scripts map[string]bool // normalised URLs of the <script src> elements seen, on any host

	ids *identifierSet // the identifiers the scanned pages name
}

// storageRef is a storage URL a page links to or loads.
type storageRef struct {
	ref       cloudstorage.Ref
	url, page string
	via       string // "link" for an <a> or <area>, else "asset"
}

// Run fails only when the root fetch errors; other page failures are skipped.
func (*Crawl) Run(ctx context.Context, chk run.Check, e egress.Clients) ([]run.Observation, error) {
	in := chk.Input.(crawlInput)
	c := &crawler{ctx: ctx, in: in, e: e, visited: map[string]bool{in.start: true}, recorded: map[string]int{}, hosts: map[string]bool{}, storage: map[string]*storageRef{}, scripts: map[string]bool{}, ids: newIdentifierSet(in.origin, in.host, newObsSet())}
	c.record(in.start)
	root, scan, err := c.fetchPage(egress.Root(in.host, in.scheme, in.port), in.start)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", chk.Key, err)
	}
	if !scan { // not answering, or the root moved to another origin, which has its own crawl
		return c.observations(), nil
	}
	// egress.Link only needs where the root came from, not its body.
	c.anchor = root
	c.anchor.Body, c.anchor.Header, c.anchor.PeerCerts = nil, nil, nil
	robots, _ := weburl.NormaliseURL(in.origin + "/robots.txt")
	sitemap, _ := weburl.NormaliseURL(in.origin + "/sitemap.xml")
	c.visited[robots], c.visited[sitemap] = true, true // read as lists below, not crawled as pages
	c.scan(root, 0)
	c.readLists(robots, sitemap)
	for len(c.queue) > 0 && c.gets < in.pages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q := c.queue[0]
		c.queue = c.queue[1:]
		req, err := egress.Link(c.anchor, q.url)
		if err != nil {
			continue
		}
		resp, scan, err := c.fetchPage(req, q.url)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			continue
		}
		if scan {
			c.scan(resp, q.depth)
		}
	}
	return c.observations(), nil
}

// fetchPage follows same-origin redirects, charging each GET to the page limit. External
// redirects are recorded without fetching. scan is true only when a page answered on this
// origin.
func (c *crawler) fetchPage(req egress.Request, page string) (resp egress.Response, scan bool, err error) {
	for hop := 0; ; hop++ {
		c.gets++
		res, err := c.e.HTTP.Get(c.ctx, req)
		if err != nil {
			return resp, false, err
		}
		r, live := res.(egress.Response)
		if !live {
			return resp, false, nil
		}
		resp = r
		c.setStatus(page, r.Status)
		if !isRedirect(r.Status) || r.Location == "" || hop >= maxHops {
			return resp, true, nil
		}
		target, tok := redirectTarget(r)
		if !tok {
			return resp, true, nil
		}
		c.record(target)
		if originOf(target) != c.in.origin {
			return resp, false, nil
		}
		if c.visited[target] || c.gets >= c.in.pages {
			return resp, true, nil
		}
		c.visited[target] = true
		if req, err = egress.Redirect(r); err != nil {
			return resp, true, nil //nolint:nilerr // a redirect that cannot be followed ends the crawl of this page, which is a result, not a failure
		}
		page = target
	}
}

// scan records the links of an HTML page and queues the followable ones.
func (c *crawler) scan(resp egress.Response, depth int) {
	if resp.ContentType() != "text/html" {
		return
	}
	pg, ok := parsePage(resp.Body)
	if !ok {
		return
	}
	c.ids.source(resp.Body)
	if depth == 0 { // the root page
		c.ids.add(kinds.IdentifierCopyright, pg.copyright())
	}
	base, err := url.Parse(resp.URL())
	if err != nil {
		return
	}
	l := pg.links()
	base = withBase(base, l.base)
	absolute := func(href string) (string, bool) {
		t, err := base.Parse(href)
		if err != nil {
			return "", false
		}
		return weburl.NormaliseURL(t.String())
	}
	handle := func(href string, follow bool) {
		abs, ok := absolute(href)
		if !ok {
			return
		}
		c.record(abs)
		if follow {
			c.enqueue(abs, depth+1)
		}
	}
	for _, h := range l.follow {
		handle(h, true)
	}
	for _, h := range l.record {
		handle(h, false)
	}
	pageURL, _ := weburl.NormaliseURL(resp.URL())
	for _, r := range l.refs {
		abs, ok := absolute(r.url)
		if !ok {
			continue
		}
		c.storageRef(abs, r.tag, pageURL)
		if r.tag == "script" {
			c.scriptRef(abs)
		}
	}
}

// scriptRef records loaded script URLs, including external hosts, without fetching them.
// jsparse later selects in-scope scripts.
func (c *crawler) scriptRef(abs string) {
	if len(c.scripts) < urlsPerPage*c.in.pages {
		c.scripts[abs] = true
	}
}

// enqueue admits unseen, non-static same-origin URLs within depth/page limits.
func (c *crawler) enqueue(abs string, depth int) {
	if depth > c.in.depth || originOf(abs) != c.in.origin || c.visited[abs] || len(c.queue)+c.gets >= c.in.pages {
		return
	}
	if u, err := url.Parse(abs); err != nil || weburl.IsStaticAsset(u.Path) {
		return
	}
	c.visited[abs] = true
	c.queue = append(c.queue, queued{abs, depth})
}

// storageRef records cloud references even outside scope because they may attribute storage to
// the target. It sends no request.
func (c *crawler) storageRef(abs, tag, page string) {
	if page == "" {
		return
	}
	ref, ok := cloudstorage.ParseRef(abs)
	if !ok {
		return
	}
	via := "asset"
	if tag == "a" || tag == "area" {
		via = "link"
	}
	key := page + "|" + abs
	if prev, seen := c.storage[key]; seen {
		if via == "asset" {
			prev.via = via // a browser loading it matters more than a link to it
		}
		return
	}
	c.storage[key] = &storageRef{ref: ref, url: abs, page: page, via: via}
	c.storageKeys = append(c.storageKeys, key)
}

// record saves in-scope URLs within the cap and different in-scope hostname references,
// ignoring external hosts.
func (c *crawler) record(abs string) {
	if _, seen := c.recorded[abs]; seen { // its host was handled when it was first recorded
		return
	}
	host := weburl.HostOfURL(abs)
	if !c.in.sc.WebHostInScope(host) {
		return
	}
	if len(c.urls) < urlsPerPage*c.in.pages {
		c.recorded[abs] = len(c.urls)
		c.urls = append(c.urls, recordedURL{url: abs, host: host})
	}
	if d, ok := otherHost(host, c.in.host); ok {
		c.hosts[d] = true
	}
}

func (c *crawler) setStatus(page string, status int) {
	if i, ok := c.recorded[page]; ok {
		c.urls[i].status = status
	}
}

func (c *crawler) observations() []run.Observation {
	var out []run.Observation
	for _, u := range c.urls {
		out = append(out, kinds.URL.Obs(u.url, kinds.URLAttrs{URL: u.url, Host: u.host, Status: u.status}))
	}
	for _, h := range slices.Sorted(maps.Keys(c.hosts)) {
		out = append(out, kinds.Hostname.Obs(h, kinds.HostnameAttrs{}))
	}
	for _, k := range c.storageKeys {
		out = append(out, storageObservation(*c.storage[k]))
	}
	for _, u := range slices.Sorted(maps.Keys(c.scripts)) {
		out = append(out, kinds.Script.Obs(u, kinds.ScriptAttrs{URL: u, Host: weburl.HostOfURL(u), Service: c.in.origin}))
	}
	return append(out, c.ids.obs.list...)
}

// originOf is the origin of a normalised absolute URL, in Origin's form.
func originOf(abs string) string {
	u, err := url.Parse(abs)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + egress.HostPort(u.Scheme, strings.ToLower(u.Hostname()), u.Port())
}

// storageObservation keys a reference by its source page and destination URL.
func storageObservation(r storageRef) run.Observation {
	return kinds.StorageRef.Obs(r.page+"|"+r.url, kinds.StorageRefAttrs{
		Provider: r.ref.Provider, Name: r.ref.Name, Container: r.ref.Container, Object: r.ref.Object,
		URL: r.url, Page: r.page, PageHost: weburl.HostOfURL(r.page), Via: r.via,
	})
}
