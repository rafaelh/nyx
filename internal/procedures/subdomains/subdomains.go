// Package subdomains shares root-job enumeration across independent source fetchers. Retired
// OTX/Anubis procedures no longer support unkeyed queries.
package subdomains

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rafaelh/nyx/internal/candidates"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/httpsrc"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/knowledge/weburl"
	"github.com/rafaelh/nyx/internal/run"
)

// maxPages caps archive and API paging inside one job.
const maxPages = 30

// result holds fetched names, shared attributes and optional archive URLs.
type result struct {
	names []string
	attrs kinds.HostnameAttrs
	urls  []string
}

type fetcher func(ctx context.Context, in rootInput, c egress.Clients) (result, error)

// rootInput carries source inputs separately from job keys, which may also encode
// archive/page caps.
type rootInput struct {
	root    string
	maxURLs int
	pages   int  // the paging cap of a procedure with pageCap
	keyed   bool // optional credentials are attached without becoming part of job identity
}

// Procedure is one subdomain source.
type Procedure struct {
	name    string
	family  string // of the candidates it finds; see package candidates
	sources []string
	keyed   bool
	// optionalKey names sources that work without credentials but use configured keys when
	// available.
	optionalKey bool
	archive     bool // also records URLs; its job key carries archive.max_urls
	// pageCap versions paginated jobs so raising the cap repeats them.
	pageCap func(config.Settings) int
	fetch   fetcher
}

// New returns every subdomain procedure in registry order.
func New() []run.Procedure {
	return []run.Procedure{
		&Procedure{name: "crtsh", family: candidates.CertTransparency, sources: []string{"crt.sh"}, fetch: crtsh},
		&Procedure{name: "wayback", family: candidates.WebArchive, sources: []string{"web.archive.org"}, archive: true, fetch: wayback},
		&Procedure{name: "commoncrawl", family: candidates.WebArchive, sources: []string{"index.commoncrawl.org"}, archive: true, fetch: commoncrawl},
		&Procedure{name: "virustotal", family: candidates.PassiveDNS, sources: []string{"www.virustotal.com"}, keyed: true, fetch: virustotal},
		&Procedure{name: "securitytrails", family: candidates.PassiveDNS, sources: []string{"api.securitytrails.com"}, keyed: true, fetch: securitytrails},
		&Procedure{name: "hackertarget", family: candidates.PassiveDNS, sources: []string{"api.hackertarget.com"}, fetch: hackertarget},
		&Procedure{name: "urlscan", family: candidates.PassiveDNS, sources: []string{"urlscan.io"}, fetch: urlscan},
		&Procedure{name: "certspotter", family: candidates.CertTransparency, sources: []string{"api.certspotter.com"}, optionalKey: true,
			pageCap: func(c config.Settings) int { return c.Certspotter.MaxPages }, fetch: certspotter},
		&Procedure{name: "censys", family: candidates.CertTransparency, sources: []string{"api.platform.censys.io"}, keyed: true,
			pageCap: func(c config.Settings) int { return c.Censys.MaxPages }, fetch: censys},
		&Procedure{name: "chaos", family: candidates.PassiveDNS, sources: []string{"dns.projectdiscovery.io"}, keyed: true,
			pageCap: func(c config.Settings) int { return c.Chaos.MaxPages }, fetch: chaos},
	}
}

func (s *Procedure) Name() string         { return s.name }
func (s *Procedure) Contact() run.Contact { return run.ThirdParty }
func (s *Procedure) Sources() []string    { return s.sources }

// CandidateSources declares the procedure's evidence family.
func (s *Procedure) CandidateSources() map[string]string { return map[string]string{s.name: s.family} }

// Configured: keyed sources need keys.<source>.
func (s *Procedure) Configured(e run.Env) (bool, string) {
	return httpsrc.Configured(e, s.name, s.keyed)
}

// Jobs emits in-scope, non-excluded roots. Archive and paged keys include their respective
// caps so changing one limit reruns only affected sources.
func (s *Procedure) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		set := v.Settings()
		in := rootInput{maxURLs: set.Archive.MaxURLs}
		if s.pageCap != nil {
			in.pages = s.pageCap(set)
		}
		if s.optionalKey {
			_, in.keyed = run.Env{Settings: set}.Key(s.name)
		}
		for _, r := range v.InScopeRoots() {
			key := r
			switch {
			case s.archive:
				key = fmt.Sprintf("%s|urls=%d", r, in.maxURLs)
			case s.pageCap != nil:
				key = fmt.Sprintf("%s|pages=%d", r, in.pages)
			}
			in.root = r
			if !yield(run.Job{Key: key, Input: in}, nil) {
				return
			}
		}
	}
}

// Run fetches the root's subdomains and records those under it.
func (s *Procedure) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(rootInput)
	root := in.root
	res, err := s.fetch(ctx, in, e)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", s.name, root, err)
	}
	seen := map[string]bool{}
	var obs []run.Observation
	for _, n := range res.names {
		n = input.CleanName(n)
		if n == "" || seen[n] || !dnsname.Under(n, root) {
			continue
		}
		seen[n] = true
		obs = append(obs, kinds.Hostname.Obs(n, res.attrs))
	}
	slices.SortFunc(obs, func(a, b run.Observation) int { return strings.Compare(a.Key, b.Key) })
	for _, u := range pickURLs(res.urls, root, in.maxURLs) {
		obs = append(obs, kinds.URL.Obs(u.url, kinds.URLAttrs{URL: u.url, Host: u.host}))
	}
	return obs, nil
}

type archivedURL struct{ url, host string }

// pickURLs normalises non-static URLs under root and selects them round-robin across sorted
// hosts. Sorted URLs within each host make capped selection deterministic and prevent one host
// taking every slot.
func pickURLs(raw []string, root string, max int) []archivedURL {
	byHost := map[string][]string{}
	for _, r := range raw {
		u, ok := weburl.NormaliseURL(r)
		if !ok {
			continue
		}
		pu, err := url.Parse(u)
		if err != nil || !dnsname.Under(pu.Hostname(), root) || weburl.IsStaticAsset(pu.Path) {
			continue
		}
		byHost[pu.Hostname()] = append(byHost[pu.Hostname()], u)
	}
	hosts := make([]string, 0, len(byHost))
	for h, l := range byHost {
		slices.Sort(l)
		byHost[h] = slices.Compact(l)
		hosts = append(hosts, h)
	}
	slices.Sort(hosts)
	var out []archivedURL
	for i := 0; len(out) < max; i++ {
		took := false
		for _, h := range hosts {
			if i < len(byHost[h]) && len(out) < max {
				out = append(out, archivedURL{byHost[h][i], h})
				took = true
			}
		}
		if !took {
			break
		}
	}
	return out
}

// --- crt.sh ---

// crtshNames returns the names in a crt.sh JSON answer: name_value holds one or
// more names separated by newlines.
func crtshNames(body []byte) ([]string, error) {
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("unreadable crt.sh response: %w", err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, strings.Split(r.NameValue, "\n")...)
	}
	return out, nil
}

func crtsh(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	body, err := httpsrc.Crtsh(ctx, c, url.Values{"q": {"%." + in.root}})
	if err != nil {
		return result{}, err
	}
	names, err := crtshNames(body)
	return result{names: names}, err
}

// --- Wayback Machine (CDX) ---

// withScheme adds HTTP to scheme-less archive URLs so both host and URL survive parsing.
func withScheme(raw string) string {
	if !strings.Contains(raw, "://") {
		return "http://" + raw
	}
	return raw
}

func wayback(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	root := in.root
	base := url.Values{"url": {root}, "matchType": {"domain"}, "output": {"json"}, "fl": {"original"}, "collapse": {"urlkey"}}
	count := url.Values{"url": {root}, "matchType": {"domain"}, "showNumPages": {"true"}}
	body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: "https://web.archive.org/cdx/search/cdx?" + count.Encode()})
	if err != nil {
		return result{}, err
	}
	pages, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		return result{}, fmt.Errorf("unreadable CDX page count: %w", err)
	}
	pages = min(pages, maxPages)
	var names, urls []string
	for p := range pages {
		q := maps.Clone(base) // shallow is enough: only Set follows
		q.Set("page", strconv.Itoa(p))
		body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: "https://web.archive.org/cdx/search/cdx?" + q.Encode()})
		if err != nil {
			return result{}, err
		}
		var rows [][]string
		if err := json.Unmarshal(body, &rows); err != nil {
			return result{}, fmt.Errorf("unreadable CDX page %d: %w", p, err)
		}
		for i, r := range rows {
			if i == 0 && len(r) > 0 && r[0] == "original" || len(r) == 0 {
				continue
			}
			u := withScheme(r[0])
			names = append(names, weburl.HostOfURL(u))
			urls = append(urls, u)
		}
	}
	return result{names: names, urls: urls}, nil
}

// --- Common Crawl ---

// Common Crawl gateway failures can indicate a slow working index. Retry 502/503/504 responses
// up to ccRetries, honouring bounded Retry-After values or using exponential ccBackoff.
const (
	ccRetries = 3
	ccBackoff = time.Second
	ccMaxWait = 60 * time.Second
)

// errPastLastPage is the index's answer to a page beyond the last.
var errPastLastPage = errors.New("past the last page")

// collection fetches the latest Common Crawl collection once per run for all roots. A fetch
// failure fails each root's job for later retry.
type collection struct {
	once sync.Once
	id   string
	err  error
}

type collectionKey struct{}

func latestCollection(ctx context.Context, c egress.Clients) (string, error) {
	col := run.PerRun(ctx, collectionKey{}, func() *collection { return &collection{} })
	col.once.Do(func() {
		body, err := ccGet(ctx, c, "https://index.commoncrawl.org/collinfo.json")
		if err != nil {
			col.err = err
			return
		}
		var colls []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &colls); err != nil || len(colls) == 0 {
			col.err = errors.New("unreadable Common Crawl collection list")
			return
		}
		col.id = colls[0].ID
	})
	return col.id, col.err
}

// commoncrawl reads pages until the index rejects an out-of-range page or maxPages is reached.
// It skips a separate page-count query because that adds another slow request that can fail.
func commoncrawl(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	root := in.root
	id, err := latestCollection(ctx, c)
	if err != nil {
		return result{}, err
	}
	endpoint := "https://index.commoncrawl.org/" + id + "-index?"
	var names, urls []string
	for p := range maxPages {
		q := url.Values{"url": {"*." + root}, "output": {"json"}, "fl": {"url"}, "page": {strconv.Itoa(p)}}
		body, err := ccGet(ctx, c, endpoint+q.Encode())
		if errors.Is(err, errPastLastPage) {
			break
		}
		// Common Crawl pages contain index blocks, so an empty match page can
		// legitimately return a no-captures 404.
		if errors.Is(err, httpsrc.ErrNotFound) {
			continue
		}
		if err != nil {
			return result{}, err
		}
		for line := range strings.SplitSeq(string(body), "\n") {
			var row struct {
				URL string `json:"url"`
			}
			if line = strings.TrimSpace(line); line != "" && json.Unmarshal([]byte(line), &row) == nil {
				u := withScheme(row.URL)
				names = append(names, weburl.HostOfURL(u))
				urls = append(urls, u)
			}
		}
	}
	return result{names: names, urls: urls, attrs: kinds.HostnameAttrs{Index: id}}, nil
}

// ccGet retries overloaded Common Crawl responses. A specific invalid-page 400 marks
// exhaustion; other responses follow httpsrc.Get error rules.
func ccGet(ctx context.Context, c egress.Clients, u string) ([]byte, error) {
	req := egress.ThirdPartyRequest{Method: "GET", URL: u}
	wait := ccBackoff
	for retry := 0; ; retry++ {
		resp, err := c.ThirdParty.Do(ctx, req)
		if err != nil {
			return nil, err
		}
		switch resp.Status {
		case 502, 503, 504:
			if retry == ccRetries {
				return nil, fmt.Errorf("HTTP %d (index overloaded; gave up after %d retries)", resp.Status, ccRetries)
			}
			d := wait
			if secs, err := strconv.Atoi(resp.HeaderValue("Retry-After")); err == nil && secs >= 0 && secs <= int(ccMaxWait/time.Second) {
				d = time.Duration(secs) * time.Second
			}
			if err := httpsrc.Sleep(ctx, d); err != nil {
				return nil, err
			}
			wait *= 2
			continue
		case 400:
			var m struct {
				Message string `json:"message"`
			}
			if json.Unmarshal(resp.Body, &m) == nil && strings.HasPrefix(m.Message, "Page ") && strings.Contains(m.Message, " invalid") {
				return nil, errPastLastPage
			}
		}
		return httpsrc.Body(req, resp)
	}
}

// --- VirusTotal ---

func virustotal(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	root := in.root
	var names []string
	cursor := ""
	for range maxPages {
		q := url.Values{"limit": {"40"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{
			Method: "GET", URL: "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(root) + "/subdomains?" + q.Encode(),
			KeySource: "virustotal", KeyHeader: "x-apikey",
		})
		// VirusTotal answers 404 NotFoundError for a domain it has no data on.
		if errors.Is(err, httpsrc.ErrNotFound) {
			break
		}
		if err != nil {
			return result{}, err
		}
		var r struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
			Meta struct {
				Cursor string `json:"cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return result{}, fmt.Errorf("unreadable VirusTotal response: %w", err)
		}
		for _, d := range r.Data {
			names = append(names, d.ID)
		}
		if cursor = r.Meta.Cursor; cursor == "" {
			break
		}
	}
	return result{names: names}, nil
}

// --- SecurityTrails ---

func securitytrails(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	root := in.root
	body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{
		Method: "GET", URL: "https://api.securitytrails.com/v1/domain/" + url.PathEscape(root) + "/subdomains?children_only=false&include_inactive=true",
		KeySource: "securitytrails", KeyHeader: "APIKEY",
	})
	if err != nil {
		return result{}, err
	}
	var r struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return result{}, fmt.Errorf("unreadable SecurityTrails response: %w", err)
	}
	return result{names: httpsrc.JoinLabels(root, r.Subdomains)}, nil
}
