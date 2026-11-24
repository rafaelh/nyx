package web

import (
	"maps"
	"slices"
	"strings"

	"golang.org/x/net/html"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// hop stores response data for posture checks and shares one parsed page with title and
// directory-listing readers.
type hop struct {
	https  bool
	origin string              // scheme://host[:port], in Origin's form
	header map[string][]string // canonical keys, as a real response has them
	body   []byte
	isHTML bool

	resp egress.Response // the response the hop was built from, for egress.Link; zero for hopAt

	pg     page
	pgOK   bool
	parsed bool
}

func newHop(r egress.Response) *hop {
	h := hopAt(r.URL(), r.ContentType(), r.Header, r.Body)
	h.resp = r
	return h
}

// hopAt creates posture input for a URL/media-type pair.
func hopAt(url, contentType string, header map[string][]string, body []byte) *hop {
	return &hop{https: strings.HasPrefix(url, "https://"), origin: originOf(url), header: header, body: body, isHTML: contentType == "text/html"}
}

// page is the parsed body of an HTML response.
func (h *hop) page() (page, bool) {
	if !h.isHTML {
		return page{}, false
	}
	if !h.parsed {
		h.pg, h.pgOK = parsePage(h.body)
		h.parsed = true
	}
	return h.pg, h.pgOK
}

// posture uses only already-received redirect-chain responses. The first response supplies HSTS
// and version banners; HSTS applies only over HTTPS. All responses contribute cookie names and
// HttpOnly state; Secure is judged only over HTTPS. Cookie values are discarded. Directory
// evidence comes from the last same-origin page.
func posture(host string, chain []*hop) kinds.WebPostureAttrs {
	first := chain[0]
	a := kinds.WebPostureAttrs{Host: host}
	if first.https {
		has := strings.TrimSpace(strings.Join(first.header["Strict-Transport-Security"], "")) != ""
		a.HSTS = &has
	}
	noSecure, noHTTPOnly := map[string]bool{}, map[string]bool{}
	for _, h := range chain {
		for _, line := range h.header["Set-Cookie"] {
			name, secure, httpOnly, ok := parseSetCookie(line)
			if !ok {
				continue
			}
			if !secure && h.https {
				noSecure[name] = true
			}
			if !httpOnly {
				noHTTPOnly[name] = true
			}
		}
	}
	a.CookiesNoSecure = strings.Join(slices.Sorted(maps.Keys(noSecure)), ";")
	a.CookiesNoHTTPOnly = strings.Join(slices.Sorted(maps.Keys(noHTTPOnly)), ";")
	a.DirectoryListing = lastSameOrigin(chain).isDirectoryListing()
	a.VersionDisclosure = versionHeaders(first)
	return a
}

// parseSetCookie returns a sanitised cookie name and Secure/HttpOnly flags, discarding values.
// Lines without name=value are ignored.
func parseSetCookie(line string) (name string, secure, httpOnly, ok bool) {
	pair, attrs, _ := strings.Cut(line, ";")
	name, _, hasValue := strings.Cut(pair, "=")
	name = strings.TrimSpace(sanitize.Text(name))
	if !hasValue || name == "" {
		return "", false, false, false
	}
	for attr := range strings.SplitSeq(attrs, ";") {
		key, _, _ := strings.Cut(attr, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "secure":
			secure = true
		case "httponly":
			httpOnly = true
		}
	}
	return name, secure, httpOnly, true
}

// lastSameOrigin selects the final response on the initial origin.
func lastSameOrigin(chain []*hop) *hop {
	return lastWhere(chain, func(h *hop) bool { return h.origin == chain[0].origin })
}

// lastWhere finds the final accepted redirect response, falling back to the first.
func lastWhere(chain []*hop, same func(*hop) bool) *hop {
	for i := len(chain) - 1; i > 0; i-- {
		if same(chain[i]) {
			return chain[i]
		}
	}
	return chain[0]
}

const listingPrefix = "Index of /"

// isDirectoryListing recognises automatic "Index of /" listings in HTML titles or first
// headings.
func (h *hop) isDirectoryListing() bool {
	pg, ok := h.page()
	if !ok {
		return false
	}
	isHeading := func(n *html.Node) bool {
		return len(n.Data) == 2 && n.Data[0] == 'h' && n.Data[1] >= '1' && n.Data[1] <= '6'
	}
	return strings.HasPrefix(pg.title(), listingPrefix) || strings.HasPrefix(pg.firstText(isHeading), listingPrefix)
}

// versionHeaders keeps semicolon-joined Server/X-Powered-By values containing slash-digit
// version syntax.
func versionHeaders(h *hop) string {
	var out []string
	for _, name := range []string{"Server", "X-Powered-By"} {
		for _, v := range h.header[name] {
			if v = strings.TrimSpace(sanitize.Text(v)); hasVersion(v) && !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
	}
	return strings.Join(out, ";")
}

func hasVersion(v string) bool {
	for i := 0; i+1 < len(v); i++ {
		if v[i] == '/' && v[i+1] >= '0' && v[i+1] <= '9' {
			return true
		}
	}
	return false
}
