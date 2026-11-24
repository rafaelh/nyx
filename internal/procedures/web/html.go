package web

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/rafaelh/nyx/internal/webpage"
	"golang.org/x/net/html"
)

// page is a parsed text/html body.
type page struct{ doc *html.Node }

func parsePage(body []byte) (page, bool) {
	doc, err := html.Parse(bytes.NewReader(body))
	return page{doc}, err == nil
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

// firstText is the text of the first element match accepts (webpage.FirstText).
func (p page) firstText(match func(*html.Node) bool) string { return webpage.FirstText(p.doc, match) }

// withBase resolves the first base href against the page URL when it yields HTTP(S), otherwise
// retaining the page URL.
func withBase(u *url.URL, baseHref string) *url.URL {
	if baseHref != "" {
		if b, err := u.Parse(baseHref); err == nil && (b.Scheme == "http" || b.Scheme == "https") {
			return b
		}
	}
	return u
}

// title is the first <title>, by the rule of webpage.Title.
func (p page) title() string { return webpage.TitleOf(p.doc) }

// links preserves document order, separating crawlable links/frames from record-only
// scripts/styles/forms. The first base href controls relative reference resolution.
type links struct {
	follow, record []string
	base           string
	// refs collects URL-bearing attributes with their HTML elements for storage
	// attribution.
	refs []linkRef
}

// linkRef is a URL found in an element of a page.
type linkRef struct{ tag, url string }

func (p page) links() links {
	var l links
	for n := range p.doc.Descendants() {
		if n.Type != html.ElementNode {
			continue
		}
		var dst *[]string
		var key string
		switch n.Data {
		case "base":
			if l.base == "" {
				l.base = attr(n, "href")
			}
			continue
		case "a", "area":
			dst, key = &l.follow, "href"
		case "iframe":
			dst, key = &l.follow, "src"
		case "link":
			dst, key = &l.record, "href"
		case "script":
			dst, key = &l.record, "src"
		case "form":
			dst, key = &l.record, "action"
		case "img", "source":
			key = "src"
		default:
			continue
		}
		if v := attr(n, key); v != "" {
			if dst != nil {
				*dst = append(*dst, v)
			}
			l.refs = append(l.refs, linkRef{tag: n.Data, url: v})
		}
	}
	return l
}
