package web

import (
	"bytes"
	"net/url"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

const maxTitleRunes = 200

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

// firstText is the text of the first element match accepts, in document order,
// with whitespace collapsed and invalid UTF-8 replaced; "" if there is none.
func (p page) firstText(match func(*html.Node) bool) string {
	for n := range p.doc.Descendants() {
		if n.Type == html.ElementNode && match(n) {
			var b strings.Builder
			for t := range n.Descendants() {
				if t.Type == html.TextNode {
					b.WriteString(t.Data)
				}
			}
			return collapse(b.String())
		}
	}
	return ""
}

// collapse collapses the whitespace of text and replaces invalid UTF-8.
func collapse(s string) string {
	return strings.Join(strings.Fields(strings.ToValidUTF8(s, "�")), " ")
}

// cutRunes is s cut to at most n runes.
func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) > n {
		return string([]rune(s)[:n])
	}
	return s
}

// withBase is what relative references in a page at u resolve against, as a
// browser does: the page's first <base href> (baseHref) resolved against u, if
// that is an http or https URL, else u.
func withBase(u *url.URL, baseHref string) *url.URL {
	if baseHref != "" {
		if b, err := u.Parse(baseHref); err == nil && (b.Scheme == "http" || b.Scheme == "https") {
			return b
		}
	}
	return u
}

// title is the first <title>, with whitespace collapsed, invalid UTF-8
// replaced and at most 200 runes.
func (p page) title() string {
	return cutRunes(p.firstText(func(n *html.Node) bool { return n.Data == "title" }), maxTitleRunes)
}

// links are the references in a page, in document order. follow holds the ones
// the crawl may fetch (a[href], area[href], iframe[src]); record holds the ones
// it only records (link[href], script[src], form[action]). base is the first
// base[href], which relative references resolve against, or "".
type links struct {
	follow, record []string
	base           string
	// refs is every URL-bearing attribute of an a, area, link, script, img,
	// iframe, source or form element, with its element, for storage references.
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
