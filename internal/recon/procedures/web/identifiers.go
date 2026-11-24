package web

import (
	"bytes"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/html"

	"github.com/rafaelh/nyx/internal/knowledge/webpage"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/term/sanitize"
)

// maxCopyrightRunes is the longest copyright line recorded.
const maxCopyrightRunes = 120

// Identifier patterns require tracker installation syntax and word boundaries, so loose
// mentions and prefixes of longer tokens do not count as installed IDs.
const (
	analyticsID = `(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{4,10})\b`
	pixelID     = `(\d{6,20})\b`
)

var (
	// A gtag.js or Tag Manager loader URL, or the Tag Manager noscript frame.
	analyticsLoader = regexp.MustCompile(`(?:gtag/js|googletagmanager\.com/(?:gtm\.js|ns\.html))\?id=` + analyticsID)
	// gtag('config', 'G-XXXXXXXXXX')
	analyticsConfig = regexp.MustCompile(`gtag\(\s*['"]config['"]\s*,\s*['"]` + analyticsID + `['"]`)
	// The Tag Manager snippet: (window,document,'script','dataLayer','GTM-XXXX')
	analyticsSnippet = regexp.MustCompile(`['"]script['"]\s*,\s*['"][\w$]+['"]\s*,\s*['"](GTM-[A-Z0-9]{4,10})['"]`)
	// fbq('init', '1234567890')
	pixelInit = regexp.MustCompile(`fbq\(\s*['"]init['"]\s*,\s*['"]` + pixelID + `['"]`)
	// The pixel's noscript image: facebook.com/tr?id=1234567890
	pixelImage = regexp.MustCompile(`facebook\.com/tr/?\?id=` + pixelID)

	// Match a copyright mark and year on one line, with the year before or after the
	// holder.
	copyrightMark = regexp.MustCompile(`(?i)(?:©|\(c\)).*?\b(?:19|20)\d\d\b`)
)

// extractIdentifiers finds installed Google Analytics/Tag Manager and Facebook pixel IDs,
// returning each group sorted and unique.
func extractIdentifiers(body []byte) (analytics, pixels []string) {
	// Skip regex work when none of the group's required literal hints occurs in the page.
	if containsAny(body, "gtag", "googletagmanager", "GTM-") {
		analytics = findAll(body, analyticsLoader, analyticsConfig, analyticsSnippet)
	}
	if containsAny(body, "fbq", "facebook.com/tr") {
		pixels = findAll(body, pixelInit, pixelImage)
	}
	return analytics, pixels
}

func containsAny(body []byte, hints ...string) bool {
	for _, h := range hints {
		if bytes.Contains(body, []byte(h)) {
			return true
		}
	}
	return false
}

// findAll returns sorted, unique first-capture matches across patterns.
func findAll(body []byte, patterns ...*regexp.Regexp) []string {
	var out []string
	for _, re := range patterns {
		for _, m := range re.FindAllSubmatch(body, -1) {
			out = append(out, string(m[1]))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// skippedText are the elements whose text a reader does not see.
var skippedText = map[string]bool{"script": true, "style": true, "noscript": true, "template": true, "head": true, "title": true}

// lineBreaks identifies block/line-break elements for visible-text extraction.
var lineBreaks = map[string]bool{
	"br": true, "address": true, "article": true, "aside": true, "blockquote": true, "dd": true, "div": true, "dl": true, "dt": true,
	"fieldset": true, "figcaption": true, "figure": true, "footer": true, "form": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"h5": true, "h6": true, "header": true, "hr": true, "li": true, "main": true, "nav": true, "ol": true, "p": true, "pre": true,
	"section": true, "table": true, "td": true, "th": true, "tr": true, "ul": true,
}

// visibleLines joins inline text and breaks at block/line-break elements. It collapses
// whitespace, replaces invalid UTF-8 and drops empty lines.
func (p page) visibleLines() []string {
	var lines []string
	var cur strings.Builder
	flush := func() {
		if s := webpage.Collapse(cur.String()); s != "" {
			lines = append(lines, s)
		}
		cur.Reset()
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.TextNode:
			cur.WriteString(n.Data)
		case html.ElementNode:
			if skippedText[n.Data] {
				return
			}
			if lineBreaks[n.Data] {
				flush()
				defer flush()
			}
		default:
			// Other nodes hold no text of their own, only children.
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(p.doc)
	flush()
	return lines
}

// copyright returns the first visible copyright/year line, sanitised and capped at 120
// characters, or "".
func (p page) copyright() string {
	for _, line := range p.visibleLines() {
		if copyrightMark.MatchString(line) {
			return strings.TrimSpace(webpage.CutRunes(sanitize.Text(line), maxCopyrightRunes))
		}
	}
	return ""
}

// identifierSet deduplicates identifier observations for one service.
type identifierSet struct {
	service, host string
	obs           *obsSet
}

func newIdentifierSet(service, host string, obs *obsSet) *identifierSet {
	return &identifierSet{service: service, host: host, obs: obs}
}

// add records one identifier of the service.
func (s *identifierSet) add(typ, value string) {
	if value != "" {
		s.obs.add(kinds.WebIdentifier.Obs(kinds.WebIdentifierAttrs{Service: s.service, Host: s.host, Type: typ, Value: value}))
	}
}

// source reads the tracking IDs in a page's source.
func (s *identifierSet) source(body []byte) {
	analytics, pixels := extractIdentifiers(body)
	for _, id := range analytics {
		s.add(kinds.IdentifierAnalytics, id)
	}
	for _, id := range pixels {
		s.add(kinds.IdentifierPixel, id)
	}
}

// chain extracts identifiers from same-origin redirect pages and copyright from the last such
// page.
func (s *identifierSet) chain(chain []*hop) {
	for _, h := range chain {
		if h.isHTML && h.origin == chain[0].origin {
			s.source(h.body)
		}
	}
	if pg, ok := lastSameOrigin(chain).page(); ok {
		s.add(kinds.IdentifierCopyright, pg.copyright())
	}
}
