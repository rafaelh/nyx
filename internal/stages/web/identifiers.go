package web

import (
	"bytes"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/net/html"

	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// maxCopyrightRunes is the longest copyright line recorded.
const maxCopyrightRunes = 120

// The shapes of the identifiers. Each is read only in one of the contexts a
// tracker is installed in, never from loose text: a page that merely mentions
// "UA-12345678-1" does not use it. Each ends at a word boundary, so that a longer
// token is not read as the ID that is its first characters.
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

	// A copyright mark with a year after it on the same line, next to it ("© 2026
	// Acme") or after the holder's name ("© Acme Pty Ltd 2026").
	copyrightMark = regexp.MustCompile(`(?i)(?:©|\(c\)).*?\b(?:19|20)\d\d\b`)
)

// extractIdentifiers returns the Google Analytics and Tag Manager IDs and the
// Facebook pixel IDs a page's source names in the contexts a tracker is
// installed in, each sorted and without repeats.
func extractIdentifiers(body []byte) (analytics, pixels []string) {
	// Every match of a group's patterns contains one of its hints, so a page with
	// none of them, as most pages are, is not scanned by the patterns.
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

// findAll is the first group of every match of any of the patterns, sorted, without repeats.
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

// lineBreaks are the elements that start and end a line of text, as a browser
// lays them out.
var lineBreaks = map[string]bool{
	"br": true, "address": true, "article": true, "aside": true, "blockquote": true, "dd": true, "div": true, "dl": true, "dt": true,
	"fieldset": true, "figcaption": true, "figure": true, "footer": true, "form": true, "h1": true, "h2": true, "h3": true, "h4": true,
	"h5": true, "h6": true, "header": true, "hr": true, "li": true, "main": true, "nav": true, "ol": true, "p": true, "pre": true,
	"section": true, "table": true, "td": true, "th": true, "tr": true, "ul": true,
}

// visibleLines are the lines of the page's visible text, as a browser would lay
// them out: text runs together across inline elements, and a line break element
// starts a new line. Whitespace is collapsed and invalid UTF-8 replaced; empty
// lines are left out.
func (p page) visibleLines() []string {
	var lines []string
	var cur strings.Builder
	flush := func() {
		if s := collapse(cur.String()); s != "" {
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
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(p.doc)
	flush()
	return lines
}

// copyright is the first line of the page's visible text that has a copyright
// mark, "©" or "(c)", followed by a year: sanitised and cut to 120 characters. It
// is "" if there is none.
func (p page) copyright() string {
	for _, line := range p.visibleLines() {
		if copyrightMark.MatchString(line) {
			return strings.TrimSpace(cutRunes(sanitize.Text(line), maxCopyrightRunes))
		}
	}
	return ""
}

// identifierSet collects the web_identifier observations of one web service
// into an obsSet, which drops repeats.
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
		s.obs.add(kinds.WebIdentifier.Obs(s.service+"|"+typ+"|"+value,
			kinds.WebIdentifierAttrs{Service: s.service, Host: s.host, Type: typ, Value: value}))
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

// chain reads the pages of a probe's redirect chain that the service's own origin
// served, and the copyright line of the last of them, the root page the service
// ends on.
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
