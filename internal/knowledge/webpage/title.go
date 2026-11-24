// Package webpage holds pure rules for reading an HTML page.
package webpage

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// maxTitleRunes is the longest title Title returns.
const maxTitleRunes = 200

// Title extracts the first HTML title, collapsing whitespace, replacing invalid UTF-8 and
// limiting runes. Missing titles or parse failures return "".
func Title(body []byte) string {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	return TitleOf(doc)
}

// TitleOf is Title for a page already parsed.
func TitleOf(doc *html.Node) string {
	return CutRunes(FirstText(doc, func(n *html.Node) bool { return n.Data == "title" }), maxTitleRunes)
}

// FirstText returns cleaned, whitespace-collapsed text from the first matching element in
// document order, or "" if none matches.
func FirstText(doc *html.Node, match func(*html.Node) bool) string {
	for n := range doc.Descendants() {
		if n.Type == html.ElementNode && match(n) {
			var b strings.Builder
			for t := range n.Descendants() {
				if t.Type == html.TextNode {
					b.WriteString(t.Data)
				}
			}
			return Collapse(b.String())
		}
	}
	return ""
}

// Collapse collapses the whitespace of text and replaces invalid UTF-8.
func Collapse(s string) string {
	return strings.Join(strings.Fields(strings.ToValidUTF8(s, "�")), " ")
}

// CutRunes is s cut to at most n runes.
func CutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) > n {
		return string([]rune(s)[:n])
	}
	return s
}
