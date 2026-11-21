package webpage_test

import (
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/webpage"
	"golang.org/x/net/html"
)

func TestTitle(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, body, want string }{
		{"plain", "<html><head><title>Hello</title></head></html>", "Hello"},
		{"whitespace collapsed", "<title>\n  Hello \t  world\n</title>", "Hello world"},
		{"first title wins", "<title>one</title><title>two</title>", "one"},
		{"none", "<html><body>no title</body></html>", ""},
		{"empty body", "", ""},
		{"invalid utf-8 replaced", "<title>a\xffb</title>", "a�b"},
		{"truncated to 200 runes", "<title>" + strings.Repeat("é", 300) + "</title>", strings.Repeat("é", 200)},
		{"exactly 200 runes", "<title>" + strings.Repeat("x", 200) + "</title>", strings.Repeat("x", 200)},
		{"entities decoded", "<title>a &amp; b</title>", "a & b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := webpage.Title([]byte(tc.body)); got != tc.want {
				t.Errorf("Title = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTitleOf_ParsedDocument(t *testing.T) {
	t.Parallel()
	doc, err := html.Parse(strings.NewReader("<title> x  y </title>"))
	if err != nil {
		t.Fatal(err)
	}
	if got := webpage.TitleOf(doc); got != "x y" {
		t.Errorf("TitleOf = %q, want %q", got, "x y")
	}
}
