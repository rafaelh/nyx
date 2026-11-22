package cli_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/asn"
	"github.com/rafaelh/nyx/internal/testkit"
)

func newASN() run.Stage { return asn.New() }

// expander is a fake stage that expands the input ASNs, as the asn stage does: a
// netblock it observes under a check for an input ASN is in scope.
type expander struct{ *testkit.Stage }

func (expander) ExpandsInputASNs() {}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// docsText is the user documentation: README.md and then each docs/*.md page but the to-do
// list, in name order. Each page starts with its "# " title.
func docsText(t *testing.T) string {
	t.Helper()
	pages, err := filepath.Glob("../../docs/*.md")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, p := range append([]string{"../../README.md"}, pages...) {
		if filepath.Base(p) == "todo.md" {
			continue
		}
		text, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(text)
		b.WriteString("\n")
	}
	return b.String()
}

// flatWords is s in lower case with each run of white space one space, so a
// phrase that wraps across lines or starts a sentence still matches.
func flatWords(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// docsSection is the documentation's section that starts at heading, up to the next "## "
// heading or the end of its page, in lower case, and the whole documentation.
func docsSection(t *testing.T, heading string) (section, whole string) {
	t.Helper()
	whole = docsText(t)
	start := strings.Index(whole, heading)
	if start < 0 {
		t.Fatalf("the docs have no %q section", heading)
	}
	rest := whole[start+1:]
	end := len(rest)
	for _, next := range []string{"\n## ", "\n# "} {
		if i := strings.Index(rest, next); i >= 0 && i < end {
			end = i
		}
	}
	return strings.ToLower(whole[start : start+1+end]), whole
}
