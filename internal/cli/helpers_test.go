package cli_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/procedures/asn"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

func newASN() run.Procedure { return asn.New() }

// expander marks fake input-ASN expansion through the same interface as the real procedure.
type expander struct{ *testkit.Procedure }

func (expander) ExpandsInputASNs() {}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// docsText joins README and sorted guide pages, excluding the maintainer pages (todo and release
// preparation), while retaining page titles.
func docsText(t *testing.T) string {
	t.Helper()
	pages, err := filepath.Glob("../../docs/*.md")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, p := range append([]string{"../../README.md"}, pages...) {
		if base := filepath.Base(p); base == "todo.md" || base == "release-preparation.md" {
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

// flatWords normalises case/whitespace for assertions spanning lines or sentence starts.
func flatWords(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// docsSection returns the named level-two section and full normalised documentation.
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
