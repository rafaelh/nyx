package cli_test

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/asn"
)

func newASN() run.Stage { return asn.New() }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// readmeText is the text of README.md.
func readmeText(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// flatWords is s in lower case with each run of white space one space, so a
// phrase that wraps across lines or starts a sentence still matches.
func flatWords(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// readmeSection is the README's section that starts at heading, up to the next
// "## " heading, in lower case, and the whole README.
func readmeSection(t *testing.T, heading string) (section, whole string) {
	t.Helper()
	whole = readmeText(t)
	start := strings.Index(whole, heading)
	if start < 0 {
		t.Fatalf("README has no %q section", heading)
	}
	end := strings.Index(whole[start+1:], "\n## ")
	if end < 0 {
		t.Fatalf("README has nothing after %q", heading)
	}
	return strings.ToLower(whole[start : start+1+end]), whole
}
