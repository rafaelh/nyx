package sanitize_test

import (
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/term/sanitize"
)

func TestSquash(t *testing.T) {
	t.Parallel()
	if got := sanitize.Squash("  a\x1b[31m\r\n\tb   c \u202e "); got != "a b c" {
		t.Errorf("Squash = %q, want %q", got, "a b c")
	}
}

func TestText(t *testing.T) {
	t.Parallel()
	in := "ok\x1b[31m red\x1b]0;title\x07 \x00bell\x07 tab\there \u202e\u061c bidi"
	got := sanitize.Text(in)
	for _, bad := range []string{"\x1b", "\x07", "\x00", "\t", "\u202e", "\u061c", "[31m", "title"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived in %q", bad, got)
		}
	}
	for _, want := range []string{"ok", "red", "bell", "tab here", "bidi"} {
		if !strings.Contains(got, want) {
			t.Errorf("visible text %q lost: %q", want, got)
		}
	}
}

func TestLine(t *testing.T) {
	t.Parallel()
	if got, want := sanitize.Line("a\vb\fc\u0085d\u2028e\u2029f"), "a b c d e f"; got != want {
		t.Errorf("Line = %q, want %q", got, want)
	}
}
