package shellquote_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/shellquote"
)

// Quote only shell-sensitive arguments while preserving argument boundaries.
func TestQuote(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"example.com": "example.com", "--engagement=acme": "--engagement=acme", "a/b,c:d@e%f+g_h": "a/b,c:d@e%f+g_h",
		"": "''", "Acme Pty": "'Acme Pty'", "it's": `'it'\''s'`, "$HOME": "'$HOME'", "a*": "'a*'", "née": "'née'",
	} {
		if got := shellquote.Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestJoin(t *testing.T) {
	t.Parallel()
	if got, want := shellquote.Join([]string{"recon", "Acme Pty", "x.com"}), "recon 'Acme Pty' x.com"; got != want {
		t.Errorf("Join = %s, want %s", got, want)
	}
}
