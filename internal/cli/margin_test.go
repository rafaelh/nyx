package cli_test

import (
	"strings"
	"testing"
)

// unmargined verifies and removes the blank lines separating terminal output from prompts.
func unmargined(t *testing.T, out string) string {
	t.Helper()
	if !strings.HasPrefix(out, "\n") || !strings.HasSuffix(out, "\n\n") {
		t.Fatalf("terminal output is not set apart by a blank line before and after:\n%q", out)
	}
	return out[1 : len(out)-1]
}

// Output on a terminal has a blank line before and after it; off a terminal, or under --json, it
// is unchanged.
func TestMargin_OnlyOnATerminal(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	h.version = "1.2.3"
	if code := h.execRoot("--version"); code != 0 || h.stdout.String() != "nyx 1.2.3\n" {
		t.Errorf("piped: exit %d, %q", code, h.stdout.String())
	}
	h.stdoutTTY = true
	if code := h.execRoot("--version"); code != 0 || h.stdout.String() != "\nnyx 1.2.3\n\n" {
		t.Errorf("terminal: exit %d, %q", code, h.stdout.String())
	}
	h.stderrTTY = true
	if code := h.exec("a.com", "--json"); code != 0 || strings.HasPrefix(h.stdout.String(), "\n") || strings.HasSuffix(h.stdout.String(), "\n\n") {
		t.Errorf("--json on a terminal: exit %d, %q", code, h.stdout.String())
	}
	if h.stderr.Len() != 0 {
		t.Errorf("--json on a terminal: stderr %q", h.stderr.String())
	}
}

// Terminal streams share opening/closing margins on the first/last written stream; unused
// streams remain empty.
func TestMargin_SharedByBothStreams(t *testing.T) {
	t.Parallel()
	h := newHarness(t, someFindings())
	h.stdoutTTY, h.stderrTTY = true, true
	h.setenv("NO_COLOR", "1")
	if code := h.exec("a.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	errOut, out := h.stderr.String(), h.stdout.String()
	if !strings.HasPrefix(errOut, "\n") || strings.HasSuffix(errOut, "\n\n") {
		t.Errorf("stderr, written first, should open the margin and not close it:\n%q", errOut)
	}
	if strings.HasPrefix(out, "\n") || !strings.HasSuffix(out, "\n\n") {
		t.Errorf("stdout, written last, should close the margin and not open it:\n%q", out)
	}
	// A failure writes only to stderr, which then has both lines; stdout stays empty.
	if code := h.exec(); code != 2 {
		t.Fatalf("exit %d", code)
	}
	if h.stdout.Len() != 0 {
		t.Errorf("stdout %q, want it empty", h.stdout.String())
	}
	if got := unmargined(t, h.stderr.String()); !strings.HasPrefix(got, "error: no inputs") {
		t.Errorf("stderr %q", got)
	}
}
