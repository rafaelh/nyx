package cli_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/rafaelh/nyx/internal/cli"
)

// --version prints "nyx <version>" and exits without doing any work.
func TestVersionFlag(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	h.version = "v0.0.0-20261106032157-7e34c1b8d74f"
	if code := h.execRoot("--version"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	if got, want := h.stdout.String(), "nyx "+h.version+"\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if h.stderr.Len() != 0 {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	h.untouched()
}

// With no Version in Deps (as the test harnesses build them), the version is "devel".
func TestVersionFlagZeroDeps(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := cli.Execute(context.Background(), []string{"--version"}, cli.Deps{Stdout: &stdout, Stderr: &stderr})
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
	if got := stdout.String(); got != "nyx devel\n" {
		t.Errorf("stdout = %q", got)
	}
}

// --version is long-only; -v must not become a shorthand that could be mistaken for --verbose.
func TestNoVersionShorthand(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.execRoot("-v"); code != 2 {
		t.Errorf("-v: exit %d, want 2 (unknown shorthand)", code)
	}
}
