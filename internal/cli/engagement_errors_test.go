package cli_test

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/engagement"
)

const (
	lockedHint   = "another run holds this engagement; wait for it to finish, or use another -e"
	startOneTail = "give domains, --org, --asn or --cidr to start one"
)

// exportExec runs nyx recon export through the harness, so its stdout and stderr are the
// harness's, which h.failed checks.
func (h *harness) exportExec(args ...string) int {
	h.t.Helper()
	return h.execRoot(append([]string{"recon", "export", "--output-dir", h.out}, args...)...)
}

func reversed(s []string) []string {
	s = slices.Clone(s)
	slices.Reverse(s)
	return s
}

// makeEngagements creates recognisable directory layouts without needing readable database
// contents.
func makeEngagements(t *testing.T, out string, names ...string) {
	t.Helper()
	for _, n := range names {
		if err := os.MkdirAll(filepath.Join(out, n, ".nyx"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, n, ".nyx", "state.db"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// An active engagement lock is a retryable LOCKED error with actionable guidance.
func TestEngagementErrors_LockedEngagement(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.exec("a.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	eng, err := engagement.Open(h.eng("a.com"), engagement.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	for _, jsonMode := range []bool{false, true} {
		args := []string{"-e", "a.com"}
		if jsonMode {
			args = append(args, "--json")
		}
		f := h.failed(h.exec(args...), 1, jsonMode)
		if f.code != "LOCKED" || !f.transient || f.hint != lockedHint || !strings.Contains(f.msg, "a.com") {
			t.Errorf("json=%v: %+v", jsonMode, f)
		}
	}
	// With inputs too: the lock is met when the engagement opens.
	f := h.failed(h.exec("-e", "a.com", "b.com"), 1, false)
	if f.code != "LOCKED" || !f.transient || f.hint != lockedHint {
		t.Errorf("with inputs: %+v", f)
	}
}

// Foreign directories are preserved and reported alongside other validation failures.
func TestEngagementErrors_ForeignDirectory(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	dir := h.eng("old")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.eng("plain-file"), []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotDir(t, h.out)

	cases := []struct {
		name string
		args []string
	}{
		{"no inputs", []string{"-e", "old"}},
		{"with inputs", []string{"-e", "old", "a.com"}},
		{"with a bad flag value", []string{"-e", "old", "--concurrency", "abc"}},
		{"with inputs and a bad flag value", []string{"-e", "old", "a.com", "--concurrency", "abc"}},
	}
	for _, c := range cases {
		for _, jsonMode := range []bool{false, true} {
			args := c.args
			if jsonMode {
				args = append(slices.Clone(args), "--json")
			}
			f := h.failed(h.exec(args...), 2, jsonMode)
			if f.code != "INVALID_INPUT" || f.transient || !strings.Contains(f.msg, dir+" exists but is not a nyx engagement") ||
				!strings.Contains(f.hint, "choose another engagement name with -e") || !strings.Contains(f.hint, dir) {
				t.Errorf("%s json=%v: %+v", c.name, jsonMode, f)
			}
			// Only the JSON error carries the input.
			if jsonMode && !slices.Contains(f.inputOf("engagement"), "old") {
				t.Errorf("%s: input %v", c.name, f.input)
			}
			if strings.Contains(strings.Join(c.args, " "), "abc") &&
				(!strings.Contains(f.msg, "concurrency") || jsonMode && !f.hasInput("concurrency")) {
				t.Errorf("%s json=%v: the bad flag is not reported with the directory: %+v", c.name, jsonMode, f)
			}
		}
	}
	if after := snapshotDir(t, h.out); !maps.Equal(before, after) {
		t.Errorf("the output directory changed: %v -> %v", slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
	}
	if h.network() != 0 {
		t.Error("the call made network contact")
	}

	// A file where the engagement's directory should be is not an engagement either.
	f := h.failed(h.exec("-e", "plain-file", "a.com"), 2, false)
	if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, h.eng("plain-file")) {
		t.Errorf("a file: %+v", f)
	}
	if after := snapshotDir(t, h.out); !maps.Equal(before, after) {
		t.Errorf("the output directory changed: %v -> %v", slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
	}
}

// Missing named engagements without scope inputs return NOT_FOUND without creating directories.
func TestEngagementErrors_NotFoundCreatesNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	none := "no engagements in " + h.out + "; " + startOneTail

	for _, jsonMode := range []bool{false, true} {
		args := []string{"-e", "nope"}
		if jsonMode {
			args = append(args, "--json")
		}
		f := h.failed(h.exec(args...), 3, jsonMode)
		if f.code != "NOT_FOUND" || f.transient || f.msg != fmt.Sprintf("no engagement named %q in %s", "nope", h.out) || f.hint != none {
			t.Errorf("json=%v: %+v", jsonMode, f)
		}
		if jsonMode && !slices.Equal(f.inputOf("engagement"), []string{"nope"}) {
			t.Errorf("input %v", f.input)
		}
		h.untouched()
	}
	if want := `"input":{"engagement":["nope"]},"transient":false}` + "\n"; !strings.HasSuffix(h.stderr.String(), want) {
		t.Errorf("JSON error: %s", h.stderr.String())
	}

	// The output directory itself is absent.
	absent := filepath.Join(h.out, "not-yet", "out")
	if code := h.execRoot("recon", "--output-dir", absent, "-e", "nope"); code != 3 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if _, err := os.Stat(filepath.Join(h.out, "not-yet")); !os.IsNotExist(err) {
		t.Errorf("the output directory was created (%v)", err)
	}

	// The engagement's own directory is present and empty.
	if err := os.Mkdir(h.eng("nope"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := h.failed(h.exec("-e", "nope"), 3, false)
	if f.code != "NOT_FOUND" {
		t.Errorf("empty directory: %+v", f)
	}
	if entries, _ := os.ReadDir(h.eng("nope")); len(entries) != 0 {
		t.Errorf("the call created %d entries in the empty engagement directory", len(entries))
	}

	// Errors preserve the typed -e value while messages use the derived engagement name.
	f = h.failed(h.exec("-e", "Nope Two", "--json"), 3, true)
	if !slices.Equal(f.inputOf("engagement"), []string{"Nope Two"}) || !strings.Contains(f.msg, `"nope-two"`) {
		t.Errorf("input %v, message %q", f.input, f.msg)
	}
	f = h.failed(h.exportExec("-e", "Nope Two", "--json"), 3, true)
	if !slices.Equal(f.inputOf("engagement"), []string{"Nope Two"}) {
		t.Errorf("export: input %v", f.input)
	}

	// Invalid input takes precedence over missing-engagement errors.
	f = h.failed(h.exec("-e", "nope", "--concurrency", "abc"), 2, false)
	if f.code != "INVALID_INPUT" {
		t.Errorf("with a bad flag: %+v", f)
	}
}

// The hint lists the engagements there are: up to ten, sorted, and how many more.
func TestEngagementErrors_NotFoundHintListsEngagements(t *testing.T) {
	t.Parallel()
	names := func(n int) []string {
		var out []string
		for i := range n {
			out = append(out, fmt.Sprintf("eng%02d", i))
		}
		return out
	}
	cases := []struct {
		name   string
		count  int
		listed string // after "engagements in <dir>: ", before the tail
	}{
		{"three", 3, "eng00, eng01, eng02"},
		{"ten", 10, strings.Join(names(10), ", ")},
		{"twelve", 12, strings.Join(names(10), ", ") + " and 2 more"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, noop())
			// Create fixtures in reverse order to verify hints sort names and
			// ignore non-engagement entries.
			makeEngagements(t, h.out, reversed(names(c.count))...)
			if err := os.MkdirAll(filepath.Join(h.out, "aaa-not-one"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(h.out, "aab-file"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			prefix := "engagements in " + h.out + ": " + c.listed
			f := h.failed(h.exec("-e", "nope"), 3, false)
			if want := prefix + "; or " + startOneTail; f.hint != want {
				t.Errorf("recon hint:\n got %q\nwant %q", f.hint, want)
			}

			// export names the same engagements and has no way to start one.
			f = h.failed(h.exportExec("-e", "nope"), 3, false)
			if f.code != "NOT_FOUND" || f.hint != prefix {
				t.Errorf("export hint:\n got %q\nwant %q", f.hint, prefix)
			}
		})
	}
}

// Export distinguishes missing engagements, foreign directories and output-write failures
// without creating state.
func TestExport_EngagementErrors(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if err := os.Mkdir(h.eng("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.eng("old"), "notes.txt"), []byte("mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotDir(t, h.out)

	for _, jsonMode := range []bool{false, true} {
		flags := []string{}
		if jsonMode {
			flags = append(flags, "--json")
		}
		// Absent, with the output directory empty.
		f := h.failed(h.exportExec(append([]string{"-e", "nope"}, flags...)...), 3, jsonMode)
		if f.code != "NOT_FOUND" || f.transient || f.hint != "no engagements in "+h.out ||
			f.msg != fmt.Sprintf("no engagement named %q in %s", "nope", h.out) {
			t.Errorf("absent json=%v: %+v", jsonMode, f)
		}
		if jsonMode && !slices.Equal(f.inputOf("engagement"), []string{"nope"}) {
			t.Errorf("absent: input %v", f.input)
		}
		if strings.Contains(f.hint, startOneTail) {
			t.Errorf("export's hint offers to start an engagement: %q", f.hint)
		}

		// Foreign, alone and with another problem.
		f = h.failed(h.exportExec(append([]string{"-e", "old"}, flags...)...), 2, jsonMode)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, h.eng("old")+" exists but is not a nyx engagement") ||
			!strings.Contains(f.hint, "choose another engagement name with -e") {
			t.Errorf("foreign json=%v: %+v", jsonMode, f)
		}
		if jsonMode && !slices.Equal(f.inputOf("engagement"), []string{"old"}) {
			t.Errorf("foreign: input %v", f.input)
		}
		f = h.failed(h.exportExec(append([]string{"-e", "old", "--kind", "nope"}, flags...)...), 2, jsonMode)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "is not a nyx engagement") || !strings.Contains(f.msg, `unknown kind "nope"`) {
			t.Errorf("foreign with a bad kind json=%v: %+v", jsonMode, f)
		}
	}
	if after := snapshotDir(t, h.out); !maps.Equal(before, after) {
		t.Errorf("export changed the output directory: %v -> %v", slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
	}
	if h.network() != 0 {
		t.Error("export made network contact")
	}

	// A .nyx with no state database is an engagement that was never finished: not found.
	if err := os.MkdirAll(filepath.Join(h.out, "hollow", ".nyx"), 0o755); err != nil {
		t.Fatal(err)
	}
	if f := h.failed(h.exportExec("-e", "hollow"), 3, false); f.code != "NOT_FOUND" {
		t.Errorf("hollow: %+v", f)
	}
}

// Export write failures leave engagement/output state unchanged and return UNEXPECTED_ERROR.
func TestExport_WriteFailureIsUnexpected(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	h := w.h
	dir := t.TempDir()
	asDir := filepath.Join(dir, "taken")
	if err := os.Mkdir(asDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, jsonMode := range []bool{false, true} {
		args := []string{"-e", "a.com", "--output", asDir}
		if jsonMode {
			args = append(args, "--json")
		}
		f := h.failed(h.exportExec(args...), 1, jsonMode)
		if f.code != "UNEXPECTED_ERROR" || f.transient {
			t.Errorf("json=%v: %+v", jsonMode, f)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("a temporary file was left beside the target: %v", entries)
	}
}

// --json changes the format of export's errors and not one byte of its lines.
func TestExport_JSONLeavesLinesUnchanged(t *testing.T) {
	t.Parallel()
	w := newExportWorld(t)
	plain := export(w.h, "-e", "a.com")
	asJSON := export(w.h, "-e", "a.com", "--json")
	if plain.code != 0 || asJSON.code != 0 {
		t.Fatalf("exit %d and %d: %s %s", plain.code, asJSON.code, plain.stderr, asJSON.stderr)
	}
	if plain.stdout == "" || plain.stdout != asJSON.stdout {
		t.Errorf("--json changed the lines:\n%s\nwant\n%s", asJSON.stdout, plain.stdout)
	}
	if plain.stderr != "" || asJSON.stderr != "" {
		t.Errorf("a successful export wrote to stderr: %q, %q", plain.stderr, asJSON.stderr)
	}

	// An error keeps stdout empty in both modes and differs only in its format.
	human := export(w.h, "-e", "nope")
	jsonErr := export(w.h, "-e", "nope", "--json")
	if human.code != 3 || jsonErr.code != 3 || human.stdout != "" || jsonErr.stdout != "" {
		t.Errorf("exit %d and %d, stdout %q and %q", human.code, jsonErr.code, human.stdout, jsonErr.stdout)
	}
	if !strings.HasPrefix(human.stderr, "error: ") || !strings.HasPrefix(jsonErr.stderr, `{"error":`) {
		t.Errorf("formats: %q and %q", human.stderr, jsonErr.stderr)
	}
}
