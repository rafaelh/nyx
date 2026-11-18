package cli_test

import (
	"context"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// blocking is a stage with n checks that wait until the context ends, and quick checks q0, q1... that
// finish at once. Its checks never fail.
func blocking(name string, quick, blocked int) *testkit.Stage {
	return &testkit.Stage{StageName: name, Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check {
			return append(testkit.Keys("q", quick), testkit.Keys("b", blocked)...)
		},
		RunFn: func(ctx context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
			if strings.HasPrefix(c.Key, "q") {
				return nil, nil
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}}
}

// A bad --timeout is a usage error with the value in input, reported with the other problems, and
// nothing is created or contacted.
func TestTimeout_InvalidValues(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"0", "-5s", "abc", "30", ""} {
		t.Run("value "+v, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, noop())
			f := h.failed(h.exec("a.com", "--json", "--timeout", v), 2, true)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, `timeout: invalid value "`+v+`": not a positive duration`) {
				t.Errorf("%+v", f)
			}
			if got := f.inputOf("timeout"); !f.hasInput("timeout") || v != "" && !slices.Equal(got, []string{v}) {
				t.Errorf("input timeout = %v, want it to hold %q", got, v)
			}
			if f.hint != "--timeout 30m" {
				t.Errorf("hint = %q", f.hint)
			}
			h.untouched()
		})
	}
	h := newHarness(t, noop())
	f := h.failed(h.exec("a.com", "--timeout", "abc", "--concurrency", "abc", "--json"), 2, true)
	if !f.hasInput("timeout") || !f.hasInput("concurrency") {
		t.Errorf("both problems are reported together: %+v", f)
	}
	h.untouched()
}

// --timeout is a flag and nothing else: not a setting, so no environment variable and no config key.
func TestTimeout_IsNotASetting(t *testing.T) {
	t.Parallel()
	h := newHarness(t, blocking("slow", 1, 0))
	h.setenv("NYX_TIMEOUT", "1ms")
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("NYX_TIMEOUT changed the run: exit %d\n%s", code, h.stderr.String())
	}
	if env := h.envelope(); env.Meta.DeadlineExceeded {
		t.Error("NYX_TIMEOUT set a deadline")
	}

	h = newHarness(t, noop())
	cfg := writeFile(t, t.TempDir(), "config.yaml", "timeout: 5s\n")
	f := h.failed(h.exec("a.com", "--config", cfg), 2, false)
	if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "timeout") {
		t.Errorf("a timeout key in the config file is accepted: %+v", f)
	}

	h = newHarness(t, noop())
	f = h.failed(h.exportExec("-e", "a.com", "--timeout", "5s"), 2, false)
	if !strings.Contains(f.msg, "unknown flag: --timeout") {
		t.Errorf("export takes no --timeout: %+v", f)
	}
}

// With a deadline, the checks that are cut are neither done nor failed, the run ends by the deadline
// with its files written, and the next run does exactly what was left.
func TestTimeout_CutChecksAreNeitherDoneNorFailed(t *testing.T) {
	t.Parallel()
	st := blocking("slow", 2, 4)
	h := newHarness(t, st)
	start := time.Now()
	code := h.exec("a.com", "--json", "--timeout", "400ms", "--concurrency", "6")
	elapsed := time.Since(start)
	f := h.theError(true)
	if code != 7 || f.code != "PARTIAL" {
		t.Fatalf("exit %d: %+v\n%s", code, f, h.stderr.String())
	}
	if elapsed > 2*time.Second {
		t.Errorf("the run took %v for a 400ms deadline", elapsed)
	}
	env := h.envelope()
	if !env.Meta.DeadlineExceeded || env.Meta.ChecksCompleted != 2 || env.Meta.ChecksCancelled != 4 {
		t.Errorf("meta = %+v", env.Meta)
	}
	if got := h.completed("a.com", "slow"); !slices.Equal(got, []string{"q000", "q001"}) {
		t.Errorf("checks = %v, want only the two quick ones", got)
	}
	if got := queryStrings(t, h.openDB("a.com"), "SELECT key FROM failures WHERE stage='slow'"); len(got) != 0 {
		t.Errorf("a cancelled check was recorded as failed: %v", got)
	}
	if _, err := os.Stat(filepath.Join(h.eng("a.com"), "scope.csv")); err != nil {
		t.Errorf("the files were not written: %v", err)
	}

	// Without a deadline the next run is exactly the four that were cut.
	st.Reset()
	st.RunFn = nil
	if code := h.exec("-e", "a.com", "--json"); code != 0 {
		t.Fatalf("second run: exit %d\n%s", code, h.stderr.String())
	}
	if got := st.Executed(); len(got) != 4 || got[0][0] != 'b' {
		t.Errorf("the second run executed %v, want the four cancelled checks", got)
	}
	if env := h.envelope(); env.Meta.DeadlineExceeded || env.Meta.ChecksCancelled != 0 {
		t.Errorf("second run meta = %+v", env.Meta)
	}
}

// A run that finishes before the timer is unaffected by it.
func TestTimeout_FinishedBeforeTheDeadlineIsUnaffected(t *testing.T) {
	t.Parallel()
	h := newHarness(t, blocking("quick", 3, 0))
	if code := h.exec("a.com", "--json", "--timeout", "30s"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	env := h.envelope()
	if env.Meta.DeadlineExceeded || env.Meta.ChecksCompleted != 3 || env.Meta.ChecksCancelled != 0 {
		t.Errorf("meta = %+v", env.Meta)
	}
	if h.stderr.Len() != 0 {
		t.Errorf("stderr = %q", h.stderr.String())
	}
}

// Checks waiting on a rate limiter when the timer fires are cancelled, not failed: a context
// deadline would make the limiter fail them early.
func TestTimeout_CheckWaitingOnTheLimiterIsNotAFailure(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.crtsh(map[string][]string{"a.example": {"www.a.example"}}, nil)
	code := w.run("--rate-per-source", "1", "--concurrency", "6", "--timeout", "1s", "--passive",
		"a.example", "b.example", "c.example", "d.example", "e.example", "f.example")
	if code != 7 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	env := w.h.envelope()
	if env.Meta.ChecksCancelled == 0 {
		t.Fatalf("no check was waiting when the timer fired: %+v", env.Meta)
	}
	if got := queryStrings(t, w.h.openDB("a.example"), "SELECT stage||':'||key FROM failures"); len(got) != 0 {
		t.Errorf("checks waiting on the limiter were recorded as failed: %v", got)
	}
}

// A deadline during enumeration must not sweep: a Retiring stage that has listed only some of its
// checks keeps the evidence of the checks it never got to list.
func TestTimeout_CutEnumerationKeepsEarlierEvidence(t *testing.T) {
	t.Parallel()
	listed := []string{"c0", "c1"}
	fake := &testkit.Stage{StageName: "retiring", Kind: run.ThirdParty,
		RunFn: func(_ context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("hostname", c.Key+".a.com")}, nil
		}}
	st := &enumStage{Stage: fake, list: &listed}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("first run: exit %d\n%s", code, h.stderr.String())
	}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Contains(got, "c0.a.com") || !slices.Contains(got, "c1.a.com") {
		t.Fatalf("first run found %q, want c0 and c1", got)
	}
	// Second run: only c0 is listed, then enumeration blocks until the deadline. c1 is unlisted, but
	// the run never finished listing, so its evidence must stay.
	listed = []string{"c0"}
	st.block = true
	if code := h.exec("-e", "a.com", "--json", "--timeout", "400ms"); code != 7 {
		t.Fatalf("second run: exit %d\n%s", code, h.stderr.String())
	}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Contains(got, "c1.a.com") {
		t.Errorf("evidence of an unlisted check was retired by a cut enumeration: %q", got)
	}

	// The same for a redo that is pending when the enumeration is cut: the sweep that follows a redo
	// would forget what the checks it never listed found.
	if code := h.exec("-e", "a.com", "--json", "--redo", "retiring", "--timeout", "400ms"); code != 7 {
		t.Fatalf("redo run: exit %d\n%s", code, h.stderr.String())
	}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Contains(got, "c1.a.com") {
		t.Errorf("evidence of an unlisted check was swept by a cut redo: %q", got)
	}
}

// enumStage is a Retiring stage whose enumeration can block until the context ends.
type enumStage struct {
	*testkit.Stage
	list  *[]string
	block bool
}

func (*enumStage) RetiresUnlistedChecks() {}

func (s *enumStage) Checks(ctx context.Context, _ run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, k := range *s.list {
			if !yield(run.Check{Key: k}, nil) {
				return
			}
		}
		if s.block {
			<-ctx.Done()
		}
	}
}

// The recon example in both helps passes --timeout and --json, and the root help lists --timeout
// among recon's everyday flags.
func TestTimeout_InHelp(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.execRoot("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	root := h.stdout.String()
	if !strings.Contains(root, "--timeout") || !strings.Contains(root, "nyx recon example.com --json --timeout 30m") {
		t.Errorf("root help lacks --timeout:\n%s", root)
	}
	if code := h.execRoot("recon", "--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	recon := h.stdout.String()
	if !strings.Contains(recon, "--timeout duration") || !strings.Contains(recon, "nyx recon example.com --json --timeout 30m") {
		t.Errorf("recon help lacks --timeout:\n%s", recon)
	}
	if strings.Contains(recon, "--timeout") && !strings.Contains(recon, "(default: none)") {
		t.Errorf("--timeout help does not say it has no default:\n%s", recon)
	}
}
