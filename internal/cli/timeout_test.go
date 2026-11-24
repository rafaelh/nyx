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

// blocking combines context-blocked and immediately successful jobs without returning job
// errors.
func blocking(name string, quick, blocked int) *testkit.Procedure {
	return &testkit.Procedure{ProcedureName: name, Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job {
			return append(testkit.Keys("q", quick), testkit.Keys("b", blocked)...)
		},
		RunFn: func(ctx context.Context, c run.Job, _ egress.Clients) ([]run.Observation, error) {
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

// Deadline-cancelled jobs stay pending without failure counts and resume exactly once later.
func TestTimeout_CutJobsAreNeitherDoneNorFailed(t *testing.T) {
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
	if !env.Meta.DeadlineExceeded || env.Meta.JobsCompleted != 2 || env.Meta.JobsCancelled != 4 {
		t.Errorf("meta = %+v", env.Meta)
	}
	if got := h.completed("a.com", "slow"); !slices.Equal(got, []string{"q000", "q001"}) {
		t.Errorf("checks = %v, want only the two quick ones", got)
	}
	if got := h.failedJobs("slow"); len(got) != 0 {
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
	if env := h.envelope(); env.Meta.DeadlineExceeded || env.Meta.JobsCancelled != 0 {
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
	if env.Meta.DeadlineExceeded || env.Meta.JobsCompleted != 3 || env.Meta.JobsCancelled != 0 {
		t.Errorf("meta = %+v", env.Meta)
	}
	if h.stderr.Len() != 0 {
		t.Errorf("stderr = %q", h.stderr.String())
	}
}

// Timer cancellation keeps rate-limit waits from failing early as they would under a context
// deadline.
func TestTimeout_JobWaitingOnTheLimiterIsNotAFailure(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.crtsh(map[string][]string{"a.example": {"www.a.example"}}, nil)
	code := w.run("--rate-per-source", "1", "--concurrency", "6", "--timeout", "1s", "--passive",
		"a.example", "b.example", "c.example", "d.example", "e.example", "f.example")
	if code != 7 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	env := w.h.envelope()
	if env.Meta.JobsCancelled == 0 {
		t.Fatalf("no check was waiting when the timer fired: %+v", env.Meta)
	}
	if got := w.h.failedJobs(""); len(got) != 0 {
		t.Errorf("checks waiting on the limiter were recorded as failed: %v", got)
	}
}

// Interrupted enumeration cannot retire unlisted jobs because the procedure never finished
// declaring its valid keys.
func TestTimeout_CutEnumerationKeepsEarlierEvidence(t *testing.T) {
	t.Parallel()
	listed := []string{"c0", "c1"}
	fake := &testkit.Procedure{ProcedureName: "retiring", Kind: run.ThirdParty,
		RunFn: func(_ context.Context, c run.Job, _ egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("hostname", c.Key+".a.com")}, nil
		}}
	st := &enumProcedure{Procedure: fake, list: &listed}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("first run: exit %d\n%s", code, h.stderr.String())
	}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Contains(got, "c0.a.com") || !slices.Contains(got, "c1.a.com") {
		t.Fatalf("first run found %q, want c0 and c1", got)
	}
	// Block after c0 so c1 remains unlisted solely because enumeration was interrupted;
	// preserve its evidence.
	listed = []string{"c0"}
	st.block = true
	if code := h.exec("-e", "a.com", "--json", "--timeout", "400ms"); code != 7 {
		t.Fatalf("second run: exit %d\n%s", code, h.stderr.String())
	}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Contains(got, "c1.a.com") {
		t.Errorf("evidence of an unlisted check was retired by a cut enumeration: %q", got)
	}

	// Pending redo sweeps also wait for complete enumeration before removing evidence.
	if code := h.exec("-e", "a.com", "--json", "--redo", "retiring", "--timeout", "400ms"); code != 7 {
		t.Fatalf("redo run: exit %d\n%s", code, h.stderr.String())
	}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Contains(got, "c1.a.com") {
		t.Errorf("evidence of an unlisted check was swept by a cut redo: %q", got)
	}
}

// enumProcedure is a Retiring procedure whose enumeration can block until the context ends.
type enumProcedure struct {
	*testkit.Procedure
	list  *[]string
	block bool
}

func (*enumProcedure) RetiresUnlistedJobs() {}

func (s *enumProcedure) Jobs(ctx context.Context, _ run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		for _, k := range *s.list {
			if !yield(run.Job{Key: k}, nil) {
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
