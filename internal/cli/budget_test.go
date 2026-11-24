package cli_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// costed returns jobs c0, c1, ... with the given costs.
func costed(costs ...int) []run.Job {
	var out []run.Job
	for i, c := range costs {
		out = append(out, run.Job{Key: fmt.Sprintf("c%d", i), Cost: c})
	}
	return out
}

func budgeted(limit int, jobs func(v run.View) []run.Job) *testkit.Budgeted {
	return &testkit.Budgeted{Procedure: &testkit.Procedure{ProcedureName: "budgeted", Kind: run.ThirdParty, JobsFn: jobs}, Limit: limit}
}

// deferredOf is the summary event's count of deferred work for a procedure.
func deferredOf(t *testing.T, h *harness, procedure string) int {
	t.Helper()
	sum := h.summaryEvent()
	m, ok := sum["deferred"].(map[string]any)
	if !ok {
		t.Fatalf("summary has no deferred object: %v", sum)
	}
	n, _ := m[procedure].(float64)
	return int(n)
}

// deferredBlock is the console summary's "Deferred to the next run" block.
func deferredBlock(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "Deferred to the next run")
	if i < 0 {
		t.Fatalf("the console summary has no deferred block:\n%s", out)
	}
	return out[i:]
}

// Overflowing jobs and all later jobs are deferred without attempts, failures or completion
// markers.
func TestBudget_StopsAtFirstOverflow(t *testing.T) {
	t.Parallel()
	st := budgeted(3, func(run.View) []run.Job { return costed(1, 1, 1, 1, 1) })
	h := newHarness(t, st)
	if code := h.exec("--json", "a.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got := ran(st); !slices.Equal(got, []string{"c0", "c1", "c2"}) {
		t.Errorf("executed = %v, want c0 c1 c2", got)
	}
	state := lastState(h.events(), "budgeted")
	if state.str("state") != "done" || state.num("jobs") != 3 || state.num("failed") != 0 {
		t.Errorf("state = %v, want done with 3 jobs and none failed", state)
	}
	if got := h.completed("a.com", "budgeted"); !slices.Equal(got, []string{"c0", "c1", "c2"}) {
		t.Errorf("completed = %v", got)
	}
	if n := deferredOf(t, h, "budgeted"); n != 2 {
		t.Errorf("deferred = %d, want 2", n)
	}
}

// Stop at the first overflowing job even when cheaper later jobs could fit.
func TestBudget_CostsAddUpAndLaterJobsWait(t *testing.T) {
	t.Parallel()
	st := budgeted(10, func(run.View) []run.Job { return costed(4, 4, 3, 1, 1) })
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	if got := ran(st); !slices.Equal(got, []string{"c0", "c1"}) {
		t.Errorf("executed = %v, want c0 c1 (c2 would reach 11, and c3 and c4 follow it)", got)
	}
	if n := deferredOf(t, h, "budgeted"); n != 5 {
		t.Errorf("deferred = %d, want 5 (the cost of c2, c3 and c4)", n)
	}
}

// A cost of 0 counts as 1.
func TestBudget_ZeroCostIsOne(t *testing.T) {
	t.Parallel()
	st := budgeted(2, func(run.View) []run.Job { return costed(0, 0, 0) })
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	if got := ran(st); len(got) != 2 {
		t.Errorf("executed = %v, want two", got)
	}
}

// The first pending job of the run is taken even when it alone exceeds the
// budget, so a run always makes progress.
func TestBudget_FirstJobAlwaysTaken(t *testing.T) {
	t.Parallel()
	st := budgeted(3, func(run.View) []run.Job { return costed(10, 1) })
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	if got := ran(st); !slices.Equal(got, []string{"c0"}) {
		t.Errorf("executed = %v, want only the oversized c0", got)
	}
	if n := deferredOf(t, h, "budgeted"); n != 1 {
		t.Errorf("deferred = %d, want 1", n)
	}
	// And it is the next run's first job that goes next.
	h.exec("--json", "-e", "a.com")
	if got := ran(st); !slices.Equal(got, []string{"c0", "c1"}) {
		t.Errorf("after the second run executed = %v", got)
	}
}

// Completed jobs cost nothing, so each run does the next slice of the work
// and the last run defers nothing.
func TestBudget_RemainderRunsNextTime(t *testing.T) {
	t.Parallel()
	st := budgeted(2, func(run.View) []run.Job { return costed(1, 1, 1, 1, 1) })
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	want := [][]string{{"c0", "c1"}, {"c2", "c3"}, {"c4"}}
	wantDeferred := []int{3, 1, 0}
	var all []string
	for i, w := range want {
		if i > 0 {
			h.exec("--json", "-e", "a.com")
		}
		all = append(all, w...)
		if got := ran(st); !slices.Equal(got, all) {
			t.Fatalf("after run %d executed = %v, want %v", i+1, got, all)
		}
		if n := deferredOf(t, h, "budgeted"); n != wantDeferred[i] {
			t.Errorf("run %d deferred = %d, want %d", i+1, n, wantDeferred[i])
		}
	}
	// Nothing left: the procedure has nothing to do and runs nothing.
	h.exec("--json", "-e", "a.com")
	if got := ran(st); len(got) != 5 {
		t.Errorf("a finished procedure ran again: %v", got)
	}
}

// The first-job budget exception applies once per run, not once per pass.
func TestBudget_LaterPassDoesNotTakeAnotherOverflowingJob(t *testing.T) {
	t.Parallel()
	passes := 0
	st := budgeted(3, func(run.View) []run.Job {
		passes++
		if passes == 1 {
			return costed(10)
		}
		return costed(10, 10) // c1 appears in a later pass
	})
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	if got := ran(st); !slices.Equal(got, []string{"c0"}) {
		t.Errorf("executed = %v, want only c0", got)
	}
	if passes < 2 {
		t.Fatalf("the procedure was enumerated in %d pass(es); the test needs a later pass", passes)
	}
	if n := deferredOf(t, h, "budgeted"); n != 10 {
		t.Errorf("deferred = %d, want the last pass's 10", n)
	}
}

// A procedure without a budget is not limited, however many jobs it has.
func TestBudget_UnbudgetedProcedureIsUnlimited(t *testing.T) {
	t.Parallel()
	plain := &testkit.Procedure{ProcedureName: "plain", Kind: run.ThirdParty, JobsFn: func(run.View) []run.Job { return costed(5, 5, 5) }}
	h := newHarness(t, plain, budgeted(1, func(run.View) []run.Job { return nil }))
	h.exec("--json", "a.com")
	if got := ran(plain); len(got) != 3 {
		t.Errorf("executed = %v", got)
	}
	if n := deferredOf(t, h, "plain"); n != 0 {
		t.Errorf("deferred = %d", n)
	}
}

// Failed jobs still consume budget; deferred jobs do not become failures.
func TestBudget_FailedJobSpendsBudgetDeferredAreNotFailures(t *testing.T) {
	t.Parallel()
	st := budgeted(2, func(run.View) []run.Job { return costed(1, 1, 1) })
	st.RunFn = func(_ context.Context, c run.Job, _ egress.Clients) ([]run.Observation, error) {
		if c.Key == "c0" {
			return nil, fmt.Errorf("transient")
		}
		return nil, nil
	}
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	if got := ran(st); !slices.Equal(got, []string{"c0", "c1"}) {
		t.Errorf("executed = %v, want c0 c1 (the failed c0 spent its budget; c2 waits)", got)
	}
	if state := lastState(h.events(), "budgeted"); state.num("jobs") != 2 || state.num("failed") != 1 {
		t.Errorf("state = %v, want 2 jobs and 1 failed", state)
	}
}

// With nothing deferred the console says nothing about it; with something
// deferred it lists each procedure under its own heading.
func TestBudget_ConsoleBlock(t *testing.T) {
	t.Parallel()
	st := budgeted(2, func(run.View) []run.Job { return costed(1, 1, 1, 1) })
	h := newHarness(t, st)
	h.exec("a.com")
	if block := deferredBlock(t, h.stdout.String()); !strings.Contains(block, "budgeted") || !strings.Contains(block, "2") {
		t.Errorf("block does not give the procedure and count:\n%s", block)
	}
	h.exec("-e", "a.com")
	if strings.Contains(h.stdout.String(), "Deferred to the next run") {
		t.Errorf("nothing was deferred, yet the console says so:\n%s", h.stdout.String())
	}
}

// Deferred jobs retain earlier evidence through redo/retirement; rerun jobs replace their
// evidence.
func TestBudget_RedoKeepsDeferredHitsCurrent(t *testing.T) {
	t.Parallel()
	hit := func(_ context.Context, c run.Job, _ egress.Clients) ([]run.Observation, error) {
		return []run.Observation{obs("hostname", "host-"+c.Key+".a.com")}, nil
	}
	jobs := func(run.View) []run.Job { return costed(1, 1, 1, 1) }
	st := &retiringBudgeted{Budgeted: *budgeted(100, jobs)}
	st.RunFn = hit
	h := newHarness(t, st)
	h.exec("--json", "a.com")
	want := []string{"host-c0.a.com", "host-c1.a.com", "host-c2.a.com", "host-c3.a.com"}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Equal(got, want) {
		t.Fatalf("setup: subdomains = %v", got)
	}

	st.Limit = 1
	st.Reset()
	h.exec("--json", "-e", "a.com", "--redo", "budgeted")
	if got := ran(st); !slices.Equal(got, []string{"c0"}) {
		t.Errorf("redo executed = %v, want only c0", got)
	}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Equal(got, want) {
		t.Errorf("after the budgeted redo subdomains = %v, want all four still current", got)
	}
	if n := deferredOf(t, h, "budgeted"); n != 3 {
		t.Errorf("deferred = %d, want 3", n)
	}
}

// ran are the keys a fake procedure has executed, sorted: workers run concurrently.
func ran(s interface{ Executed() []string }) []string { return sorted(s.Executed()) }

// retiringBudgeted is a budgeted procedure that also retires the jobs it no longer yields.
type retiringBudgeted struct{ testkit.Budgeted }

func (retiringBudgeted) RetiresUnlistedJobs() {}
