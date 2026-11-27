package cli_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// endNote is a value a run's jobs share that has something to say when the run ends: its text
// and how many jobs used it, or nothing when its text is empty.
type endNote struct {
	mu   sync.Mutex
	text string
	jobs int
}

func (n *endNote) EndWarning() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.text == "" {
		return ""
	}
	return fmt.Sprintf("%s after %d jobs", n.text, n.jobs)
}

var _ run.EndWarner = (*endNote)(nil)

// endKey is the run-state key of an endNote.
type endKey string

// noteJob counts a job on the run's endNote under key, which starts with text.
func noteJob(ctx context.Context, key, text string) {
	n := run.PerRun(ctx, endKey(key), func() *endNote { return &endNote{text: text} })
	n.mu.Lock()
	n.jobs++
	n.mu.Unlock()
}

// endNoting is a procedure whose n jobs each count themselves on the endNote under key.
func endNoting(key, text string, n int) *testkit.Procedure {
	return &testkit.Procedure{ProcedureName: "noting", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("c", n) },
		RunFn: func(ctx context.Context, _ run.Job, _ egress.Clients) ([]run.Observation, error) {
			noteJob(ctx, key, text)
			return nil, nil
		}}
}

// A value shared through the run state is asked once, when the run ends, and its text is a
// warning of the run, in the envelope too.
func TestEndWarning_WarnedOnceWhenTheRunEnds(t *testing.T) {
	t.Parallel()
	const text = "names were left behind"
	h := newHarness(t, endNoting("k", text, 3))
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	want := []string{text + " after 3 jobs"}
	if got := h.messages("warning", text); !slices.Equal(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	var inEnvelope []string
	for _, w := range h.envelope().Meta.Warnings {
		if strings.Contains(w, text) {
			inEnvelope = append(inEnvelope, w)
		}
	}
	if !slices.Equal(inEnvelope, want) {
		t.Errorf("envelope warnings = %q, want %q", inEnvelope, want)
	}
}

func TestEndWarning_IsAWarnLine(t *testing.T) {
	t.Parallel()
	const text = "names were left behind"
	h := newHarness(t, endNoting("k", text, 2))
	if code := h.exec("a.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	n := 0
	for _, m := range h.logMsgs("WARN") {
		if strings.Contains(m, text+" after 2 jobs") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d WARN lines with the end warning, want 1\n%s", n, h.stderr.String())
	}
}

// A run cancelled part-way still warns what its values have to say.
func TestEndWarning_WarnedWhenTheRunIsInterrupted(t *testing.T) {
	t.Parallel()
	const text = "names were left behind"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &testkit.Procedure{ProcedureName: "noting", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("c", 50) },
		RunFn: func(ctx context.Context, c run.Job, _ egress.Clients) ([]run.Observation, error) {
			noteJob(ctx, "k", text)
			if c.Key == "c005" {
				cancel()
			}
			return nil, nil
		}}
	h := newHarness(t, st)
	if code := h.execCtx(ctx, "a.com", "--json", "--concurrency", "1"); code != 130 {
		t.Fatalf("exit %d, want 130\n%s", code, h.stderr.String())
	}
	if got := h.messages("warning", text); len(got) != 1 {
		t.Errorf("warnings = %q, want one end warning", got)
	}
}

// Two values' texts come out in sorted order, whichever was stored first.
func TestEndWarning_TextsInSortedOrder(t *testing.T) {
	t.Parallel()
	st := &testkit.Procedure{ProcedureName: "noting", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("c", 2) },
		RunFn: func(ctx context.Context, c run.Job, _ egress.Clients) ([]run.Observation, error) {
			if c.Key == "c000" {
				noteJob(ctx, "first", "zulu end warning")
			} else {
				noteJob(ctx, "second", "alpha end warning")
			}
			return nil, nil
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--json", "--concurrency", "1"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	want := []string{"alpha end warning after 1 jobs", "zulu end warning after 1 jobs"}
	if got := h.messages("warning", "end warning"); !slices.Equal(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	var inEnvelope []string
	for _, w := range h.envelope().Meta.Warnings {
		if strings.Contains(w, "end warning") {
			inEnvelope = append(inEnvelope, w)
		}
	}
	if !slices.Equal(inEnvelope, want) {
		t.Errorf("envelope warnings = %q, want %q", inEnvelope, want)
	}
}

// A value with nothing to say adds no warning.
func TestEndWarning_EmptyTextWarnsNothing(t *testing.T) {
	t.Parallel()
	base := newHarness(t, endNoting("k", "unused", 0))
	if code := base.exec("a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, base.stderr.String())
	}
	h := newHarness(t, endNoting("k", "", 2))
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	got, want := h.messages("warning", ""), base.messages("warning", "")
	if !slices.Equal(got, want) || slices.Contains(got, "") {
		t.Errorf("warnings = %q, want those of a run with no value: %q", got, want)
	}
}
