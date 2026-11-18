package cli

import (
	"fmt"
	"strings"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/run"
)

// stageCounts writes counts as "stage n, stage n".
func stageCounts(counts []report.StageCount) string {
	parts := make([]string, len(counts))
	for i, c := range counts {
		parts[i] = fmt.Sprintf("%s %d", c.Stage, c.N)
	}
	return strings.Join(parts, ", ")
}

func sumCounts(counts []report.StageCount) int {
	n := 0
	for _, c := range counts {
		n += c.N
	}
	return n
}

// partialError is the PARTIAL error of a run that wrote its result but did not finish its work: the
// deadline stopped it (timeout is the --timeout text as the caller typed it), or checks failed. It
// returns nil for a run that did all its work.
//
// The hint is the caller's own call without --redo, which carries on where the run stopped. When the
// deadline ended a run in which no check succeeded, repeating the call would go no further, so the
// hint says to raise --timeout and the error is not transient. A failure that is only a refused key
// is not transient either: waiting does not cure it.
func partialError(args []string, timeout string, deadline bool, res run.Result) *clierr.Error {
	failed := sumCounts(res.Summary.FailedChecks)
	if !deadline && failed == 0 {
		return nil
	}
	e := &clierr.Error{Code: clierr.Partial, Hint: invocationHint(args)}
	if !deadline {
		e.Message = fmt.Sprintf("%d checks failed: %s", failed, stageCounts(res.Summary.FailedChecks))
		e.Transient = failed > res.KeyRejected
		return e
	}
	cancelled := sumCounts(res.Cancelled)
	e.Message = fmt.Sprintf("the deadline (--timeout %s) stopped the run: %d checks completed, %d cancelled", timeout, res.Completed, cancelled)
	if cancelled > 0 {
		e.Message += " (" + stageCounts(res.Cancelled) + ")"
	}
	if failed > 0 {
		e.Message += "; failed checks: " + stageCounts(res.Summary.FailedChecks)
	}
	e.Transient = res.Succeeded > 0
	if !e.Transient {
		e.Hint = fmt.Sprintf("raise --timeout: no check succeeded within %s", timeout)
	}
	return e
}
