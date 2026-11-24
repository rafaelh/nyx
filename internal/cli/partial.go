package cli

import (
	"fmt"
	"strings"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/run"
)

// procedureCounts writes counts as "procedure n, procedure n".
func procedureCounts(counts []report.ProcedureCount) string {
	parts := make([]string, len(counts))
	for i, c := range counts {
		parts[i] = fmt.Sprintf("%s %d", c.Procedure, c.N)
	}
	return strings.Join(parts, ", ")
}

func sumCounts(counts []report.ProcedureCount) int {
	n := 0
	for _, c := range counts {
		n += c.N
	}
	return n
}

// partialError reports deadline-limited or failed work after results are written, or nil for a
// complete run. Its retry hint preserves the original invocation without --redo. If a deadline
// allowed no successes, the hint asks for a longer timeout and the error is non-transient.
// Failures caused solely by rejected keys are also non-transient.
func partialError(args []string, timeout string, deadline bool, res run.Result) *clierr.Error {
	failed := sumCounts(res.Summary.FailedJobs)
	if !deadline && failed == 0 {
		return nil
	}
	e := &clierr.Error{Code: clierr.Partial, Hint: invocationHint(args)}
	if !deadline {
		e.Message = fmt.Sprintf("%d checks failed: %s", failed, procedureCounts(res.Summary.FailedJobs))
		e.Transient = failed > res.KeyRejected
		return e
	}
	cancelled := sumCounts(res.Cancelled)
	e.Message = fmt.Sprintf("the deadline (--timeout %s) stopped the run: %d checks completed, %d cancelled", timeout, res.Completed, cancelled)
	if cancelled > 0 {
		e.Message += " (" + procedureCounts(res.Cancelled) + ")"
	}
	if failed > 0 {
		e.Message += "; failed checks: " + procedureCounts(res.Summary.FailedJobs)
	}
	e.Transient = res.Succeeded > 0
	if !e.Transient {
		e.Hint = fmt.Sprintf("raise --timeout: no check succeeded within %s", timeout)
	}
	return e
}
