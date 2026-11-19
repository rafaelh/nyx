package cve

import (
	"fmt"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
)

// maxListed is how many IDs a hint lists; past it, the hint points at the
// failures instead.
const maxListed = 20

// Result is how one argument of a batch ended: a record, or the failure that
// stopped it.
type Result struct {
	Input  string // the argument exactly as given
	ID     string // its normalised form; "" when it is not a CVE ID
	Record *Record
	Fail   *Failure
}

// HintFunc is the command that looks ids up again, with the caller's flags.
type HintFunc func(ids []string) string

// Outcome is what a batch returns, from its results in argument order: the
// records, a meta.errors entry for each failure (its error, with the argument
// as given as its input) and the error the call ends with, nil when every ID
// succeeded.
//
// When some succeeded, or none did with different error codes, the error is
// PARTIAL: it counts what succeeded and what did not, lists the failed
// arguments in its input, and is transient when any failure is. When none
// succeeded and all failed with one code, the error has that code and covers
// every ID. Either way the hint is the command that retries the transient
// failures, or else says to check the IDs that failed; a single code's error
// that is not transient keeps that code's hint, and one of timeouts also
// says to raise --timeout.
func Outcome(results []Result, hint HintFunc) ([]Record, []*clierr.Error, *clierr.Error) {
	var records []Record
	var metaErrs []*clierr.Error
	var failed []Result
	var inputs []string
	transient := false
	for _, r := range results {
		if r.Fail == nil {
			records = append(records, *r.Record)
			continue
		}
		failed, inputs = append(failed, r), append(inputs, r.Input)
		transient = transient || r.Fail.Err.Transient
		e := *r.Fail.Err
		e.Input = r.Input
		metaErrs = append(metaErrs, &e)
	}
	if len(failed) == 0 {
		return records, metaErrs, nil
	}
	code, single := oneCode(failed)
	single = single && len(records) == 0
	// A single code's error is all that is written, so its hint lists every ID however many.
	e := &clierr.Error{Input: map[string][]string{"id": inputs}, Transient: transient, Hint: retryHint(failed, inputs, hint, !single)}
	if single {
		first := failed[0].Fail.Err
		e.Code = code
		e.Message = oneCodeMessage(failed)
		switch {
		case !transient:
			e.Hint = first.Hint
		case code == clierr.Timeout: // the same deadline may time out again
			e.Hint += ", or " + hintTimeout
		}
		return nil, metaErrs, e
	}
	e.Code = clierr.Partial
	e.Message = fmt.Sprintf("%d of %d IDs returned, %d failed", len(records), len(results), len(failed))
	if len(records) == 0 {
		e.Message = fmt.Sprintf("none of %d IDs returned", len(results))
	}
	for _, f := range failed {
		e.Targets = append(e.Targets, clierr.Target{Input: f.Input, Message: f.Fail.Err.Message, Code: f.Fail.Err.Code})
	}
	return records, metaErrs, e
}

// oneCode is the code every failure has, if they share one.
func oneCode(failed []Result) (clierr.Code, bool) {
	code := failed[0].Fail.Err.Code
	for _, f := range failed[1:] {
		if f.Fail.Err.Code != code {
			return "", false
		}
	}
	return code, true
}

// oneCodeMessage is the message of an error that covers every failure, all
// with one code: "<input>: <message>" for one, "<n> IDs: <message>" when the
// messages agree, else "<n> IDs failed (<CODE>)".
func oneCodeMessage(failed []Result) string {
	first := failed[0].Fail.Err
	if len(failed) == 1 {
		return failed[0].Input + ": " + first.Message
	}
	for _, f := range failed[1:] {
		if f.Fail.Err.Message != first.Message {
			return fmt.Sprintf("%d IDs failed (%s)", len(failed), first.Code)
		}
	}
	return fmt.Sprintf("%d IDs: %s", len(failed), first.Message)
}

// retryHint is the command that retries the transient failures, after the
// longest known wait, or, when none is worth retrying, the IDs to check.
// When the failures are written (shown), past maxListed IDs it points at them
// instead of listing them.
func retryHint(failed []Result, inputs []string, hint HintFunc, shown bool) string {
	var ids []string
	var wait time.Duration
	for _, f := range failed {
		if f.Fail.Err.Transient {
			ids = append(ids, f.ID)
			wait = max(wait, f.Fail.Wait)
		}
	}
	switch {
	case len(ids) == 0 && shown && len(inputs) > maxListed:
		return fmt.Sprintf("check the %d IDs that failed in meta.errors (or the error: lines)", len(inputs))
	case len(ids) == 0:
		return "check the IDs that failed: " + strings.Join(inputs, ", ")
	}
	prefix := ""
	if wait > 0 {
		prefix = "after " + seconds(wait) + ", "
	}
	if shown && len(ids) > maxListed {
		return prefix + fmt.Sprintf("retry the %d failed IDs marked transient in meta.errors (or the error: lines)", len(ids))
	}
	return prefix + "run: " + hint(ids)
}
