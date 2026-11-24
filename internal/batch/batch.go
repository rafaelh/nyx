// Package batch shares lookup concurrency and outcome rules between nyx cve and nyx ip without
// I/O or knowledge of record contents. Each schedules items; Outcome builds per-item errors and
// the final command error.
//
// Failure separates display Name, meta.errors Entry, original Given inputs and Retry arguments.
// This allows a failed CIDR input to be displayed as entered but retried as individual
// addresses. Config supplies wording and the retry-command builder.
//
// If nothing returns and failures share a code, Outcome returns that code. Otherwise failures
// produce PARTIAL with returned/failed counts. Transient failures can be retried after the
// longest suggested wait; timeout hints also suggest raising --timeout. Non-retryable failures
// get input-check guidance. Long failure lists point to meta.errors instead of expanding every
// item.
package batch

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
)

// maxListed bounds expanded failure lists in hints.
const maxListed = 20

// HintTimeout suggests increasing the caller-controlled deadline.
const HintTimeout = "raise --timeout"

// Config supplies item wording and retry-command construction.
type Config struct {
	// Noun names the items in messages: "IDs", "inputs".
	Noun string
	// Key names the final error's map entry containing failed original inputs.
	Key string
	// Command builds a retry invocation using the caller's flags.
	Command func(retry []string) string
}

// Failure is one item that failed.
type Failure struct {
	// Name preserves the user's item text for display.
	Name string
	// Entry overrides meta.errors input; nil defaults to Name.
	Entry any
	// Given preserves original inputs for the final error, defaulting to Name. Failed
	// addresses can name every input that produced them.
	Given []string
	// Retry supplies the retry-command argument. Empty disables retry guidance for this
	// failure even if Err is transient.
	Retry string
	// Err supplies failure details; Outcome copies it before attaching input.
	Err *clierr.Error
	// Wait suggests a retry delay; zero means unknown.
	Wait time.Duration
}

// Outcome returns ordered per-failure errors and the final error for total items and returned
// records. No failures means nil error.
func Outcome(c Config, total, returned int, failures []Failure) ([]*clierr.Error, *clierr.Error) {
	if len(failures) == 0 {
		return nil, nil
	}
	var metaErrs []*clierr.Error
	var names []string
	given, seen := []string{}, map[string]bool{}
	transient := false
	for _, f := range failures {
		names = append(names, f.Name)
		typed := f.Given
		if typed == nil {
			typed = []string{f.Name}
		}
		for _, g := range typed {
			if !seen[g] {
				seen[g] = true
				given = append(given, g)
			}
		}
		transient = transient || f.Err.Transient
		e := *f.Err
		e.Input = f.Name
		if f.Entry != nil {
			e.Input = f.Entry
		}
		metaErrs = append(metaErrs, &e)
	}
	code, single := oneCode(failures)
	single = single && returned == 0
	// Without per-item output, the shared-code error hint must name all failed items.
	e := &clierr.Error{Input: map[string][]string{c.Key: given}, Transient: transient, Hint: retryHint(c, failures, names, !single)}
	if single {
		first := failures[0].Err
		e.Code = code
		e.Message = oneCodeMessage(c, failures)
		switch {
		case !transient:
			e.Hint = first.Hint
		case code == clierr.Timeout: // the same deadline may time out again
			e.Hint += ", or " + HintTimeout
		}
		return metaErrs, e
	}
	e.Code = clierr.Partial
	e.Message = fmt.Sprintf("%d of %d %s returned, %d failed", returned, total, c.Noun, len(failures))
	if returned == 0 {
		e.Message = fmt.Sprintf("none of %d %s returned", total, c.Noun)
	}
	for _, f := range failures {
		e.Targets = append(e.Targets, clierr.Target{Input: f.Name, Message: f.Err.Message, Code: f.Err.Code})
	}
	return metaErrs, e
}

// oneCode detects a code shared by all failures.
func oneCode(failures []Failure) (clierr.Code, bool) {
	code := failures[0].Err.Code
	for _, f := range failures[1:] {
		if f.Err.Code != code {
			return "", false
		}
	}
	return code, true
}

// oneCodeMessage summarises failures sharing an error code.
func oneCodeMessage(c Config, failures []Failure) string {
	first := failures[0].Err
	if len(failures) == 1 {
		return failures[0].Name + ": " + first.Message
	}
	for _, f := range failures[1:] {
		if f.Err.Message != first.Message {
			return fmt.Sprintf("%d %s failed (%s)", len(failures), c.Noun, first.Code)
		}
	}
	return fmt.Sprintf("%d %s: %s", len(failures), c.Noun, first.Message)
}

// retryHint uses retryable failures and their longest wait. Without any, it lists items to
// check. Large failure lists already shown in output point to meta.errors.
func retryHint(c Config, failures []Failure, names []string, shown bool) string {
	var retry []string
	var wait time.Duration
	for _, f := range failures {
		if f.Err.Transient && f.Retry != "" {
			retry = append(retry, f.Retry)
			wait = max(wait, f.Wait)
		}
	}
	switch {
	case len(retry) == 0 && shown && len(names) > maxListed:
		return fmt.Sprintf("check the %d %s that failed in meta.errors (or the error: lines)", len(names), c.Noun)
	case len(retry) == 0:
		return "check the " + c.Noun + " that failed: " + strings.Join(names, ", ")
	}
	prefix := ""
	if wait > 0 {
		prefix = "after " + Seconds(wait) + ", "
	}
	if shown && len(retry) > maxListed {
		return prefix + fmt.Sprintf("retry the %d failed %s marked transient in meta.errors (or the error: lines)", len(retry), c.Noun)
	}
	return prefix + "run: " + c.Command(retry)
}

// Seconds rounds delays up to whole seconds, with a one-second minimum to avoid early retries.
func Seconds(d time.Duration) string {
	return strconv.Itoa(max(int((d+time.Second-1)/time.Second), 1)) + "s"
}

// Each starts indexes in order with at most workers concurrent calls, then waits for all
// started work to finish.
func Each(n, workers int, fn func(i int)) {
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(workers, n) {
		wg.Go(func() {
			for {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				fn(i)
			}
		})
	}
	wg.Wait()
}
