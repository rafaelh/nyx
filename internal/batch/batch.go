// Package batch decides how a command that looks up several inputs ends: which
// error it returns, what that error says, and the hint that tells the caller
// how to retry. nyx cve and nyx ip share it, so a batch of either one ends the
// same way. It has no I/O and knows nothing of what is looked up.
//
// # Terms
//
// An item is one thing the caller looked up and that either succeeded, giving
// a record, or failed. The caller counts them: total is how many were asked and
// returned how many gave a record.
//
// A Failure is one item that failed. It has a Name, the item as the user gave
// it, which is what the messages and the "check ..." hint show; an Entry, the
// value of its meta.errors entry's input (the Name when nil); a Retry, the text
// the retry command is given for it, which is empty for a failure that is not
// worth retrying (a quota that resets daily, say); and the Err that stopped it.
// A failure's Retry may differ from its Name: a CIDR that failed on some
// addresses is shown by its Name and retried by those addresses.
//
// A Config says how the call is worded: the Noun for the items ("IDs",
// "inputs"), the Key under which the failed Names are listed in the error's
// input ("id", "input"), and the Command that retries a list of Retry texts.
//
// # The error a call ends with
//
// [Outcome] returns the meta.errors entries (one per failure, each a copy of
// its Err with the input set) and the error the call ends with, nil when
// nothing failed.
//
//   - When no record was returned and every failure has one code, the error has
//     that code and covers every failure: its message is "<name>: <message>" for
//     one failure, "<n> <noun>: <message>" when the messages agree, else
//     "<n> <noun> failed (<CODE>)". A failure that is not transient keeps the
//     hint of the first one. A transient one gets the retry hint, and when the
//     code is TIMEOUT also "or raise --timeout", since the same deadline may
//     time out again ([HintTimeout]).
//   - In any other case (some records and some failures, or no records and
//     several codes) the error is PARTIAL: "<returned> of <total> <noun>
//     returned, <k> failed", or "none of <total> <noun> returned". It lists
//     each failure in its Targets, names the failed Names under Config.Key in
//     its input, and is transient when any failure is.
//
// The retry hint is "run: <command>" for the Retry texts of the transient
// failures, after the longest Wait among them ("after 5s, run: ..."). With
// none to retry it says "check the <noun> that failed: <names>". When the
// failures are shown (a PARTIAL error, which a caller writes beside its
// records) and more than twenty would be listed, it points at meta.errors
// instead of listing them.
package batch

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
)

// maxListed is how many items a hint lists; past it, the hint points at the
// failures instead.
const maxListed = 20

// HintTimeout is the hint that goes with a timeout: the deadline is the
// caller's to raise.
const HintTimeout = "raise --timeout"

// Config is how a batch is worded and retried.
type Config struct {
	// Noun names the items in messages: "IDs", "inputs".
	Noun string
	// Key is the key of the error's input map that lists the failed Names.
	Key string
	// Command is the command, with the caller's flags, that looks the given
	// Retry texts up again.
	Command func(retry []string) string
}

// Failure is one item that failed.
type Failure struct {
	// Name is the item as the user gave it.
	Name string
	// Entry is the value of the failure's meta.errors entry's input; Name when nil.
	Entry any
	// Retry is what the retry command is given for this failure. Empty when it
	// is not worth retrying, whether or not Err is transient.
	Retry string
	// Err is why it failed. Its Input is set by Outcome on a copy.
	Err *clierr.Error
	// Wait is how long to wait before a retry may succeed; 0 when not known.
	Wait time.Duration
}

// Outcome is the meta.errors entries and the error a batch of total items
// ends with, when returned of them gave a record and failures failed, in the
// order the items were given. The error is nil when there are no failures.
func Outcome(c Config, total, returned int, failures []Failure) ([]*clierr.Error, *clierr.Error) {
	if len(failures) == 0 {
		return nil, nil
	}
	var metaErrs []*clierr.Error
	var names []string
	transient := false
	for _, f := range failures {
		names = append(names, f.Name)
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
	// A single code's error is all that is written, so its hint lists every item however many.
	e := &clierr.Error{Input: map[string][]string{c.Key: names}, Transient: transient, Hint: retryHint(c, failures, names, !single)}
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

// oneCode is the code every failure has, if they share one.
func oneCode(failures []Failure) (clierr.Code, bool) {
	code := failures[0].Err.Code
	for _, f := range failures[1:] {
		if f.Err.Code != code {
			return "", false
		}
	}
	return code, true
}

// oneCodeMessage is the message of an error that covers every failure, all
// with one code.
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

// retryHint is the command that retries the transient failures, after the
// longest known wait, or, when none is worth retrying, the items to check.
// When the failures are written (shown), past maxListed items it points at
// them instead of listing them.
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

// Seconds is d in whole seconds, rounded up so a caller never retries early,
// and at least 1s: "5s".
func Seconds(d time.Duration) string {
	return strconv.Itoa(max(int((d+time.Second-1)/time.Second), 1)) + "s"
}
