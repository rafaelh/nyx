// Package clierr is the one error a nyx command reports: what went wrong (the
// message), its error code, what to try next (the hint), the failing input,
// and whether a retry after a wait may succeed. The error codes, the exit code
// each one gets and the five keys of the JSON error are a stable interface:
// adding one is compatible, renaming or removing one is a breaking change.
//
// The package does no I/O. cli writes the error and picks the exit code;
// config, input and the stages classify their own failures with these codes.
package clierr

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Code is an error code.
type Code string

// The error codes, grouped by the exit code they get.
const (
	NetworkError  Code = "NETWORK_ERROR"
	Timeout       Code = "TIMEOUT"
	RateLimited   Code = "RATE_LIMITED"
	UpstreamError Code = "UPSTREAM_ERROR"
	AuthFailed    Code = "AUTH_FAILED"
	Unexpected    Code = "UNEXPECTED_ERROR"
	Locked        Code = "LOCKED"
	InvalidInput  Code = "INVALID_INPUT"
	NotFound      Code = "NOT_FOUND"
	Partial       Code = "PARTIAL"
	Interrupted   Code = "INTERRUPTED"
)

// exitCodes maps each error code to its exit code. INTERRUPTED's is SIGINT's;
// the caller that knows which signal arrived uses that signal's code instead.
var exitCodes = map[Code]int{
	NetworkError: 1, Timeout: 1, RateLimited: 1, UpstreamError: 1, AuthFailed: 1, Unexpected: 1, Locked: 1,
	InvalidInput: 2,
	NotFound:     3,
	Partial:      7,
	Interrupted:  130,
}

// ExitCode is the exit code of an error code; an unknown code is a system
// error.
func ExitCode(c Code) int {
	if n, ok := exitCodes[c]; ok {
		return n
	}
	return 1
}

// Target is how one target of a call with several failed, for the per-target
// lines of a partial result.
type Target struct {
	Input, Message string
	Code           Code
}

// Error is everything the error a command reports needs. Input is what the
// JSON error's input key holds: nil when no input was at fault.
type Error struct {
	Code      Code
	Message   string
	Hint      string
	Input     any
	Transient bool
	Targets   []Target
}

func (e *Error) Error() string { return e.Message }

// Problem is one failed check of a value or a combination: the argument's name
// (a setting's key, an input's flag name), the value as given, what is wrong
// and what to try instead.
type Problem struct {
	Name, Value, Message, Hint string
}

// Problems collects every problem a command's checks find, so they are
// reported together as one usage error. It is an error when it holds any.
type Problems []Problem

// Add records one problem.
func (p *Problems) Add(name, value, message, hint string) {
	*p = append(*p, Problem{Name: name, Value: value, Message: message, Hint: hint})
}

// Merge records err: the problems it holds when it is Problems, else one
// problem with its text.
func (p *Problems) Merge(err error) {
	if err == nil {
		return
	}
	if q, ok := errors.AsType[Problems](err); ok {
		*p = append(*p, q...)
		return
	}
	p.Add("", "", err.Error(), "")
}

// Err is p as an error, or nil when it holds no problem.
func (p Problems) Err() error {
	if len(p) == 0 {
		return nil
	}
	return p
}

// Error joins the messages with "; ".
func (p Problems) Error() string {
	msgs := make([]string, len(p))
	for i, q := range p {
		msgs[i] = q.Message
	}
	return strings.Join(msgs, "; ")
}

// Usage is p as one INVALID_INPUT error: the messages joined by "; ", the
// distinct hints joined by "; " (defaultHint when none has one), and an input
// that maps each named argument to the list of its failing values. Each name
// maps to a list whatever the number of values, so the shape never depends on
// how many failed.
func (p Problems) Usage(defaultHint string) *Error {
	var hints []string
	input := map[string][]string{}
	for _, q := range p {
		if q.Hint != "" && !slices.Contains(hints, q.Hint) {
			hints = append(hints, q.Hint)
		}
		if q.Name == "" {
			continue
		}
		vals := input[q.Name]
		if vals == nil {
			vals = []string{}
		}
		if q.Value != "" && !slices.Contains(vals, q.Value) {
			vals = append(vals, q.Value)
		}
		input[q.Name] = vals
	}
	e := &Error{Code: InvalidInput, Message: p.Error(), Hint: strings.Join(hints, "; ")}
	if e.Hint == "" {
		e.Hint = defaultHint
	}
	if len(input) > 0 {
		e.Input = input
	}
	return e
}

// PanicError is a panic recovered on the way to the exit: an unexpected
// failure, with the stack where it happened.
type PanicError struct {
	Value any
	Stack []byte
}

func (e *PanicError) Error() string { return fmt.Sprintf("unexpected failure: %v", e.Value) }
