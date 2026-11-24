// Package clierr defines command errors with a code, message, hint, input and retry status.
// Codes, exit mappings and JSON keys form a stable interface. The package performs no I/O; cli
// prints errors and selects exit codes, while callers classify failures.
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

// exitCodes maps errors to process status. INTERRUPTED defaults to SIGINT; signal-aware callers
// use the received signal's status instead.
var exitCodes = map[Code]int{
	NetworkError: 1, Timeout: 1, RateLimited: 1, UpstreamError: 1, AuthFailed: 1, Unexpected: 1, Locked: 1,
	InvalidInput: 2,
	NotFound:     3,
	Partial:      7,
	Interrupted:  130,
}

// ExitCode defaults unrecognised error codes to system failure.
func ExitCode(c Code) int {
	if n, ok := exitCodes[c]; ok {
		return n
	}
	return 1
}

// Target supplies failed-item detail lines for partial command outcomes.
type Target struct {
	Input, Message string
	Code           Code
}

// Error describes a command failure. Input is nil when no particular input caused it.
type Error struct {
	Code      Code
	Message   string
	Hint      string
	Input     any
	Transient bool
	Targets   []Target
}

func (e *Error) Error() string { return e.Message }

// Problem identifies an invalid argument or combination, preserving its original value,
// explanation and suggested correction.
type Problem struct {
	Name, Value, Message, Hint string
}

// Problems collects validation failures for one usage error; an empty collection is not an
// error.
type Problems []Problem

// Add records one problem.
func (p *Problems) Add(name, value, message, hint string) {
	*p = append(*p, Problem{Name: name, Value: value, Message: message, Hint: hint})
}

// Merge flattens Problems or adds a generic error's text as one problem.
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

// Err returns nil for no problems, otherwise the collection as an error.
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

// Usage combines problems as INVALID_INPUT. It joins messages and distinct hints, falling back
// to defaultHint. Input maps each argument name to a list of invalid values, keeping the JSON
// shape consistent even for one value.
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

// PanicError carries an unexpected recovered panic with its captured stack.
type PanicError struct {
	Value any
	Stack []byte
}

func (e *PanicError) Error() string { return fmt.Sprintf("unexpected failure: %v", e.Value) }
