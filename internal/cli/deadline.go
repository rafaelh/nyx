package cli

import (
	"errors"
	"time"
)

// errDeadline is the cause of the cancel the --timeout timer sends: the runner returns an error
// that wraps the context's cause, so recon tells a deadline from a signal by it.
var errDeadline = errors.New("deadline reached")

// reserve is how long before the deadline recon stops starting checks and cancels those in
// flight, so that its files and summary are written by the deadline: a tenth of the timeout, at
// least 2 seconds and at most 60, and never more than half the timeout.
func reserve(timeout time.Duration) time.Duration {
	return min(max(timeout/10, 2*time.Second), 60*time.Second, timeout/2)
}

// timeoutFlag is --timeout. It keeps the text as given, so that recon checks it with every other
// value and reports a bad one with the rest; its Type is "duration", as shown in help.
type timeoutFlag struct{ raw *string }

func (t timeoutFlag) String() string {
	if t.raw == nil {
		return ""
	}
	return *t.raw
}
func (t timeoutFlag) Set(s string) error { *t.raw = s; return nil }
func (timeoutFlag) Type() string         { return "duration" }
