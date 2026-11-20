package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
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

// rawFlag is a flag whose text is kept as given, so that it is checked after parsing with every
// other value and a bad one is reported with the rest. When n is set it counts how many times the
// flag was set, for a flag that may be given only once. typ is what help calls its value.
type rawFlag struct {
	raw *string
	n   *int
	typ string
}

// timeoutFlag is --timeout, a duration.
func timeoutFlag(raw *string) rawFlag { return rawFlag{raw: raw, typ: "duration"} }

func (f rawFlag) String() string {
	if f.raw == nil {
		return ""
	}
	return *f.raw
}

func (f rawFlag) Set(s string) error {
	*f.raw = s
	if f.n != nil {
		*f.n++
	}
	return nil
}

func (f rawFlag) Type() string { return f.typ }

// parseTimeout is --timeout's value as a duration. A value that is not a positive duration is
// recorded as a problem, with example as its hint.
func parseTimeout(probs *clierr.Problems, value, example string) time.Duration {
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout <= 0 {
		probs.Add("timeout", value, fmt.Sprintf("timeout: invalid value %q: not a positive duration", value), example)
	}
	return timeout
}
