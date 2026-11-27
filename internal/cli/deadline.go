package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/rafaelh/nyx/internal/clierr"
)

// errDeadline identifies cancellation caused by --timeout, allowing recon to distinguish it
// from a signal through the runner's wrapped context cause.
var errDeadline = errors.New("deadline reached")

// reserve leaves time to save files and the summary before the deadline. It uses 10% of the
// timeout, bounded to 2–60 seconds and at most half the total timeout.
func reserve(timeout time.Duration) time.Duration {
	return min(max(timeout/10, 2*time.Second), 60*time.Second, timeout/2)
}

// rawFlag preserves text for validation alongside other inputs. n optionally counts occurrences
// for single-use flags; typ supplies the help placeholder.
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

// optionalTimeout parses --timeout when it was given and is zero when it was not, collecting an
// invalid value as a problem.
func optionalTimeout(probs *clierr.Problems, cmd *cobra.Command, value, example string) time.Duration {
	if !cmd.Flags().Changed("timeout") {
		return 0
	}
	return parseTimeout(probs, value, example)
}

// parseTimeout validates a positive duration and adds invalid values to the combined problem
// list.
func parseTimeout(probs *clierr.Problems, value, example string) time.Duration {
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout <= 0 {
		probs.Add("timeout", value, fmt.Sprintf("timeout: invalid value %q: not a positive duration", value), example)
	}
	return timeout
}
