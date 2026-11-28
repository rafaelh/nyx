package cli

// Shared lookup-command support covers input/stdin handling, retry hints, partial results and
// JSON envelopes for nyx cve and nyx ip.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/recon/report"
	"github.com/rafaelh/nyx/internal/term/shellquote"
)

// maxStdinLine is the longest line a lookup command reads from stdin.
const maxStdinLine = 64 << 10

// stdinWords supplies lookup-specific input and error wording.
type stdinWords struct {
	// none is the message of a call with no arguments, before ", or - to read them from stdin".
	none string
	// key names an argument in an error's input: "id", "input".
	key string
	// plural names stdin entries in messages such as "no CVE IDs on stdin".
	plural string
	// perLine is the hint of a line that is too long, after "give".
	perLine string
	// asArgs names what could be passed as arguments instead, as in "pass the IDs as arguments".
	asArgs string
}

// lookupArgs validates nonempty inputs and the standalone "-" stdin form, collecting problems
// in probs. It returns whether stdin was selected.
func lookupArgs(probs *clierr.Problems, args []string, w stdinWords) (stdin bool) {
	switch {
	case len(args) == 0:
		probs.Add("", "", w.none+", or - to read them from stdin", "nyx --help")
	case slices.Contains(args, "-") && len(args) > 1:
		probs.Add(w.key, "-", "- reads the "+w.asArgs+" from stdin, and is given alone",
			"pass the "+w.asArgs+" as arguments, or - alone")
	}
	return len(args) == 1 && args[0] == "-"
}

// readLines preserves nonblank input lines without their line endings. Cancellation or deadline
// abandons a blocked read so open stdin cannot hang the command.
func readLines(ctx context.Context, r io.Reader, w stdinWords) ([]string, error) {
	type read struct {
		lines []string
		err   error
	}
	done := make(chan read, 1)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 4096), maxStdinLine)
		var lines []string
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) != "" {
				lines = append(lines, sc.Text())
			}
		}
		done <- read{lines, sc.Err()}
	}()
	select {
	case got := <-done:
		switch {
		case errors.Is(got.err, bufio.ErrTooLong):
			return nil, &clierr.Error{Code: clierr.InvalidInput, Message: "a line on stdin is longer than 64 KiB", Hint: "give " + w.perLine}
		case got.err != nil:
			return nil, fmt.Errorf("read stdin: %w", got.err)
		case len(got.lines) == 0:
			return nil, &clierr.Error{Code: clierr.InvalidInput, Message: "no " + w.plural + " on stdin", Hint: "nyx --help"}
		}
		return got.lines, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &clierr.Error{Code: clierr.Timeout, Message: "stdin was not closed before the deadline",
				Hint: "close stdin, or pass the " + w.asArgs + " as arguments"}
		}
		return nil, ctx.Err() // a signal, which Execute reports
	}
}

// retryCommand builds a shell-quoted invocation for failed inputs, preserving --json and
// explicitly supplied flag values. Boolean flags are included only when true.
func retryCommand(name string, jsonMode bool, fs *pflag.FlagSet, flags ...string) func(inputs []string) string {
	var tail []string
	if jsonMode {
		tail = append(tail, "--json")
	}
	for _, n := range flags {
		f := fs.Lookup(n)
		switch {
		case !f.Changed:
		case f.Value.Type() == "bool":
			if f.Value.String() == "true" {
				tail = append(tail, "--"+n)
			}
		default:
			tail = append(tail, "--"+n, f.Value.String())
		}
	}
	return func(inputs []string) string {
		return "nyx " + name + " " + shellquote.Join(append(slices.Clone(inputs), tail...))
	}
}

// endLookup writes available records before returning a partial error. When every input fails
// with one error code, it returns the error without writing output.
func endLookup(outErr *clierr.Error, write func() error) error {
	if outErr != nil && outErr.Code != clierr.Partial {
		return outErr
	}
	if err := write(); err != nil {
		return err
	}
	if outErr != nil {
		return outErr // not a nil *clierr.Error in a non-nil error
	}
	return nil
}

// lookupEnvelope is the --json result of a lookup command.
type lookupEnvelope[T any] struct {
	Data []T        `json:"data"`
	Meta lookupMeta `json:"meta"`
}

// lookupMeta always includes every envelope key. Empty errors/warnings are lists; absent hints
// are null. CVE uses the hint to explain how to include omitted lists.
type lookupMeta struct {
	Count    int         `json:"count"`
	Errors   []errorLine `json:"errors"`
	Warnings []string    `json:"warnings"`
	Hint     *string     `json:"hint"`
}

// writeEnvelope emits lookup data, per-input errors, warnings and an optional hint.
func writeEnvelope[T any](inv *invocation, data []T, metaErrs []*clierr.Error, warnings *report.Warnings, hint string, red *config.Redactor) error {
	env := lookupEnvelope[T]{Data: data,
		Meta: lookupMeta{Count: len(data), Errors: make([]errorLine, len(metaErrs)), Warnings: warnings.List()}}
	if hint != "" {
		env.Meta.Hint = &hint
	}
	for i, e := range metaErrs {
		env.Meta.Errors[i] = newErrorLine(e, red)
	}
	for i, w := range env.Meta.Warnings {
		env.Meta.Warnings[i] = red.Redact(w) // again after sanitisation, which can rejoin a key
	}
	return lineEncoder(inv.d.Stdout).Encode(env)
}
