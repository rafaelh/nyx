package cli

// What the lookup commands (nyx cve and nyx ip) share: their arguments and stdin, the retry
// command of their hints, how a call that failed in part still writes, and the --json envelope.

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
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/shellquote"
)

// maxStdinLine is the longest line a lookup command reads from stdin.
const maxStdinLine = 64 << 10

// stdinWords are the words of the errors of a lookup command's arguments and stdin, which differ
// by what the command looks up.
type stdinWords struct {
	// none is the message of a call with no arguments, before ", or - to read them from stdin".
	none string
	// key names an argument in an error's input: "id", "input".
	key string
	// plural names what the lines are, as in "no CVE IDs on stdin".
	plural string
	// perLine is the hint of a line that is too long, after "give".
	perLine string
	// asArgs names what could be passed as arguments instead, as in "pass the IDs as arguments".
	asArgs string
}

// lookupArgs adds to probs the problem of args that name nothing to look up, or that give - with
// other arguments, and reports whether the inputs are read from stdin: a lone -.
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

// readLines reads the lines of stdin that are not blank, each as given without
// its line ending. The read is abandoned at the deadline or a signal, as a
// stdin that is never closed would otherwise block the call.
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

// retryCommand is the command that looks the given inputs up again: nyx with the command's name,
// the inputs, --json under it, then each of the named flags the caller set, as typed (a bool flag
// only when true), shell-quoted.
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

// endLookup is how a lookup call ends once outErr is known: with outErr alone when no record came
// back (all failed with one code, so stdout stays empty), else after write has written the result,
// with outErr, which is then PARTIAL or nil.
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

// lookupMeta is the envelope's meta. Every key is there every time: errors and warnings are empty
// lists when there is none, and hint is null when the command has nothing to say about the result
// (nyx cve's note on how to see the lists the default leaves out).
type lookupMeta struct {
	Count    int         `json:"count"`
	Errors   []errorLine `json:"errors"`
	Warnings []string    `json:"warnings"`
	Hint     *string     `json:"hint"`
}

// writeEnvelope writes the --json envelope of data, with the meta.errors entries, the warnings
// and the hint, null when empty.
func writeEnvelope[T any](inv *invocation, data []T, metaErrs []*clierr.Error, warnings *report.Warnings, hint string, red *config.Redactor) error {
	env := lookupEnvelope[T]{Data: data,
		Meta: lookupMeta{Count: len(data), Errors: make([]errorLine, len(metaErrs)), Warnings: warnings.List()}}
	if hint != "" {
		env.Meta.Hint = &hint
	}
	for i, e := range metaErrs {
		env.Meta.Errors[i] = newErrorLine(e, red)
	}
	return lineEncoder(inv.d.Stdout).Encode(env)
}
