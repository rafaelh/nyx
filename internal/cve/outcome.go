package cve

import (
	"github.com/rafaelh/nyx/internal/batch"
	"github.com/rafaelh/nyx/internal/clierr"
)

// Result is how one argument of a batch ended: a record, or the failure that
// stopped it.
type Result struct {
	Input  string // the argument exactly as given
	ID     string // its normalised form; "" when it is not a CVE ID
	Record *Record
	Fail   *Failure
}

// Outcome is what a batch returns, from its results in argument order: the
// records, a meta.errors entry for each failure (its error, with the argument
// as given as its input) and the error the call ends with, nil when every ID
// succeeded. command is the command, with the caller's flags, that looks the
// given IDs up again.
//
// When some succeeded, or none did with different error codes, the error is
// PARTIAL: it counts what succeeded and what did not, lists the failed
// arguments in its input, and is transient when any failure is. When none
// succeeded and all failed with one code, the error has that code and covers
// every ID. Either way the hint is the command that retries the transient
// failures, or else says to check the IDs that failed; a single code's error
// that is not transient keeps that code's hint, and one of timeouts also
// says to raise --timeout.
func Outcome(results []Result, command func(ids []string) string) ([]Record, []*clierr.Error, *clierr.Error) {
	var records []Record
	var failures []batch.Failure
	for _, r := range results {
		if r.Fail == nil {
			records = append(records, *r.Record)
			continue
		}
		failures = append(failures, batch.Failure{Name: r.Input, Retry: r.ID, Err: r.Fail.Err, Wait: r.Fail.Wait})
	}
	metaErrs, err := batch.Outcome(batch.Config{Noun: "IDs", Key: "id", Command: command},
		len(results), len(records), failures)
	return records, metaErrs, err
}
