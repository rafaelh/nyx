package cve

import (
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/lookup/batch"
)

// Result pairs one original argument with its record or failure.
type Result struct {
	Input  string // the argument exactly as given
	ID     string // its normalised form; "" when it is not a CVE ID
	Record *Record
	Fail   *Failure
}

// Outcome collects records and per-input errors in argument order. All successes return nil
// error. Mixed results or differing failure codes return PARTIAL; all failures sharing a code
// return that code. Partial results are transient if any failure is. Retry hints include
// transient failures, otherwise input-check guidance; timeout hints also suggest raising
// --timeout.
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
