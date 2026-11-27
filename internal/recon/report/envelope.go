package report

import (
	"encoding/json"
	"io"
	"sync"
)

// Envelope is recon's single stdout JSON object. Its keys follow the stable Summary interface.
type Envelope struct {
	Data Summary `json:"data"`
	Meta Meta    `json:"meta"`
}

// Meta describes invocation status and diagnostics around the data.
type Meta struct {
	Count            int      `json:"count"`
	DeadlineExceeded bool     `json:"deadline_exceeded"`
	JobsCompleted    int      `json:"jobs_completed"`
	JobsCancelled    int      `json:"jobs_cancelled"`
	Warnings         []string `json:"warnings"`
}

// Map deep-copies all strings, including warnings, without sharing slices or pointers. Nil
// lists stay nil.
func (e Envelope) Map(f func(string) string) Envelope {
	return e.clone(f, false)
}

// WriteEnvelope emits one compact JSON line in struct-field order without HTML escaping. Nil
// lists become []; nil detail/changes remain null. It does not mutate e.
func WriteEnvelope(w io.Writer, e Envelope) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(e.clone(func(s string) string { return s }, true))
}

// clone maps strings in a deep copy and optionally converts nil lists to empty lists.
func (e Envelope) clone(f func(string) string, nonNil bool) Envelope {
	s := e.Data
	procedure := func(r ProcedureCount) ProcedureCount { return ProcedureCount{f(r.Procedure), r.N} }
	out := Envelope{Meta: e.Meta}
	out.Data = Summary{
		Engagement:            f(s.Engagement),
		Directory:             f(s.Directory),
		Counts:                mapRows(s.Counts, nonNil, func(r CountRow) CountRow { return CountRow{f(r.Category), r.N} }),
		FailedJobs:            mapRows(s.FailedJobs, nonNil, procedure),
		Deferred:              mapRows(s.Deferred, nonNil, procedure),
		NotConfigured:         mapRows(s.NotConfigured, nonNil, func(r ProcedureReason) ProcedureReason { return ProcedureReason{f(r.Procedure), f(r.Reason)} }),
		Findings:              mapFindings(s.Findings, nonNil, f),
		Candidates:            mapRows(s.Candidates, nonNil, func(r CandidateRow) CandidateRow { return cloneCandidate(r, nonNil, f) }),
		CandidatesTotal:       s.CandidatesTotal,
		UnconfirmedRiskyPorts: s.UnconfirmedRiskyPorts,
		HostsInScopeByAddress: s.HostsInScopeByAddress,
		Notes:                 mapRows(s.Notes, nonNil, f),
	}
	if s.Changes != nil {
		out.Data.Changes = &Changes{
			Counts: mapRows(s.Changes.Counts, nonNil, func(r ChangeCount) ChangeCount {
				return ChangeCount{f(r.Kind), f(r.Change), r.N}
			}),
			Findings: mapFindings(s.Changes.Findings, nonNil, f),
		}
	}
	out.Meta.Warnings = mapRows(e.Meta.Warnings, nonNil, f)
	return out
}

func cloneCandidate(r CandidateRow, nonNil bool, f func(string) string) CandidateRow {
	return CandidateRow{
		Kind: f(r.Kind), Value: f(r.Value), Sources: mapRows(r.Sources, nonNil, f),
		EvidenceCount: r.EvidenceCount, Confidence: f(r.Confidence), Promote: f(r.Promote),
	}
}

func mapFindings(rows []FindingRow, nonNil bool, f func(string) string) []FindingRow {
	return mapRows(rows, nonNil, func(r FindingRow) FindingRow {
		out := FindingRow{Severity: f(r.Severity), Category: f(r.Category), Target: f(r.Target)}
		if r.Detail != nil {
			d := f(*r.Detail)
			out.Detail = &d
		}
		return out
	})
}

// mapRows copies mapped elements, optionally normalising nil to an empty slice.
func mapRows[T any](rows []T, nonNil bool, f func(T) T) []T {
	if rows == nil && !nonNil {
		return nil
	}
	out := make([]T, len(rows))
	for i, r := range rows {
		out[i] = f(r)
	}
	return out
}

// Warnings safely collects only warning messages in emission order across goroutines.
type Warnings struct {
	mu   sync.Mutex
	msgs []string
}

// Emit keeps a warning's message.
func (w *Warnings) Emit(ev Event) {
	if ev.Type != "warning" {
		return
	}
	msg := str(ev.Fields, "message")
	w.mu.Lock()
	w.msgs = append(w.msgs, msg)
	w.mu.Unlock()
}

// List is a copy of the messages kept so far, never nil.
func (w *Warnings) List() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string{}, w.msgs...)
}
