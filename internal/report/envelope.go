package report

import (
	"encoding/json"
	"io"
	"sync"
)

// Envelope is the one object a recon --json run writes to stdout. Its keys are a
// stable interface (see Summary).
type Envelope struct {
	Data Summary `json:"data"`
	Meta Meta    `json:"meta"`
}

// Meta is what the envelope says about the run itself.
type Meta struct {
	Count            int      `json:"count"`
	DeadlineExceeded bool     `json:"deadline_exceeded"`
	ChecksCompleted  int      `json:"checks_completed"`
	ChecksCancelled  int      `json:"checks_cancelled"`
	Warnings         []string `json:"warnings"`
}

// Map returns a copy of e with every string mapped, the warnings included. The copy
// shares no slice or pointer with e. A nil list stays nil.
func (e Envelope) Map(f func(string) string) Envelope {
	return e.clone(f, false)
}

// WriteEnvelope writes e as one compact JSON line, with the keys in the order of the
// types and HTML characters as they are. Every list is written as [] when it is nil, so
// every key appears on every run; a nil detail and nil changes are null. e is not changed.
func WriteEnvelope(w io.Writer, e Envelope) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(e.clone(func(s string) string { return s }, true))
}

// clone is the deep copy behind Map and WriteEnvelope: every string goes through f, and
// when nonNil is set a nil list becomes an empty one.
func (e Envelope) clone(f func(string) string, nonNil bool) Envelope {
	s := e.Data
	stage := func(r StageCount) StageCount { return StageCount{f(r.Stage), r.N} }
	out := Envelope{Meta: e.Meta}
	out.Data = Summary{
		Engagement:            f(s.Engagement),
		Directory:             f(s.Directory),
		Counts:                mapRows(s.Counts, nonNil, func(r CountRow) CountRow { return CountRow{f(r.Category), r.N} }),
		FailedChecks:          mapRows(s.FailedChecks, nonNil, stage),
		Deferred:              mapRows(s.Deferred, nonNil, stage),
		NotConfigured:         mapRows(s.NotConfigured, nonNil, func(r StageReason) StageReason { return StageReason{f(r.Stage), f(r.Reason)} }),
		Findings:              mapFindings(s.Findings, nonNil, f),
		Candidates:            mapRows(s.Candidates, nonNil, func(r CandidateRow) CandidateRow { return cloneCandidate(r, nonNil, f) }),
		CandidatesTotal:       s.CandidatesTotal,
		UnconfirmedRiskyPorts: s.UnconfirmedRiskyPorts,
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

// mapRows is a new slice of f of each element. A nil slice stays nil unless nonNil is
// set.
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

// Warnings is an Emitter that keeps the message of each warning event, in order, and
// nothing else. It is safe for concurrent use.
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
