package run

import (
	"cmp"
	"maps"
	"path/filepath"
	"slices"

	"github.com/rafaelh/nyx/internal/candidates"
	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/store"
)

// maxListedCandidates limits the console list; candidates.csv contains the rest.
const maxListedCandidates = 20

// Result contains the rendered summary and counters used to decide the command's outcome.
// Completed includes checks that returned successfully or with an error; Succeeded counts only
// successes. Cancelled checks are retried next run and are counted separately, by stage. Checks
// abandoned after a stage abort count as failures without being completed. Summary.FailedChecks
// holds the failure totals.
type Result struct {
	Summary   report.Summary
	Completed int
	Succeeded int
	Cancelled []report.StageCount
	// KeyRejected counts failures caused by a rejected API key, including checks abandoned
	// after the rejection.
	KeyRejected int
}

// result builds the outcome using run counters and the last render's category totals.
func (r *Runner) result() Result {
	res := Result{}
	r.mu.Lock()
	failed, deferred := []report.StageCount{}, []report.StageCount{}
	for _, name := range slices.Sorted(maps.Keys(r.stats)) {
		s := r.stats[name]
		if s.failed > 0 {
			failed = append(failed, report.StageCount{Stage: name, N: s.failed})
		}
		if s.deferred > 0 {
			deferred = append(deferred, report.StageCount{Stage: name, N: s.deferred})
		}
		res.Completed += s.completed
		res.Succeeded += s.succeeded
		res.KeyRejected += s.rejected
	}
	for _, name := range r.order {
		if s := r.stats[name]; s != nil && s.cancelled > 0 {
			res.Cancelled = append(res.Cancelled, report.StageCount{Stage: name, N: s.cancelled})
		}
	}
	r.mu.Unlock()

	dir := r.cfg.Engagement.Dir()
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	recs, _ := r.records(kinds.Finding.Name())
	ranked := r.rankedCandidates()
	sum := report.Summary{
		Engagement: filepath.Base(r.cfg.Engagement.Dir()), Directory: dir,
		Counts: []report.CountRow{}, FailedChecks: failed, Deferred: deferred,
		NotConfigured: r.notConfigured(), Findings: headlineRows(recs),
		Candidates: ranked[:min(len(ranked), maxListedCandidates)], CandidatesTotal: len(ranked),
		UnconfirmedRiskyPorts: findings.UnconfirmedRisky(recs), Notes: r.notes(),
		Changes: r.changesSummary(recs),
	}
	for _, k := range slices.Sorted(maps.Keys(r.lastTot)) {
		sum.Counts = append(sum.Counts, report.CountRow{Category: k, N: r.lastTot[k]})
	}
	res.Summary = sum
	return res
}

// notConfigured lists blocked stages and their reasons in registry order.
func (r *Runner) notConfigured() []report.StageReason {
	out := []report.StageReason{}
	for _, s := range r.cfg.Stages {
		if ok, reason := r.gate(s); !ok {
			out = append(out, report.StageReason{Stage: s.Name(), Reason: reason})
		}
	}
	return out
}

// rankedCandidates builds the summary list with the scope input needed to promote each
// candidate.
func (r *Runner) rankedCandidates() []report.CandidateRow {
	recs, _ := r.currentRecords(kinds.CandidateRank)
	ranked := make([]candidates.Ranked, len(recs))
	for i, rec := range recs {
		a := kinds.CandidateRank.Attrs(rec)
		ranked[i] = candidates.Ranked{Type: a.Type, Value: a.Value, Current: a.Current, Rank: rankOf(a)}
	}
	listed := candidates.Listed(ranked)
	rows := make([]report.CandidateRow, len(listed))
	for i, c := range listed {
		rows[i] = report.CandidateRow{Kind: c.Type, Value: c.Value, Sources: append([]string{}, c.Sources...), EvidenceCount: c.Count,
			Confidence: string(c.Confidence), Promote: candidates.Promote(c.Type, c.Value)}
	}
	return rows
}

// changesSummary counts changes by kind and lists new high- or medium-severity findings. It
// returns nil on a first run.
func (r *Runner) changesSummary(recs []store.Record) *report.Changes {
	if r.base == nil {
		return nil
	}
	type kindChange struct{ kind, change string }
	n := map[kindChange]int{}
	newKeys := map[string]bool{}
	for _, c := range r.changes {
		n[kindChange{c.Kind, c.Change}]++
		if c.Kind == kinds.LabelFinding && c.Change != output.ChangeGone {
			newKeys[c.Key] = true
		}
	}
	var fresh []store.Record
	for _, rec := range recs {
		if newKeys[rec.Key] {
			fresh = append(fresh, rec)
		}
	}
	counts := []report.ChangeCount{}
	for _, kc := range slices.SortedFunc(maps.Keys(n), func(a, b kindChange) int {
		return cmp.Or(cmp.Compare(a.kind, b.kind), cmp.Compare(a.change, b.change))
	}) {
		counts = append(counts, report.ChangeCount{Kind: kc.kind, Change: kc.change, N: n[kc]})
	}
	return &report.Changes{Counts: counts, Findings: headlineRows(fresh)}
}

// headlineRows formats high- and medium-severity findings for the summary.
func headlineRows(recs []store.Record) []report.FindingRow {
	listed := []report.FindingRow{}
	for _, f := range findings.Headline(recs) {
		row := report.FindingRow{Severity: f.Severity, Category: f.Category, Target: f.Target}
		if f.Detail != "" {
			detail := f.Detail
			row.Detail = &detail
		}
		listed = append(listed, row)
	}
	return listed
}
