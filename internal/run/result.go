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

// maxListedCandidates is how many candidates the summary lists; the rest are in
// candidates.csv only.
const maxListedCandidates = 20

// Result is what a run reports when it has rendered its files: the summary, and the
// counts the caller decides the outcome from. The number of failed checks is the sum of
// Summary.FailedChecks.
//
// Completed is the checks that ran and finished in this run, whether they succeeded or
// failed (Succeeded is the ones that did). A check the context ended while it ran is
// neither completed nor failed: it is Cancelled, per stage in registry order, and runs
// on the next run. A check a stage abandoned without running it is failed, and in
// neither count. KeyRejected is the failed checks a rejected key caused.
type Result struct {
	Summary   report.Summary
	Completed int
	Succeeded int
	Cancelled []report.StageCount
	// KeyRejected is how many of the failed checks a refused API key caused: the check
	// that met the refusal, and each check its stage then abandoned.
	KeyRejected int
}

// result builds the Result from what the run has counted and stored. The category
// counts are those of the last render.
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

// notConfigured lists, in registry order, each stage whose gate is closed when the run
// ends, and why.
func (r *Runner) notConfigured() []report.StageReason {
	out := []report.StageReason{}
	for _, s := range r.cfg.Stages {
		if ok, reason := r.gate(s); !ok {
			out = append(out, report.StageReason{Stage: s.Name(), Reason: reason})
		}
	}
	return out
}

// rankedCandidates are the candidates the summary lists (candidates.Listed),
// each with the input that promotes it.
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

// changesSummary is the summary's changes: how many of each kind changed in each way, and the
// findings of high or medium severity that are new. It is nil on a first run, which has no
// changes to count.
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

// headlineRows are the findings of high or medium severity among recs, as the summary
// lists them.
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
