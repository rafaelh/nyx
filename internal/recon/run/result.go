package run

import (
	"cmp"
	"maps"
	"path/filepath"
	"slices"

	"github.com/rafaelh/nyx/internal/recon/analysis/candidates"
	"github.com/rafaelh/nyx/internal/recon/analysis/findings"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/output"
	"github.com/rafaelh/nyx/internal/recon/report"
	"github.com/rafaelh/nyx/internal/recon/store"
)

// maxListedCandidates limits the console list; candidates.csv contains the rest.
const maxListedCandidates = 20

// Result contains the rendered summary and counters used to decide the command's outcome.
// Completed includes jobs that returned successfully or with an error; Succeeded counts only
// successes. Cancelled jobs are retried next run and are counted separately, by procedure. Jobs
// abandoned after a procedure abort count as failures without being completed. Summary.FailedJobs
// holds the failure totals.
type Result struct {
	Summary   report.Summary
	Completed int
	Succeeded int
	Cancelled []report.ProcedureCount
	// KeyRejected counts failures caused by a rejected API key, including jobs abandoned
	// after the rejection.
	KeyRejected int
}

// result builds the outcome using run counters and the last render's category totals.
func (r *Runner) result() Result {
	res := Result{}
	r.mu.Lock()
	failed, deferred := []report.ProcedureCount{}, []report.ProcedureCount{}
	for _, name := range slices.Sorted(maps.Keys(r.stats)) {
		s := r.stats[name]
		if s.failed > 0 {
			failed = append(failed, report.ProcedureCount{Procedure: name, N: s.failed})
		}
		if s.deferred > 0 {
			deferred = append(deferred, report.ProcedureCount{Procedure: name, N: s.deferred})
		}
		res.Completed += s.completed
		res.Succeeded += s.succeeded
		res.KeyRejected += s.rejected
	}
	for _, name := range r.order {
		if s := r.stats[name]; s != nil && s.cancelled > 0 {
			res.Cancelled = append(res.Cancelled, report.ProcedureCount{Procedure: name, N: s.cancelled})
		}
	}
	r.mu.Unlock()

	dir := r.cfg.Engagement.Dir()
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	recs, err := r.records(kinds.Finding.Name())
	if err != nil {
		r.warn("reading %s records: %v", kinds.Finding.Name(), err)
	}
	ranked := r.rankedCandidates()
	sum := report.Summary{
		Engagement: filepath.Base(r.cfg.Engagement.Dir()), Directory: dir,
		Counts: []report.CountRow{}, FailedJobs: failed, Deferred: deferred,
		NotConfigured: r.notConfigured(), Findings: headlineRows(recs),
		Candidates: ranked[:min(len(ranked), maxListedCandidates)], CandidatesTotal: len(ranked),
		UnconfirmedRiskyPorts: findings.UnconfirmedRisky(recs), HostsInScopeByAddress: r.hostsInScopeByAddress(),
		Notes:   r.notes(),
		Changes: r.changesSummary(recs),
	}
	for _, k := range slices.Sorted(maps.Keys(r.lastTot)) {
		sum.Counts = append(sum.Counts, report.CountRow{Category: k, N: r.lastTot[k]})
	}
	res.Summary = sum
	return res
}

// notConfigured lists blocked procedures and their reasons in registry order, leaving out a paid
// procedure without its key.
func (r *Runner) notConfigured() []report.ProcedureReason {
	out := []report.ProcedureReason{}
	for _, s := range r.cfg.Procedures {
		if ok, reason := r.gate(s); !ok && !unlisted(s, ok, reason) {
			out = append(out, report.ProcedureReason{Procedure: s.Name(), Reason: reason})
		}
	}
	return out
}

// rankedCandidates builds the summary list with the scope input needed to promote each
// candidate.
func (r *Runner) rankedCandidates() []report.CandidateRow {
	recs, err := r.currentRecords(kinds.CandidateRank)
	if err != nil {
		r.warn("reading %s records: %v", kinds.CandidateRank.Name(), err)
	}
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

// hostsInScopeByAddress counts the current hostname records in scope by an address of their
// candidate lookup.
func (r *Runner) hostsInScopeByAddress() int {
	built := r.built.Load()
	if built == nil {
		return 0
	}
	recs, err := r.records(kinds.Hostname.Name())
	if err != nil {
		r.warn("reading %s records: %v", kinds.Hostname.Name(), err)
	}
	return len(kinds.ByAddressHosts(built.Scope, recs))
}
