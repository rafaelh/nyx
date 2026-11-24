package output

import (
	"cmp"
	"slices"
	"strconv"

	"github.com/rafaelh/nyx/internal/recon/analysis/candidates"
	"github.com/rafaelh/nyx/internal/recon/kinds"
)

var candidateColumns = []string{"type", "value", "sources", "evidence_count", "confidence"}

// Find sort-column indexes by name so reordering candidateColumns cannot silently change the
// sort.
var (
	candidateValue = slices.Index(candidateColumns, "value")
	candidateCount = slices.Index(candidateColumns, "evidence_count")
	candidateLevel = slices.Index(candidateColumns, "confidence")
)

// candidateRows uses the snapshot's Visibility to match summary candidates. It combines derived
// ranks with the candidate's own dates and current status. Missing derivation yields low
// confidence and no sources.
func candidateRows(s Snapshot) []Row {
	ranks := map[string]kinds.CandidateRankAttrs{}
	for _, r := range s.of(kinds.CandidateRank) {
		if r.Current {
			ranks[r.Key] = kinds.CandidateRank.Attrs(r)
		}
	}
	var rows []Row
	vis := s.vis()
	for _, kind := range kinds.CandidateKinds {
		for _, r := range s.of(kind) {
			if vis.Category(kind, r) != kinds.Candidates {
				continue
			}
			rank, ok := ranks[kinds.CandidateRank.Key(kinds.CandidateRankAttrs{Type: kind.Name(), Value: r.Key})]
			if !ok {
				rank.Confidence = string(candidates.Low)
			}
			rows = append(rows, recordRow(r, kind.Name(), r.Key, rank.Sources, strconv.Itoa(rank.EvidenceCount), rank.Confidence))
		}
	}
	return rows
}

// candidateOrder sorts current rows first, then confidence, evidence count and value.
// Non-current rows retain their last confidence.
func candidateOrder(a, b Row) int {
	entry := func(r Row) candidates.Entry {
		n, _ := strconv.Atoi(r.Cells[candidateCount])
		return candidates.Entry{Value: r.Cells[candidateValue], Current: r.Current, Confidence: candidates.Confidence(r.Cells[candidateLevel]), Count: n}
	}
	return cmp.Or(candidates.Compare(entry(a), entry(b)), slices.Compare(a.Cells, b.Cells))
}
