package kinds

import (
	"cmp"
	"strings"

	"github.com/rafaelh/nyx/internal/recon/analysis/candidates"
	"github.com/rafaelh/nyx/internal/recon/store"
)

// CandidateRank stores the runner's derived confidence in a candidate's completed-job
// evidence. The candidate-rank analysis writes it for candidates.csv and the summary. It has no
// console event or category count.
var CandidateRank = defineJoined(Kind{Name: "candidate_rank"},
	func(a *CandidateRankAttrs) []*string { return []*string{&a.Type, &a.Value} })

// CandidateRankAttrs identifies the candidate by type and value, with semicolon-separated
// sources, a distinct source/item count and confidence. Non-current candidates retain their
// last rank with Current=false. Keys use "<type>|<value>".
type CandidateRankAttrs struct {
	Type          string `json:"type"`
	Value         string `json:"value"`
	Sources       string `json:"sources"`
	EvidenceCount int    `json:"evidence_count"`
	Confidence    string `json:"confidence"`
	Current       bool   `json:"current"`
}

// CandidateKinds lists entity kinds supported by candidate ranking.
var CandidateKinds = []Named{Root, Hostname, Netblock, ASN, Organisation}

// CandidateRecord is a record candidates.csv lists, with its current rank.
type CandidateRecord struct {
	Kind   Named
	Record store.Record
	Rank   CandidateRankAttrs
}

// CandidateRecords lists, kind by kind in CandidateKinds order, the records records gives that
// vis places among the candidates, each with its current rank among ranks; one with no rank has
// low confidence and no sources. candidates.csv and the order candidates are looked up in both
// come from it.
func CandidateRecords(vis *Visibility, records func(Named) []store.Record, ranks []store.Record) []CandidateRecord {
	current := map[string]CandidateRankAttrs{}
	for _, r := range ranks {
		if r.Current {
			current[r.Key] = CandidateRank.Attrs(r)
		}
	}
	var out []CandidateRecord
	for _, k := range CandidateKinds {
		for _, r := range records(k) {
			if vis.Category(k, r) != Candidates {
				continue
			}
			rank, ok := current[CandidateRank.Key(CandidateRankAttrs{Type: k.Name(), Value: r.Key})]
			if !ok {
				rank.Confidence = string(candidates.Low)
			}
			out = append(out, CandidateRecord{k, r, rank})
		}
	}
	return out
}

// Compare orders candidates as candidates.csv does: by candidates.Compare, then by kind.
func (c CandidateRecord) Compare(o CandidateRecord) int {
	entry := func(c CandidateRecord) candidates.Entry {
		return candidates.Entry{Value: c.Record.Key, Current: c.Record.Current,
			Confidence: candidates.Confidence(c.Rank.Confidence), Count: c.Rank.EvidenceCount}
	}
	return cmp.Or(candidates.Compare(entry(c), entry(o)), strings.Compare(c.Kind.Name(), o.Kind.Name()))
}
