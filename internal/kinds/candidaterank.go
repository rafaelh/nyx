package kinds

// CandidateRank stores the runner's derived confidence in a candidate's completed-check
// evidence. The synthetic candidate-rank stage writes it for candidates.csv and the summary. It
// has no console event or category count.
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
