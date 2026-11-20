package kinds

// CandidateRank is how well supported a candidate is. Like a finding it is
// derived, never written by a stage: the runner ranks every candidate from the
// completed checks that currently observe it and stores the result under the
// pseudo-stage "candidate-rank". It has no category and is never printed, so it
// changes no total; candidates.csv and the summary read it.
var CandidateRank = defineJoined(Kind{Name: "candidate_rank"},
	func(a *CandidateRankAttrs) []*string { return []*string{&a.Type, &a.Value} })

// CandidateRankAttrs: the candidate (its kind, "root", "hostname", "netblock",
// "asn" or "organisation", and its value), the distinct sources that support it (";"-joined), the number
// of distinct (source, item) pairs, the confidence ("low", "medium" or "high")
// and whether the candidate was current when it was ranked. A candidate that
// stops being current keeps its last rank, with Current false. A record's key
// is "<type>|<value>".
type CandidateRankAttrs struct {
	Type          string `json:"type"`
	Value         string `json:"value"`
	Sources       string `json:"sources"`
	EvidenceCount int    `json:"evidence_count"`
	Confidence    string `json:"confidence"`
	Current       bool   `json:"current"`
}

// CandidateKinds are the kinds whose records can be candidates, and so are ranked.
var CandidateKinds = []Named{Root, Hostname, Netblock, ASN, Organisation}
