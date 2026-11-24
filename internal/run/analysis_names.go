package run

// The names of the analyses: the producers of the records nyx makes itself rather than a
// procedure observes. Each analysis writes a kind of its own (apart from third_party, which a
// procedure may also observe), so a record has at most one analysis. Export names the analysis
// of a record under its analysis key.
const (
	AnalysisFindings        = "findings"
	AnalysisCandidateRank   = "candidate-rank"
	AnalysisThirdPartyCNAME = "thirdparty-cname"
	AnalysisGuard           = "guard"
)

// AnalysisNames lists every analysis name: the three calculations in run order, then the guard,
// which records the addresses egress refused to dial as the run goes.
func AnalysisNames() []string {
	return []string{AnalysisFindings, AnalysisCandidateRank, AnalysisThirdPartyCNAME, AnalysisGuard}
}
