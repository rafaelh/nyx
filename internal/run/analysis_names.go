package run

// The names of the analyses (see the package doc).
const (
	AnalysisFindings        = "findings"
	AnalysisCandidateRank   = "candidate-rank"
	AnalysisThirdPartyCNAME = "thirdparty-cname"
	AnalysisGuard           = "guard"
)

// AnalysisNames lists every analysis name: the calculations in run order, then the guard, which
// records the addresses egress refused to dial as the run goes.
func AnalysisNames() []string {
	var names []string
	for _, a := range (&Runner{}).newAnalyses() {
		names = append(names, a.name)
	}
	return append(names, AnalysisGuard)
}
