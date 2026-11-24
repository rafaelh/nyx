package run

import (
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/recon/kinds"
)

// The analysis names keep the values export already writes.
func TestAnalysisNames_Values(t *testing.T) {
	t.Parallel()
	for got, want := range map[string]string{
		AnalysisFindings:        "findings",
		AnalysisCandidateRank:   "candidate-rank",
		AnalysisThirdPartyCNAME: "thirdparty-cname",
		AnalysisGuard:           "guard",
	} {
		if got != want {
			t.Errorf("analysis name %q, want %q", got, want)
		}
	}
}

// AnalysisNames lists each analysis once.
func TestAnalysisNames_NoDuplicate(t *testing.T) {
	t.Parallel()
	names := AnalysisNames()
	if sorted := slices.Sorted(slices.Values(names)); len(slices.Compact(sorted)) != len(names) {
		t.Errorf("AnalysisNames() = %q has a duplicate", names)
	}
	for _, n := range []string{AnalysisFindings, AnalysisCandidateRank, AnalysisThirdPartyCNAME, AnalysisGuard} {
		if !slices.Contains(names, n) {
			t.Errorf("AnalysisNames() = %q lacks %q", names, n)
		}
	}
}

// Each analysis writes a kind of its own, and none writes the kind the guard writes, so a record
// has at most one analysis.
func TestAnalysisNames_EachWritesAKindOfItsOwn(t *testing.T) {
	t.Parallel()
	writer := map[string]string{kinds.ExcludedKind.Name(): AnalysisGuard}
	for _, a := range (&Runner{}).newAnalyses() {
		k := a.writes.Name()
		if other, ok := writer[k]; ok {
			t.Errorf("analyses %q and %q both write %s", other, a.name, k)
		}
		writer[k] = a.name
	}
}
