package cli_test

import (
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/run"
)

// No analysis shares a name with a procedure of the registry, so export can tell a record's
// procedures from its analysis by name alone.
func TestAnalysisNames_NoneIsAProcedure(t *testing.T) {
	t.Parallel()
	names := run.AnalysisNames()
	for _, n := range []string{run.AnalysisFindings, run.AnalysisCandidateRank, run.AnalysisThirdPartyCNAME, run.AnalysisGuard} {
		if !slices.Contains(names, n) {
			t.Errorf("AnalysisNames() = %q lacks %q", names, n)
		}
	}
	procedures := cli.DefaultDeps().Procedures
	if len(procedures) == 0 {
		t.Fatal("the registry is empty")
	}
	for _, p := range procedures {
		if slices.Contains(names, p.Name()) {
			t.Errorf("procedure %q has the name of an analysis", p.Name())
		}
	}
}
