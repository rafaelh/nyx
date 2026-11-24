package cli_test

import (
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/run"
)

// The export section of docs/output.md describes the procedures and analysis keys of a record line
// and names every analysis a record can come from.
func TestAnalysisDocs_ExportSectionNamesEveryAnalysis(t *testing.T) {
	t.Parallel()
	section, _ := docsSection(t, "## Exporting an engagement")
	for _, name := range run.AnalysisNames() {
		if !strings.Contains(section, "`"+name+"`") {
			t.Errorf("the export section does not name the analysis %q", name)
		}
	}
	for _, want := range []string{"`procedures`", "`analysis`"} {
		if !strings.Contains(section, want) {
			t.Errorf("the export section does not describe the %s key", want)
		}
	}
	if strings.Contains(section, "`stages`") {
		t.Error("the export section still names the stages key")
	}
}
