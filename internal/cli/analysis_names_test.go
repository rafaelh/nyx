package cli_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/run"
)

// No analysis shares a name with a procedure of the registry, so export can tell a record's
// procedures from its analysis by name alone.
func TestAnalysisNames_NoneIsAProcedure(t *testing.T) {
	t.Parallel()
	names := run.AnalysisNames()
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

// An analysis writes a kind of its own, so a record has at most one analysis. The one kind a
// procedure and an analysis share is third_party. A procedure has no way to say which kinds it
// writes, so this reads the source of the procedures for the other analyses' kinds.
func TestAnalysisNames_NoProcedureWritesAnAnalysesKind(t *testing.T) {
	t.Parallel()
	own := regexp.MustCompile(`\bkinds\.(Finding|CandidateRank|ExcludedKind)\b`)
	err := filepath.WalkDir("../procedures", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if m := own.Find(src); m != nil {
			t.Errorf("%s writes %s, a kind an analysis owns", path, m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
