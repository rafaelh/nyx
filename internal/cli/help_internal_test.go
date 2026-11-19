package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rafaelh/nyx/internal/palette"
)

// rootWith is the tree with one more command, as a later command adds itself.
func rootWith(t *testing.T) *cobra.Command {
	t.Helper()
	inv := newInvocation(withDefaults(Deps{Stages: nil}), nil)
	root := newRoot(inv)
	extra := &cobra.Command{
		Use:     "kev <id>... [flags]",
		Short:   "Look up known exploited vulnerabilities",
		Example: "  nyx kev CVE-2021-44228 --json\n  nyx kev CVE-2021-44228 CVE-2014-0160 --json",
		Annotations: map[string]string{
			annotationValues: "Fields accepted by --fields: id, score, summary",
		},
		RunE: func(*cobra.Command, []string) error { return nil },
	}
	extra.Flags().Bool("all", false, "Walk every page")
	extra.Flags().String("fields", "", "Fields to return")
	root.AddCommand(extra)
	return root
}

// A command added to the tree is in the root help, with its example, its
// flags and the values of its fixed-set flags, and the pre-scan knows it,
// with no second list of commands to keep in step.
func TestRootHelp_CommandAddedLater(t *testing.T) {
	t.Parallel()
	root := rootWith(t)
	help := rootHelp(root, palette.None)
	for _, want := range []string{
		"nyx kev <id>... [flags]", "Look up known exploited vulnerabilities", "Example: nyx kev CVE-2021-44228 --json",
		"--all", "Walk every page", "--fields", "Fields accepted by --fields: id, score, summary",
		"nyx recon [domain...] [flags]",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("the root help lacks %q:\n%s", want, help)
		}
	}
	// Its first example is among the examples the help opens with.
	examples, _, _ := strings.Cut(help, "\n\n")
	if !strings.Contains(examples, "nyx kev CVE-2021-44228 --json") {
		t.Errorf("the opening examples lack the new command's:\n%s", examples)
	}
	if strings.Contains(help, "CVE-2014-0160") {
		t.Error("the root help shows more than one example of the command")
	}

	// The pre-scan knows it as a command, and its flag as no recon flag.
	if sc := classify([]string{"kev", "CVE-1"}, root); sc.err != nil || sc.help || sc.version {
		t.Errorf("kev: %+v", sc)
	}
	if sc := classify([]string{"--all", "CVE-1"}, root); sc.err == nil || sc.err.Message != "no command given" {
		t.Errorf("--all with no command: %+v", sc.err)
	}
	if sc := classify([]string{"--all", "kev", "CVE-1"}, root); sc.err == nil || sc.err.Hint != "nyx kev --all CVE-1" {
		t.Errorf("--all before kev: %+v", sc.err)
	}
	// A flag both recon and kev took is the old form of a call when the first positional has a dot,
	// as a domain does, and is ambiguous with no command otherwise.
	for _, c := range root.Commands() {
		if c.Name() == "kev" || c.Name() == "recon" {
			c.Flags().Bool("both", false, "")
		}
	}
	if sc := classify([]string{"--both", "x.com"}, root); sc.err == nil || sc.err.Hint != "nyx recon --both x.com" {
		t.Errorf("--both x.com: %+v", sc.err)
	}
	if sc := classify([]string{"--both", "CVE-1"}, root); sc.err == nil || sc.err.Message != "no command given" || sc.err.Hint != "nyx --help" {
		t.Errorf("--both CVE-1: %+v", sc.err)
	}
}
