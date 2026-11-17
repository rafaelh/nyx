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
		Use:     "cve <id>... [flags]",
		Short:   "Look up CVEs in the NVD",
		Example: "  nyx cve CVE-2021-44228 --json\n  nyx cve CVE-2021-44228 CVE-2014-0160 --json",
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
	root := rootWith(t)
	help := rootHelp(root, palette.None)
	for _, want := range []string{
		"nyx cve <id>... [flags]", "Look up CVEs in the NVD", "Example: nyx cve CVE-2021-44228 --json",
		"--all", "Walk every page", "--fields", "Fields accepted by --fields: id, score, summary",
		"nyx recon [domain...] [flags]",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("the root help lacks %q:\n%s", want, help)
		}
	}
	// Its first example is among the examples the help opens with.
	examples, _, _ := strings.Cut(help, "\n\n")
	if !strings.Contains(examples, "nyx cve CVE-2021-44228 --json") {
		t.Errorf("the opening examples lack the new command's:\n%s", examples)
	}
	if strings.Contains(help, "CVE-2014-0160") {
		t.Error("the root help shows more than one example of the command")
	}

	// The pre-scan knows it as a command, and its flag as no recon flag.
	if sc := classify([]string{"cve", "CVE-1"}, root); sc.err != nil || sc.help || sc.version {
		t.Errorf("cve: %+v", sc)
	}
	if sc := classify([]string{"--all", "CVE-1"}, root); sc.err == nil || sc.err.Message != "no command given" {
		t.Errorf("--all with no command: %+v", sc.err)
	}
	if sc := classify([]string{"--all", "cve", "CVE-1"}, root); sc.err == nil || sc.err.Hint != "nyx cve --all CVE-1" {
		t.Errorf("--all before cve: %+v", sc.err)
	}
	// A flag both recon and cve took would be ambiguous with no command.
	for _, c := range root.Commands() {
		if c.Name() == "cve" || c.Name() == "recon" {
			c.Flags().Bool("both", false, "")
		}
	}
	if sc := classify([]string{"--both", "x.com"}, root); sc.err == nil || sc.err.Message != "no command given" || sc.err.Hint != "nyx --help" {
		t.Errorf("--both: %+v", sc.err)
	}
}

// Hints quote each argument for a POSIX shell, only when it needs it.
func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"example.com": "example.com", "--engagement=acme": "--engagement=acme", "a/b,c:d@e%f+g_h": "a/b,c:d@e%f+g_h",
		"": "''", "Acme Pty": "'Acme Pty'", "it's": `'it'\''s'`, "$HOME": "'$HOME'", "a*": "'a*'", "née": "'née'",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}
