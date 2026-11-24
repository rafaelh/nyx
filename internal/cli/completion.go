package cli

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/cve"
	"github.com/rafaelh/nyx/internal/iplookup"
)

// completionShells are the shells nyx completion writes a script for. Windows is not supported,
// so PowerShell is not offered.
var completionShells = []string{"bash", "zsh"}

// newCompletionCommand builds the command that prints a shell's completion script. The script
// calls the hidden __complete command, which Execute hands straight to Cobra.
func newCompletionCommand(inv *invocation, root *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion bash|zsh",
		Short: "Print the script that tab-completes nyx's commands, flags and their values in bash or zsh",
		Long: "completion prints a script to stdout that makes the shell complete nyx's commands, flags, help topics\n" +
			"and the values a flag takes from a fixed list: stages, fields and record kinds. Save it where the shell\n" +
			"loads completions, or add source <(nyx completion bash) to ~/.bashrc, or source <(nyx completion zsh) to\n" +
			"~/.zshrc after compinit. bash needs the bash-completion package. The script asks nyx for its\n" +
			"completions, so it stays current when nyx is upgraded. To answer, nyx reads no file and contacts\n" +
			"nothing; file and directory names are completed by the shell.",
		Example: "  nyx completion zsh > \"${fpath[1]}/_nyx\"\n" +
			"  nyx completion bash > ~/.local/share/bash-completion/completions/nyx\n" +
			"  source <(nyx completion zsh)",
		Args:      cobra.ArbitraryArgs,
		ValidArgs: completionShells,
		// Set up once, so it stays out of the reference; setup's help and editor point to it.
		Annotations: map[string]string{annotationNotInRoot: "true"},
		RunE: func(c *cobra.Command, args []string) error {
			return inv.start(c, runCompletion(inv, root, args))
		},
	}
	cmd.Flags().BoolP("help", "h", false, "Help for completion")
	return cmd
}

// runCompletion writes the script unwrapped: a terminal margin would break it if copied.
// --json changes only the error, as for setup.
func runCompletion(inv *invocation, root *cobra.Command, args []string) error {
	if err := inv.problems().Err(); err != nil {
		return err
	}
	if len(args) != 1 || !slices.Contains(completionShells, args[0]) {
		msg := "name one shell: " + strings.Join(completionShells, " or ")
		if len(args) == 1 {
			msg = fmt.Sprintf("unsupported shell %q: the shells are %s", args[0], strings.Join(completionShells, ", "))
		}
		e := &clierr.Error{Code: clierr.InvalidInput, Message: msg, Hint: "nyx completion --help"}
		if len(args) > 0 {
			e.Input = map[string][]string{"argument": args}
		}
		return e
	}
	if args[0] == "bash" {
		return root.GenBashCompletionV2(inv.rawOut, true)
	}
	return root.GenZshCompletion(inv.rawOut)
}

// completionHint is the line that turns on tab completion in the shell SHELL names, for the
// setup editor, or "" for a shell nyx completion does not support.
func completionHint(env config.Env) string {
	switch filepath.Base(env.Get("SHELL")) {
	case "zsh":
		return "Tab completion: add source <(nyx completion zsh) to ~/.zshrc, after compinit"
	case "bash":
		return "Tab completion: add source <(nyx completion bash) to ~/.bashrc; it needs the bash-completion package"
	}
	return ""
}

// isCompletionRequest reports whether args are a completion script's call of the hidden command.
func isCompletionRequest(args []string) bool {
	return len(args) > 0 && (args[0] == cobra.ShellCompRequestCmd || args[0] == cobra.ShellCompNoDescRequestCmd)
}

// complete answers a completion script. It skips the pre-scan, which knows no hidden command,
// and the margins, which would corrupt the answer. Cobra runs no command's RunE for it.
func (inv *invocation) complete(ctx context.Context, root *cobra.Command) error {
	registerCompletions(root, inv)
	root.SetArgs(inv.args)
	root.SetOut(inv.rawOut)
	root.SetErr(io.Discard) // Cobra's own debug lines; the scripts discard stderr too
	_, err := root.ExecuteContextC(ctx)
	return err
}

// registerCompletions attaches the value completions. Only a completion request needs them, and
// Cobra keeps them in a process-wide map, so ordinary invocations do not register any.
func registerCompletions(root *cobra.Command, inv *invocation) {
	noFiles := func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	stages := stageNames(inv.d.Stages)
	for _, c := range descendants(root) {
		switch c.CommandPath() {
		case "nyx recon":
			c.ValidArgsFunction = noFiles // domains
			flagValues(c, "redo", func(*cobra.Command) []string { return stages })
			flagValues(c, "skip", func(*cobra.Command) []string { return skippable(stages) })
			dirValues(c, "output-dir")
		case "nyx recon export":
			flagValues(c, "kind", func(*cobra.Command) []string { return exportKinds() })
			dirValues(c, "output-dir")
		case "nyx cve":
			c.ValidArgsFunction = noFiles // CVE IDs
			listValues(c, "fields", func(*cobra.Command) []string { return append(cve.FieldNames(), "all") })
		case "nyx ip":
			c.ValidArgsFunction = noFiles // addresses, hostnames and CIDRs
			listValues(c, "fields", ipFieldChoices)
		case "nyx setup":
			c.ValidArgsFunction = noFiles
		case "nyx help":
			c.ValidArgsFunction = helpTargets(root)
		}
	}
}

// skippable are the stages --skip accepts, and none.
func skippable(stages []string) []string {
	out := slices.DeleteFunc(slices.Clone(stages), func(s string) bool { return slices.Contains(unskippable, s) })
	return append(out, "none")
}

// ipFieldChoices are the --fields names ip accepts, with the active-only ones once --active is
// on the line.
func ipFieldChoices(c *cobra.Command) []string {
	active, _ := c.Flags().GetBool("active")
	return append(iplookup.ChoosableFieldNames(active), "all")
}

// flagValues completes a flag that takes one value from choices.
func flagValues(c *cobra.Command, flag string, choices func(*cobra.Command) []string) {
	mustRegister(c, flag, func(c *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
		return choices(c), cobra.ShellCompDirectiveNoFileComp
	})
}

// listValues completes a comma-separated list: it offers the choices not yet in the list after
// the text already typed, and leaves the cursor there so another comma can follow.
func listValues(c *cobra.Command, flag string, choices func(*cobra.Command) []string) {
	mustRegister(c, flag, func(c *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var have []string
		done, _, found := strings.CutLast(toComplete, ",")
		if found {
			have = strings.Split(done, ",")
			done += ","
		} else {
			done = ""
		}
		var out []string
		for _, ch := range choices(c) {
			if !slices.Contains(have, ch) {
				out = append(out, done+ch)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	})
}

// dirValues completes a flag that names a directory.
func dirValues(c *cobra.Command, flag string) {
	mustRegister(c, flag, func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveFilterDirs
	})
}

// mustRegister panics on a flag the command lacks: a renamed flag must not lose its completion
// unnoticed. Execute recovers the panic, and the completion tests catch it.
func mustRegister(c *cobra.Command, flag string, f cobra.CompletionFunc) {
	if err := c.RegisterFlagCompletionFunc(flag, f); err != nil {
		panic(fmt.Sprintf("completion for %s --%s: %v", c.CommandPath(), flag, err))
	}
}

// helpTargets completes nyx help's arguments: the commands and topics, then each one's
// subcommands.
func helpTargets(root *cobra.Command) cobra.CompletionFunc {
	return func(_ *cobra.Command, args []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
		parent := root
		if len(args) > 0 {
			c, rest, err := root.Find(args)
			if err != nil || len(rest) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			parent = c
		}
		var out []cobra.Completion
		for _, c := range parent.Commands() {
			if !c.Hidden && c.Name() != "help" {
				out = append(out, cobra.CompletionWithDesc(c.Name(), c.Short))
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}
