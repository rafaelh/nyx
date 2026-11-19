package cli

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/palette"
)

// The annotations a command carries for the help, so a command added to the
// tree is in the root help with no list of commands to keep in step.
const (
	// annotationEveryday names the flags the root help shows, separated by
	// commas; absent means every flag of the command.
	annotationEveryday = "nyx.everyday"
	// annotationValues is the lines that name the valid values of the
	// command's fixed-set flags, shown in the root help.
	annotationValues = "nyx.values"
	// annotationNote is a line the root help adds after them.
	annotationNote = "nyx.note"
	// annotationFooter is what the command's own help shows after its flags.
	annotationFooter = "nyx.footer"
)

// exitCodesLine is the last line of every help text.
const exitCodesLine = "Exit codes: 0 success, 1 system error, 2 usage error, 3 not found, 7 partial result, 130/143/129 interrupted (SIGINT/SIGTERM/SIGHUP)"

// newRoot builds the command tree: nyx, recon and its export, help and the
// help topics. The root owns the shared flags, which every command takes
// before or after its name.
func newRoot(inv *invocation) *cobra.Command {
	root := &cobra.Command{
		Use:   "nyx",
		Short: "Passive-first reconnaissance for authorised engagements",
		Long: "nyx is passive-first reconnaissance for authorised engagements. Every command takes the shared\n" +
			"flags, and each command's own flags follow its name.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// A subcommand would otherwise bring cobra's completion command with it.
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	pf := root.PersistentFlags()
	pf.SortFlags = false
	pf.BoolVarP(&inv.sh.json, "json", "J", false, "Print one JSON object with the run's outcome on stdout when the run ends (recon), and any error as one JSON line on stderr")
	pf.BoolVarP(&inv.sh.quiet, "quiet", "q", false, "Write only warnings and errors to stderr; the summary is still printed")
	pf.BoolVar(&inv.sh.debug, "debug", false, "Also write each failed check, and the stack of an unexpected failure, to stderr")
	f := root.Flags()
	f.SortFlags = false
	f.Bool("version", false, "Print the version and exit") // long-only: -v is usually read as verbose
	f.BoolP("help", "h", false, "Help for nyx")

	recon := newReconCommand(inv)
	recon.AddCommand(newExportCommand(inv))
	help := newHelpCommand(inv, root)
	depth := inv.helpDepth()
	root.AddCommand(recon, help,
		newTopic(inv, "findings", "Finding types and their default severities", findingsHelp, depth),
		newTopic(inv, "stages", "The stages, in run order, and what each one contacts and does",
			func(dep palette.Depth) string { return stagesHelp(dep, inv.d.Stages) }, depth))
	root.SetHelpCommand(help)
	root.SetHelpFunc(func(c *cobra.Command, _ []string) { inv.printHelp(root, c) })
	return root
}

// newHelpCommand is nyx help [command]: the root help, or the named command's,
// exactly as --help prints it.
func newHelpCommand(inv *invocation, root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "help [command]",
		Short: "The help of nyx, or of one command or topic: the same as --help",
		Args:  cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if err := inv.problems().Err(); err != nil {
				return inv.start(c, err)
			}
			target, rest, err := root.Find(args)
			if err != nil || len(rest) > 0 || target.Hidden {
				word := args[0]
				if len(rest) > 0 {
					word = rest[0]
				}
				return inv.start(c, unknownCommand(word, root))
			}
			if target == c {
				target = root
			}
			return inv.start(c, target.Help())
		},
	}
}

// helpDepth is the colour of help text: stdout's, except under --json.
func (inv *invocation) helpDepth() palette.Depth {
	if inv.raw.json || inv.sh.json {
		return palette.None
	}
	return inv.dp.out
}

// printHelp writes the help of c: the root help for the root and for help.
func (inv *invocation) printHelp(root, c *cobra.Command) {
	inv.showHelp(c, func() string {
		if c == root || c.Name() == "help" && c.Parent() == root {
			return rootHelp(root, inv.helpDepth())
		}
		return commandHelp(c, inv.helpDepth())
	})
}

// showHelp writes a help text to stdout, unless the shared flags are refused
// (--quiet with --debug): then that usage error is the call's outcome and
// nothing is printed.
func (inv *invocation) showHelp(c *cobra.Command, text func() string) {
	if err := inv.problems().Err(); err != nil {
		_ = inv.start(c, err)
		return
	}
	fmt.Fprint(inv.d.Stdout, text())
}

// runnable are the commands that do work, in tree order, children after
// their parent; help and the topics are not among them.
func runnable(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	for _, c := range descendants(root) {
		if c.Runnable() && !c.Hidden && c.Name() != "help" {
			out = append(out, c)
		}
	}
	return out
}

// firstExample is the first line of a command's examples.
func firstExample(c *cobra.Command) string {
	for l := range strings.SplitSeq(c.Example, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

// rootHelp is the whole reference, rendered from the tree: examples that pass
// --json, the shared flags, then every command with its usage, one example,
// its everyday flags and the valid values of its fixed-set flags, the help
// commands, and the exit codes.
func rootHelp(root *cobra.Command, depth palette.Depth) string {
	cmds := runnable(root)
	var b strings.Builder
	b.WriteString("Examples:\n")
	for _, c := range cmds {
		if ex := firstExample(c); ex != "" {
			b.WriteString("  " + ex + "\n")
		}
	}
	b.WriteString("\n" + root.Long + "\n\n")
	b.WriteString("Shared flags (every command takes them; they alone may also come before the command):\n")
	b.WriteString(flagUsages(root.PersistentFlags()))
	for _, c := range cmds {
		writeCommandReference(&b, root, c)
	}
	writeHelpCommands(&b, root)
	own := pflag.NewFlagSet("nyx", pflag.ContinueOnError)
	own.SortFlags = false
	own.AddFlag(root.Flags().Lookup("version"))
	own.AddFlag(root.Flags().Lookup("help"))
	b.WriteString("\nFlags:\n" + flagUsages(own))
	b.WriteString("\n" + exitCodesLine + "\n")
	return colourHelp(depth, b.String())
}

// writeCommandReference writes one command's entry in the reference: its
// usage, its summary, one example, its everyday flags and its notes.
func writeCommandReference(b *strings.Builder, root, c *cobra.Command) {
	b.WriteString("\n" + c.UseLine() + "\n")
	b.WriteString("  " + c.Short + "\n")
	if ex := firstExample(c); ex != "" {
		b.WriteString("  Example: " + ex + "\n")
	}
	if fs := everydayFlags(c, root.PersistentFlags()); fs.HasAvailableFlags() {
		b.WriteString(strings.TrimPrefix(c.CommandPath(), root.Name()+" ") + " flags:\n")
		b.WriteString(flagUsages(fs))
	}
	for _, key := range []string{annotationValues, annotationNote} {
		if v := c.Annotations[key]; v != "" {
			b.WriteString(v + "\n")
		}
	}
}

// everydayFlags are the flags the reference shows for c: those its everyday
// annotation names, in that order, or else all of them, leaving out help,
// hidden flags and the shared flags.
func everydayFlags(c *cobra.Command, shared *pflag.FlagSet) *pflag.FlagSet {
	fs := pflag.NewFlagSet(c.Name(), pflag.ContinueOnError)
	fs.SortFlags = false
	add := func(f *pflag.Flag) {
		if f != nil && f.Name != "help" && !f.Hidden && shared.Lookup(f.Name) == nil {
			fs.AddFlag(f)
		}
	}
	if names, ok := c.Annotations[annotationEveryday]; ok {
		for n := range strings.SplitSeq(names, ",") {
			add(c.Flags().Lookup(n))
		}
	} else {
		c.Flags().VisitAll(add)
	}
	return fs
}

// writeHelpCommands writes the reference's list of help commands: help itself
// and each help topic, with their summaries in one aligned column.
func writeHelpCommands(b *strings.Builder, root *cobra.Command) {
	b.WriteString("\nHelp:\n")
	type row struct{ use, short string }
	var rows []row
	for _, c := range root.Commands() {
		if c.Hidden || c.Runnable() && c.Name() != "help" {
			continue
		}
		use := "nyx help " + c.Name()
		if c.Name() == "help" {
			use = "nyx help [command]"
		}
		rows = append(rows, row{use, c.Short})
	}
	width := 0
	for _, r := range rows {
		width = max(width, len(r.use))
	}
	for _, r := range rows {
		fmt.Fprintf(b, "  %-*s   %s\n", width, r.use, r.short)
	}
}

// flagUsages is fs's flag list as help shows it: a switch reads "--passive",
// not pflag's "--passive[=true|false]". It renders a copy of fs, leaving the
// flags that parsing uses unchanged.
func flagUsages(fs *pflag.FlagSet) string {
	shown := pflag.NewFlagSet(fs.Name(), pflag.ContinueOnError)
	shown.SortFlags = fs.SortFlags
	fs.VisitAll(func(f *pflag.Flag) {
		c := *f
		if c.Value.Type() == "bool" {
			c.Value = plainSwitch{c.Value} // NoOptDefVal is already "true", set when f was added
		}
		shown.AddFlag(&c)
	})
	return shown.FlagUsages()
}

// plainSwitch hides a bool flag value's IsBoolFlag method, which pflag's usage
// text marks with "[=true|false]".
type plainSwitch struct{ pflag.Value }

// commandHelp is a command's own help: its examples, its description, its
// usage, its subcommands, every flag, its footer and the exit codes.
func commandHelp(c *cobra.Command, depth palette.Depth) string {
	var b strings.Builder
	if c.Example != "" {
		b.WriteString("Examples:\n" + c.Example + "\n\n")
	}
	if c.Long != "" {
		b.WriteString(c.Long + "\n\n")
	}
	b.WriteString("Usage:\n  " + c.UseLine() + "\n")
	if c.HasAvailableSubCommands() {
		b.WriteString("\nCommands:\n")
		for _, sub := range c.Commands() {
			if sub.IsAvailableCommand() {
				fmt.Fprintf(&b, "  %-*s %s\n", sub.NamePadding(), sub.Name(), sub.Short)
			}
		}
	}
	if local := c.LocalFlags(); local.HasAvailableFlags() {
		b.WriteString("\nFlags:\n" + flagUsages(local))
	}
	if inherited := c.InheritedFlags(); inherited.HasAvailableFlags() {
		b.WriteString("\nShared flags:\n" + flagUsages(inherited))
	}
	if footer := c.Annotations[annotationFooter]; footer != "" {
		b.WriteString("\n" + footer)
	}
	b.WriteString("\n" + exitCodesLine + "\n")
	return colourHelp(depth, b.String())
}

// findingsTopic is the text of nyx help findings.
var findingsTopic = "Findings and their default severities (fixed in code, not configurable; the summary lists high and medium):\n" +
	findings.HelpTable()

// newTopic builds a help topic: a command with no run of its own, which the root's help lists under
// "Help topics" and which nyx help <name>, nyx <name> and nyx <name> --help print. render gives its
// text at depth, the colour of stdout at that depth.
func newTopic(inv *invocation, name, short string, render func(palette.Depth) string, depth palette.Depth) *cobra.Command {
	cmd := &cobra.Command{Use: name, Short: short}
	cmd.SetHelpFunc(func(c *cobra.Command, _ []string) {
		inv.showHelp(c, func() string { return render(depth) })
	})
	return cmd
}

// findingsHelp is the findings topic at depth d.
func findingsHelp(d palette.Depth) string { return colourHelp(d, findingsTopic) }

var (
	// helpFlag is a flag line: indent, names, an optional value type, the gap
	// and the description.
	helpFlag = regexp.MustCompile(`^(\s+)((?:-\w, )?--[\w-]+)( \w+)?(\s{2,})(.*)$`)
	// helpAside is the default or example a flag's description ends with.
	helpAside = regexp.MustCompile(` \((?:default[ :]|e\.g\.).*\)$`)
	// helpNote is a usage note anywhere in a flag's description.
	helpNote = regexp.MustCompile(`\((?:# comments allowed|repeatable)\)`)
	// helpCommand is a line of the command list: indent, name, gap, summary.
	helpCommand = regexp.MustCompile(`^(\s+)(\S+)(\s{2,})(.*)$`)
	// helpFinding is a row of the findings table: category and type, the
	// severity and its padding, then the meaning.
	helpFinding = regexp.MustCompile(`^(\s+\S+\s+\S+\s+)(high|medium|low)(\s+)(.*)$`)
	// helpListLabel is the label of a line such as "Kinds accepted by --kind: ...".
	helpListLabel = regexp.MustCompile(`^(\S[^:]* accepted by --[\w-]+:)(.*)$`)
)

// colourHelp styles help text at depth d. It only adds escape codes around parts of lines and keeps
// every column's padding, so at palette.None the text is returned as it is. Headings are bold, flag
// and command names take the info colour, value types, defaults and examples the muted chrome
// colour, and the findings table's severities are badges as in the summary.
func colourHelp(d palette.Depth, text string) string {
	if d == palette.None {
		return text
	}
	muted := func(s string) string { return d.Text(palette.Chrome, "TIMESTAMP", s) }
	name := func(s string) string { return d.Text(palette.Semantic, "info", s) }
	lines := strings.Split(text, "\n")
	section := ""
	for i, l := range lines {
		switch {
		case l == "":
			continue
		case !strings.HasPrefix(l, " ") && strings.HasSuffix(l, ":"):
			section = l
			lines[i] = d.Bold(l)
			continue
		case !strings.HasPrefix(l, " "):
			section = ""
			if m := helpListLabel.FindStringSubmatch(l); m != nil {
				lines[i] = d.Bold(m[1]) + m[2]
			}
			continue
		}
		switch {
		case strings.Contains(strings.ToLower(section), "flags"):
			if m := helpFlag.FindStringSubmatch(l); m != nil {
				desc, aside := m[5], ""
				if loc := helpAside.FindStringIndex(desc); loc != nil {
					desc, aside = desc[:loc[0]], muted(desc[loc[0]:])
				}
				desc = helpNote.ReplaceAllStringFunc(desc, muted) + aside
				lines[i] = m[1] + name(m[2]) + muted(m[3]) + m[4] + desc
			}
		case section == "Commands:":
			if m := helpCommand.FindStringSubmatch(l); m != nil {
				lines[i] = m[1] + name(m[2]) + m[3] + m[4]
			}
		case strings.HasPrefix(section, "Findings"):
			if m := helpFinding.FindStringSubmatch(l); m != nil {
				lines[i] = m[1] + d.Value(palette.Severity, m[2]) + " " + m[4]
			}
		}
	}
	return strings.Join(lines, "\n")
}
