package cli

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
)

// Command annotations supply help content so adding a command does not require a second command
// list.
const (
	// annotationEveryday lists root-help flags in order; absent means all command flags.
	annotationEveryday = "nyx.everyday"
	// annotationValues supplies fixed-choice value lines for root help.
	annotationValues = "nyx.values"
	// annotationNote is a line the root help adds after them.
	annotationNote = "nyx.note"
	// annotationFooter supplies text after command flags.
	annotationFooter = "nyx.footer"
	// annotationNotInRoot keeps a command out of the root help; nyx help <command> still shows
	// its own.
	annotationNotInRoot = "nyx.notinroot"
)

// exitCodesLine is the last line of every help text.
const exitCodesLine = "Exit codes: 0 success, 1 system error, 2 usage error, 3 not found, 7 partial result, 130/143/129 interrupted (SIGINT/SIGTERM/SIGHUP)"

// newRoot builds commands and help topics. Shared root flags work before or after command
// names.
func newRoot(inv *invocation) *cobra.Command {
	root := &cobra.Command{
		Use:   "nyx",
		Short: "Passive-first reconnaissance for authorised engagements",
		Long: "nyx is passive-first reconnaissance for authorised engagements. Every command takes the shared\n" +
			"flags, and each command's own flags follow its name.",
		SilenceUsage:  true,
		SilenceErrors: true,
		// nyx completion replaces cobra's own, which offers shells nyx does not support.
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	pf := root.PersistentFlags()
	pf.SortFlags = false
	pf.BoolVarP(&inv.sh.json, "json", "J", false, "Print the result as one JSON object on stdout, and any error as one JSON line on stderr")
	pf.BoolVarP(&inv.sh.quiet, "quiet", "q", false, "Write only warnings and errors to stderr; recon's summary is still printed")
	pf.BoolVar(&inv.sh.debug, "debug", false, "Also write diagnostics to stderr: each failed job (recon), each request to the NVD (cve), each address probed (ip --active), and the stack of an unexpected failure")
	f := root.Flags()
	f.SortFlags = false
	f.Bool("version", false, "Print the version and exit") // long-only: -v is usually read as verbose
	f.BoolP("help", "h", false, "Help for nyx")

	recon := newReconCommand(inv)
	recon.AddCommand(newExportCommand(inv))
	help := newHelpCommand(inv, root)
	stream := inv.helpStream()
	root.AddCommand(recon, newCVECommand(inv), newIPCommand(inv), newSetupCommand(inv), newCompletionCommand(inv, root), help,
		newTopic(inv, "findings", "Finding types and their default severities", findingsHelp, stream),
		newTopic(inv, "procedures", "The procedures, in run order, and what each one contacts and does",
			func(s layout.Stream) string { return proceduresHelp(s, inv.d.Procedures) }, stream))
	root.SetHelpCommand(help)
	root.SetHelpFunc(func(c *cobra.Command, _ []string) { inv.printHelp(root, c) })
	return root
}

// newHelpCommand resolves nyx help [command] to the same text as --help.
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

// helpStream uses stdout's layout, except --json always selects non-terminal formatting.
func (inv *invocation) helpStream() layout.Stream {
	if inv.raw.json || inv.sh.json {
		return layout.Stream{Width: inv.st.out.Width}
	}
	return inv.st.out
}

// printHelp writes the help of c: the root help for the root and for help.
func (inv *invocation) printHelp(root, c *cobra.Command) {
	inv.showHelp(c, func() string {
		if c == root || c.Name() == "help" && c.Parent() == root {
			return rootHelp(root, inv.helpStream())
		}
		return commandHelp(c, inv.helpStream())
	})
}

// showHelp validates shared flags before writing help. Conflicting --quiet/--debug returns a
// usage error with no help output.
func (inv *invocation) showHelp(c *cobra.Command, text func() string) {
	if err := inv.problems().Err(); err != nil {
		_ = inv.start(c, err)
		return
	}
	fmt.Fprint(inv.d.Stdout, text())
}

// runnable walks work-performing commands parent-first, omitting help/topics.
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

// Help uses typed blocks so plain output can preserve its text while terminal output lays each
// block out to the available width.
type blockKind int

const (
	blockHeading   blockKind = iota // an unindented line ending in a colon
	blockUsage                      // a usage line: never wraps
	blockExample                    // an example line: never wraps, its nyx call in the example colour
	blockSummary                    // a command's indented one-line summary
	blockFlags                      // pflag's flag list, a row to a line
	blockCommands                   // the rows of a command list: a name and its summary
	blockValues                     // a labelled list of values, such as "Exit codes: 0 success, ..."
	blockParagraph                  // running text, re-flowed on a terminal
	blockTable                      // a table of a help topic
	blockBlank                      // an empty line
)

// helpBlock is one block of a help screen.
type helpBlock struct {
	kind  blockKind
	lines []string // plain block lines without newline characters
	// rows are the rows of a command list.
	rows []commandRow
	// table builds a help table using the selected stream's styles.
	table func(layout.Stream) layout.Table
}

// commandRow separates indentation, name, alignment gap and summary while preserving plain
// text.
type commandRow struct{ lead, name, gap, summary string }

func (r commandRow) plain() string { return r.lead + r.name + r.gap + r.summary }

// plainHelp joins block lines with newline endings for non-terminal output.
func plainHelp(blocks []helpBlock) string {
	var b strings.Builder
	for _, bl := range blocks {
		for _, l := range bl.lines {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// renderHelp preserves plain-stream text or lays out blocks to a terminal's width.
func renderHelp(blocks []helpBlock, s layout.Stream) string {
	if !s.Terminal {
		return plainHelp(blocks)
	}
	s = s.Fixed()
	var b strings.Builder
	for _, bl := range blocks {
		b.WriteString(layoutBlock(bl, s))
	}
	return b.String()
}

// layoutBlock returns newline-terminated terminal lines. Text wraps to width; usage and example
// lines remain unwrapped.
func layoutBlock(b helpBlock, s layout.Stream) string {
	if b.kind == blockTable {
		return b.table(s).Render(s)
	}
	cols := s.Cols()
	info := func(x string) string { return s.Depth.Text(palette.Semantic, "info", x) }
	muted := func(x string) string { return s.Depth.Text(palette.Semantic, "muted", x) }
	var lines []string
	switch b.kind {
	case blockHeading:
		for _, l := range b.lines {
			lines = append(lines, layout.Heading(s, l, false)...)
		}
	case blockUsage, blockBlank, blockTable: // a table returned above; listed for the exhaustive lint
		lines = b.lines
	case blockExample:
		for _, l := range b.lines {
			lines = append(lines, exampleLine(l, s.Depth))
		}
	case blockSummary, blockParagraph:
		lines = reflow(b.lines, cols)
	case blockFlags:
		for _, l := range b.lines {
			m := helpFlag.FindStringSubmatch(l)
			if m == nil {
				lines = append(lines, reflow([]string{l}, cols)...)
				continue
			}
			prefix := m[1] + info(m[2])
			if m[3] != "" {
				prefix += muted(m[3])
			}
			prefix += m[4]
			lines = append(lines, layout.Hang(prefix, flagSpans(m[5], muted), cols, layout.Spaces)...)
		}
	case blockCommands:
		for _, r := range b.rows {
			lines = append(lines, layout.Hang(r.lead+info(r.name)+r.gap, layout.Plain(r.summary), cols, layout.Spaces)...)
		}
	case blockValues:
		for _, l := range b.lines {
			label, items, ok := strings.Cut(l, ": ")
			if !ok {
				lines = append(lines, reflow([]string{l}, cols)...)
				continue
			}
			label += ":"
			lines = append(lines, layout.Hang(s.Depth.Bold(label)+" ", layout.Plain(items), cols, layout.Commas)...)
		}
	}
	var out strings.Builder
	for _, l := range lines {
		out.WriteString(l + "\n")
	}
	return out.String()
}

// exampleLine colours the nyx invocation while leaving indentation and any preceding label
// plain.
func exampleLine(l string, d palette.Depth) string {
	at := strings.Index(l, "nyx ")
	if at < 0 {
		return l
	}
	return l[:at] + d.Text(palette.Semantic, "example", l[at:])
}

// reflow joins paragraph lines and wraps to cols, preserving the first line's indentation
// throughout.
func reflow(lines []string, cols int) []string {
	words := make([]string, len(lines))
	for i, l := range lines {
		words[i] = strings.TrimSpace(l)
	}
	return layout.Hang(strings.Repeat(" ", indentOf(lines[0])), layout.Plain(strings.Join(words, " ")), cols, layout.Spaces)
}

// indentOf is the number of spaces l starts with.
func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

// flagNotes are the usage notes that may come anywhere in a flag's description.
var flagNotes = []string{"(# comments allowed)", "(repeatable)"}

// asideAt locates the leading space of a trailing default/example note, or -1 when absent.
func asideAt(desc string) int {
	if !strings.HasSuffix(desc, ")") {
		return -1
	}
	at := -1
	for _, open := range []string{" (default ", " (default:", " (e.g."} {
		if i := strings.Index(desc, open); i >= 0 && (at < 0 || i < at) {
			at = i
		}
	}
	return at
}

// flagSpans de-emphasises notes and trailing defaults/examples while keeping the main
// description plain.
func flagSpans(desc string, muted func(string) string) []layout.Span {
	aside := ""
	if at := asideAt(desc); at >= 0 {
		desc, aside = desc[:at], desc[at:]
	}
	var spans []layout.Span
	for {
		at, note := -1, ""
		for _, n := range flagNotes {
			if i := strings.Index(desc, n); i >= 0 && (at < 0 || i < at) {
				at, note = i, n
			}
		}
		if at < 0 {
			break
		}
		spans = append(spans, layout.Span{Text: desc[:at]}, layout.Span{Text: note, Style: muted})
		desc = desc[at+len(note):]
	}
	spans = append(spans, layout.Span{Text: desc})
	if aside != "" {
		spans = append(spans, layout.Span{Text: aside, Style: muted})
	}
	return spans
}

// helpBuilder collects the blocks of a screen.
type helpBuilder struct{ blocks []helpBlock }

func (h *helpBuilder) add(kind blockKind, lines ...string) {
	h.blocks = append(h.blocks, helpBlock{kind: kind, lines: lines})
}

func (h *helpBuilder) blank()              { h.add(blockBlank, "") }
func (h *helpBuilder) heading(text string) { h.add(blockHeading, text) }
func (h *helpBuilder) usage(line string)   { h.add(blockUsage, line) }
func (h *helpBuilder) example(line string) { h.add(blockExample, line) }
func (h *helpBuilder) summary(line string) { h.add(blockSummary, line) }
func (h *helpBuilder) values(line string)  { h.add(blockValues, line) }

// flags adds the flag list text of flagUsages, a row to a line.
func (h *helpBuilder) flags(text string) { h.add(blockFlags, textLines(text)...) }

// textLines splits newline-terminated text without adding a spurious final line.
func textLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// free adds newline-terminated text using labelled values where known and freeBlocks for other
// text.
func (h *helpBuilder) free(text string, values map[string]bool) {
	h.blocks = append(h.blocks, freeBlocks(text, values)...)
}

// valueLines identifies labelled value lines from an annotation.
func valueLines(text string) map[string]bool {
	set := map[string]bool{}
	for l := range strings.SplitSeq(text, "\n") {
		set[l] = true
	}
	return set
}

// freeBlocks recognises blank lines, labelled value lists, unindented colon-ended headings and
// paragraphs sharing an indent.
func freeBlocks(text string, values map[string]bool) []helpBlock {
	var out []helpBlock
	var run []string
	flush := func() {
		if len(run) > 0 {
			out = append(out, helpBlock{kind: blockParagraph, lines: run})
			run = nil
		}
	}
	for l := range strings.SplitSeq(text, "\n") {
		switch {
		case strings.TrimSpace(l) == "":
			flush()
			out = append(out, helpBlock{kind: blockBlank, lines: []string{l}})
		case values[l]:
			flush()
			out = append(out, helpBlock{kind: blockValues, lines: []string{l}})
		case indentOf(l) == 0 && strings.HasSuffix(l, ":"):
			flush()
			out = append(out, helpBlock{kind: blockHeading, lines: []string{l}})
		default:
			if len(run) > 0 && indentOf(l) != indentOf(run[0]) {
				flush()
			}
			run = append(run, l)
		}
	}
	flush()
	return out
}

// rootHelp builds the reference from the command tree: JSON examples, shared flags, commands
// and their common flags, help topics, then exit codes.
func rootHelp(root *cobra.Command, s layout.Stream) string {
	return renderHelp(rootHelpBlocks(root), s)
}

// rootHelpBlocks are the blocks of rootHelp.
func rootHelpBlocks(root *cobra.Command) []helpBlock {
	cmds := slices.DeleteFunc(runnable(root), func(c *cobra.Command) bool { return c.Annotations[annotationNotInRoot] != "" })
	var b helpBuilder
	b.heading("Examples:")
	for _, c := range cmds {
		if ex := firstExample(c); ex != "" {
			b.example("  " + ex)
		}
	}
	b.blank()
	b.free(root.Long, nil)
	b.blank()
	b.heading("Shared flags (every command takes them; they alone may also come before the command):")
	b.flags(flagUsages(root.PersistentFlags()))
	for _, c := range cmds {
		b.commandReference(root, c)
	}
	b.helpCommands(root)
	own := pflag.NewFlagSet("nyx", pflag.ContinueOnError)
	own.SortFlags = false
	own.AddFlag(root.Flags().Lookup("version"))
	own.AddFlag(root.Flags().Lookup("help"))
	b.blank()
	b.heading("Flags:")
	b.flags(flagUsages(own))
	b.blank()
	b.values(exitCodesLine)
	return b.blocks
}

// commandReference assembles usage, summary, example, common flags and notes.
func (h *helpBuilder) commandReference(root, c *cobra.Command) {
	h.blank()
	h.usage(c.UseLine())
	h.summary("  " + c.Short)
	if ex := firstExample(c); ex != "" {
		h.example("  Example: " + ex)
	}
	if fs := everydayFlags(c, root.PersistentFlags()); fs.HasAvailableFlags() {
		h.heading(strings.TrimPrefix(c.CommandPath(), root.Name()+" ") + " flags:")
		h.flags(flagUsages(fs))
	}
	if v := c.Annotations[annotationValues]; v != "" {
		h.free(v, valueLines(v))
	}
	if v := c.Annotations[annotationNote]; v != "" {
		h.free(v, nil)
	}
}

// everydayFlags uses a command's annotated flag order, or all flags by default. It omits help,
// hidden and shared flags.
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

// helpCommands aligns help-command and topic summaries in the root reference.
func (h *helpBuilder) helpCommands(root *cobra.Command) {
	h.blank()
	h.heading("Help:")
	var rows []commandRow
	width := 0
	for _, c := range root.Commands() {
		if c.Hidden || c.Runnable() && c.Name() != "help" {
			continue
		}
		use := "nyx help " + c.Name()
		if c.Name() == "help" {
			use = "nyx help [command]"
		}
		rows = append(rows, commandRow{lead: "  ", name: use, summary: c.Short})
		width = max(width, len(use))
	}
	for i := range rows {
		rows[i].gap = strings.Repeat(" ", width-len(rows[i].name)+3)
	}
	h.commands(rows)
}

// commands adds a list of command rows.
func (h *helpBuilder) commands(rows []commandRow) {
	lines := make([]string, len(rows))
	for i, r := range rows {
		lines[i] = r.plain()
	}
	h.blocks = append(h.blocks, helpBlock{kind: blockCommands, lines: lines, rows: rows})
}

// flagUsages renders boolean switches as --passive rather than pflag's value syntax. It works
// on a copy so help formatting cannot affect parsing.
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

// plainSwitch hides IsBoolFlag so pflag omits the [=true|false] usage suffix.
type plainSwitch struct{ pflag.Value }

// commandHelp assembles complete help for one command.
func commandHelp(c *cobra.Command, s layout.Stream) string {
	return renderHelp(commandHelpBlocks(c), s)
}

// commandHelpBlocks are the blocks of commandHelp.
func commandHelpBlocks(c *cobra.Command) []helpBlock {
	var b helpBuilder
	if c.Example != "" {
		b.heading("Examples:")
		for l := range strings.SplitSeq(c.Example, "\n") {
			b.example(l)
		}
		b.blank()
	}
	if c.Long != "" {
		b.free(c.Long, nil)
		b.blank()
	}
	b.heading("Usage:")
	b.usage("  " + c.UseLine())
	if c.HasAvailableSubCommands() {
		b.blank()
		b.heading("Commands:")
		var rows []commandRow
		for _, sub := range c.Commands() {
			if sub.IsAvailableCommand() {
				rows = append(rows, commandRow{lead: "  ", name: sub.Name(), gap: strings.Repeat(" ", sub.NamePadding()-len(sub.Name())+1), summary: sub.Short})
			}
		}
		b.commands(rows)
	}
	if local := c.LocalFlags(); local.HasAvailableFlags() {
		b.blank()
		b.heading("Flags:")
		b.flags(flagUsages(local))
	}
	if inherited := c.InheritedFlags(); inherited.HasAvailableFlags() {
		b.blank()
		b.heading("Shared flags:")
		b.flags(flagUsages(inherited))
	}
	// The footer already has a final newline; add spacing only when it explicitly ends with
	// a blank line.
	b.blank()
	if footer := c.Annotations[annotationFooter]; footer != "" {
		b.free(footer, valueLines(c.Annotations[annotationValues]))
	}
	b.values(exitCodesLine)
	return b.blocks
}

// findingsHeading is the heading of the findings topic.
const findingsHeading = "Findings and their default severities (fixed in code, not configurable; the summary lists high and medium):"

// findingsBlocks builds the findings heading and severity table.
func findingsBlocks() []helpBlock {
	var b helpBuilder
	b.heading(findingsHeading)
	b.blocks = append(b.blocks, helpBlock{kind: blockTable, lines: textLines(findings.HelpTable()), table: findingsTable})
	return b.blocks
}

// findingsTable is the table of finding types for s.
func findingsTable(s layout.Stream) layout.Table {
	t := layout.Table{
		Indent:   2,
		Bordered: true,
		Columns: []layout.Column{{Header: "CATEGORY"}, {Header: "TYPE"}, {Header: "SEVERITY"},
			{Header: "MEANING", Wrap: layout.Spaces, Shrink: 1}},
	}
	badge := func(x string) string { return s.Depth.Value(palette.Severity, x) }
	for _, r := range findings.SeverityTable() {
		t.Rows = append(t.Rows, []layout.Cell{layout.Plain(r.Category), layout.Plain(r.Type),
			{{Text: r.Severity, Style: badge, Keep: true}}, layout.Plain(r.Meaning)})
	}
	return t
}

// newTopic creates a help-only command available through nyx help <name>, nyx <name> and
// --help. render receives the stream selected when building the tree.
func newTopic(inv *invocation, name, short string, render func(layout.Stream) string, s layout.Stream) *cobra.Command {
	cmd := &cobra.Command{Use: name, Short: short}
	cmd.SetHelpFunc(func(c *cobra.Command, _ []string) {
		inv.showHelp(c, func() string { return render(s) })
	})
	return cmd
}

// findingsHelp is the findings topic for s.
func findingsHelp(s layout.Stream) string { return renderHelp(findingsBlocks(), s) }

// helpFlag separates flag names/type from alignment and description.
var helpFlag = regexp.MustCompile(`^(\s+)((?:-\w, )?--[\w-]+)( \w+)?(\s{2,})(.*)$`)
