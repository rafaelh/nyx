package cli

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/layout"
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

// newRoot builds the command tree: nyx, recon and its export, cve, help and
// the help topics. The root owns the shared flags, which every command takes
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
	pf.BoolVarP(&inv.sh.json, "json", "J", false, "Print the result as one JSON object on stdout, and any error as one JSON line on stderr")
	pf.BoolVarP(&inv.sh.quiet, "quiet", "q", false, "Write only warnings and errors to stderr; recon's summary is still printed")
	pf.BoolVar(&inv.sh.debug, "debug", false, "Also write diagnostics to stderr: each failed check (recon), each request to the NVD (cve), and the stack of an unexpected failure")
	f := root.Flags()
	f.SortFlags = false
	f.Bool("version", false, "Print the version and exit") // long-only: -v is usually read as verbose
	f.BoolP("help", "h", false, "Help for nyx")

	recon := newReconCommand(inv)
	recon.AddCommand(newExportCommand(inv))
	help := newHelpCommand(inv, root)
	stream := inv.helpStream()
	root.AddCommand(recon, newCVECommand(inv), newIPCommand(inv), help,
		newTopic(inv, "findings", "Finding types and their default severities", findingsHelp, stream),
		newTopic(inv, "stages", "The stages, in run order, and what each one contacts and does",
			func(s layout.Stream) string { return stagesHelp(s, inv.d.Stages) }, stream))
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

// helpStream is the stream help text and the palette sheet are laid out for: stdout's, except
// under --json, when they are written as for a stream that is not a terminal.
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

// A help screen is built as a list of blocks, each of one kind, so that it can be written two ways:
// off a terminal the blocks are joined back into the text nyx has always written, and on a terminal
// each kind is laid out to the stream's width.
type blockKind int

const (
	blockHeading   blockKind = iota // an unindented line ending in a colon
	blockUsage                      // a usage line: never wraps
	blockExample                    // an example line: never wraps
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
	lines []string // the block's plain text, a line each, without line breaks
	// rows are the rows of a command list.
	rows []commandRow
	// table builds the table of a blockTable for a stream, whose colours its cells take.
	table func(layout.Stream) layout.Table
}

// commandRow is a row of a command list: its indent, the name, the gap that aligns the summaries
// and the summary, which together are the row's plain text.
type commandRow struct{ lead, name, gap, summary string }

func (r commandRow) plain() string { return r.lead + r.name + r.gap + r.summary }

// plainHelp is the blocks as text for a stream that is not a terminal: every line of every block,
// each ended by a line break.
func plainHelp(blocks []helpBlock) string {
	var b strings.Builder
	for _, bl := range blocks {
		for _, l := range bl.lines {
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// renderHelp is the blocks as text for s: the text of a stream that is not a terminal, or each block
// laid out to the width of one that is.
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

// layoutBlock is one block laid out for a terminal stream: its lines, each ended by a line break.
// Text wraps to the stream's width, but for a usage or example line, which never wraps.
func layoutBlock(b helpBlock, s layout.Stream) string {
	if b.kind == blockTable {
		return b.table(s).Render(s)
	}
	cols := s.Cols()
	info := func(x string) string { return s.Depth.Text(palette.Semantic, "info", x) }
	muted := func(x string) string { return s.Depth.Text(palette.Chrome, "TIMESTAMP", x) }
	var lines []string
	switch b.kind {
	case blockHeading:
		for _, l := range b.lines {
			lines = append(lines, layout.Heading(s, l, false)...)
		}
	case blockUsage, blockExample, blockBlank, blockTable: // a table returned above; listed for the exhaustive lint
		lines = b.lines
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

// reflow is the lines of a paragraph joined by spaces and wrapped to cols, its first line and its
// continuation lines indented as the first line was.
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

// asideAt is where the default or example that a flag's description ends with begins, at its
// leading space, or -1 when it has none.
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

// flagSpans are the parts of a flag's description: its notes and its trailing default or example
// take style muted, and the rest is plain.
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

// textLines are the lines of text, which ends with a line break unless it is empty.
func textLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// free adds free text, a line break ending each line: a line in values is a labelled list of
// values, and the rest is split by freeBlocks.
func (h *helpBuilder) free(text string, values map[string]bool) {
	h.blocks = append(h.blocks, freeBlocks(text, values)...)
}

// valueLines is the set of lines of text, the lines of an annotation that names values.
func valueLines(text string) map[string]bool {
	set := map[string]bool{}
	for l := range strings.SplitSeq(text, "\n") {
		set[l] = true
	}
	return set
}

// freeBlocks splits free text into blocks: a blank line is a blank block, a line in values is a
// labelled list of values, an unindented line that ends in a colon is a heading, and a run of the
// other lines with one indent is a paragraph.
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

// rootHelp is the whole reference, rendered from the tree: examples that pass
// --json, the shared flags, then every command with its usage, one example,
// its everyday flags and the valid values of its fixed-set flags, the help
// commands, and the exit codes.
func rootHelp(root *cobra.Command, s layout.Stream) string {
	return renderHelp(rootHelpBlocks(root), s)
}

// rootHelpBlocks are the blocks of rootHelp.
func rootHelpBlocks(root *cobra.Command) []helpBlock {
	cmds := runnable(root)
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

// commandReference adds one command's entry in the reference: its usage, its summary, one
// example, its everyday flags and its notes.
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

// helpCommands adds the reference's list of help commands: help itself and each help topic, with
// their summaries in one aligned column.
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
	// A line break ends the footer's last line, so a blank line follows it only when the footer
	// itself ends with one.
	b.blank()
	if footer := c.Annotations[annotationFooter]; footer != "" {
		b.free(footer, valueLines(c.Annotations[annotationValues]))
	}
	b.values(exitCodesLine)
	return b.blocks
}

// findingsHeading is the heading of the findings topic.
const findingsHeading = "Findings and their default severities (fixed in code, not configurable; the summary lists high and medium):"

// findingsBlocks are the blocks of nyx help findings: its heading and its table of severities.
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

// newTopic builds a help topic: a command with no run of its own, which the root's help lists under
// "Help topics" and which nyx help <name>, nyx <name> and nyx <name> --help print. render gives its
// text for s, the stream help is laid out for when the tree is built.
func newTopic(inv *invocation, name, short string, render func(layout.Stream) string, s layout.Stream) *cobra.Command {
	cmd := &cobra.Command{Use: name, Short: short}
	cmd.SetHelpFunc(func(c *cobra.Command, _ []string) {
		inv.showHelp(c, func() string { return render(s) })
	})
	return cmd
}

// findingsHelp is the findings topic for s.
func findingsHelp(s layout.Stream) string { return renderHelp(findingsBlocks(), s) }

// helpFlag is a flag line: indent, names, an optional value type, the gap and the description.
var helpFlag = regexp.MustCompile(`^(\s+)((?:-\w, )?--[\w-]+)( \w+)?(\s{2,})(.*)$`)
