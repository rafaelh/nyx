package cli_test

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
)

// helpOn is a help screen written to a terminal of colour depth d, cols wide, by a harness with
// the production stages. Depth None is a terminal under NO_COLOR.
func helpOn(t *testing.T, d palette.Depth, cols int, args ...string) string {
	t.Helper()
	h := newHarness(t, defaultStageList()...)
	setTerminal(h, d, cols)
	if code := h.execRoot(args...); code != 0 {
		t.Fatalf("%v: exit %d, stderr %q", args, code, h.stderr.String())
	}
	return h.stdout.String()
}

// setTerminal makes h's streams terminals of depth d, cols wide.
func setTerminal(h *harness, d palette.Depth, cols int) {
	colourAt(h.t, h, d)
	if d == palette.None {
		h.setenv("NO_COLOR", "1")
	}
	if cols > 0 {
		h.setenv("COLUMNS", strconv.Itoa(cols))
	}
}

func textLines(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }

// blockFrom is the lines from the first line that starts with start to the next blank line.
func blockFrom(t *testing.T, lines []string, start string) []string {
	t.Helper()
	i := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, start) })
	if i < 0 {
		t.Fatalf("no line starts with %q in:\n%s", start, strings.Join(lines, "\n"))
	}
	j := i
	for j < len(lines) && lines[j] != "" {
		j++
	}
	return lines[i:j]
}

// hangFrom is the line that starts with start and the lines after it that are indented at least
// indent cells: a labelled row and its continuation lines.
func hangFrom(t *testing.T, lines []string, start string, indent int) []string {
	t.Helper()
	i := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, start) })
	if i < 0 {
		t.Fatalf("no line starts with %q in:\n%s", start, strings.Join(lines, "\n"))
	}
	j := i + 1
	for j < len(lines) && lines[j] != "" && leadingSpaces(lines[j]) >= indent {
		j++
	}
	return lines[i:j]
}

func joinedWords(lines []string) string {
	return strings.Join(strings.Fields(strings.Join(lines, " ")), " ")
}

func widest(lines []string) int {
	w := 0
	for _, l := range lines {
		w = max(w, layout.Measure(l))
	}
	return w
}

func leadingSpaces(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }

var (
	flagRowRE = regexp.MustCompile(`^(\s+(?:-\w, )?--[\w-]+(?: \w+)?\s{2,})\S`)
	flagAnyRE = regexp.MustCompile(`^\s+(?:-\w, )?--[\w-]+`)
)

// Flag descriptions wrap to the width, and a continuation line is aligned under the description.
func TestHelp_FlagDescriptionsWrap(t *testing.T) {
	t.Parallel()
	lines := textLines(helpOn(t, palette.None, 80, "recon", "--help"))
	continued := 0
	for i := range lines {
		m := flagRowRE.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		col := len(m[1])
		for j := i + 1; j < len(lines) && lines[j] != "" && !flagAnyRE.MatchString(lines[j]); j++ {
			continued++
			if got := leadingSpaces(lines[j]); got != col {
				t.Errorf("continuation %q is indented %d, want the description column %d", lines[j], got, col)
			}
		}
	}
	if continued < 10 {
		t.Errorf("only %d continuation lines: the descriptions are not wrapping", continued)
	}
	flags := hangFrom(t, lines, "      --skip stringArray", 47)
	if want := "Stage to turn off for this run (repeatable; replaces the skip setting, and none clears it; see nyx help stages)"; !strings.HasSuffix(joinedWords(flags), want) || len(flags) < 2 {
		t.Errorf("the --skip row, wrapped, is %q", flags)
	}
	// The shared flags wrap too, on a command's own help and in the root's.
	for _, args := range [][]string{{"cve", "--help"}, {"--help"}} {
		got := helpOn(t, palette.None, 80, args...)
		if w := widest(hangFrom(t, textLines(got), "      --debug", 16)); w > 80 {
			t.Errorf("%v: the --debug row is %d cells wide", args, w)
		}
	}
}

// Descriptions, footers and the free text of a command re-flow to the width, ignoring the hard
// line breaks they are written with.
func TestHelp_ParagraphsReflow(t *testing.T) {
	t.Parallel()
	const rootLong = "nyx is passive-first reconnaissance for authorised engagements. Every command takes the shared flags, and each command's own flags follow its name."
	root := blockFrom(t, textLines(helpOn(t, palette.None, 80, "--help")), "nyx is passive-first")
	if joinedWords(root) != rootLong || len(root) < 2 || widest(root) > 80 {
		t.Errorf("root description: %q", root)
	}
	if slices.Contains(root, "flags, and each command's own flags follow its name.") {
		t.Errorf("the root description keeps its hard line break:\n%s", strings.Join(root, "\n"))
	}

	const configuration = "Settings come from a YAML config file, NYX_* environment variables or flags; flags override environment variables, which override the file. " +
		"The default config file is $XDG_CONFIG_HOME/nyx/config.yaml (default ~/.config/nyx/config.yaml). " +
		"Environment variables are NYX_<SETTING> with dots as underscores, e.g. NYX_CONCURRENCY and NYX_RATE_PER_HOST. " +
		"API keys are never flags: set keys.<source> in the config file or NYX_KEYS_<SOURCE> in the environment."
	recon := blockFrom(t, textLines(helpOn(t, palette.None, 80, "recon", "--help")), "Configuration:")
	if recon[0] != "Configuration:" || joinedWords(recon[1:]) != configuration || widest(recon) > 80 {
		t.Errorf("recon's Configuration footer: %q", recon)
	}
	for _, l := range recon[1:] {
		if leadingSpaces(l) != 2 {
			t.Errorf("footer line %q is not indented 2", l)
		}
	}
	if len(recon) < 6 {
		t.Errorf("the footer was not re-flowed into the width: %d lines", len(recon))
	}

	const stagesFooter = "Third-party stages ask public sources and resolvers, and run under --passive. Target stages contact the target's own systems: " +
		"they are skipped under --passive, and unless --authorised has confirmed, on this run or an earlier one, that you are authorised. " +
		"A stage with a KEY needs keys.<KEY> and is not-configured without it; a key in brackets is optional. " +
		"--redo <stage> performs every check of one stage again, and --skip <stage> turns one off, except the stages marked *, which other stages' safety depends on."
	stages := blockFrom(t, textLines(helpOn(t, palette.None, 80, "help", "stages")), "Third-party stages")
	if joinedWords(stages) != stagesFooter || widest(stages) > 80 {
		t.Errorf("stages footer: %q", stages)
	}
}

// A list of values wraps after a comma, and a continuation line is indented under the text after
// its label.
func TestHelp_ValueListsWrapAfterCommas(t *testing.T) {
	t.Parallel()
	var names []string
	for _, s := range defaultStageList() {
		names = append(names, s.Name())
	}
	check := func(screen []string, label, items string) {
		t.Helper()
		block := hangFrom(t, screen, label, 1)
		if !strings.HasPrefix(block[0], label+" ") || widest(block) > 80 || len(block) < 2 {
			t.Errorf("%s: %q", label, block)
			return
		}
		if got := strings.TrimPrefix(joinedWords(block), label+" "); got != items {
			t.Errorf("%s lists %q, want %q", label, got, items)
		}
		for i, l := range block[1:] {
			if leadingSpaces(l) != len(label)+1 {
				t.Errorf("%s: continuation %q is indented %d, want %d", label, l, leadingSpaces(l), len(label)+1)
			}
			if !strings.HasSuffix(block[i], ",") {
				t.Errorf("%s: line %q does not break after a comma", label, block[i])
			}
		}
	}
	root := textLines(helpOn(t, palette.None, 80, "--help"))
	check(root, "Stages accepted by --redo and --skip:", strings.Join(names, ", "))
	check(root, "Exit codes:", "0 success, 1 system error, 2 usage error, 3 not found, 7 partial result, 130/143/129 interrupted (SIGINT/SIGTERM/SIGHUP)")
	if got := hangFrom(t, root, "Stages --skip refuses:", 1); len(got) != 1 || got[0] != "Stages --skip refuses: resolve, wildcard, ipowner, providerranges" {
		t.Errorf("Stages --skip refuses: %q", got)
	}
	export := textLines(helpOn(t, palette.None, 80, "recon", "export", "--help"))
	wide := hangFrom(t, textLines(helpOn(t, palette.None, 1000, "recon", "export", "--help")), "Kinds accepted by --kind:", 1)
	if len(wide) != 1 {
		t.Fatalf("the kinds do not fit one line of 1000 cells: %q", wide)
	}
	check(export, "Kinds accepted by --kind:", strings.TrimPrefix(wide[0], "Kinds accepted by --kind: "))
	check(export, "Exit codes:", "0 success, 1 system error, 2 usage error, 3 not found, 7 partial result, 130/143/129 interrupted (SIGINT/SIGTERM/SIGHUP)")
	cve := textLines(helpOn(t, palette.None, 80, "cve", "--help"))
	check(cve, "Fields accepted by --fields:", "id, status, published, last_modified, description, cvss_version, cvss_score, cvss_severity, cvss_vector, cvss_source, weaknesses, affected_products_count, affected_products, references_count, references, all")
}

// Usage and example lines are never broken, even when they run past the width.
func TestHelp_UsageAndExamplesNeverWrap(t *testing.T) {
	t.Parallel()
	const longExample = "  nyx recon example.com --org 'Example Pty Ltd' --authorised --json --timeout 30m"
	if len(longExample) <= 80 {
		t.Fatal("the example no longer runs past 80 columns")
	}
	recon := textLines(helpOn(t, palette.None, 80, "recon", "--help"))
	for _, want := range []string{longExample, "  nyx recon example.com --json --timeout 30m", "  nyx recon [domain...] [flags]"} {
		if !slices.Contains(recon, want) {
			t.Errorf("recon --help lacks the unbroken line %q", want)
		}
	}
	root := textLines(helpOn(t, palette.None, 80, "--help"))
	for _, want := range []string{"nyx recon [domain...] [flags]", "  Example: nyx recon example.com --json --timeout 30m", "  nyx cve CVE-2021-44228 CVE-2024-3094 --json"} {
		if !slices.Contains(root, want) {
			t.Errorf("root help lacks the unbroken line %q", want)
		}
	}
	// A line of a table or paragraph is held to the width, which only these lines may pass.
	d := palette.TrueColor
	if got := helpOn(t, d, 80, "recon", "--help"); !strings.Contains(got, "  "+d.Text(palette.Semantic, "example", strings.TrimPrefix(longExample, "  "))+"\n") {
		t.Error("coloured recon --help breaks the example")
	}
}

// A command's summary wraps under its indent, and the rows of a command list wrap under the summary
// column, with the name in the info colour.
func TestHelp_CommandRowsWrap(t *testing.T) {
	t.Parallel()
	root := textLines(helpOn(t, palette.None, 80, "--help"))
	rows := blockFrom(t, root, "  nyx help findings")
	if len(rows) < 4 || widest(rows) > 80 {
		t.Fatalf("the help commands do not fit:\n%s", strings.Join(rows, "\n"))
	}
	col := strings.Index(rows[0], "Finding types")
	if col != len("  nyx help [command]   ") {
		t.Errorf("the summary column is %d: %q", col, rows[0])
	}
	for _, l := range rows {
		if !strings.HasPrefix(l, "  nyx help ") && leadingSpaces(l) != col {
			t.Errorf("continuation %q is not under the summary column %d", l, col)
		}
	}
	if joined := joinedWords(rows); !strings.Contains(joined, "The help of nyx, or of one command or topic: the same as --help") {
		t.Errorf("the help summary was cut: %q", joined)
	}
	at := slices.IndexFunc(root, func(l string) bool { return strings.HasPrefix(l, "  Passive-first reconnaissance") })
	if at < 0 || root[at+1] != "  netblocks" || widest(root[at:at+2]) > 80 {
		t.Errorf("recon's summary does not wrap under its indent:\n%s", strings.Join(root, "\n"))
	}

	d := palette.TrueColor
	for _, args := range [][]string{{"--help"}, {"recon", "--help"}} {
		got := helpOn(t, d, 80, args...)
		want := d.Text(palette.Semantic, "info", map[bool]string{true: "nyx help findings", false: "export"}[len(args) == 1])
		if !strings.Contains(got, want) {
			t.Errorf("%v: no command name in the info colour %q", args, want)
		}
	}
}

// Every help heading is bold in the info colour, a heading wider than the width wraps with each
// line in that style, and an uncoloured terminal has plain headings.
func TestHelp_HeadingsStyled(t *testing.T) {
	t.Parallel()
	d := palette.TrueColor
	head := func(s string) string { return d.BoldText(palette.Semantic, "info", s) }
	screens := []struct {
		args     []string
		headings []string
	}{
		{[]string{"--help"}, []string{"Examples:", "Flags:", "Help:", "cve flags:", "recon flags:", "recon export flags:"}},
		{[]string{"recon", "--help"}, []string{"Examples:", "Usage:", "Commands:", "Flags:", "Shared flags:", "Configuration:"}},
		{[]string{"cve", "--help"}, []string{"Examples:", "Usage:", "Flags:", "Shared flags:"}},
		{[]string{"help", "stages"}, []string{"Stages, in the order each pass runs them:"}},
	}
	for _, s := range screens {
		got := helpOn(t, d, 80, s.args...)
		for _, want := range s.headings {
			if !strings.Contains(got, "\n"+head(want)+"\n") && !strings.HasPrefix(got, head(want)+"\n") {
				t.Errorf("%v: heading %q is not bold in the info colour", s.args, want)
			}
		}
	}

	// A heading of 85 cells wraps at spaces, each line in the heading style from column 0.
	const long = "Shared flags (every command takes them; they alone may also come before the command):"
	lines := textLines(helpOn(t, d, 80, "--help"))
	i := slices.IndexFunc(lines, func(l string) bool {
		return strings.HasPrefix(l, head("Shared flags (every")[:len(head(""))-4]+"Shared flags (every")
	})
	if i < 0 || i+1 >= len(lines) {
		t.Fatalf("no wrapped shared-flags heading in:\n%s", strings.Join(lines, "\n"))
	}
	open := strings.TrimSuffix(head(""), "\x1b[0m")
	var words []string
	for _, l := range lines[i : i+2] {
		if !strings.HasPrefix(l, open) || !strings.HasSuffix(l, "\x1b[0m") || widest([]string{l}) > 80 {
			t.Errorf("heading line %q is not one styled line within 80 cells", l)
		}
		words = append(words, strings.TrimSuffix(strings.TrimPrefix(l, open), "\x1b[0m"))
	}
	if strings.Join(words, " ") != long {
		t.Errorf("the wrapped heading reads %q", words)
	}

	// Help headings have no rule beneath them.
	if got := helpOn(t, d, 80, "recon", "--help"); strings.Contains(got, "─") {
		t.Error("a help heading has a rule beneath it")
	}

	// Without colour a heading is plain text.
	if got := helpOn(t, palette.None, 80, "recon", "--help"); strings.Contains(got, "\x1b") || !strings.Contains(got, "\nFlags:\n") {
		t.Errorf("an uncoloured terminal's headings:\n%s", got)
	}
}

// tableCells are the cells of the rows of a bordered table of ASCII borders, a row to a line.
func tableCells(line string) []string {
	var cells []string
	for c := range strings.SplitSeq(strings.Trim(strings.TrimSpace(line), "|"), "|") {
		cells = append(cells, strings.TrimSpace(c))
	}
	return cells
}

// tableOf is the lines of the bordered table in a screen, from its top border to its bottom one.
func tableOf(t *testing.T, lines []string) []string {
	t.Helper()
	top := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "  +-") })
	if top < 0 {
		t.Fatalf("no table in:\n%s", strings.Join(lines, "\n"))
	}
	end := top
	for end < len(lines) && strings.HasPrefix(lines[end], "  ") && strings.ContainsAny(lines[end], "|+") {
		end++
	}
	return lines[top:end]
}

// The findings topic is a bordered table with the columns CATEGORY, TYPE, SEVERITY and MEANING,
// whose meanings wrap within their column.
func TestHelp_FindingsTopicTable(t *testing.T) {
	t.Parallel()
	lines := textLines(helpOn(t, palette.None, 80, "help", "findings"))
	if widest(lines) > 80 {
		t.Errorf("a line is %d cells wide", widest(lines))
	}
	table := tableOf(t, lines)
	if !strings.HasPrefix(table[len(table)-1], "  +-") || !strings.HasPrefix(table[2], "  +-") {
		t.Errorf("the table's borders:\n%s", strings.Join(table, "\n"))
	}
	if got := tableCells(table[1]); !slices.Equal(got, []string{"CATEGORY", "TYPE", "SEVERITY", "MEANING"}) {
		t.Errorf("header %q", got)
	}
	type row struct{ category, typ, severity, meaning string }
	var got []row
	for _, l := range table[3 : len(table)-1] {
		c := tableCells(l)
		if len(c) != 4 {
			t.Fatalf("row %q has %d cells", l, len(c))
		}
		if c[0] != "" {
			got = append(got, row{c[0], c[1], c[2], c[3]})
		} else {
			got[len(got)-1].meaning += c[3] + " "
		}
	}
	// A word wider than the meaning column is broken at its width, so the pieces are compared
	// without the spaces between them.
	var want []row
	for i := range got {
		got[i].meaning = strings.ReplaceAll(got[i].meaning, " ", "")
	}
	for _, r := range findings.SeverityTable() {
		want = append(want, row{r.Category, r.Type, r.Severity, strings.ReplaceAll(r.Meaning, " ", "")})
	}
	if !slices.Equal(got, want) {
		t.Errorf("the table's rows differ from the severity table:\n got %v\nwant %v", got, want)
	}
	if len(table) < len(want)+5 {
		t.Error("no meaning wrapped within its column")
	}

	d := palette.TrueColor
	coloured := helpOn(t, d, 80, "help", "findings")
	for _, want := range []string{"┌", "┬", "┐", "│", "├", "┼", "┤", "└", "┴", "┘", d.Value(palette.Severity, "high"), d.Value(palette.Severity, "medium"),
		d.Value(palette.Severity, "low"), d.BoldText(palette.Semantic, "muted", "CATEGORY"), d.Text(palette.Chrome, "SEPARATOR", "│")} {
		if !strings.Contains(coloured, want) {
			t.Errorf("the coloured findings topic lacks %q", want)
		}
	}
	if widest(textLines(coloured)) > 80 {
		t.Error("the coloured findings topic is wider than 80 cells")
	}
}

// The stages topic is a bordered table that keeps the contact colours, wraps what each stage does
// within its column, and marks the stages --skip refuses.
func TestHelp_StagesTopicTable(t *testing.T) {
	t.Parallel()
	d := palette.TrueColor
	got := helpOn(t, d, 80, "help", "stages")
	for _, want := range []string{"┌", "│", "└", d.Text(palette.Semantic, "warning", "target"), d.Text(palette.Semantic, "success", "third party"),
		d.Text(palette.Semantic, "info", "resolve*"), d.Text(palette.Semantic, "info", "ports"), d.Text(palette.Semantic, "muted", "securitytrails"),
		d.BoldText(palette.Semantic, "muted", "WHAT IT DOES")} {
		if !strings.Contains(got, want) {
			t.Errorf("the coloured stages topic lacks %q", want)
		}
	}
	for _, name := range []string{"resolve", "wildcard", "ipowner", "providerranges"} {
		if !strings.Contains(got, d.Text(palette.Semantic, "info", name+"*")) {
			t.Errorf("%s is not marked *", name)
		}
	}

	plain := textLines(helpOn(t, palette.None, 80, "help", "stages"))
	if widest(plain) > 80 {
		t.Errorf("a line is %d cells wide", widest(plain))
	}
	table := tableOf(t, plain)
	if c := tableCells(table[1]); !slices.Equal(c, []string{"STAGE", "CONTACT", "KEY", "WHAT IT DOES"}) {
		t.Errorf("header %q", c)
	}
	rows := 0
	var origin []string
	in := false
	for _, l := range table[3 : len(table)-1] {
		c := tableCells(l)
		if c[0] != "" {
			rows++
			in = c[0] == "origincheck"
		}
		if in {
			origin = append(origin, c[3])
		}
	}
	if rows != len(defaultStageList()) {
		t.Errorf("%d stage rows, want %d", rows, len(defaultStageList()))
	}
	if len(origin) < 2 || strings.Join(origin, " ") != "One GET of / to each candidate origin of a CDN- or WAF-fronted hostname, to see whether it serves the site" {
		t.Errorf("origincheck does not wrap within WHAT IT DOES: %q", origin)
	}
}

// On a terminal with no colour, whether NO_COLOR or a dumb terminal says so, the help is laid out
// and writes no escape byte.
func TestHelp_UncolouredTerminalsHaveNoEscapes(t *testing.T) {
	t.Parallel()
	for _, mode := range []struct {
		name string
		env  map[string]string
	}{{"NO_COLOR", map[string]string{"NO_COLOR": "1"}}, {"TERM=dumb", map[string]string{"TERM": "dumb"}}} {
		for _, s := range helpScreens {
			t.Run(mode.name+"/"+s.name, func(t *testing.T) {
				t.Parallel()
				h := newHarness(t, helpStages()...)
				h.stdoutTTY, h.stderrTTY = true, true
				h.setenv("COLUMNS", "80")
				for k, v := range mode.env {
					h.setenv(k, v)
				}
				if code := h.execRoot(s.args...); code != 0 {
					t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
				}
				out := h.stdout.String()
				if strings.Contains(out, "\x1b") || out == "" {
					t.Errorf("an uncoloured terminal got %q", out)
				}
				if s.name == "findings" || s.name == "stages" {
					if !strings.Contains(out, "\n  +-") || !strings.Contains(out, "  | ") {
						t.Errorf("the topic's table is not laid out with ASCII borders:\n%s", out)
					}
				}
			})
		}
	}
}

// Every escape sequence in help on a terminal is one the palette writes: the headings, the names,
// the muted parts, the table borders and the severity badges.
func TestHelp_EverySequenceIsThePalettes(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.TrueColor, palette.Color256, palette.Color16} {
		t.Run(strconv.Itoa(int(d)), func(t *testing.T) {
			t.Parallel()
			var palettes strings.Builder
			palettes.WriteString(d.Bold("x"))
			for _, g := range [][2]string{{"semantic", "info"}, {"semantic", "success"}, {"semantic", "warning"}, {"semantic", "muted"}, {"semantic", "example"}, {"chrome", "SEPARATOR"}} {
				palettes.WriteString(d.Text(palette.Group(g[0]), g[1], "x") + d.BoldText(palette.Group(g[0]), g[1], "x"))
			}
			for _, sev := range []string{"high", "medium", "low"} {
				palettes.WriteString(d.Value(palette.Severity, sev))
			}
			allowed := map[string]bool{}
			for _, s := range sgr.FindAllString(palettes.String(), -1) {
				allowed[s] = true
			}
			for _, s := range helpScreens {
				out := helpOn(t, d, 80, s.args...)
				seen := sgr.FindAllString(out, -1)
				if len(seen) == 0 {
					t.Errorf("%s: no colour at all", s.name)
				}
				for _, q := range seen {
					if !allowed[q] {
						t.Errorf("%s: %q is not a sequence the palette writes", s.name, q)
					}
				}
			}
		})
	}
}

// Help follows the stream's own width when COLUMNS says nothing.
func TestHelp_FollowsTheTerminalWidth(t *testing.T) {
	t.Parallel()
	h := newHarness(t, defaultStageList()...)
	h.stdoutTTY, h.stdoutWidth = true, 70
	h.setenv("NO_COLOR", "1")
	if code := h.execRoot("help", "findings"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	// The table cannot shrink to 70 cells, and runs past; the heading above it wraps.
	lines := textLines(h.stdout.String())
	heading := 0
	for _, l := range lines {
		if !strings.HasPrefix(l, "  ") {
			heading++
			if w := widest([]string{l}); w > 70 {
				t.Errorf("a heading line is %d cells wide at a width of 70: %q", w, l)
			}
		}
	}
	if heading < 2 {
		t.Errorf("the heading did not wrap at 70: %q", lines[:3])
	}
}
