package layout_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/palette"
)

func stream(d palette.Depth, width int) layout.Stream {
	return layout.Stream{Terminal: true, Depth: d, Width: func() int { return width }}
}

var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

func noEsc(s string) string { return sgr.ReplaceAllString(s, "") }

func cells(texts ...string) []layout.Cell {
	out := make([]layout.Cell, len(texts))
	for i, t := range texts {
		out[i] = layout.Plain(t)
	}
	return out
}

func lines(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }

// A table with no rows renders as nothing.
func TestTable_Empty(t *testing.T) {
	t.Parallel()
	tb := layout.Table{Columns: []layout.Column{{Header: "A"}}}
	if got := tb.Render(stream(palette.None, 80)); got != "" {
		t.Errorf("empty table = %q", got)
	}
	tb.Bordered = true
	if got := tb.Render(stream(palette.TrueColor, 80)); got != "" {
		t.Errorf("empty bordered table = %q", got)
	}
}

// Unbordered: the indent, a gap of two spaces, a plain header when uncoloured
// and no trailing spaces.
func TestTable_Unbordered(t *testing.T) {
	t.Parallel()
	tb := layout.Table{
		Indent:  2,
		Columns: []layout.Column{{Header: "NAME"}, {Header: "COUNT"}, {Header: "NOTE"}},
		Rows: [][]layout.Cell{
			cells("alpha", "1", "first"),
			cells("b", "22", ""),
		},
	}
	want := "  NAME   COUNT  NOTE\n" +
		"  alpha  1      first\n" +
		"  b      22\n"
	if got := tb.Render(stream(palette.None, 80)); got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

// The header row is bold in the TIMESTAMP colour when coloured.
func TestTable_HeaderStyle(t *testing.T) {
	t.Parallel()
	tb := layout.Table{
		Columns: []layout.Column{{Header: "A"}, {Header: "B"}},
		Rows:    [][]layout.Cell{cells("x", "y")},
	}
	cases := map[palette.Depth]string{
		palette.TrueColor: "\x1b[1;38;2;124;129;145mA\x1b[0m  \x1b[1;38;2;124;129;145mB\x1b[0m\nx  y\n",
		palette.Color256:  "\x1b[1;38;5;102mA\x1b[0m  \x1b[1;38;5;102mB\x1b[0m\nx  y\n",
		palette.Color16:   "\x1b[1;90mA\x1b[0m  \x1b[1;90mB\x1b[0m\nx  y\n",
		palette.None:      "A  B\nx  y\n",
	}
	for d, want := range cases {
		if got := tb.Render(stream(d, 80)); got != want {
			t.Errorf("depth %v:\n got %q\nwant %q", d, got, want)
		}
	}
}

// Topic tables use styled box borders or plain ASCII with a separate header rule.
func TestTable_Bordered(t *testing.T) {
	t.Parallel()
	tb := layout.Table{
		Bordered: true,
		Indent:   1,
		Columns:  []layout.Column{{Header: "A"}, {Header: "BB"}},
		Rows:     [][]layout.Cell{cells("x", "yy"), cells("zz", "w")},
	}
	plain := " +----+----+\n" +
		" | A  | BB |\n" +
		" +----+----+\n" +
		" | x  | yy |\n" +
		" | zz | w  |\n" +
		" +----+----+\n"
	if got := tb.Render(stream(palette.None, 80)); got != plain {
		t.Errorf("uncoloured:\n%s\nwant:\n%s", got, plain)
	}
	sep := func(s string) string { return "\x1b[90m" + s + "\x1b[0m" }
	h := func(s string) string { return "\x1b[1;90m" + s + "\x1b[0m" }
	v := sep("│")
	coloured := " " + sep("┌────┬────┐") + "\n" +
		" " + v + " " + h("A") + "  " + v + " " + h("BB") + " " + v + "\n" +
		" " + sep("├────┼────┤") + "\n" +
		" " + v + " x  " + v + " yy " + v + "\n" +
		" " + v + " zz " + v + " w  " + v + "\n" +
		" " + sep("└────┴────┘") + "\n"
	if got := tb.Render(stream(palette.Color16, 80)); got != coloured {
		t.Errorf("coloured:\n%q\nwant:\n%q", got, coloured)
	}
}

// Without colour there is no escape byte anywhere, and no box-drawing character.
func TestTable_NoEscapeUncoloured(t *testing.T) {
	t.Parallel()
	for _, bordered := range []bool{false, true} {
		tb := layout.Table{
			Bordered: bordered,
			Columns:  []layout.Column{{Header: "A", Wrap: layout.Spaces, Shrink: 1}, {Header: "B"}},
			Rows:     [][]layout.Cell{cells(strings.Repeat("word ", 40), "y")},
		}
		got := tb.Render(stream(palette.None, 60))
		if strings.Contains(got, "\x1b") {
			t.Errorf("bordered %v: escape in %q", bordered, got)
		}
		for _, r := range "┌─┬┐│├┼┤└┴┘" {
			if strings.ContainsRune(got, r) {
				t.Errorf("bordered %v: box character %q in uncoloured table", bordered, r)
			}
		}
	}
	for _, l := range []string{layout.Rule(stream(palette.None, 80), 0)} {
		if strings.Contains(l, "\x1b") || l != strings.Repeat("-", 80) {
			t.Errorf("uncoloured rule = %q", l)
		}
	}
}

func threeColumns(tID, tTarget, tDetail string) layout.Table {
	return layout.Table{
		Columns: []layout.Column{
			{Header: "ID"},
			{Header: "TARGET", Wrap: layout.Spaces, Shrink: 2},
			{Header: "DETAIL", Wrap: layout.Spaces, Shrink: 1},
		},
		Rows: [][]layout.Cell{cells(tID, tTarget, tDetail)},
	}
}

// Columns shrink in Shrink order, each only as far as needed, and never below 10.
func TestTable_ShrinkOrder(t *testing.T) {
	t.Parallel()
	target := "aaaa bbbb cccc dddd eeee ffff gggg" // 34 cells
	detail := "11111 22222 33333 44444 55555 666"  // 33 cells
	id := strings.Repeat("i", 30)
	tb := threeColumns(id, target, detail)
	render := func(width int) []string { return lines(noEsc(tb.Render(stream(palette.None, width)))) }
	gap := func(n int) string { return strings.Repeat(" ", n) }

	// 30 + 34 + 33 and two gaps is 101: it fits untouched.
	got := render(101)
	if len(got) != 2 || got[1] != id+"  "+target+"  "+detail {
		t.Errorf("fits: %q", got)
	}
	// 21 over: DETAIL gives up 21 (to 12) and TARGET stays whole.
	got = render(80)
	want := []string{id + "  " + target + "  11111 22222", gap(30+2+34+2) + "33333 44444", gap(30+2+34+2) + "55555 666"}
	if len(got) != 4 || got[1] != want[0] || got[2] != want[1] || got[3] != want[2] {
		t.Errorf("DETAIL shrinks first:\n%q\nwant %q", got, want)
	}
	// 31 over: DETAIL is at its floor of 10 and TARGET gives up the other 8.
	got = render(70)
	if at := strings.Index(got[0], "DETAIL"); at != 30+2+26+2 {
		t.Errorf("at 70: DETAIL at %d, want %d\n%q", at, 30+2+26+2, got)
	}
	if want := id + "  " + layout.PadRight("aaaa bbbb cccc dddd eeee", 26) + "  11111"; got[1] != want {
		t.Errorf("at 70: first line %q, want %q", got[1], want)
	}
	// At 60 TARGET gives up more, down to 16, and the table fits.
	got = render(60)
	if at := strings.Index(got[0], "DETAIL"); at != 30+2+16+2 {
		t.Errorf("at 60: DETAIL at %d, want %d\n%q", at, 30+2+16+2, got)
	}
	for _, l := range got {
		if layout.Measure(l) > 60 {
			t.Errorf("at 60: %q is wider than the width", l)
		}
	}
}

// When all columns reach minimum widths, allow overflow while preserving alignment.
func TestTable_AtTheFloors(t *testing.T) {
	t.Parallel()
	target := "aaaa bbbb cccc dddd eeee ffff gggg"
	detail := "11111 22222 33333 44444 55555 666"
	tb := threeColumns(strings.Repeat("i", 60), target, detail)
	got := lines(noEsc(tb.Render(stream(palette.None, 60))))
	at := strings.Index(got[0], "DETAIL")
	if at != 60+2+10+2 {
		t.Fatalf("DETAIL at %d: %q", at, got)
	}
	if got[1] != strings.Repeat("i", 60)+"  aaaa bbbb   11111" {
		t.Errorf("first row line %q", got[1])
	}
	if layout.Measure(got[1]) <= 60 {
		t.Errorf("the table should run past the width: %q", got[1])
	}
	for _, l := range got[1:] {
		if len(l) > at && (l[at-2:at] != "  " || l[at] == ' ') {
			t.Errorf("DETAIL is not aligned on %q", l)
		}
	}
}

// Protected URLs set column floors, preventing narrow layouts from splitting targets or
// misaligning details.
func TestTable_FloorOfProtectedWord(t *testing.T) {
	t.Parallel()
	url := "https://www.example.com/path/to/thing/ab" // 40 cells
	if layout.Measure(url) != 40 {
		t.Fatalf("test URL is %d cells", layout.Measure(url))
	}
	tb := layout.Table{
		Columns: []layout.Column{
			{Header: "SEVERITY"},
			{Header: "TARGET", Wrap: layout.Spaces, Shrink: 2},
			{Header: "DETAIL", Wrap: layout.Spaces, Shrink: 1},
		},
		Rows: [][]layout.Cell{
			cells("xxxxxxxxxxxxxxxxxxxxxxxxxx", url+" and some more words after it", "one two three four five six seven eight nine ten eleven twelve"),
			cells("low", "a.example.com", "short"),
			cells("medium", url, "another long detail with plenty of words to wrap onto lines"),
		},
	}
	out := lines(noEsc(tb.Render(stream(palette.None, 80))))
	at := strings.Index(out[0], "DETAIL")
	if at != 26+2+40+2 {
		t.Fatalf("TARGET is not 40 wide, DETAIL at %d:\n%s", at, strings.Join(out, "\n"))
	}
	for _, l := range out[1:] {
		if len(l) <= at || l[at-2:at] != "  " || l[at] == ' ' {
			t.Errorf("DETAIL is not aligned on %q", l)
		}
		if strings.Contains(l[:at], "https://") && !strings.Contains(l, url) {
			t.Errorf("the URL was broken: %q", l)
		}
	}
	// The URL's own row wrapped TARGET's other words under it.
	if !strings.Contains(strings.Join(out, "\n"), url+"  ") {
		t.Errorf("URL line missing:\n%s", strings.Join(out, "\n"))
	}
}

// A protected word wider than the whole table is left whole: the table runs past
// the width, and every row still lines up.
func TestTable_FloorWiderThanTable(t *testing.T) {
	t.Parallel()
	url := "https://www.example.com/" + strings.Repeat("p", 70)
	tb := threeColumns("id", url, "x y z")
	out := lines(noEsc(tb.Render(stream(palette.None, 80))))
	if len(out) != 2 || !strings.Contains(out[1], url+"  x y z") || strings.Index(out[0], "DETAIL") != strings.Index(out[1], "x y z") {
		t.Errorf("got %q", out)
	}
}

// Widths come from every row, so the columns line up however the rows differ.
func TestTable_WidthsDecidedOnce(t *testing.T) {
	t.Parallel()
	tb := layout.Table{
		Bordered: true,
		Columns:  []layout.Column{{Header: "A"}, {Header: "B", Wrap: layout.Spaces, Shrink: 1}},
		Rows: [][]layout.Cell{
			cells("x", "short"),
			cells("wide column here", strings.Repeat("word ", 30)),
			cells("y", "tiny"),
		},
	}
	out := lines(tb.Render(stream(palette.None, 70)))
	for _, l := range out {
		if layout.Measure(l) != layout.Measure(out[0]) {
			t.Errorf("rows differ in width: %q vs %q", l, out[0])
		}
		if l[19] != '|' && l[19] != '+' {
			t.Errorf("column separator is not in line at 19: %q", l)
		}
	}
	if layout.Measure(out[0]) > 70 {
		t.Errorf("table is %d wide", layout.Measure(out[0]))
	}
}

// A Keep cell (a badge) is measured as it is styled, never wrapped, and its column
// never shrinks.
func TestTable_KeepBadgeColumn(t *testing.T) {
	t.Parallel()
	d := palette.TrueColor
	badge := func(v string) layout.Cell {
		return []layout.Span{{Text: v, Keep: true, Style: func(s string) string { return d.Value(palette.Severity, s) }}}
	}
	tb := layout.Table{
		Columns: []layout.Column{{Header: "SEVERITY"}, {Header: "DETAIL", Wrap: layout.Spaces, Shrink: 1}},
		Rows: [][]layout.Cell{
			{badge("high"), layout.Plain(strings.Repeat("word ", 30))},
			{badge("critical"), layout.Plain("x")},
		},
	}
	out := tb.Render(stream(d, 60))
	if !strings.Contains(out, d.Value(palette.Severity, "high")) || !strings.Contains(out, d.Value(palette.Severity, "critical")) {
		t.Errorf("badges missing: %q", out)
	}
	for i, l := range lines(noEsc(out)) {
		if layout.Measure(l) > 60 {
			t.Errorf("line %d is %d wide: %q", i, layout.Measure(l), l)
		}
		if i > 0 && len(l) > 12 && l[10:12] != "  " {
			t.Errorf("DETAIL is not aligned: %q", l)
		}
	}
}

// A header wraps like its column.
func TestTable_HeaderWraps(t *testing.T) {
	t.Parallel()
	tb := layout.Table{
		Columns: []layout.Column{{Header: "ID"}, {Header: "A VERY LONG HEADER", Wrap: layout.Spaces, Shrink: 1}},
		Rows:    [][]layout.Cell{cells("1", "x")},
	}
	// The ID column is 61 wide, so this column shrinks to its floor of 10.
	tb.Rows[0][0] = layout.Plain(strings.Repeat("i", 61))
	out := lines(noEsc(tb.Render(stream(palette.None, 60))))
	if len(out) != 4 || !strings.HasSuffix(out[0], "A VERY") || strings.TrimSpace(out[1]) != "LONG" || strings.TrimSpace(out[2]) != "HEADER" {
		t.Errorf("header did not wrap: %q", out)
	}
}

// A heading is bold info when coloured, plain otherwise; a rule follows on request.
func TestHeading(t *testing.T) {
	t.Parallel()
	d := palette.TrueColor
	rule := d.Text(palette.Chrome, "SEPARATOR", strings.Repeat("─", 80))
	got := layout.Heading(stream(d, 80), "Summary", true)
	want := []string{"\x1b[1;38;2;143;179;255mSummary\x1b[0m", rule}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("coloured heading = %q, want %q", got, want)
	}
	if got := layout.Heading(stream(d, 80), "Usage:", false); len(got) != 1 || got[0] != "\x1b[1;38;2;143;179;255mUsage:\x1b[0m" {
		t.Errorf("heading without rule = %q", got)
	}
	got = layout.Heading(stream(palette.None, 80), "Summary", true)
	if len(got) != 2 || got[0] != "Summary" || got[1] != strings.Repeat("-", 80) {
		t.Errorf("uncoloured heading = %q", got)
	}
	if got := layout.Rule(stream(palette.Color16, 80), 5); got != "\x1b[90m─────\x1b[0m" {
		t.Errorf("rule = %q", got)
	}
	if got := layout.Rule(stream(palette.None, 70), 0); got != strings.Repeat("-", 70) {
		t.Errorf("rule at the stream's width = %q", got)
	}
}

// A heading wider than the width wraps at spaces; each continuation line starts at
// column 0 in the heading style.
func TestHeading_Wraps(t *testing.T) {
	t.Parallel()
	d := palette.Color256
	text := strings.Repeat("alpha ", 14) + "omega" // 89 cells
	got := layout.Heading(stream(d, 60), text, true)
	if len(got) != 3 {
		t.Fatalf("lines = %q", got)
	}
	for _, l := range got[:2] {
		if !strings.HasPrefix(l, "\x1b[1;38;5;111m") || !strings.HasSuffix(l, "\x1b[0m") || strings.HasPrefix(noEsc(l), " ") {
			t.Errorf("heading line %q is not in the heading style at column 0", l)
		}
		if layout.Measure(l) > 60 {
			t.Errorf("heading line %q is wider than 60", l)
		}
	}
	if layout.Measure(got[2]) != 60 {
		t.Errorf("rule is %d wide", layout.Measure(got[2]))
	}
}
