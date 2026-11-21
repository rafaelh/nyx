package layout

import (
	"sort"
	"strings"

	"github.com/rafaelh/nyx/internal/palette"
)

// Cell is the content of one table cell: spans laid out in the cell's column.
// A cell may hold "\n" for several lines.
type Cell = []Span

// Column describes one column of a Table.
type Column struct {
	// Header is the column's heading text.
	Header string
	// Wrap is how the column's cells break when the column is narrower than a cell.
	// None never wraps and the column never shrinks.
	Wrap Mode
	// Shrink orders the columns that give up width when the table is too wide:
	// 1 shrinks first, then 2 and so on. 0 means the column never shrinks.
	Shrink int
}

// Table is rows of left-aligned cells under a header row, laid out to fit a
// stream's width.
type Table struct {
	Columns []Column
	Rows    [][]Cell
	// Indent is the number of spaces before each line. It counts against the width.
	Indent int
	// Bordered draws a box around the table and a border under the header, with
	// each column separated by a vertical border and one space either side.
	// Without it columns are separated by two spaces and trailing spaces are trimmed.
	Bordered bool
}

// minShrink is the narrowest a wrapping column shrinks to, unless it is already
// narrower or holds a word that cannot be broken.
const minShrink = 10

// Render lays the table out for s as lines each ending in "\n", or "" when it has
// no rows, in which case the caller writes no heading either.
//
// Column widths are decided once from every row, so the columns line up. A
// column's natural width is its widest cell, header included. When the table is
// wider than the stream, the wrapping columns shrink in Shrink order, each only as
// far as needed and no narrower than its floor: the larger of 10 and the widest
// unbreakable token in it (a protected word or a Keep span). A table that still
// does not fit runs past the width.
//
// The header row is bold, in the muted colour; uncoloured it is plain.
// Borders are box-drawing characters in the chrome SEPARATOR colour when the
// stream is coloured, and ASCII (- | +) when it is not. At no depth other than
// None is any other escape written, and at None there is no escape byte at all.
func (t Table) Render(s Stream) string {
	if len(t.Rows) == 0 || len(t.Columns) == 0 {
		return ""
	}
	n := len(t.Columns)
	header := make([]Cell, n)
	hstyle := func(x string) string { return s.Depth.BoldText(palette.Semantic, "muted", x) }
	for i, c := range t.Columns {
		header[i] = []Span{{Text: c.Header, Style: hstyle}}
	}
	rows := make([][]Cell, 0, len(t.Rows)+1)
	rows = append(rows, header)
	for _, r := range t.Rows {
		row := make([]Cell, n) // a short row has empty cells; extra cells are dropped
		copy(row, r)
		rows = append(rows, row)
	}
	widths := t.widths(rows, s.Cols())

	var out strings.Builder
	line := func(l string) { out.WriteString(strings.Repeat(" ", t.Indent) + l + "\n") }
	ch := newChrome(s)
	if t.Bordered {
		line(ch.border(widths, 0))
	}
	for i, r := range rows {
		for _, l := range t.rowLines(s, r, widths, ch) {
			line(l)
		}
		if t.Bordered && i == 0 {
			line(ch.border(widths, 1))
		}
	}
	if t.Bordered {
		line(ch.border(widths, 2))
	}
	return out.String()
}

// widths decides each column's width from every row (the header is rows[0]).
func (t Table) widths(rows [][]Cell, avail int) []int {
	n := len(t.Columns)
	w := make([]int, n)
	floor := make([]int, n)
	for _, r := range rows {
		for i, c := range r {
			natural, unbreakable := measureSpans(c)
			w[i] = max(w[i], natural)
			floor[i] = max(floor[i], unbreakable)
		}
	}
	for i := range floor {
		floor[i] = min(w[i], max(minShrink, floor[i]))
	}
	total := t.Indent + sum(w)
	if t.Bordered {
		total += 4 + 3*(n-1)
	} else {
		total += 2 * (n - 1)
	}
	over := total - avail
	order := make([]int, 0, n)
	for i, c := range t.Columns {
		if c.Wrap != None && c.Shrink > 0 {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(a, b int) bool { return t.Columns[order[a]].Shrink < t.Columns[order[b]].Shrink })
	for _, i := range order {
		if over <= 0 {
			break
		}
		cut := min(over, w[i]-floor[i])
		w[i] -= cut
		over -= cut
	}
	return w
}

func sum(xs []int) int {
	t := 0
	for _, x := range xs {
		t += x
	}
	return t
}

// rowLines lays one row out: each cell wrapped to its column, padded to the
// column's width, and the cells joined.
func (t Table) rowLines(s Stream, row []Cell, widths []int, ch chrome) []string {
	cells := make([][]string, len(row))
	height := 1
	for i, c := range row {
		cells[i] = Wrap(c, widths[i], 0, 0, t.Columns[i].Wrap)
		height = max(height, len(cells[i]))
	}
	out := make([]string, height)
	for y := range out {
		var b strings.Builder
		if t.Bordered {
			b.WriteString(ch.vert + " ")
		}
		for i := range cells {
			text := ""
			if y < len(cells[i]) {
				text = cells[i][y]
			}
			if i > 0 {
				if t.Bordered {
					b.WriteString(" " + ch.vert + " ")
				} else {
					b.WriteString("  ")
				}
			}
			b.WriteString(PadRight(text, widths[i]))
		}
		if t.Bordered {
			b.WriteString(" " + ch.vert)
		}
		out[y] = b.String()
		if !t.Bordered {
			out[y] = strings.TrimRight(out[y], " ")
		}
	}
	return out
}

// chrome is the rule and border characters of a stream, in the colour it shows.
type chrome struct {
	style                              func(string) string
	horiz                              string
	vert                               string
	tl, tm, tr, ml, mm, mr, bl, bm, br string
}

func newChrome(s Stream) chrome {
	style := func(x string) string { return s.Depth.Text(palette.Chrome, "SEPARATOR", x) }
	if s.Coloured() {
		return chrome{style, "─", style("│"), "┌", "┬", "┐", "├", "┼", "┤", "└", "┴", "┘"}
	}
	return chrome{style, "-", "|", "+", "+", "+", "+", "+", "+", "+", "+", "+"}
}

// border is the top (0), header (1) or bottom (2) border for columns of the widths.
func (c chrome) border(widths []int, which int) string {
	left, mid, right := c.tl, c.tm, c.tr
	switch which {
	case 1:
		left, mid, right = c.ml, c.mm, c.mr
	case 2:
		left, mid, right = c.bl, c.bm, c.br
	}
	var b strings.Builder
	b.WriteString(left)
	for i, w := range widths {
		if i > 0 {
			b.WriteString(mid)
		}
		b.WriteString(strings.Repeat(c.horiz, w+2))
	}
	b.WriteString(right)
	return c.style(b.String())
}

// Rule is a horizontal rule width cells wide, or the stream's width when width is
// not positive: ─ in the chrome SEPARATOR colour on a coloured stream, - with no
// colour otherwise.
func Rule(s Stream, width int) string {
	if width <= 0 {
		width = s.Cols()
	}
	c := newChrome(s)
	return c.style(strings.Repeat(c.horiz, width))
}

// Heading lays a heading out as lines (without line ends) at the stream's width,
// in the heading style: bold in the palette's semantic info colour, and plain
// text when the stream has no colour. after follows the text, in its own styles.
// A heading wider than the width wraps at spaces, and its continuation lines
// start at column 0. With rule, a full width Rule follows the last line.
func Heading(s Stream, text string, rule bool, after ...Span) []string {
	style := func(x string) string { return s.Depth.BoldText(palette.Semantic, "info", x) }
	lines := Wrap(append([]Span{{Text: text, Style: style}}, after...), s.Cols(), 0, 0, Spaces)
	if rule {
		lines = append(lines, Rule(s, 0))
	}
	return lines
}
