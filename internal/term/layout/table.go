package layout

import (
	"sort"
	"strings"

	"github.com/rafaelh/nyx/internal/term/palette"
)

// Cell contains styled spans and optional hard newlines within one column.
type Cell = []Span

// Column describes one column of a Table.
type Column struct {
	// Header is the column's heading text.
	Header string
	// Wrap controls cell line-breaking. None preserves natural width without shrinking.
	Wrap Mode
	// Shrink sets column reduction priority, lowest positive value first. Zero preserves a
	// column's natural width.
	Shrink int
}

// Table aligns cell rows beneath headers within the stream's available width.
type Table struct {
	Columns []Column
	Rows    [][]Cell
	// Indent is the number of spaces before each line. It counts against the width.
	Indent int
	// Bordered adds a box, header rule and vertical separators with one-space padding.
	// Plain tables use two-space column gaps and trim line endings.
	Bordered bool
}

// minShrink sets the normal wrapping floor; wider protected tokens can raise it.
const minShrink = 10

// Render aligns all rows using widths measured across headers and cells. Oversized tables
// shrink columns in Shrink order, no narrower than ten cells or their widest unbreakable token.
// Tables may exceed width when tokens cannot fit.
//
// Headers are bold/muted with colour. Borders use palette separators or plain ASCII; colour
// depth None emits no escapes. Empty tables return "" so callers can omit the heading too.
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
		for _, l := range t.rowLines(r, widths, ch) {
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

// rowLines wraps and pads each cell before joining aligned columns.
func (t Table) rowLines(row []Cell, widths []int, ch chrome) []string {
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

// chrome chooses plain or styled rule/border characters.
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

// border selects top, header or bottom table geometry for measured column widths.
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

// Rule uses the requested cell width, falling back to stream width. Coloured output uses a
// palette-styled line; plain output uses hyphens.
func Rule(s Stream, width int) string {
	if width <= 0 {
		width = s.Cols()
	}
	c := newChrome(s)
	return c.style(strings.Repeat(c.horiz, width))
}

// Heading wraps text at spaces with unindented continuations, appending styled after spans.
// Terminal colour uses bold info styling; plain output has no styling. rule adds a full-width
// line below.
func Heading(s Stream, text string, rule bool, after ...Span) []string {
	style := func(x string) string { return s.Depth.BoldText(palette.Semantic, "info", x) }
	lines := Wrap(append([]Span{{Text: text, Style: style}}, after...), s.Cols(), 0, 0, Spaces)
	if rule {
		lines = append(lines, Rule(s, 0))
	}
	return lines
}
