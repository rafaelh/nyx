package setup

import (
	"fmt"
	"strings"

	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// bullet is what a key field draws for each rune typed.
const bullet = "•"

// field is a one-line text entry: a rune buffer with a cursor. It stores the runes exactly as
// they were typed or pasted. A secret field draws one bullet for each rune; any other field draws
// the text after sanitize.Line.
type field struct {
	buf    []rune
	cur    int
	secret bool
}

// newField starts a field holding text, with the cursor at its end.
func newField(secret bool, text string) *field {
	f := &field{secret: secret, buf: []rune(text)}
	f.cur = len(f.buf)
	return f
}

// text is what was typed, unchanged.
func (f *field) text() string { return string(f.buf) }

// insert puts s at the cursor.
func (f *field) insert(s string) {
	in := []rune(s)
	f.buf = append(f.buf[:f.cur], append(in, f.buf[f.cur:]...)...)
	f.cur += len(in)
}

// press handles one named editing key and reports whether it was one.
func (f *field) press(name string) bool {
	switch name {
	case "left":
		f.cur = max(f.cur-1, 0)
	case "right":
		f.cur = min(f.cur+1, len(f.buf))
	case "home", "ctrl+a":
		f.cur = 0
	case "end", "ctrl+e":
		f.cur = len(f.buf)
	case "backspace":
		if f.cur > 0 {
			f.buf = append(f.buf[:f.cur-1], f.buf[f.cur:]...)
			f.cur--
		}
	case "delete":
		if f.cur < len(f.buf) {
			f.buf = append(f.buf[:f.cur], f.buf[f.cur+1:]...)
		}
	case "ctrl+u":
		f.buf, f.cur = nil, 0
	default:
		return false
	}
	return true
}

// Format never prints the text: a field may hold a key.
func (f field) Format(s fmt.State, _ rune) {
	fmt.Fprintf(s, "field{%d runes}", len(f.buf))
}

// cell is one rune as drawn.
type cell struct {
	s string
	w int
}

// cells is each rune of the text as it is drawn.
func (f *field) cells() []cell {
	out := make([]cell, len(f.buf))
	for i, r := range f.buf {
		s := bullet
		if !f.secret {
			s = sanitize.Line(string(r))
		}
		out[i] = cell{s, layout.Measure(s)}
	}
	return out
}

// view draws the text in at most width cells, scrolled so the cursor stays in view, and returns it
// with the cursor's cell offset.
func (f *field) view(width int) (string, int) {
	cells := f.cells()
	// One cell stays free after the text for the cursor.
	room := max(width-1, 1)
	start := 0
	for start < f.cur && cellWidth(cells[start:f.cur]) > room-1 {
		start++
	}
	var sb strings.Builder
	used, cursor := 0, 0
	for i := start; i < len(cells); i++ {
		if i == f.cur {
			cursor = used
		}
		if used+cells[i].w > room {
			break
		}
		sb.WriteString(cells[i].s)
		used += cells[i].w
	}
	if f.cur >= len(cells) {
		cursor = used
	}
	return sb.String(), cursor
}

func cellWidth(cs []cell) int {
	w := 0
	for _, c := range cs {
		w += c.w
	}
	return w
}
