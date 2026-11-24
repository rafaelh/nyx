package setup

import (
	"fmt"
	"strings"

	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/sanitize"
)

// bullet masks each typed key rune.
const bullet = "•"

// field preserves typed or pasted runes in a one-line buffer. Secrets display as bullets;
// ordinary text passes through sanitize.Line for display.
type field struct {
	buf    []rune
	cur    int
	secret bool
}

func newField(secret bool, text string) *field {
	f := &field{secret: secret, buf: []rune(text)}
	f.cur = len(f.buf)
	return f
}

// text preserves original input runes.
func (f *field) text() string { return string(f.buf) }

// insert puts s at the cursor.
func (f *field) insert(s string) {
	in := []rune(s)
	f.buf = append(f.buf[:f.cur], append(in, f.buf[f.cur:]...)...)
	f.cur += len(in)
}

// press handles recognised editing keys and reports whether it consumed the key.
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

// Format hides field text because the buffer may contain a secret.
func (f field) Format(s fmt.State, _ rune) {
	fmt.Fprintf(s, "field{%d runes}", len(f.buf))
}

// cell describes one displayed rune.
type cell struct {
	s string
	w int
}

// cells measures displayed input runes.
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

// view scrolls text to keep the cursor visible within width cells, returning the cursor's cell
// offset.
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
