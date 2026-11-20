// Package layout lays text out for a terminal: it measures strings in cells,
// wraps spans of styled text, protects words that must never be broken and
// renders tables, headings and rules. It is pure: it does no I/O and never reads
// the environment. Every escape byte it writes comes from package palette.
//
// A layout is made only for a Stream that is a terminal. A caller that writes
// to anything else keeps its own output and never reaches this package.
package layout

import (
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/palette"
)

const (
	// DefaultWidth is the layout width when neither COLUMNS nor the stream's
	// terminal gives one.
	DefaultWidth = 100
	// MinWidth is the narrowest layout width.
	MinWidth = 60
)

// Stream is an output as the layout sees it: whether it is a terminal, the colour
// depth it shows and a function that reports its terminal width in cells.
// Width is read each time a layout is made, so a resize applies from the next
// one. A nil Width, or one that returns zero or less, means no width is known.
type Stream struct {
	Terminal bool
	Depth    palette.Depth
	Width    func() int
}

// Cols is the stream's layout width now: what Width reports, or DefaultWidth
// when it reports nothing, and never less than MinWidth.
func (s Stream) Cols() int {
	term := 0
	if s.Width != nil {
		term = s.Width()
	}
	return Width("", term)
}

// Fixed is the stream with its width read once, now. A layout made of several parts takes it first,
// so that every part has the same width even if the terminal is resized while it is written.
func (s Stream) Fixed() Stream {
	cols := s.Cols()
	s.Width = func() int { return cols }
	return s
}

// Coloured reports whether the stream shows any colour.
func (s Stream) Coloured() bool { return s.Depth != palette.None }

// Width decides a layout width: columns when it is a positive integer (spaces
// around it are ignored), else term when that is positive, else DefaultWidth;
// and never less than MinWidth.
func Width(columns string, term int) int {
	w := DefaultWidth
	if n, err := strconv.Atoi(strings.TrimSpace(columns)); err == nil && n > 0 {
		w = n
	} else if term > 0 {
		w = term
	}
	return max(w, MinWidth)
}
