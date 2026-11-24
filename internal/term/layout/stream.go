// Package layout measures, wraps and aligns terminal text without I/O or environment access. It
// protects identifiers from splitting and obtains escape sequences from palette. Renderers
// retain their own plain-output path for non-terminal streams.
package layout

import (
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/term/palette"
)

const (
	// DefaultWidth is the layout width when neither COLUMNS nor the stream's
	// terminal gives one.
	DefaultWidth = 100
	// MinWidth is the narrowest layout width.
	MinWidth = 60
)

// Stream supplies terminal status, colour depth and a width callback. Width is read for each
// layout so resizes take effect. Nil or nonpositive widths mean unknown.
type Stream struct {
	Terminal bool
	Depth    palette.Depth
	Width    func() int
}

// Cols measures current layout width with DefaultWidth fallback and MinWidth floor.
func (s Stream) Cols() int {
	term := 0
	if s.Width != nil {
		term = s.Width()
	}
	return Width("", term)
}

// Fixed captures width once so a multipart layout stays aligned if the terminal resizes during
// output.
func (s Stream) Fixed() Stream {
	cols := s.Cols()
	s.Width = func() int { return cols }
	return s
}

// Coloured reports whether the stream shows any colour.
func (s Stream) Coloured() bool { return s.Depth != palette.None }

// Width chooses positive COLUMNS, then terminal width, then DefaultWidth, with a floor of
// MinWidth. Surrounding COLUMNS whitespace is ignored.
func Width(columns string, term int) int {
	w := DefaultWidth
	if n, err := strconv.Atoi(strings.TrimSpace(columns)); err == nil && n > 0 {
		w = n
	} else if term > 0 {
		w = term
	}
	return max(w, MinWidth)
}
