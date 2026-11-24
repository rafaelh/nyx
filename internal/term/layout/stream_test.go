package layout_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/palette"
)

// Width selection prefers positive COLUMNS, terminal width, then 100, with a 60-cell floor.
func TestWidth(t *testing.T) {
	t.Parallel()
	cases := []struct {
		columns string
		want    [3]int // unknown, undersized and wide terminal measurements
	}{
		{"80", [3]int{80, 80, 80}},
		{" 90 ", [3]int{90, 90, 90}},
		{"0", [3]int{100, 60, 120}},
		{"-5", [3]int{100, 60, 120}},
		{"abc", [3]int{100, 60, 120}},
		{"", [3]int{100, 60, 120}},
		{"40", [3]int{60, 60, 60}},
		{"60", [3]int{60, 60, 60}},
		{"61", [3]int{61, 61, 61}},
	}
	for _, c := range cases {
		for i, term := range []int{0, 50, 120} {
			if got := layout.Width(c.columns, term); got != c.want[i] {
				t.Errorf("Width(%q, %d) = %d, want %d", c.columns, term, got, c.want[i])
			}
		}
	}
}

// Width is remeasured for every layout while retaining fallback/minimum bounds.
func TestStreamCols(t *testing.T) {
	t.Parallel()
	if got := (layout.Stream{}).Cols(); got != 100 {
		t.Errorf("nil Width = %d, want 100", got)
	}
	zero := layout.Stream{Width: func() int { return 0 }}
	if got := zero.Cols(); got != 100 {
		t.Errorf("Width 0 = %d, want 100", got)
	}
	narrow := layout.Stream{Width: func() int { return 20 }}
	if got := narrow.Cols(); got != 60 {
		t.Errorf("Width 20 = %d, want 60", got)
	}
	w := 80
	resize := layout.Stream{Width: func() int { return w }}
	first := resize.Cols()
	w = 120
	if first != 80 || resize.Cols() != 120 {
		t.Errorf("resize: %d then %d, want 80 then 120", first, resize.Cols())
	}
}

func TestStreamColoured(t *testing.T) {
	t.Parallel()
	if (layout.Stream{Depth: palette.None}).Coloured() {
		t.Error("depth None is coloured")
	}
	if !(layout.Stream{Depth: palette.Color16}).Coloured() {
		t.Error("depth 16 is not coloured")
	}
}
