package layout_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/palette"
)

func TestMeasure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"empty", "", 0},
		{"ascii", "hello", 5},
		{"sgr counts zero", "\x1b[38;2;1;2;3mhi\x1b[0m", 2},
		{"bold sgr", "\x1b[1mhi\x1b[0m", 2},
		{"badge", palette.TrueColor.Value(palette.Severity, "high"), 10},
		{"wide CJK counts two", "日本語", 6},
		{"fullwidth counts two", "ＡＢ", 4},
		{"combining mark counts zero", "e\u0301", 1},
		{"enclosing mark counts zero", "a\u20dd", 1},
		{"zero width space and joiners", "a\u200b\u200c\u200db", 2},
		{"variation selector", "a\ufe0f", 1},
		{"ambiguous counts one", "±§°", 3},
		{"box drawing counts one", "┌─┐", 3},
		{"mixed", "ab日\x1b[1mc\x1b[0m", 5},
		{"unfinished escape counts nothing", "a\x1b[1", 1},
	}
	for _, c := range cases {
		if got := layout.Measure(c.in); got != c.want {
			t.Errorf("%s: Measure(%q) = %d, want %d", c.name, c.in, got, c.want)
		}
	}
}

func TestPad(t *testing.T) {
	t.Parallel()
	if got := layout.PadRight("日", 4); got != "日  " {
		t.Errorf("PadRight = %q", got)
	}
	if got := layout.PadLeft("7", 3); got != "  7" {
		t.Errorf("PadLeft = %q", got)
	}
	if got := layout.PadLeft("1234", 3); got != "1234" {
		t.Errorf("PadLeft of a wider string = %q", got)
	}
	styled := palette.Color16.Bold("ab")
	if got := layout.PadRight(styled, 4); got != styled+"  " {
		t.Errorf("PadRight counts escapes as zero: %q", got)
	}
}
