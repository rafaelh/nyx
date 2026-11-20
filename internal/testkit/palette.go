package testkit

import (
	"regexp"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/palette"
)

// sgr is one SGR escape sequence.
var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

// paletteSequences are every SGR sequence the palette can write at depth d, from each of its
// functions over each of its tables.
func paletteSequences(d palette.Depth) map[string]bool {
	set := map[string]bool{}
	add := func(s string) {
		for _, m := range sgr.FindAllString(s, -1) {
			set[m] = true
		}
	}
	add(d.Bold("x"))
	for _, c := range palette.Categories() {
		for _, l := range palette.Labels(c) {
			add(d.Badge(c, l))
			add(d.Value(c, l))
			add(d.BadgeText(c, l, "x"))
		}
		add(d.Value(c, "no-such-label"))
		add(d.BadgeText(c, "no-such-label", "x"))
	}
	for _, g := range palette.Groups() {
		for _, n := range palette.Names(g) {
			add(d.Text(g, n, "x"))
			add(d.BoldText(g, n, "x"))
		}
	}
	return set
}

// OnlyPaletteEscapes fails the test when out holds an escape byte that does not start a sequence
// the palette writes at depth d, and when it holds any other control character or bidi override
// besides the newline.
func OnlyPaletteEscapes(t *testing.T, d palette.Depth, out string) {
	t.Helper()
	allowed := paletteSequences(d)
	found := sgr.FindAllString(out, -1)
	for _, m := range found {
		if !allowed[m] {
			t.Errorf("depth %d: %q is not a sequence the palette writes", d, m)
		}
	}
	if n := strings.Count(out, "\x1b"); n != len(found) {
		t.Errorf("depth %d: %d escape bytes, %d of them in palette sequences", d, n, len(found))
	}
	for _, r := range sgr.ReplaceAllString(out, "") {
		if r != '\n' && (r < 0x20 || r == 0x7f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069)) {
			t.Errorf("depth %d: control character %U in the output", d, r)
		}
	}
}
