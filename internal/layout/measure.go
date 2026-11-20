package layout

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/width"
)

// Measure is the width of s in terminal cells. Each escape sequence (ESC [ …
// up to its final byte) counts zero. East Asian Wide and Fullwidth runes count
// two. Combining marks (categories Mn and Me), U+200B to U+200D and the
// variation selectors U+FE00 to U+FE0F count zero. Every other rune counts one,
// East Asian Ambiguous ones included. Emoji sequences may be measured
// imprecisely.
func Measure(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			i = j + 1
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		n += runeWidth(r)
		i += size
	}
	return n
}

func runeWidth(r rune) int {
	switch {
	case r < 0x300:
		return 1 // ASCII, Latin-1 and the Latin extensions: the common case
	case r >= 0x200b && r <= 0x200d, r >= 0xfe00 && r <= 0xfe0f:
		return 0
	case unicode.In(r, unicode.Mn, unicode.Me):
		return 0
	}
	switch width.LookupRune(r).Kind() {
	case width.EastAsianWide, width.EastAsianFullwidth:
		return 2
	default:
		return 1
	}
}

// PadRight pads s with spaces on the right to w cells. A string already w cells
// wide or wider is returned unchanged.
func PadRight(s string, w int) string {
	if n := Measure(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// PadLeft pads s with spaces on the left to w cells, so it is right-aligned. A
// string already w cells wide or wider is returned unchanged.
func PadLeft(s string, w int) string {
	if n := Measure(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}
