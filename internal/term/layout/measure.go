package layout

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/width"
)

// Measure counts terminal cells, ignoring ANSI control sequences, combining marks and
// zero-width modifiers. Wide/fullwidth runes count two; other runes, including ambiguous-width
// characters, count one. Complex emoji may be approximate.
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
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == ']' { // OSC, ended by BEL or ESC \
			j := i + 2
			for j < len(s) && s[j] != 0x07 && s[j] != 0x1b {
				j++
			}
			if j+1 < len(s) && s[j] == 0x1b && s[j+1] == '\\' {
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
	case r >= 0x200b && r <= 0x200d, r >= 0x2060 && r <= 0x2064, r == 0xfeff, r >= 0xfe00 && r <= 0xfe0f:
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

// PadRight left-aligns s to w cells without truncating wider strings.
func PadRight(s string, w int) string {
	if n := Measure(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

// PadLeft right-aligns s to w cells without truncating wider strings.
func PadLeft(s string, w int) string {
	if n := Measure(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}
