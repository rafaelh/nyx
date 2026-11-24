// Package sanitize removes display controls from target text before terminal/viewer output.
package sanitize

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	ansiCSI = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	ansiOSC = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)?`)
)

// lineBreaks preserves word boundaries when Line removes line endings.
var lineBreaks = strings.NewReplacer("\n", " ", "\r", " ")

// Line also replaces line breaks with spaces for single-line display.
func Line(s string) string { return Text(lineBreaks.Replace(s)) }

// Text removes terminal escapes, controls and bidi overrides, replacing tabs with spaces.
func Text(s string) string {
	if strings.IndexByte(s, 0x1b) >= 0 { // every escape sequence starts with ESC
		s = ansiOSC.ReplaceAllString(s, "")
		s = ansiCSI.ReplaceAllString(s, "")
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return ' '
		case unicode.IsControl(r), r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0x200E, r == 0x200F:
			return -1
		}
		return r
	}, s)
}
