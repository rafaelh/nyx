package layout_test

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/palette"
)

// mark styles text with visible markers, so a test sees where a style opens and closes.
func mark(s string) string { return "<" + s + ">" }

func wrapPlain(text string, width, first, rest int, mode layout.Mode) []string {
	return layout.Wrap(layout.Plain(text), width, first, rest, mode)
}

func checkLines(t *testing.T, name string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s:\n got %q\nwant %q", name, got, want)
	}
}

// hasBrokenEscape reports whether s holds an escape byte that does not start a
// complete ESC [ ... m sequence.
func hasBrokenEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != 0x1b {
			continue
		}
		if i+1 >= len(s) || s[i+1] != '[' {
			return true
		}
		j := i + 2
		for j < len(s) && s[j] != 'm' {
			if (s[j] < '0' || s[j] > '9') && s[j] != ';' {
				return true
			}
			j++
		}
		if j == len(s) {
			return true
		}
		i = j
	}
	return false
}

func TestWrap_Spaces(t *testing.T) {
	t.Parallel()
	checkLines(t, "fits", wrapPlain("aaa bbb", 20, 0, 0, layout.Spaces), []string{"aaa bbb"})
	checkLines(t, "breaks at spaces", wrapPlain("aaa bbb ccc ddd", 7, 0, 0, layout.Spaces), []string{"aaa bbb", "ccc ddd"})
	checkLines(t, "exactly the width", wrapPlain("aaa bbb", 7, 0, 0, layout.Spaces), []string{"aaa bbb"})
	checkLines(t, "empty", wrapPlain("", 10, 0, 0, layout.Spaces), []string{""})
	checkLines(t, "no break after a hyphen or slash",
		wrapPlain("aa-bb/cc dd", 9, 0, 0, layout.Spaces), []string{"aa-bb/cc", "dd"})
}

// The prefix the caller writes uses up the first line's room; later lines are
// indented by rest.
func TestWrap_FirstAndRest(t *testing.T) {
	t.Parallel()
	checkLines(t, "first and rest", wrapPlain("aaa bbb ccc", 10, 4, 2, layout.Spaces), []string{"aaa", "  bbb ccc"})
	checkLines(t, "rest 19", wrapPlain("aaaa bbbb", 24, 19, 19, layout.Spaces),
		[]string{"aaaa", strings.Repeat(" ", 19) + "bbbb"})
}

// Indentation, runs of spaces and a padded name survive; only the one space at
// which a line is broken is consumed.
func TestWrap_KeepsSpaces(t *testing.T) {
	t.Parallel()
	checkLines(t, "padded procedure line", layout.Wrap([]layout.Span{{Text: "dns           "}, {Text: "running"}}, 80, 0, 0, layout.Spaces),
		[]string{"dns           running"})
	checkLines(t, "two-space count line", wrapPlain("  records     12", 80, 0, 0, layout.Spaces), []string{"  records     12"})
	checkLines(t, "two-space header", wrapPlain("A  B  C", 80, 0, 0, layout.Spaces), []string{"A  B  C"})
	checkLines(t, "one space consumed at a break", wrapPlain("aaaa  bbbb", 5, 0, 0, layout.Spaces), []string{"aaaa", " bbbb"})
	checkLines(t, "trailing spaces kept", wrapPlain("ab  ", 10, 0, 0, layout.Spaces), []string{"ab  "})
	checkLines(t, "trailing spaces clipped to the width", wrapPlain("abcd   ", 5, 0, 0, layout.Spaces), []string{"abcd "})
	checkLines(t, "leading spaces before a long protected word",
		wrapPlain("  example.com", 5, 0, 0, layout.Spaces), []string{"  example.com"})
}

func TestWrap_HardBreak(t *testing.T) {
	t.Parallel()
	checkLines(t, "newline", wrapPlain("ab\ncd", 10, 0, 2, layout.Spaces), []string{"ab", "  cd"})
	checkLines(t, "blank line", wrapPlain("ab\n\ncd", 10, 0, 0, layout.Spaces), []string{"ab", "", "cd"})
	checkLines(t, "newline in a no-wrap block", wrapPlain("a b\nc d", 3, 0, 1, layout.None), []string{"a b", " c d"})
}

// A protected word longer than the space is left whole and the line runs past the width.
func TestWrap_ProtectedLeftWhole(t *testing.T) {
	t.Parallel()
	words := []string{
		"https://example.com/very/long/path",
		"someone.long@example.com",
		"192.0.2.123",
		"2001:db8:1234:5678::1",
		"192.0.2.0/24",
		"2001:db8:1234::/48",
		"host.example.com",
		"*.example.com",
		"example.com,",
		"(host.example.com)",
	}
	for _, w := range words {
		got := wrapPlain("see "+w+" ok", 10, 0, 0, layout.Spaces)
		checkLines(t, w, got, []string{"see", w, "ok"})
		if layout.Measure(got[1]) <= 10 {
			t.Errorf("%s: test word is not longer than the width", w)
		}
	}
}

// Protected words remain whole even on otherwise empty lines; ordinary oversized words split.
func TestWrap_ProtectedFirstOnLine(t *testing.T) {
	t.Parallel()
	checkLines(t, "alone", wrapPlain("host.example.com", 8, 0, 0, layout.Spaces), []string{"host.example.com"})
	checkLines(t, "after a prefix", wrapPlain("host.example.com", 8, 6, 6, layout.Spaces), []string{"host.example.com"})
	checkLines(t, "version number", wrapPlain("ab 2.4.41", 5, 0, 0, layout.Spaces), []string{"ab", "2.4.41"})
}

func TestWrap_LongWordBroken(t *testing.T) {
	t.Parallel()
	checkLines(t, "alone", wrapPlain("abcdefghijklmnopqrstuvwxyz", 10, 0, 0, layout.Spaces),
		[]string{"abcdefghij", "klmnopqrst", "uvwxyz"})
	checkLines(t, "after text", wrapPlain("hi abcdefghijklmnopqrstuvwxyz", 10, 0, 0, layout.Spaces),
		[]string{"hi", "abcdefghij", "klmnopqrst", "uvwxyz"})
	checkLines(t, "with an indent", wrapPlain("abcdefghijkl", 6, 0, 2, layout.Spaces),
		[]string{"abcdef", "  ghij", "  kl"})
	checkLines(t, "after a prefix", wrapPlain("abcdefgh", 6, 4, 4, layout.Spaces),
		[]string{"ab", "    cd", "    ef", "    gh"})
	checkLines(t, "indent past the width overflows a word at a time", wrapPlain("hello world", 5, 6, 6, layout.Spaces),
		[]string{"hello", "      world"})
	checkLines(t, "wide rune with one cell left starts a fresh line", wrapPlain("日本語", 5, 4, 0, layout.Spaces),
		[]string{"", "日本", "語"})
	checkLines(t, "carried space gives way to a word that fits", wrapPlain("ab  cd", 2, 0, 0, layout.Spaces),
		[]string{"ab", "cd"})
	checkLines(t, "newline in a kept span", layout.Wrap([]layout.Span{{Text: "a\nb", Keep: true}}, 10, 0, 0, layout.Spaces),
		[]string{"a", "b"})

	cvss := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	got := wrapPlain(cvss, 20, 0, 0, layout.Spaces)
	if len(got) < 3 || strings.Join(got, "") != cvss {
		t.Errorf("CVSS string = %q", got)
	}
	for _, l := range got {
		if layout.Measure(l) > 20 {
			t.Errorf("CVSS line %q is wider than 20", l)
		}
	}
}

// Wide runes count two and are never split; a combining mark stays with its base.
func TestWrap_Cells(t *testing.T) {
	t.Parallel()
	checkLines(t, "wide", wrapPlain("日本語日本語", 5, 0, 0, layout.Spaces), []string{"日本", "語日", "本語"})
	checkLines(t, "a wide rune that does not fit moves down", wrapPlain("abc日", 4, 0, 0, layout.Spaces), []string{"abc", "日"})
	e := "e\u0301"
	checkLines(t, "combining", wrapPlain(e+e+e, 2, 0, 0, layout.Spaces), []string{e + e, e})
	checkLines(t, "a mark after a rune wider than the line stays", wrapPlain("日\u0301x", 1, 0, 0, layout.Spaces), []string{"日\u0301", "x"})
	checkLines(t, "a mark after the cut stays", wrapPlain("abc\u0301d", 3, 0, 0, layout.Spaces), []string{"abc\u0301", "d"})
}

func TestWrap_Commas(t *testing.T) {
	t.Parallel()
	checkLines(t, "after commas only", wrapPlain("ab cd, ef gh", 9, 0, 0, layout.Commas), []string{"ab cd,", "ef gh"})
	checkLines(t, "spaces mode would split inside", wrapPlain("ab cd, ef gh", 9, 0, 0, layout.Spaces), []string{"ab cd, ef", "gh"})
	checkLines(t, "a list", wrapPlain("alpha, beta, gamma, delta", 13, 0, 0, layout.Commas), []string{"alpha, beta,", "gamma, delta"})
	checkLines(t, "continuation at rest", wrapPlain("alpha, beta, gamma", 14, 6, 6, layout.Commas),
		[]string{"alpha,", "      beta,", "      gamma"})
	checkLines(t, "fits", wrapPlain("a, b", 20, 0, 0, layout.Commas), []string{"a, b"})
	checkLines(t, "a comma without a space is no break, so the word is cut", wrapPlain("a,b,c,d,e,f", 5, 0, 0, layout.Commas), []string{"a,b,c", ",d,e,", "f"})
}

func TestWrap_CommasFallback(t *testing.T) {
	t.Parallel()
	checkLines(t, "segment too long", wrapPlain("aaa bbb ccc, dd", 7, 0, 0, layout.Commas), []string{"aaa bbb", "ccc, dd"})
	checkLines(t, "after text", wrapPlain("x, aaa bbb ccc, dd", 7, 0, 0, layout.Commas),
		[]string{"x,", "aaa bbb", "ccc, dd"})
	checkLines(t, "a long word in a segment", wrapPlain("abcdefghij, kl", 6, 0, 0, layout.Commas),
		[]string{"abcdef", "ghij,", "kl"})
	checkLines(t, "a protected word in a segment", wrapPlain("see a.example.com, kl", 6, 0, 0, layout.Commas),
		[]string{"see", "a.example.com,", "kl"})
}

// Apply styling after wrapping so each line closes and reopens styles cleanly.
func TestWrap_StyleAcrossBreak(t *testing.T) {
	t.Parallel()
	got := layout.Wrap([]layout.Span{{Text: "aaa bbb ccc", Style: mark}}, 7, 0, 0, layout.Spaces)
	checkLines(t, "closed and reopened", got, []string{"<aaa bbb>", "<ccc>"})
}

func TestWrap_StyleMixed(t *testing.T) {
	t.Parallel()
	got := layout.Wrap([]layout.Span{{Text: "x "}, {Text: "aaa bbb", Style: mark}, {Text: " end"}}, 7, 0, 2, layout.Spaces)
	checkLines(t, "mixed", got, []string{"x <aaa>", "  <bbb>", "  end"})

	// A hard-broken word keeps each part in its style.
	got = layout.Wrap([]layout.Span{{Text: "abcd", Style: mark}, {Text: "efgh"}}, 6, 0, 0, layout.Spaces)
	checkLines(t, "hard break across spans", got, []string{"<abcd>ef", "gh"})
}

// With real escapes: every line is balanced, no line ends inside a sequence and
// the visible width is within the limit.
func TestWrap_NoLineEndsInsideEscape(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.Color16, palette.Color256, palette.TrueColor} {
		style := func(s string) string { return d.Text(palette.Semantic, "info", s) }
		bold := func(s string) string { return d.BoldText(palette.Semantic, "muted", s) }
		spans := []layout.Span{
			{Text: "the quick brown fox jumps over ", Style: style},
			{Text: "https://example.com/a/very/long/path", Style: bold},
			{Text: " and a-very-long-unbroken-word-that-must-be-cut and more words", Style: style},
		}
		for width := 8; width <= 40; width++ {
			for _, l := range layout.Wrap(spans, width, 3, 3, layout.Spaces) {
				if hasBrokenEscape(l) {
					t.Fatalf("depth %v width %d: broken escape in %q", d, width, l)
				}
				if strings.Count(l, "\x1b[0m") != strings.Count(l, "\x1b[")-strings.Count(l, "\x1b[0m") {
					t.Fatalf("depth %v width %d: unbalanced styles in %q", d, width, l)
				}
			}
		}
	}
}

func TestWrap_Keep(t *testing.T) {
	t.Parallel()
	// A Keep span is one token: never split, even at a space inside it, styled whole.
	got := layout.Wrap([]layout.Span{{Text: "abc def", Style: mark, Keep: true}}, 3, 0, 0, layout.Spaces)
	checkLines(t, "alone", got, []string{"<abc def>"})
}

func TestWrap_KeepThenText(t *testing.T) {
	t.Parallel()
	got := layout.Wrap([]layout.Span{{Text: "CRITICAL", Style: mark, Keep: true}, {Text: " message words here"}}, 18, 0, 0, layout.Spaces)
	checkLines(t, "badge then text", got, []string{"<CRITICAL> message", "words here"})
	// Measure Keep spans after styling because badges add padding.
	pad := func(s string) string { return " " + s + " " }
	got = layout.Wrap([]layout.Span{{Text: "ab", Style: pad, Keep: true}, {Text: " cd ef"}}, 7, 0, 0, layout.Spaces)
	checkLines(t, "styled width counts", got, []string{" ab  cd", "ef"})
	// Keep with the text glued to it is one word and stays whole.
	got = layout.Wrap([]layout.Span{{Text: "(", Style: nil}, {Text: "tag", Keep: true}, {Text: "),"}, {Text: " x"}}, 3, 0, 0, layout.Spaces)
	checkLines(t, "glued", got, []string{"(tag),", "x"})
}

func TestWrap_None(t *testing.T) {
	t.Parallel()
	checkLines(t, "never breaks", wrapPlain("a long line with many words", 5, 0, 0, layout.None), []string{"a long line with many words"})
}

// Randomised wrapping preserves text except break spaces and exceeds width only for unbreakable
// content.
func TestWrap_Property(t *testing.T) {
	t.Parallel()
	pieces := []string{
		"a", "bb", "ccc", "word", "longerword", "abcdefghijklmnopqrstuvwxyz", "日本", "e\u0301", "x-y/z",
		"example.com", "https://example.com/some/path", "192.0.2.0/24", "a@example.org", "CVSS:3.1/AV:N/AC:L",
		"foo,", "bar,", "2.4.41",
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for iter := range 300 {
		var b strings.Builder
		for n := 1 + rng.IntN(25); n > 0; n-- {
			b.WriteString(pieces[rng.IntN(len(pieces))])
			switch rng.IntN(8) {
			case 0:
				b.WriteString("  ")
			case 1:
				b.WriteString(", ")
			case 2:
				b.WriteString("\n")
			default:
				b.WriteString(" ")
			}
		}
		text := b.String()
		for _, mode := range []layout.Mode{layout.Spaces, layout.Commas} {
			width := 6 + rng.IntN(40)
			first, rest := rng.IntN(5), rng.IntN(5)
			lines := wrapPlain(text, width, first, rest, mode)
			for i, l := range lines {
				if layout.Measure(l)+map[bool]int{true: first, false: 0}[i == 0] <= width {
					continue
				}
				protected := false
				for w := range strings.FieldsSeq(l) {
					protected = protected || layout.Protected(w)
				}
				if !protected {
					t.Fatalf("iter %d mode %d width %d: line %d %q is too wide and holds no protected word\ntext %q",
						iter, mode, width, i, l, text)
				}
			}
			if strip(strings.Join(lines, "")) != strip(text) {
				t.Fatalf("iter %d mode %d width %d: text changed\n got %q\nwant %q", iter, mode, width, strings.Join(lines, "|"), text)
			}
		}
	}
}

// strip removes every space and newline.
func strip(s string) string {
	return strings.NewReplacer(" ", "", "\n", "").Replace(s)
}
