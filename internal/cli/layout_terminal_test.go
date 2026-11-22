package cli_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// maxCells is the widest line of s in terminal cells, once escapes are removed.
func maxCells(s string) int { return widest(strings.Split(s, "\n")) }

// withoutErrorLines is stderr with the closing error, its hint and its retry line removed: they are
// written as they always were, and are not laid out (under --json it is one line of JSON).
func withoutErrorLines(s string) string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		if p := stripSGR(l); !strings.HasPrefix(p, "error:") && !strings.HasPrefix(p, "hint:") && !strings.HasPrefix(p, "retry:") && !strings.HasPrefix(p, "{") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// assertNoKeyPieces fails when out holds the key, or any 8-character piece of it, as it stands or
// with each line break (and the two-space indent or message column after it) taken out.
func assertNoKeyPieces(t *testing.T, key, out string) {
	t.Helper()
	joined := regexp.MustCompile(`\n +`).ReplaceAllString(out, "")
	spaced := regexp.MustCompile(`\n +`).ReplaceAllString(out, " ")
	for i := 0; i+8 <= len(key); i++ {
		for name, text := range map[string]string{"raw": out, "joined": joined, "spaced": spaced} {
			if strings.Contains(text, key[i:i+8]) {
				t.Errorf("%s: the piece %q of the key reached the output:\n%s", name, key[i:i+8], out)
			}
		}
	}
}

// warnStage is a stage that raises each message as a warning.
func warnStage(msgs ...string) *testkit.Stage {
	return &testkit.Stage{StageName: "warner", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			for _, m := range msgs {
				v.Warn("%s", m)
			}
			return testkit.Keys("w", 1)
		}}
}

// ruleLength is the cells of the first line of stdout's rule beneath its first heading.
func ruleLength(t *testing.T, out string) int {
	t.Helper()
	lines := strings.Split(stripSGR(unmargined(t, out)), "\n")
	if len(lines) < 2 || lines[0] != "Summary" {
		t.Fatalf("stdout does not start with the summary heading:\n%s", out)
	}
	return utf8.RuneCountInString(lines[1])
}

// A terminal stream's width is COLUMNS when that is a positive number, else the terminal's own
// width, else 100, and never less than 60; the summary is laid out at it.
func TestLayout_SummaryWidth(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		columns string
		term    int
		want    int
	}{
		{"the terminal's width", "", 70, 70},
		{"COLUMNS beats the terminal", "90", 70, 90},
		{"an unusable COLUMNS falls back to the terminal", "abc", 72, 72},
		{"no width at all", "", 0, 100},
		{"never less than 60", "", 40, 60},
		{"COLUMNS below 60", "30", 120, 60},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, someFindings())
			h.stdoutTTY = true
			h.setenv("NO_COLOR", "1")
			h.stdoutWidth = c.term
			if c.columns != "" {
				h.setenv("COLUMNS", c.columns)
			}
			if code := h.exec("a.com"); code != 0 {
				t.Fatalf("exit %d\n%s", code, h.stderr.String())
			}
			if got := ruleLength(t, h.stdout.String()); got != c.want {
				t.Errorf("the rule is %d cells wide, want %d", got, c.want)
			}
		})
	}
}

// stderr has its own width: nil or 0 from the terminal gives 100, and a line wraps at it.
func TestLayout_StderrWidth(t *testing.T) {
	t.Parallel()
	words := strings.TrimSpace(strings.Repeat("alpha beta gamma delta ", 12)) // 275 cells
	run1 := func(t *testing.T, width func() int, set bool) string {
		t.Helper()
		h := newHarness(t, warnStage(words))
		h.stderrTTY = true
		h.setenv("NO_COLOR", "1")
		d := h.deps()
		if set {
			d.StderrWidth = width
		}
		args := []string{"recon", "--output-dir", h.out, "a.com", "--quiet"}
		if code := cli.Execute(context.Background(), args, d); code != 0 {
			t.Fatalf("exit %d\n%s", code, h.stderr.String())
		}
		return h.stderr.String()
	}
	for name, out := range map[string]string{
		"nil":  run1(t, nil, false),
		"zero": run1(t, func() int { return 0 }, true),
	} {
		if w := maxCells(out); w > 100 || w < 90 {
			t.Errorf("%s: widest line is %d cells, want a wrap at 100:\n%s", name, w, out)
		}
		if strings.Count(out, "\n") < 3 {
			t.Errorf("%s: not wrapped:\n%s", name, out)
		}
	}
	if out := run1(t, func() int { return 70 }, true); maxCells(out) > 70 || maxCells(out) < 60 {
		t.Errorf("a terminal of 70: widest line %d:\n%s", maxCells(out), out)
	}
	// stdout's width does not move stderr's.
	h := newHarness(t, warnStage(words))
	h.stderrTTY = true
	h.setenv("NO_COLOR", "1")
	h.stdoutWidth = 70
	h.exec("a.com", "--quiet")
	if w := maxCells(h.stderr.String()); w > 100 || w < 90 {
		t.Errorf("stdout's width changed stderr's: widest line %d", w)
	}
}

// A long warning wraps on a terminal with continuation lines at the message column, 19 uncoloured
// and 21 coloured, and logLines folds them back into the one message. Off a terminal it is one line.
func TestLayout_LongWarningWraps(t *testing.T) {
	t.Parallel()
	msg := strings.TrimSpace(strings.Repeat("the quick brown fox jumps over the lazy dog ", 8))
	for _, c := range []struct {
		name   string
		setup  func(*harness)
		indent int // 0 means one line
	}{
		{"plain terminal", func(h *harness) { h.stderrTTY = true; h.setenv("NO_COLOR", "1") }, 19},
		{"coloured terminal", func(h *harness) { colourAt(t, h, palette.TrueColor) }, 21},
		{"not a terminal", func(h *harness) {}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, warnStage(msg))
			c.setup(h)
			h.setenv("COLUMNS", "80")
			if code := h.exec("a.com", "--quiet"); code != 0 {
				t.Fatalf("exit %d\n%s", code, h.stderr.String())
			}
			lines := strings.Split(strings.TrimSpace(h.stderr.String()), "\n")
			checkWrapped(t, lines, c.indent)
			if c.name != "coloured terminal" { // logLines reads the plain layout
				if got := h.logMsgs("WARN"); len(got) != 1 || got[0] != msg {
					t.Errorf("the folded message = %q, want %q", got, msg)
				}
			}
		})
	}
}

// checkWrapped checks the lines of one log line: a single line when indent is 0, and otherwise
// several, each after the first starting at the message column, none wider than 80 cells.
func checkWrapped(t *testing.T, lines []string, indent int) {
	t.Helper()
	if indent == 0 {
		if len(lines) != 1 {
			t.Errorf("a line off a terminal wrapped: %q", lines)
		}
		return
	}
	if len(lines) < 3 {
		t.Fatalf("not wrapped: %q", lines)
	}
	for _, l := range lines[1:] {
		if p := stripSGR(l); !strings.HasPrefix(p, strings.Repeat(" ", indent)) || p[indent] == ' ' {
			t.Errorf("continuation not at column %d: %q", indent, l)
		}
	}
	for _, l := range lines {
		if layout.Measure(l) > 80 {
			t.Errorf("%d cells in %q", layout.Measure(l), l)
		}
	}
}

// Under --json a terminal stderr's --debug lines are log lines and are laid out, and stdout is the
// envelope it is off a terminal.
func TestLayout_JSONDebugLinesWrap(t *testing.T) {
	t.Parallel()
	words := strings.TrimSpace(strings.Repeat("alpha beta gamma delta ", 12))
	failing := &testkit.Stage{StageName: "bad", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return testkit.Keys("b", 1) },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			return nil, errors.New(words)
		}}
	var envelopes [2]string
	for i, tty := range []bool{false, true} {
		h := newHarness(t, failing)
		h.stdoutTTY, h.stderrTTY = tty, tty
		h.setenv("COLUMNS", "80")
		h.setenv("NO_COLOR", "1")
		if code := h.exec("a.com", "--json", "--debug"); code != 7 {
			t.Fatalf("exit %d\n%s", code, h.stderr.String())
		}
		envelopes[i] = strings.ReplaceAll(h.stdout.String(), h.out, "OUT")
		wrapped := maxCells(withoutErrorLines(h.stderr.String())) <= 80 && strings.Contains(h.stderr.String(), "\n"+strings.Repeat(" ", 19))
		if wrapped != tty {
			t.Errorf("terminal=%v: wrapped debug line = %v:\n%s", tty, wrapped, h.stderr.String())
		}
	}
	if envelopes[0] != envelopes[1] {
		t.Errorf("the envelope differs on a terminal:\n got %q\nwant %q", envelopes[1], envelopes[0])
	}
}

// The goal: at COLUMNS=80 every line of the summary and of the log is at most 80 cells, coloured or
// not, for a run with no unbreakable token wider than its space.
func TestLayout_RunFitsEightyColumns(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.None, palette.TrueColor, palette.Color16} {
		h := newHarness(t, someFindings(), failingCheck("boom"))
		if d == palette.None {
			h.stdoutTTY, h.stderrTTY = true, true
			h.setenv("NO_COLOR", "1")
		} else {
			colourAt(t, h, d)
		}
		h.setenv("COLUMNS", "80")
		if code := h.exec("a.com"); code != 7 {
			t.Fatalf("exit %d\n%s", code, h.stderr.String())
		}
		for name, out := range map[string]string{"stdout": h.stdout.String(), "stderr": withoutErrorLines(h.stderr.String())} {
			if w := maxCells(out); w > 80 {
				t.Errorf("depth %d %s: a line of %d cells:\n%s", d, name, w, stripSGR(out))
			}
		}
	}
}

// Every escape in the output of a run on terminals is a sequence the palette can produce at the
// stream's depth, in the summary and the log.
func TestLayout_RunWritesOnlyPaletteSequences(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.TrueColor, palette.Color256, palette.Color16} {
		h := newHarness(t, someFindings(), failingCheck("boom"))
		colourAt(t, h, d)
		h.setenv("COLUMNS", "80")
		if code := h.exec("a.com", "--debug"); code != 7 {
			t.Fatalf("exit %d\n%s", code, h.stderr.String())
		}
		testkit.OnlyPaletteEscapes(t, d, h.stdout.String())
		testkit.OnlyPaletteEscapes(t, d, h.stderr.String())
	}
}

// On a NO_COLOR terminal and a TERM=dumb terminal the layout still applies and no escape byte is
// written: not in the summary, the log or the palette sheet.
func TestLayout_UncolouredTerminalsHaveNoEscape(t *testing.T) {
	t.Parallel()
	for name, env := range map[string]map[string]string{"NO_COLOR": {"NO_COLOR": "1"}, "dumb": {"TERM": "dumb"}} {
		h := newHarness(t, someFindings(), failingCheck("boom"))
		h.stdoutTTY, h.stderrTTY = true, true
		h.setenv("COLORTERM", "truecolor")
		for k, v := range env {
			h.setenv(k, v)
		}
		if code := h.exec("a.com", "--debug"); code != 7 {
			t.Fatalf("%s: exit %d\n%s", name, code, h.stderr.String())
		}
		if !strings.Contains(h.stdout.String(), "SEVERITY  CATEGORY") || !strings.Contains(h.stdout.String(), "----") {
			t.Errorf("%s: the layout does not apply:\n%s", name, h.stdout.String())
		}
		h.exec("--palette")
		if !strings.Contains(h.stdout.String(), "layout") {
			t.Errorf("%s: no layout part in the sheet", name)
		}
		if strings.Contains(h.stdout.String()+h.stderr.String(), esc) {
			t.Errorf("%s: an escape byte:\n%q", name, h.stdout.String())
		}
	}
}

// --palette on a terminal shows the layout part, coloured and not; under --json it is the sheet it
// is off a terminal.
func TestLayout_PaletteSheetOnATerminal(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	h.setenv("COLUMNS", "80")
	if code := h.exec("--palette"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	plainSheet := h.stdout.String()
	h.stdoutTTY = true
	h.setenv("NO_COLOR", "1")
	h.exec("--palette")
	got := unmargined(t, h.stdout.String())
	for _, want := range []string{"\nlayout\n", "SEVERITY  CATEGORY", "[HIGH]", "[UNKNOWN]", "[NONE]", "running", "done-previously", "not-configured", "+ host: "} {
		if !strings.Contains(got, want) {
			t.Errorf("uncoloured terminal sheet lacks %q", want)
		}
	}
	entries, _, _ := strings.Cut(plainSheet, "log lines")
	if !strings.HasPrefix(got, entries) {
		t.Error("the sheet no longer starts with today's entries")
	}
	d := palette.TrueColor
	colourAt(t, h, d)
	h.setenv("NO_COLOR", "")
	h.exec("--palette")
	col := h.stdout.String()
	if !strings.Contains(col, "\n"+d.BoldText(palette.Semantic, "info", "layout")+"\n") {
		t.Errorf("the layout heading is not in the heading style:\n%q", col)
	}
	testkit.OnlyPaletteEscapes(t, d, col)
	// Under --json, on a terminal, it is today's sheet, byte for byte.
	h.exec("--palette", "--json")
	h2 := newHarness(t, noop())
	h2.setenv("COLUMNS", "80")
	h2.exec("--palette", "--json")
	if h.stdout.String() != h2.stdout.String() {
		t.Errorf("the sheet under --json differs on a terminal")
	}
}

// A stage's note is sanitised and has any key masked before the summary lays it out on a terminal,
// wherever it wraps: a control sequence, a key split by one and a key inside a long word that is
// broken at the width leave no escape and no part of the key.
func TestLayout_SummaryNoteIsCleanedBeforeLayout(t *testing.T) {
	t.Parallel()
	const key = "sekret-key-4242"
	notes := []string{
		strings.Repeat("ab ", 22) + "\x1b[31mred\x1b[0m \x1b]0;title\x07 \u202eflip " + strings.Repeat("cd ", 10),
		strings.Repeat("n", 30) + " sekret-\x1b[2Jkey-4242 " + strings.Repeat("n", 30),
		strings.Repeat("h", 50) + key + strings.Repeat("j", 50),
		strings.Repeat("q", 40) + "sekret-\x07key-4242" + strings.Repeat("q", 40),
	}
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		for _, note := range notes {
			h := newHarness(t, noteStage{&testkit.Stage{StageName: "noter", Kind: run.ThirdParty}, note})
			h.setKey("fake", key)
			h.setenv("COLUMNS", "60")
			if d == palette.None {
				h.stdoutTTY = true
				h.setenv("NO_COLOR", "1")
			} else {
				colourAt(t, h, d)
			}
			if code := h.exec("a.com"); code != 0 {
				t.Fatalf("exit %d\n%s", code, h.stderr.String())
			}
			out := h.stdout.String()
			testkit.OnlyPaletteEscapes(t, d, out)
			if w := maxCells(out); w > 60 {
				t.Errorf("depth %d: a line of %d cells at width 60:\n%s", d, w, stripSGR(out))
			}
			plain := stripSGR(out)
			assertNoKeyPieces(t, key, plain)
			for _, bad := range []string{"title", "[2J", "[31m", "\u202e"} {
				if strings.Contains(plain, bad) {
					t.Errorf("depth %d: %q from the note is in the summary:\n%s", d, bad, plain)
				}
			}
		}
	}
}
