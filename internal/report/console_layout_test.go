package report_test

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/testkit"
)

// logPrefix builds the stream's timestamp, level and separators.
func logPrefix(s layout.Stream, l report.Level) string {
	return report.Line(s, noon, l, "")
}

// cells is the width of s in terminal cells.
func cells(s string) int { return layout.Measure(s) }

var depths = []palette.Depth{palette.TrueColor, palette.Color256, palette.Color16}

// Terminal log wrapping preserves word order and aligns continuations after plain/coloured
// prefixes.
func TestLineWrapsOnATerminal(t *testing.T) {
	t.Parallel()
	words := make([]string, 60)
	for i := range words {
		words[i] = "word" + string(rune('a'+i%26))
	}
	msg := strings.Join(words, " ")
	for _, c := range []struct {
		s      layout.Stream
		indent int
	}{
		{termStream(palette.None, 60), 19},
		{termStream(palette.None, 80), 19},
		{termStream(palette.TrueColor, 80), 21},
		{termStream(palette.Color16, 100), 21},
	} {
		lines := strings.Split(report.Line(c.s, noon, report.Warn, msg), "\n")
		if len(lines) < 2 {
			t.Fatalf("%+v: a message of %d cells did not wrap: %q", c.s.Depth, len(msg), lines)
		}
		width := c.s.Cols()
		var got []string
		for i, l := range lines {
			if cells(l) > width {
				t.Errorf("%+v: line %d is %d cells, width %d: %q", c.s.Depth, i, cells(l), width, l)
			}
			p := stripEscapes(l)
			if i == 0 {
				p = string([]rune(p)[c.indent:])
			} else {
				if p[:c.indent] != strings.Repeat(" ", c.indent) || p[c.indent] == ' ' {
					t.Errorf("%+v: continuation %d is not at column %d: %q", c.s.Depth, i, c.indent, p)
				}
				p = p[c.indent:]
			}
			got = append(got, p)
		}
		if strings.Join(got, " ") != msg {
			t.Errorf("%+v: the wrapped text differs from the message:\n%q", c.s.Depth, got)
		}
	}
}

// A line to a stream that is not a terminal is never wrapped, whatever its width.
func TestLineNeverWrapsOffATerminal(t *testing.T) {
	t.Parallel()
	msg := strings.Repeat("word ", 100) + "end"
	s := layout.Stream{Width: func() int { return 60 }}
	if got, want := report.Line(s, noon, report.Info, msg), "12:00:00 | INFO  | "+msg; got != want {
		t.Errorf("a plain line was changed: %q", got)
	}
}

// Protected hostnames may overflow while ordinary long words split at width.
func TestLineProtectedAndBrokenWords(t *testing.T) {
	t.Parallel()
	s := termStream(palette.None, 60)
	host := strings.Repeat("a", 30) + "." + strings.Repeat("b", 30) + ".example.com"
	lines := strings.Split(report.Line(s, noon, report.Info, "seen "+host+" twice"), "\n")
	if len(lines) != 3 && len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	if !strings.Contains(strings.Join(lines, "\n"), host) {
		t.Errorf("the hostname was broken: %q", lines)
	}
	blob := strings.Repeat("z", 120)
	lines = strings.Split(report.Line(s, noon, report.Info, blob), "\n")
	if len(lines) < 3 {
		t.Fatalf("a word of 120 cells was not broken: %q", lines)
	}
	for _, l := range lines {
		if cells(l) > 60 {
			t.Errorf("line of %d cells: %q", cells(l), l)
		}
	}
}

// The width is read for each line, so a resize applies from the next line.
func TestConsoleResize(t *testing.T) {
	t.Parallel()
	var width atomic.Int32
	width.Store(80)
	s := layout.Stream{Terminal: true, Width: func() int { return int(width.Load()) }}
	c := newCons(s, report.Info)
	msg := strings.TrimSpace(strings.Repeat("word ", 40)) // 199 cells
	c.Emit(ev("warning", map[string]any{"message": msg}))
	width.Store(120)
	c.Emit(ev("warning", map[string]any{"message": msg}))
	lines := strings.Split(strings.TrimSpace(c.log.String()), "\n")
	var first, second []string
	for _, l := range lines {
		if strings.HasPrefix(l, "12:00:00") && len(first) > 0 {
			second = append(second, l)
			continue
		}
		if len(second) > 0 {
			second = append(second, l)
		} else {
			first = append(first, l)
		}
	}
	if len(first) == len(second) || len(first) < 3 {
		t.Fatalf("80 columns gave %d lines, 120 gave %d:\n%s", len(first), len(second), c.log.String())
	}
	for i, l := range first {
		if cells(l) > 80 {
			t.Errorf("first event, line %d is %d cells", i, cells(l))
		}
	}
	for i, l := range second {
		if cells(l) > 120 {
			t.Errorf("second event, line %d is %d cells", i, cells(l))
		}
	}
	if cells(second[0]) <= 80 {
		t.Errorf("the second event did not use the new width: %d cells", cells(second[0]))
	}
}

// A found line with a badge wraps at the message column and keeps its badge whole on the first
// line, coloured and not.
func TestConsoleFoundLineWraps(t *testing.T) {
	t.Parallel()
	value := strings.TrimSpace(strings.Repeat("alpha beta gamma ", 12))
	for _, c := range []struct {
		s      layout.Stream
		indent int
	}{{termStream(palette.None, 80), 19}, {termStream(palette.TrueColor, 80), 21}} {
		con := newCons(c.s, report.Info)
		con.Emit(ev("found", map[string]any{"category": "finding", "value": value, "severity": "high"}))
		lines := strings.Split(strings.TrimSpace(con.log.String()), "\n")
		if len(lines) < 3 {
			t.Fatalf("%+v: a found line of %d cells did not wrap:\n%s", c.s.Depth, len(value), con.log.String())
		}
		if !strings.Contains(lines[0], strings.TrimSpace(c.s.Depth.Value(palette.Severity, "high"))) {
			t.Errorf("%+v: the badge is not whole on the first line: %q", c.s.Depth, lines[0])
		}
		for i, l := range lines[1:] {
			if p := stripEscapes(l); p[:c.indent] != strings.Repeat(" ", c.indent) || p[c.indent] == ' ' {
				t.Errorf("%+v: continuation %d not at column %d: %q", c.s.Depth, i+1, c.indent, p)
			}
			if cells(l) > 80 {
				t.Errorf("%+v: continuation %d is %d cells", c.s.Depth, i+1, cells(l))
			}
		}
	}
}

// Procedure state words alone gain semantic message colour; non-failing state levels remain INFO.
func TestConsoleStateWords(t *testing.T) {
	t.Parallel()
	for _, d := range depths {
		s := termStream(d, 100)
		for _, c := range []struct {
			state, reason, tail string
			level               report.Level
			style               func(string) string
		}{
			{"running", "", "", report.Info, func(x string) string { return d.Text(palette.Semantic, "info", x) }},
			{"done", "", " (3 jobs, 1 failed)", report.Info, func(x string) string { return d.Text(palette.Semantic, "success", x) }},
			{"done-previously", "", "", report.Info, func(x string) string { return d.Text(palette.Semantic, "success", x) }},
			{"failed", "", "", report.Error, func(x string) string { return d.Text(palette.Semantic, "error", x) }},
			{"not-configured", "passive-only", " (passive-only)", report.Info, func(x string) string { return d.Text(palette.Semantic, "muted", x) }},
		} {
			con := newCons(s, report.Info)
			con.Emit(ev("procedure", map[string]any{"name": "asn", "state": c.state, "reason": c.reason, "jobs": 3, "failed": 1}))
			want := logPrefix(s, c.level) + "asn           " + " " + c.style(c.state) + c.tail
			if got := strings.TrimSuffix(con.log.String(), "\n"); got != want {
				t.Errorf("depth %d %s\n got %q\nwant %q", d, c.state, got, want)
			}
			if c.level == report.Info && !strings.Contains(con.log.String(), d.Badge(palette.Level, "INFO")) {
				t.Errorf("depth %d %s: the level badge is not INFO", d, c.state)
			}
		}
		// Uncoloured, the same line has no escape; and not on a terminal the colour is off too.
		for _, u := range []layout.Stream{termStream(palette.None, 100), plainStream()} {
			con := newCons(u, report.Info)
			con.Emit(ev("procedure", map[string]any{"name": "asn", "state": "running"}))
			if strings.Contains(con.log.String(), "\x1b") {
				t.Errorf("an escape in %q", con.log.String())
			}
		}
	}
}

// Found messages style + and default categories, leaving custom message text plain.
func TestConsoleFoundColours(t *testing.T) {
	t.Parallel()
	for _, d := range depths {
		s := termStream(d, 100)
		plus := d.Text(palette.Semantic, "success", "+")
		cat := func(x string) string { return d.Text(palette.Semantic, "info", x) }
		for _, c := range []struct {
			f    map[string]any
			want string
		}{
			{map[string]any{"category": "host", "value": "a.example.com"}, plus + " " + cat("host") + ": a.example.com"},
			{map[string]any{"category": "third party", "text": "third-party Google on example.com"}, plus + " third-party Google on example.com"},
			{map[string]any{"category": "finding", "value": "x", "severity": "low", "text": "takeover"}, plus + " " + d.Value(palette.Severity, "low") + " takeover"},
			{map[string]any{"category": "finding", "value": "x", "severity": "weird"}, plus + " " + d.Value(palette.Severity, "weird") + " " + cat("finding") + ": x"},
		} {
			con := newCons(s, report.Info)
			con.Emit(ev("found", c.f))
			if got, want := strings.TrimSuffix(con.log.String(), "\n"), logPrefix(s, report.Info)+c.want; got != want {
				t.Errorf("depth %d %v\n got %q\nwant %q", d, c.f, got, want)
			}
		}
	}
	// Off a terminal and uncoloured nothing is coloured.
	con := newCons(termStream(palette.None, 100), report.Info)
	con.Emit(ev("found", map[string]any{"category": "host", "value": "a"}))
	if got := con.log.String(); got != "12:00:00 | INFO  | + host: a\n" {
		t.Errorf("uncoloured terminal line = %q", got)
	}
}

// Console escapes come exclusively from the selected palette, never event text.
func TestConsoleWritesOnlyPaletteSequences(t *testing.T) {
	t.Parallel()
	evil := "x\x1b[2J\x1b]0;pwn\x07y\u202ez\nnext\r"
	long := strings.Repeat("word ", 50)
	events := []report.Event{
		ev("run_start", map[string]any{"engagement": "eng", "scope": evil, "passive": true, "authorised": true}),
		ev("procedure", map[string]any{"name": "asn", "state": "running"}),
		ev("procedure", map[string]any{"name": "asn", "state": "done", "jobs": 3, "failed": 1}),
		ev("procedure", map[string]any{"name": "asn", "state": "done-previously"}),
		ev("procedure", map[string]any{"name": "asn", "state": "failed", "reason": evil}),
		ev("procedure", map[string]any{"name": "asn", "state": "not-configured", "reason": "no key"}),
		ev("found", map[string]any{"category": "finding", "value": evil, "severity": "high"}),
		ev("found", map[string]any{"category": "host", "value": "a.example.com"}),
		ev("count", map[string]any{"category": "hosts", "n": 1}),
		ev("warning", map[string]any{"message": long + evil}),
		ev("debug", map[string]any{"message": evil + long}),
	}
	for _, d := range []palette.Depth{palette.None, palette.TrueColor, palette.Color256, palette.Color16} {
		c := newCons(termStream(d, 70), report.Debug)
		for _, e := range events {
			c.Emit(e)
		}
		testkit.OnlyPaletteEscapes(t, d, c.log.String())
	}
}

// Remove controls before wrapping even when they fall at line boundaries.
func TestConsoleTextAtWrapPoints(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		for pad := 30; pad < 70; pad++ {
			msg := strings.Repeat("a", pad) + " \x1b[31mred\x1b[0m \x1b]0;title\x07 \u202eflip " + strings.Repeat("b", 70)
			c := newCons(termStream(d, 60), report.Info)
			c.Emit(ev("warning", map[string]any{"message": msg}))
			testkit.OnlyPaletteEscapes(t, d, c.log.String())
			if strings.Contains(stripEscapes(c.log.String()), "title") && strings.Contains(c.log.String(), "]0;") {
				t.Fatalf("pad %d: a title sequence survived: %q", pad, c.log.String())
			}
		}
	}
}

// Console redaction works without an upstream emitter and masks keys rejoined by cleaning or
// embedded in wrapped words.
func TestConsoleRedactsAfterSanitising(t *testing.T) {
	t.Parallel()
	const key = "sekret-key-4242"
	red := config.NewRedactor(key)
	windows := func() (w []string) {
		for i := 0; i+8 <= len(key); i++ {
			w = append(w, key[i:i+8])
		}
		return w
	}()
	messages := []string{
		"sekret-\x07key-4242",             // sanitising removes the bell and the key is whole again
		"sekret-\x1b[2Jkey-4242",          // a clear-screen sequence
		"sekret-\x1b]0;title\x07key-4242", // a title
		"sekret-\u202ekey-4242",           // a bidi override
		"sekret-\rkey-4242",               // a carriage return
		strings.Repeat("w", 55) + key + strings.Repeat("v", 55),
		strings.Repeat("w", 48) + "sekret-\x07key-4242" + strings.Repeat("v", 70),
		strings.Repeat("w", 40) + " " + key + "tail " + strings.Repeat("z", 90),
	}
	for _, s := range []layout.Stream{termStream(palette.None, 60), termStream(palette.TrueColor, 60), termStream(palette.None, 80), plainStream()} {
		for _, m := range messages {
			for _, typ := range []string{"warning", "debug", "found", "procedure"} {
				f := map[string]any{"message": m}
				switch typ {
				case "found":
					f = map[string]any{"category": "finding", "value": m, "severity": "high"}
				case "procedure":
					f = map[string]any{"name": "asn", "state": "failed", "reason": m}
				}
				var sb strings.Builder
				c := report.NewConsole(report.ConsoleOptions{Log: &sb, LogStream: s, Min: report.Debug, Clock: clk, Location: time.UTC, Redactor: red})
				c.Emit(ev(typ, f))
				out := sb.String()
				joined := strings.ReplaceAll(stripEscapes(out), "\n", "")
				for _, piece := range append(windows, key) {
					if strings.Contains(out, piece) || strings.Contains(joined, piece) {
						t.Errorf("%s %+v: %q reached the log in %q", typ, s, piece, out)
					}
				}
				if !strings.Contains(out, "****") {
					t.Errorf("%s: the key was not masked in %q", typ, out)
				}
			}
		}
	}
}
