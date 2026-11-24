package report_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/report"
)

var (
	clk  = func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) }
	noon = clk()
)

// cons is a console that writes its log to a buffer.
type cons struct {
	*report.Console
	log bytes.Buffer
}

// plainStream models a pipe or file.
func plainStream() layout.Stream { return layout.Stream{} }

// termStream is a terminal of the given depth and width in cells.
func termStream(d palette.Depth, width int) layout.Stream {
	return layout.Stream{Terminal: true, Depth: d, Width: func() int { return width }}
}

func newCons(log layout.Stream, min report.Level) *cons {
	c := &cons{}
	c.Console = report.NewConsole(report.ConsoleOptions{
		Log: &c.log, LogStream: log,
		Min: min, Clock: clk, Location: time.UTC,
	})
	return c
}

func plain(min report.Level) *cons { return newCons(plainStream(), min) }

func ev(typ string, f map[string]any) report.Event { return report.Event{Type: typ, Fields: f} }

func stripEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Plain log prefixes align every message at cell 19 with five-character level padding.
func TestLinePlain(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		l    report.Level
		want string
	}{
		{report.Debug, "12:00:00 | DEBUG | hello"},
		{report.Info, "12:00:00 | INFO  | hello"},
		{report.Warn, "12:00:00 | WARN  | hello"},
		{report.Error, "12:00:00 | ERROR | hello"},
		{report.Crit, "12:00:00 | CRIT  | hello"},
	} {
		got := report.Line(plainStream(), noon, c.l, "hello")
		if got != c.want || got[19:] != "hello" {
			t.Errorf("level %d: %q, want %q", c.l, got, c.want)
		}
	}
}

// A coloured line is byte for byte the example in the palette document, and its
// message follows the first 21 cells.
func TestLineColoured(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 1, 14, 2, 8, 0, time.UTC)
	want := "\x1b[38;2;124;129;145m14:02:08\x1b[0m\x1b[38;2;74;79;92m │ \x1b[0m" +
		"\x1b[38;2;236;208;143;48;2;61;52;32m WARN  \x1b[0m\x1b[38;2;74;79;92m │ \x1b[0mrate limited, retrying in 2s"
	if got := report.Line(termStream(palette.TrueColor, 100), at, report.Warn, "rate limited, retrying in 2s"); got != want {
		t.Errorf("coloured line\n got %q\nwant %q", got, want)
	}
	for _, d := range []palette.Depth{palette.TrueColor, palette.Color256, palette.Color16} {
		for _, l := range []report.Level{report.Debug, report.Info, report.Warn, report.Error, report.Crit} {
			cells := []rune(stripEscapes(report.Line(termStream(d, 100), noon, l, "msg")))
			if string(cells[21:]) != "msg" || cells[9] != '│' {
				t.Errorf("depth %d level %d: %q", d, l, string(cells))
			}
		}
	}
}

// The second and later lines of a message are indented to the message column,
// with no timestamp or level.
func TestLineContinuation(t *testing.T) {
	t.Parallel()
	got := report.Line(plainStream(), noon, report.Error, "request failed\nTraceback\n  File x")
	want := "12:00:00 | ERROR | request failed\n" + strings.Repeat(" ", 19) + "Traceback\n" + strings.Repeat(" ", 19) + "  File x"
	if got != want {
		t.Errorf("plain\n got %q\nwant %q", got, want)
	}
	col := strings.Split(report.Line(termStream(palette.TrueColor, 100), noon, report.Error, "a\nb"), "\n")
	if len(col) != 2 || col[1] != strings.Repeat(" ", 21)+"b" {
		t.Errorf("coloured continuation = %q", col)
	}
}

// Only known events render; final errors belong to the CLI, not an error event.
func TestConsoleStreams(t *testing.T) {
	t.Parallel()
	c := plain(report.Info)
	c.Emit(ev("run_start", map[string]any{"engagement": "eng", "scope": "1 roots, 0 orgs, 0 asns, 0 cidrs, 0 exclusions"}))
	c.Emit(ev("procedure", map[string]any{"name": "asn", "state": "running"}))
	c.Emit(ev("found", map[string]any{"category": "host", "value": "a.example.com"}))
	c.Emit(ev("count", map[string]any{"category": "hosts", "n": 1}))
	c.Emit(ev("warning", map[string]any{"message": "careful"}))
	c.Emit(ev("nonsense", nil))
	c.Emit(ev("error", map[string]any{"message": "no inputs", "exit_code": 2}))
	if n := strings.Count(c.log.String(), "\n"); n != 5 {
		t.Errorf("%d log lines, want 5 (unknown types print nothing):\n%s", n, c.log.String())
	}
}

// Events map to levels; the minimum level drops lower ones, but never the
// summary or the error line.
func TestConsoleLevels(t *testing.T) {
	t.Parallel()
	events := []report.Event{
		ev("run_start", map[string]any{"engagement": "eng"}),
		ev("procedure", map[string]any{"name": "asn", "state": "done", "jobs": 2, "failed": 0}),
		ev("procedure", map[string]any{"name": "dns", "state": "failed", "jobs": 2, "failed": 2}),
		ev("found", map[string]any{"category": "host", "value": "a"}),
		ev("count", map[string]any{"category": "hosts", "n": 1}),
		ev("warning", map[string]any{"message": "w"}),
		ev("debug", map[string]any{"message": "d"}),
	}
	levelOf := func(min report.Level) []string {
		c := plain(min)
		for _, e := range events {
			c.Emit(e)
		}
		var out []string
		for l := range strings.SplitSeq(strings.TrimSpace(c.log.String()), "\n") {
			out = append(out, strings.TrimSpace(l[11:16]))
		}
		return out
	}
	if got, want := strings.Join(levelOf(report.Debug), ","), "INFO,INFO,ERROR,INFO,INFO,WARN,DEBUG"; got != want {
		t.Errorf("debug: %s, want %s", got, want)
	}
	if got, want := strings.Join(levelOf(report.Info), ","), "INFO,INFO,ERROR,INFO,INFO,WARN"; got != want {
		t.Errorf("info: %s, want %s", got, want)
	}
	if got, want := strings.Join(levelOf(report.Warn), ","), "ERROR,WARN"; got != want {
		t.Errorf("warn: %s, want %s", got, want)
	}
}

// Header, procedure and count messages keep their text, with no colour in them.
func TestConsoleMessageText(t *testing.T) {
	t.Parallel()
	c := plain(report.Info)
	c.Emit(ev("run_start", map[string]any{"engagement": "eng", "scope": "1 roots", "passive": true, "authorised": true}))
	c.Emit(ev("procedure", map[string]any{"name": "ports", "state": "not-configured", "reason": "passive-only"}))
	c.Emit(ev("procedure", map[string]any{"name": "asn", "state": "done", "jobs": 3, "failed": 1}))
	c.Emit(ev("procedure", map[string]any{"name": "dns", "state": "running"}))
	c.Emit(ev("count", map[string]any{"category": "hosts", "n": 12}))
	var got []string
	for l := range strings.SplitSeq(strings.TrimSpace(c.log.String()), "\n") {
		got = append(got, l[19:])
	}
	want := []string{
		"nyx eng  1 roots  [passive-only]  [authorised]",
		"ports          not-configured (passive-only)",
		"asn            done (3 jobs, 1 failed)",
		"dns            running",
		"  hosts: 12",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("messages\n got %q\nwant %q", got, want)
	}

	// Coloured logs restrict styling to designated chrome, badges and state words.
	col := newCons(termStream(palette.TrueColor, 100), report.Info)
	col.Emit(ev("run_start", map[string]any{"engagement": "eng", "scope": "1 roots", "passive": true, "authorised": true}))
	col.Emit(ev("count", map[string]any{"category": "hosts", "n": 12}))
	for l := range strings.SplitSeq(strings.TrimSpace(col.log.String()), "\n") {
		prefix := l[:strings.LastIndex(l, "│ \x1b[0m")+len("│ \x1b[0m")]
		if rest := l[len(prefix):]; strings.Contains(rest, "\x1b") {
			t.Errorf("an escape inside the message: %q", l)
		}
	}
}

// A found line carries the severity badge after the +; its suffix is gone.
func TestConsoleFoundLines(t *testing.T) {
	t.Parallel()
	found := func(c *cons, f map[string]any) string {
		c.log.Reset()
		c.Emit(ev("found", f))
		return strings.TrimSuffix(c.log.String(), "\n")
	}
	p := plain(report.Info)
	for _, c := range []struct {
		f    map[string]any
		want string
	}{
		{map[string]any{"category": "finding exposed-admin", "value": "https://a/admin", "severity": "high"}, "+ high     finding exposed-admin: https://a/admin"},
		{map[string]any{"category": "finding", "value": "x", "text": "takeover on a.example.com", "severity": "medium"}, "+ medium   takeover on a.example.com"},
		{map[string]any{"category": "finding", "value": "x", "severity": "low"}, "+ low      finding: x"},
		{map[string]any{"category": "host", "value": "a.example.com"}, "+ host: a.example.com"},
		{map[string]any{"category": "third party", "text": "third-party Google on example.com"}, "+ third-party Google on example.com"},
		{map[string]any{"category": "finding", "value": "x", "severity": "weird"}, "+ weird    finding: x"},
	} {
		if got := found(p, c.f); got[19:] != c.want {
			t.Errorf("found %v = %q, want %q", c.f, got[19:], c.want)
		}
	}
	if got := found(p, map[string]any{"category": "f", "value": "x", "severity": "high"}); strings.Contains(got, "[") {
		t.Errorf("no brackets: %q", got)
	}

	d := palette.TrueColor
	col := newCons(termStream(d, 100), report.Info)
	want := report.Line(termStream(d, 100), noon, report.Info, "") +
		d.Text(palette.Semantic, "success", "+") + " " + d.Value(palette.Severity, "high") + " " + d.Text(palette.Semantic, "info", "finding") + ": x"
	if got := found(col, map[string]any{"category": "finding", "value": "x", "severity": "high"}); got != want {
		t.Errorf("coloured high\n got %q\nwant %q", got, want)
	}
	if got := found(col, map[string]any{"category": "finding", "value": "x", "severity": "weird"}); !strings.Contains(got, "\x1b[38;2;169;177;198;48;2;42;47;58m weird    \x1b[0m") {
		t.Errorf("an unknown severity takes the DEBUG style: %q", got)
	}
	if got := found(col, map[string]any{"category": "host", "value": "a"}); strings.Count(got, "48;2;") != 1 {
		t.Errorf("a record with no severity has only the level badge: %q", got)
	}
}

// Clean target text before laying out exactly the lines required by one event.
func TestConsoleSanitises(t *testing.T) {
	t.Parallel()
	evil := "x\x1b[2J\x1b]0;pwn\x07y\u202ez\nnext\r"
	long := strings.Repeat("a", 500)
	events := []report.Event{
		ev("found", map[string]any{"category": "finding", "value": evil, "severity": "high"}),
		ev("warning", map[string]any{"message": evil}),
		ev("debug", map[string]any{"message": evil}),
		ev("procedure", map[string]any{"name": evil, "state": "done", "reason": evil}),
		ev("warning", map[string]any{"message": long}),
	}
	for _, s := range []layout.Stream{plainStream(), termStream(palette.None, 80), termStream(palette.TrueColor, 80)} {
		c := newCons(s, report.Debug)
		for _, e := range events {
			c.Emit(e)
		}
		// Drop the escapes this package writes itself, then nothing is left.
		rest := stripEscapes(c.log.String())
		for _, bad := range []string{"\x1b", "\x07", "\u202e", "\r", "[2J", "]0;pwn"} {
			if strings.Contains(rest, bad) {
				t.Errorf("%+v: %q reached the output:\n%q", s.Depth, bad, rest)
			}
		}
		lines := strings.Count(c.log.String(), "\n")
		if !s.Terminal && lines != 5 {
			t.Errorf("not a terminal: %d log lines for 5 events: %q", lines, c.log.String())
		}
		if s.Terminal && strings.Contains(rest, long) {
			t.Errorf("a terminal line of 500 cells was not wrapped")
		}
		if !s.Terminal && !strings.Contains(rest, long) {
			t.Errorf("a line on a stream that is not a terminal was wrapped or cut")
		}
		if s.Terminal && strings.Count(stripEscapes(strings.ReplaceAll(c.log.String(), "\n", "")), "a") < 500 {
			t.Errorf("wrapping lost text")
		}
	}
	// A message is sanitised before it is split, so an injected newline makes no line of its own.
	c := plain(report.Info)
	c.Emit(ev("warning", map[string]any{"message": "one\ntwo"}))
	if n := strings.Count(c.log.String(), "\n"); n != 1 {
		t.Errorf("one event, one line: %q", c.log.String())
	}
}

// The redactor wrapper scrubs every string in an event, including nested ones.
func TestRedactingEmitter(t *testing.T) {
	t.Parallel()
	var w report.Warnings
	em := report.WithRedactor(&w, config.NewRedactor("SEKRET"))
	em.Emit(ev("warning", map[string]any{"message": "GET /?k=SEKRET failed", "extra": []map[string]any{{"x": "SEKRET"}}}))
	got := w.List()
	if len(got) != 1 || strings.Contains(got[0], "SEKRET") || !strings.Contains(got[0], "****") {
		t.Errorf("warning = %q, want it masked", got)
	}
}

// Only passes one event type, and Tee sends each event to both emitters.
func TestOnlyAndTee(t *testing.T) {
	t.Parallel()
	var w report.Warnings
	var logb bytes.Buffer
	console := report.NewConsole(report.ConsoleOptions{Log: &logb, Min: report.Debug, Clock: clk, Location: time.UTC})
	tee := report.WithRedactor(report.Tee(&w, report.Only("debug", console)), config.NewRedactor("SEKRET"))
	tee.Emit(ev("found", map[string]any{"category": "host", "value": "a"}))
	tee.Emit(ev("warning", map[string]any{"message": "w"}))
	tee.Emit(ev("debug", map[string]any{"message": "asn job k failed: key=SEKRET"}))
	if got := w.List(); len(got) != 1 || got[0] != "w" {
		t.Errorf("warnings = %q, want the one warning", got)
	}
	if want := "12:00:00 | DEBUG | asn job k failed: key=****\n"; logb.String() != want {
		t.Errorf("stderr = %q, want only the redacted DEBUG line %q", logb.String(), want)
	}
}

// Palette sheets include all entries and formatter examples while preserving plain output.
func TestSheet(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		var buf bytes.Buffer
		report.Sheet(&buf, layout.Stream{Depth: d}, clk().In(time.UTC))
		out := buf.String()
		plainOut := stripEscapes(out)
		checkSheetEntries(t, d, plainOut)
		checkSheetLevels(t, d, plainOut)
		indent := map[palette.Depth]int{palette.None: 19, palette.TrueColor: 21}[d]
		if !strings.Contains(plainOut, "\n"+strings.Repeat(" ", indent)+"continued") {
			t.Errorf("depth %d: no continuation line indented %d:\n%s", d, indent, plainOut)
		}
		if (d == palette.None) == strings.Contains(out, "\x1b") {
			t.Errorf("depth %d: escapes = %v", d, strings.Contains(out, "\x1b"))
		}
		if strings.Contains(plainOut, "layout") {
			t.Errorf("depth %d: a sheet off a terminal has the added parts:\n%s", d, plainOut)
		}
	}
}

// checkSheetEntries checks that the sheet, without escapes, has every label of every category
// and every name of every group.
func checkSheetEntries(t *testing.T, d palette.Depth, plainOut string) {
	t.Helper()
	for _, c := range palette.Categories() {
		for _, l := range palette.Labels(c) {
			if !strings.Contains(plainOut, l) {
				t.Errorf("depth %d: sheet lacks %s %s", d, c, l)
			}
		}
	}
	for _, g := range palette.Groups() {
		for _, n := range palette.Names(g) {
			if !strings.Contains(plainOut, n) {
				t.Errorf("depth %d: sheet lacks %s %s", d, g, n)
			}
		}
	}
}

// checkSheetLevels checks that the sheet, without escapes, has a sample line for each level.
func checkSheetLevels(t *testing.T, d palette.Depth, plainOut string) {
	t.Helper()
	for _, l := range []string{"DEBUG", "INFO", "WARN", "ERROR", "CRIT"} {
		found := false
		for line := range strings.SplitSeq(plainOut, "\n") {
			if strings.HasPrefix(line, "12:00:00 ") && strings.Contains(line, l) {
				found = true
			}
		}
		if !found {
			t.Errorf("depth %d: no sample %s line", d, l)
		}
	}
}
