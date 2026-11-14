package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/report"
)

var (
	clk  = func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) }
	noon = clk()
)

// harness is a console over two buffers.
type cons struct {
	*report.Console
	log, sum bytes.Buffer
}

func newCons(logDepth, sumDepth palette.Depth, min report.Level) *cons {
	c := &cons{}
	c.Console = report.NewConsole(report.ConsoleOptions{
		Log: &c.log, LogDepth: logDepth, Summary: &c.sum, SummaryDepth: sumDepth,
		Min: min, Clock: clk, Location: time.UTC,
	})
	return c
}

func plain(min report.Level) *cons { return newCons(palette.None, palette.None, min) }

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

// JSON mode is one object per line, unstyled, with type and RFC 3339 time. A
// debug event is not part of the stream.
func TestJSONRenderer(t *testing.T) {
	var buf bytes.Buffer
	em := report.NewJSON(&buf, clk)
	em.Emit(ev("found", map[string]any{"category": "host", "value": "a.example.com\x1b[31m"}))
	em.Emit(ev("debug", map[string]any{"message": "asn check x failed: boom"}))
	em.Emit(ev("count", map[string]any{"category": "host", "n": 1}))
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		if m["type"] == nil || m["type"] == "debug" {
			t.Errorf("type: %q", l)
		}
		if _, err := time.Parse(time.RFC3339, m["time"].(string)); err != nil {
			t.Errorf("time: %v", err)
		}
	}
	if strings.Contains(buf.String(), "\x1b") {
		t.Error("escape in JSON output")
	}
}

// A plain line is HH:MM:SS | LEVEL | message with the level padded to 5, so
// the message follows the first 19 characters, for every level.
func TestLinePlain(t *testing.T) {
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
		got := report.Line(palette.None, noon, c.l, "hello")
		if got != c.want || got[19:] != "hello" {
			t.Errorf("level %d: %q, want %q", c.l, got, c.want)
		}
	}
}

// A coloured line is byte for byte the example in the palette document, and its
// message follows the first 21 cells.
func TestLineColoured(t *testing.T) {
	at := time.Date(2026, 11, 1, 14, 2, 8, 0, time.UTC)
	want := "\x1b[38;2;124;129;145m14:02:08\x1b[0m\x1b[38;2;74;79;92m │ \x1b[0m" +
		"\x1b[38;2;236;208;143;48;2;61;52;32m WARN  \x1b[0m\x1b[38;2;74;79;92m │ \x1b[0mrate limited, retrying in 2s"
	if got := report.Line(palette.TrueColor, at, report.Warn, "rate limited, retrying in 2s"); got != want {
		t.Errorf("coloured line\n got %q\nwant %q", got, want)
	}
	for _, d := range []palette.Depth{palette.TrueColor, palette.Color256, palette.Color16} {
		for _, l := range []report.Level{report.Debug, report.Info, report.Warn, report.Error, report.Crit} {
			cells := []rune(stripEscapes(report.Line(d, noon, l, "msg")))
			if string(cells[21:]) != "msg" || cells[9] != '│' {
				t.Errorf("depth %d level %d: %q", d, l, string(cells))
			}
		}
	}
}

// The second and later lines of a message are indented to the message column,
// with no timestamp or level.
func TestLineContinuation(t *testing.T) {
	got := report.Line(palette.None, noon, report.Error, "request failed\nTraceback\n  File x")
	want := "12:00:00 | ERROR | request failed\n" + strings.Repeat(" ", 19) + "Traceback\n" + strings.Repeat(" ", 19) + "  File x"
	if got != want {
		t.Errorf("plain\n got %q\nwant %q", got, want)
	}
	col := strings.Split(report.Line(palette.TrueColor, noon, report.Error, "a\nb"), "\n")
	if len(col) != 2 || col[1] != strings.Repeat(" ", 21)+"b" {
		t.Errorf("coloured continuation = %q", col)
	}
}

// The log is on one stream and the summary on the other.
func TestConsoleStreams(t *testing.T) {
	c := plain(report.Info)
	c.Emit(ev("run_start", map[string]any{"engagement": "eng", "scope": "1 roots, 0 orgs, 0 asns, 0 cidrs, 0 exclusions"}))
	c.Emit(ev("stage", map[string]any{"name": "asn", "state": "running"}))
	c.Emit(ev("found", map[string]any{"category": "host", "value": "a.example.com"}))
	c.Emit(ev("count", map[string]any{"category": "hosts", "n": 1}))
	c.Emit(ev("warning", map[string]any{"message": "careful"}))
	c.Emit(ev("candidate", map[string]any{"value": "x.org"}))
	c.Emit(ev("run_end", map[string]any{"exit_code": 0}))
	c.Emit(ev("nonsense", nil))
	if c.sum.Len() != 0 {
		t.Errorf("summary stream before the summary: %q", c.sum.String())
	}
	if n := strings.Count(c.log.String(), "\n"); n != 5 {
		t.Errorf("%d log lines, want 5 (candidate, run_end and unknown types print nothing):\n%s", n, c.log.String())
	}
	c.Emit(ev("summary", map[string]any{"totals": map[string]int{"hosts": 1}}))
	if !strings.HasPrefix(c.sum.String(), "Summary\n") || strings.Contains(c.log.String(), "Summary") {
		t.Errorf("the summary belongs on the summary stream:\nsummary: %q\nlog: %q", c.sum.String(), c.log.String())
	}
}

// Events map to levels; the minimum level drops lower ones, but never the
// summary or the error line.
func TestConsoleLevels(t *testing.T) {
	events := []report.Event{
		ev("run_start", map[string]any{"engagement": "eng"}),
		ev("stage", map[string]any{"name": "asn", "state": "done", "checks": 2, "failed": 0}),
		ev("stage", map[string]any{"name": "dns", "state": "failed", "checks": 2, "failed": 2}),
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
		for _, l := range strings.Split(strings.TrimSpace(c.log.String()), "\n") {
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
	c := plain(report.Warn)
	c.Emit(ev("summary", map[string]any{"totals": map[string]int{"hosts": 1}}))
	c.Emit(ev("error", map[string]any{"message": "bad"}))
	if c.sum.Len() == 0 || c.log.String() != "error: bad\n" {
		t.Errorf("quiet still writes the summary and the error: summary %q, log %q", c.sum.String(), c.log.String())
	}
}

// Header, stage and count messages keep their text, with no colour in them.
func TestConsoleMessageText(t *testing.T) {
	c := plain(report.Info)
	c.Emit(ev("run_start", map[string]any{"engagement": "eng", "scope": "1 roots", "passive": true, "authorised": true}))
	c.Emit(ev("stage", map[string]any{"name": "ports", "state": "not-configured", "reason": "passive-only"}))
	c.Emit(ev("stage", map[string]any{"name": "asn", "state": "done", "checks": 3, "failed": 1}))
	c.Emit(ev("stage", map[string]any{"name": "dns", "state": "running"}))
	c.Emit(ev("count", map[string]any{"category": "hosts", "n": 12}))
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(c.log.String()), "\n") {
		got = append(got, l[19:])
	}
	want := []string{
		"nyx eng  1 roots  [passive-only]  [authorised]",
		"ports          not-configured (passive-only)",
		"asn            done (3 checks, 1 failed)",
		"dns            running",
		"  hosts: 12",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("messages\n got %q\nwant %q", got, want)
	}

	// On a coloured stream the only escapes are the chrome and the level badge.
	col := newCons(palette.TrueColor, palette.None, report.Info)
	col.Emit(ev("run_start", map[string]any{"engagement": "eng", "scope": "1 roots", "passive": true, "authorised": true}))
	col.Emit(ev("stage", map[string]any{"name": "asn", "state": "done", "checks": 3, "failed": 1}))
	col.Emit(ev("count", map[string]any{"category": "hosts", "n": 12}))
	for _, l := range strings.Split(strings.TrimSpace(col.log.String()), "\n") {
		prefix := l[:strings.LastIndex(l, "│ \x1b[0m")+len("│ \x1b[0m")]
		if rest := l[len(prefix):]; strings.Contains(rest, "\x1b") {
			t.Errorf("an escape inside the message: %q", l)
		}
	}
}

// A found line carries the severity badge after the +; its suffix is gone.
func TestConsoleFoundLines(t *testing.T) {
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

	col := newCons(palette.TrueColor, palette.None, report.Info)
	want := report.Line(palette.TrueColor, noon, report.Info, "+ "+palette.TrueColor.Value(palette.Severity, "high")+" finding: x")
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

// The error line has no timestamp or level, and on a coloured stream only its
// prefix is styled.
func TestConsoleErrorLine(t *testing.T) {
	p := plain(report.Info)
	p.Emit(ev("error", map[string]any{"message": "no inputs\x1b[2J", "exit_code": 2}))
	if got := p.log.String(); got != "error: no inputs\n" || p.sum.Len() != 0 {
		t.Errorf("plain error: log %q, summary %q", got, p.sum.String())
	}
	c := newCons(palette.TrueColor, palette.None, report.Info)
	c.Emit(ev("error", map[string]any{"message": "no inputs"}))
	if want := "\x1b[38;2;240;138;146merror:\x1b[0m no inputs\n"; c.log.String() != want {
		t.Errorf("coloured error = %q, want %q", c.log.String(), want)
	}
}

// Target-supplied escapes, titles, newlines and bidi controls never reach
// either stream, and a long message stays on one line.
func TestConsoleSanitises(t *testing.T) {
	evil := "x\x1b[2J\x1b]0;pwn\x07y\u202ez\nnext\r"
	long := strings.Repeat("a", 500)
	events := []report.Event{
		ev("found", map[string]any{"category": "finding", "value": evil, "severity": "high"}),
		ev("warning", map[string]any{"message": evil}),
		ev("debug", map[string]any{"message": evil}),
		ev("error", map[string]any{"message": evil}),
		ev("stage", map[string]any{"name": evil, "state": "done", "reason": evil}),
		ev("warning", map[string]any{"message": long}),
		ev("summary", map[string]any{"findings": []map[string]any{{"category": evil, "severity": "high", "target": evil, "detail": evil}},
			"totals": map[string]int{evil: 1}}),
	}
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		c := newCons(d, d, report.Debug)
		for _, e := range events {
			c.Emit(e)
		}
		// Drop the escapes this package writes itself, then nothing is left.
		for _, s := range []string{c.log.String(), c.sum.String()} {
			rest := stripEscapes(s)
			for _, bad := range []string{"\x1b", "\x07", "\u202e", "\r", "[2J", "]0;pwn"} {
				if strings.Contains(rest, bad) {
					t.Errorf("depth %d: %q reached the output:\n%q", d, bad, rest)
				}
			}
		}
		if n := strings.Count(c.log.String(), "\n"); n != 6 {
			t.Errorf("depth %d: %d log lines for 6 events: %q", d, n, c.log.String())
		}
		for _, l := range strings.Split(c.log.String(), "\n") {
			if strings.Contains(l, long) && utf8.RuneCountInString(stripEscapes(l)) != 21+500 && utf8.RuneCountInString(stripEscapes(l)) != 19+500 {
				t.Errorf("a long message was wrapped or cut: %d cells", utf8.RuneCountInString(stripEscapes(l)))
			}
		}
	}
	// A message is sanitised before it is split, so an event never makes more
	// than one line.
	c := plain(report.Info)
	c.Emit(ev("warning", map[string]any{"message": "one\ntwo"}))
	if n := strings.Count(c.log.String(), "\n"); n != 1 {
		t.Errorf("one event, one line: %q", c.log.String())
	}
}

// The summary lists totals, failed counts and each high/medium finding with its
// badge; headings are bold only on a coloured stream.
func TestConsoleSummary(t *testing.T) {
	fields := map[string]any{
		"totals": map[string]int{"hosts": 12, "open ports": 5, "urls": 340},
		"failed": map[string]int{"asn": 2},
		"findings": []map[string]any{
			{"category": "exposed-admin", "severity": "high", "target": "https://a.example.com/admin", "detail": "login page"},
			{"category": "banner", "severity": "medium", "target": "10.0.0.1:21", "detail": "ftp"},
		},
	}
	p := plain(report.Warn)
	p.Emit(ev("summary", fields))
	out := p.sum.String()
	for _, w := range []string{
		"Summary\n", "  hosts            12", "  open ports       5", "  urls             340",
		"Failed checks (retried on the next run; --debug shows each failure)\n  asn              2",
		"Findings (high and medium)\n  high     exposed-admin https://a.example.com/admin - login page\n  medium   banner 10.0.0.1:21 - ftp",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
	if strings.Contains(out, "[high]") || strings.Contains(out, "\x1b") || p.log.Len() != 0 {
		t.Errorf("plain summary:\n%q\nlog %q", out, p.log.String())
	}

	c := newCons(palette.None, palette.TrueColor, report.Info)
	c.Emit(ev("summary", fields))
	out = c.sum.String()
	for _, w := range []string{
		"\x1b[1mSummary\x1b[0m\n", "\x1b[1mFailed checks (retried on the next run; --debug shows each failure)\x1b[0m\n",
		"\x1b[1mFindings (high and medium)\x1b[0m\n",
		"  " + palette.TrueColor.Value(palette.Severity, "high") + " exposed-admin",
		"  " + palette.TrueColor.Value(palette.Severity, "medium") + " banner",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%q", w, out)
		}
	}
	// Nothing else is styled: removing the headings and badges leaves no escape.
	rest := out
	for _, s := range []string{palette.TrueColor.Value(palette.Severity, "high"), palette.TrueColor.Value(palette.Severity, "medium"), "\x1b[1m", "\x1b[0m"} {
		rest = strings.ReplaceAll(rest, s, "")
	}
	if strings.Contains(rest, "\x1b") {
		t.Errorf("something besides headings and badges is styled: %q", rest)
	}
}

// The summary lists the high candidates with the input that promotes each, at
// most 20 of them and then how many more candidates.csv holds. There is no
// list of medium candidates.
func TestConsoleSummaryCandidates(t *testing.T) {
	cand := func(kind, value, promote string, n int) map[string]any {
		return map[string]any{"kind": kind, "value": value, "sources": "crtsh;whoisxml", "evidence_count": n, "confidence": "high", "promote": promote}
	}
	var high []map[string]any
	for i := 0; i < 22; i++ {
		v := string(rune('a'+i)) + ".org"
		high = append(high, cand("root", v, v, 2))
	}
	high[0] = cand("netblock", "198.51.100.0/24", "--cidr 198.51.100.0/24", 3)
	summary := func(f map[string]any) string {
		c := plain(report.Info)
		c.Emit(ev("summary", f))
		return c.sum.String()
	}

	out := summary(map[string]any{"totals": map[string]int{"hosts": 1}, "candidates": high})
	if !strings.Contains(out, "promote: --cidr 198.51.100.0/24") || !strings.Contains(out, "promote: t.org") {
		t.Errorf("the first 20 are listed with their promoting input:\n%s", out)
	}
	if strings.Contains(out, "u.org") || strings.Contains(out, "v.org") {
		t.Errorf("only 20 are listed:\n%s", out)
	}
	if !strings.Contains(out, "and 2 more in candidates.csv") {
		t.Errorf("missing the overflow line:\n%s", out)
	}
	if out := summary(map[string]any{"totals": map[string]int{"hosts": 1}}); strings.Contains(out, "andidates") {
		t.Errorf("a run with no ranked candidates prints no candidate block:\n%s", out)
	}
}

// The redactor wrapper scrubs every string in an event, including nested ones.
func TestRedactingEmitter(t *testing.T) {
	var buf bytes.Buffer
	em := report.WithRedactor(report.NewJSON(&buf, clk), config.NewRedactor("SEKRET"))
	em.Emit(ev("warning", map[string]any{"message": "GET /?k=SEKRET failed", "extra": []map[string]any{{"x": "SEKRET"}}}))
	if strings.Contains(buf.String(), "SEKRET") {
		t.Errorf("leaked: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "****") {
		t.Errorf("expected mask: %s", buf.String())
	}
}

// Only passes one event type, the JSON stream drops debug events, and Tee
// sends each event to both emitters.
func TestOnlyAndTee(t *testing.T) {
	var js, logb, sum bytes.Buffer
	console := report.NewConsole(report.ConsoleOptions{Log: &logb, Summary: &sum, Min: report.Debug, Clock: clk, Location: time.UTC})
	tee := report.WithRedactor(report.Tee(report.NewJSON(&js, clk), report.Only("debug", console)), config.NewRedactor("SEKRET"))
	tee.Emit(ev("found", map[string]any{"category": "host", "value": "a"}))
	tee.Emit(ev("warning", map[string]any{"message": "w"}))
	tee.Emit(ev("debug", map[string]any{"message": "asn check k failed: key=SEKRET"}))
	tee.Emit(ev("summary", map[string]any{"totals": map[string]int{"hosts": 1}}))
	tee.Emit(ev("error", map[string]any{"message": "bad"}))
	if got := strings.Count(js.String(), "\n"); got != 4 {
		t.Errorf("JSON got %d events, want 4 (not the debug one):\n%s", got, js.String())
	}
	if want := "12:00:00 | DEBUG | asn check k failed: key=****\n"; logb.String() != want {
		t.Errorf("stderr = %q, want only the redacted DEBUG line %q", logb.String(), want)
	}
	if sum.Len() != 0 {
		t.Errorf("no summary on the debug console: %q", sum.String())
	}
}

// The palette sheet has every entry of every table, a line per level and a
// continuation line, through the formatter.
func TestSheet(t *testing.T) {
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		var buf bytes.Buffer
		report.Sheet(&buf, d, clk().In(time.UTC))
		out := buf.String()
		plainOut := stripEscapes(out)
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
		indent := map[palette.Depth]int{palette.None: 19, palette.TrueColor: 21}[d]
		for _, l := range []string{"DEBUG", "INFO", "WARN", "ERROR", "CRIT"} {
			found := false
			for _, line := range strings.Split(plainOut, "\n") {
				if strings.HasPrefix(line, "12:00:00 ") && strings.Contains(line, l) {
					found = true
				}
			}
			if !found {
				t.Errorf("depth %d: no sample %s line", d, l)
			}
		}
		if !strings.Contains(plainOut, "\n"+strings.Repeat(" ", indent)+"continued") {
			t.Errorf("depth %d: no continuation line indented %d:\n%s", d, indent, plainOut)
		}
		if (d == palette.None) == strings.Contains(out, "\x1b") {
			t.Errorf("depth %d: escapes = %v", d, strings.Contains(out, "\x1b"))
		}
	}
}
