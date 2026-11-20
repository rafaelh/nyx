// Package report turns run events into console lines, and a finished run into the human summary
// or the --json envelope.
package report

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// Event is one thing that happened in a run. Types: run_start, stage, found, count, warning, hint
// and debug. They drive the console log; the result of the run is the Summary, not an event. A
// debug event is one failed check. A hint is a note on how to get more from the command.
type Event struct {
	Type   string
	Fields map[string]any
}

// Emitter receives events. Implementations are safe for concurrent use.
type Emitter interface{ Emit(Event) }

type redacting struct {
	next Emitter
	r    *config.Redactor
}

// WithRedactor scrubs every string in each event before it reaches next.
func WithRedactor(next Emitter, r *config.Redactor) Emitter { return redacting{next, r} }

func (e redacting) Emit(ev Event) {
	if ev.Fields != nil {
		ev.Fields = e.r.Any(ev.Fields).(map[string]any)
	}
	e.next.Emit(ev)
}

// Only passes the events of one type to next and drops the rest.
func Only(typ string, next Emitter) Emitter { return only{typ, next} }

type only struct {
	typ  string
	next Emitter
}

func (f only) Emit(ev Event) {
	if ev.Type == f.typ {
		f.next.Emit(ev)
	}
}

// Tee sends every event to both emitters.
func Tee(a, b Emitter) Emitter { return tee{a, b} }

type tee struct{ a, b Emitter }

func (t tee) Emit(ev Event) { t.a.Emit(ev); t.b.Emit(ev) }

// Level is a log line's severity.
type Level int

// The levels a log line can have, lowest first.
const (
	Debug Level = iota
	Info
	Warn
	Error
	Crit
)

// Label is the level's name in a log line.
func (l Level) Label() string {
	if l < Debug || l > Crit {
		return ""
	}
	return levelLabels[l]
}

var levelLabels = palette.Labels(palette.Level)

// Line formats one log line from the time t as it is to be shown, from a message of plain text.
// Nothing here sanitises or redacts, so a caller does both first.
//
// A plain line is "HH:MM:SS | LEVEL | message"; a coloured one has the timestamp and separators in
// the palette's chrome colours and a level badge. On a stream that is not a terminal the message is
// written literally: it is not wrapped, and each line after its first is indented to the message
// column. On a terminal the message is wrapped to the stream's width, after the prefix, and each
// continuation line starts at the message column, 19 cells in a plain line and 21 in a coloured
// one. The message of a terminal line holds no escape of its own: LineSpans styles one.
func Line(s layout.Stream, t time.Time, l Level, msg string) string {
	return LineSpans(s, t, l, layout.Plain(msg))
}

// LineSpans is Line for a message in styled parts. The text of each span is plain, sanitised and
// redacted; the styles come from the palette. A line is broken first and styled afterwards, so
// every escape byte of the message comes from a style and none crosses a line break. On a stream
// that is not a terminal the message is its text with the styles applied and nothing is wrapped.
func LineSpans(s layout.Stream, t time.Time, l Level, msg []layout.Span) string {
	d := s.Depth
	sep := " | "
	if d != palette.None {
		sep = d.Text(palette.Chrome, "SEPARATOR", " │ ")
	}
	prefix := d.Text(palette.Chrome, "TIMESTAMP", t.Format("15:04:05")) + sep + d.Badge(palette.Level, l.Label()) + sep
	width, mode := 0, layout.None // off a terminal, the message is broken only at its own newlines
	if s.Terminal {
		width, mode = s.Cols(), layout.Spaces
	}
	return strings.Join(layout.Hang(prefix, msg, width, mode), "\n")
}

// ConsoleOptions are what NewConsole needs.
type ConsoleOptions struct {
	Log       io.Writer // the log lines (stderr)
	LogStream layout.Stream
	Min       Level // the lowest level of log line written
	Clock     func() time.Time
	Location  *time.Location // the time zone lines are shown in
	// Redactor masks the configured keys in the text of each event, after it has been sanitised,
	// so that a key which sanitising joins back together is masked too. Nil masks nothing.
	Redactor *config.Redactor
}

// Console renders events as log lines. Each event has a level (see Emit) and
// is written only when it reaches Min. The end-of-run summary is not an event
// (WriteSummary writes it), nor is the error that ends a failed command (cli
// writes it).
type Console struct {
	mu sync.Mutex
	o  ConsoleOptions
}

// NewConsole returns the console renderer. A nil Clock is time.Now and a nil
// Location is time.Local.
func NewConsole(o ConsoleOptions) *Console {
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Location == nil {
		o.Location = time.Local
	}
	return &Console{o: o}
}

// str is the text of a field as a line shows it: sanitised, then with any configured key masked.
func (c *Console) str(f map[string]any, k string) string {
	return c.o.Redactor.Redact(str(f, k))
}

// str is the text of a field with whatever could act on a terminal removed.
func str(f map[string]any, k string) string {
	switch v := f[k].(type) {
	case nil:
		return ""
	case string:
		return sanitize.Text(v)
	default:
		return sanitize.Text(fmt.Sprint(v))
	}
}

// Emit renders one event. run_start, found, count and hint are INFO; stage is INFO,
// or ERROR when its state is failed; warning is WARN and debug is DEBUG.
// Unknown types print nothing.
func (c *Console) Emit(ev Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	level, msg, ok := c.message(ev)
	if !ok || level < c.o.Min {
		return
	}
	fmt.Fprintln(c.o.Log, LineSpans(c.o.LogStream, c.o.Clock().In(c.o.Location), level, msg))
}

// textStyle is the style of a semantic or chrome entry for the text of a line, or none when the
// stream does not colour text: the message of a line is coloured beyond its badges only on a
// terminal at a colour depth.
func textStyle(s layout.Stream, g palette.Group, name string) func(string) string {
	if !s.Terminal || !s.Coloured() {
		return nil
	}
	return func(x string) string { return s.Depth.Text(g, name, x) }
}

// stateStyle is the style of a stage's state word: running is info, done and done-previously are
// success, failed is error and not-configured takes the timestamp colour.
func stateStyle(s layout.Stream, state string) func(string) string {
	switch state {
	case "running":
		return textStyle(s, palette.Semantic, "info")
	case "done", "done-previously":
		return textStyle(s, palette.Semantic, "success")
	case "failed":
		return textStyle(s, palette.Semantic, "error")
	case "not-configured":
		return textStyle(s, palette.Chrome, "TIMESTAMP")
	}
	return nil
}

// badgeSpan is a value as palette's Value writes it in category c (padded to the category's width,
// and with a space either side when coloured): one token that is never broken.
func badgeSpan(s layout.Stream, c palette.Category, value string) layout.Span {
	return layout.Span{Text: value, Style: func(x string) string { return s.Depth.Value(c, x) }, Keep: true}
}

// stageSpans is the message of a stage line. The name is padded and kept whole, the state word is
// coloured on a coloured terminal and the reason and counts are plain.
func stageSpans(s layout.Stream, name, state, reason, checks, failed string) []layout.Span {
	spans := []layout.Span{
		{Text: fmt.Sprintf("%-14s", name), Keep: true},
		{Text: " "},
		{Text: state, Style: stateStyle(s, state)},
	}
	rest := ""
	if reason != "" {
		rest += " (" + reason + ")"
	}
	if state == "done" {
		rest += fmt.Sprintf(" (%s checks, %s failed)", checks, failed)
	}
	if rest != "" {
		spans = append(spans, layout.Span{Text: rest})
	}
	return spans
}

// foundSpans is the message of a found line: the + in the success colour, the severity badge when
// there is one and then either the event's own text or category: value, with the category in the
// info colour.
func foundSpans(s layout.Stream, category, value, text, severity string) []layout.Span {
	spans := []layout.Span{{Text: "+", Style: textStyle(s, palette.Semantic, "success")}, {Text: " "}}
	if severity != "" {
		spans = append(spans, badgeSpan(s, palette.Severity, severity), layout.Span{Text: " "})
	}
	if text != "" {
		return append(spans, layout.Span{Text: text})
	}
	return append(spans, layout.Span{Text: category, Style: textStyle(s, palette.Semantic, "info")}, layout.Span{Text: ": " + value})
}

// message is the level and message of an event's line. ok is false for an event type with no line.
func (c *Console) message(ev Event) (level Level, msg []layout.Span, ok bool) {
	s, str, f := c.o.LogStream, c.str, ev.Fields
	level = Info
	switch ev.Type {
	case "run_start":
		m := "nyx " + str(f, "engagement")
		if sc := str(f, "scope"); sc != "" {
			m += "  " + sc
		}
		if p, _ := f["passive"].(bool); p {
			m += "  [passive-only]"
		}
		if a, _ := f["authorised"].(bool); a {
			m += "  [authorised]"
		}
		msg = layout.Plain(m)
	case "stage":
		state := str(f, "state")
		if state == "failed" {
			level = Error
		}
		msg = stageSpans(s, str(f, "name"), state, str(f, "reason"), str(f, "checks"), str(f, "failed"))
	case "found":
		msg = foundSpans(s, str(f, "category"), str(f, "value"), str(f, "text"), str(f, "severity"))
	case "count":
		msg = layout.Plain(fmt.Sprintf("  %s: %s", str(f, "category"), str(f, "n")))
	case "hint":
		msg = layout.Plain(str(f, "message"))
	case "warning":
		level, msg = Warn, layout.Plain(str(f, "message"))
	case "debug":
		level, msg = Debug, layout.Plain(str(f, "message"))
	default:
		return 0, nil, false
	}
	return level, msg, true
}
