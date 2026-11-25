// Package report formats progress events, final human summaries and JSON envelopes.
package report

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/palette"
	"github.com/rafaelh/nyx/internal/term/sanitize"
)

// Event drives console progress: run_start, procedure, found, count, warning and debug. Summary
// output is separate. Debug events include failed-job details.
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

// WithRedactor cleans every event string before forwarding it.
func WithRedactor(next Emitter, r *config.Redactor) Emitter { return redacting{next, r} }

func (e redacting) Emit(ev Event) {
	if ev.Fields != nil {
		ev.Fields = e.r.Any(ev.Fields).(map[string]any)
	}
	e.next.Emit(ev)
}

// Forward only the requested event type.
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

// Say adapts a formatted-message callback to an event type for warnings/debug output.
func Say(em Emitter, typ string) func(string) {
	return func(msg string) { em.Emit(Event{Type: typ, Fields: map[string]any{"message": msg}}) }
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

// Line formats already sanitised and redacted plain text with time and level. Plain streams
// preserve message lines, indenting continuations under the message. Terminals wrap after the
// prefix and align continuations at column 19, or 21 with colour. Use LineSpans for styled
// message text.
func Line(s layout.Stream, t time.Time, l Level, msg string) string {
	return LineSpans(s, t, l, layout.Plain(msg))
}

// LineSpans formats sanitised/redacted text with palette styles. Wrapping precedes styling so
// escapes cannot cross breaks. Non-terminal streams retain literal lines without wrapping.
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

// ConsoleOptions supplies output streams, filtering and redaction.
type ConsoleOptions struct {
	Log       io.Writer // the log lines (stderr)
	LogStream layout.Stream
	Min       Level // the lowest level of log line written
	Clock     func() time.Time
	Location  *time.Location // the time zone lines are shown in
	// Redactor masks configured keys after sanitisation, including keys whose characters
	// sanitisation rejoined. Nil disables masking.
	Redactor *config.Redactor
}

// Console prints events meeting Min level. Summary and final command errors are written
// separately by WriteSummary and cli.
type Console struct {
	mu sync.Mutex
	o  ConsoleOptions
}

// NewConsole defaults nil Clock/Location to time.Now/time.Local.
func NewConsole(o ConsoleOptions) *Console {
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Location == nil {
		o.Location = time.Local
	}
	return &Console{o: o}
}

// str sanitises an event field, then masks configured keys.
func (c *Console) str(f map[string]any, k string) string {
	return c.o.Redactor.Redact(str(f, k))
}

// str removes terminal controls from an event field.
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

// Emit maps run_start/found/count to INFO, procedure failures to ERROR, other procedures to INFO,
// warnings to WARN and debug to DEBUG. Unknown types are ignored.
func (c *Console) Emit(ev Event) {
	level, ok := eventLevel(ev)
	if !ok || level < c.o.Min {
		return // defer formatting until after event filtering
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintln(c.o.Log, LineSpans(c.o.LogStream, c.o.Clock().In(c.o.Location), level, c.message(ev)))
}

// eventLevel returns display severity and whether the event has a log line.
func eventLevel(ev Event) (level Level, ok bool) {
	switch ev.Type {
	case "run_start", "found", "count":
		return Info, true
	case "procedure":
		if str(ev.Fields, "state") == "failed" {
			return Error, true
		}
		return Info, true
	case "warning":
		return Warn, true
	case "debug":
		return Debug, true
	}
	return 0, false
}

// textStyle resolves a palette role for message text only on coloured terminals.
func textStyle(s layout.Stream, name string) func(string) string {
	if !s.Terminal || !s.Coloured() {
		return nil
	}
	return func(x string) string { return s.Depth.Text(palette.Semantic, name, x) }
}

// stateStyle maps running to info, completion to success, failure to error and unconfigured to
// muted.
func stateStyle(s layout.Stream, state string) func(string) string {
	switch state {
	case "running":
		return textStyle(s, "info")
	case "done", "done-previously":
		return textStyle(s, "success")
	case "failed":
		return textStyle(s, "error")
	case "not-configured":
		return textStyle(s, "muted")
	}
	return nil
}

// badgeSpan keeps a padded palette value whole during wrapping, including its coloured side
// margins.
func badgeSpan(s layout.Stream, c palette.Category, value string) layout.Span {
	return layout.Span{Text: value, Style: func(x string) string { return s.Depth.Value(c, x) }, Keep: true}
}

// procedureSpans keeps the padded procedure name whole, colours its state on terminals and leaves
// reason/counts plain.
func procedureSpans(s layout.Stream, name, state, reason, jobs, failed string) []layout.Span {
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
		rest += fmt.Sprintf(" (%s jobs, %s failed)", jobs, failed)
	}
	if rest != "" {
		spans = append(spans, layout.Span{Text: rest})
	}
	return spans
}

// foundSpans combines the success "+", optional severity badge and custom text or
// category/value pair. Categories use the info colour.
func foundSpans(s layout.Stream, category, value, text, severity string) []layout.Span {
	spans := []layout.Span{{Text: "+", Style: textStyle(s, "success")}, {Text: " "}}
	if severity != "" {
		spans = append(spans, badgeSpan(s, palette.Severity, severity), layout.Span{Text: " "})
	}
	if text != "" {
		return append(spans, layout.Span{Text: text})
	}
	return append(spans, layout.Span{Text: category, Style: textStyle(s, "info")}, layout.Span{Text: ": " + value})
}

// message extracts display text for an event recognised by eventLevel.
func (c *Console) message(ev Event) (msg []layout.Span) {
	s, str, f := c.o.LogStream, c.str, ev.Fields
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
	case "procedure":
		msg = procedureSpans(s, str(f, "name"), str(f, "state"), str(f, "reason"), str(f, "jobs"), str(f, "failed"))
	case "found":
		msg = foundSpans(s, str(f, "category"), str(f, "value"), str(f, "text"), str(f, "severity"))
	case "count":
		msg = layout.Plain(fmt.Sprintf("  %s: %s", str(f, "category"), str(f, "n")))
	case "warning", "debug":
		msg = layout.Plain(str(f, "message"))
	}
	return msg
}
