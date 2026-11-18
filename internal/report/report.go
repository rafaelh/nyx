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
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// Event is one thing that happened in a run. Types: run_start, stage, found, count, warning and
// debug. They drive the console log; the result of the run is the Summary, not an event. A debug
// event is one failed check.
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

// Line formats one log line from the time t as it is to be shown. The message
// is written literally: it is not wrapped, and each line after its first is
// indented to the message column. Nothing here sanitises or redacts, so a
// caller does both first.
//
// A plain line is "HH:MM:SS | LEVEL | message"; a coloured one has the
// timestamp and separators in the palette's chrome colours and a level badge.
func Line(d palette.Depth, t time.Time, l Level, msg string) string {
	sep, badge := " | ", palette.Width(palette.Level)
	if d != palette.None {
		sep, badge = d.Text(palette.Chrome, "SEPARATOR", " │ "), badge+2 // a coloured badge has a space each side
	}
	ts := t.Format("15:04:05")
	prefix := d.Text(palette.Chrome, "TIMESTAMP", ts) + sep + d.Badge(palette.Level, l.Label()) + sep
	indent := len(ts) + badge + 2*len(" | ") // each separator is three cells
	return prefix + strings.ReplaceAll(msg, "\n", "\n"+strings.Repeat(" ", indent))
}

// ConsoleOptions are what NewConsole needs.
type ConsoleOptions struct {
	Log      io.Writer // the log lines (stderr)
	LogDepth palette.Depth
	Min      Level // the lowest level of log line written
	Clock    func() time.Time
	Location *time.Location // the time zone lines are shown in
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

// Emit renders one event. run_start, found and count are INFO; stage is INFO,
// or ERROR when its state is failed; warning is WARN and debug is DEBUG.
// Unknown types print nothing.
func (c *Console) Emit(ev Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f := ev.Fields
	d := c.o.LogDepth
	level, msg := Info, ""
	switch ev.Type {
	case "run_start":
		msg = "nyx " + str(f, "engagement")
		if s := str(f, "scope"); s != "" {
			msg += "  " + s
		}
		if p, _ := f["passive"].(bool); p {
			msg += "  [passive-only]"
		}
		if a, _ := f["authorised"].(bool); a {
			msg += "  [authorised]"
		}
	case "stage":
		state := str(f, "state")
		if state == "failed" {
			level = Error
		}
		msg = fmt.Sprintf("%-14s %s", str(f, "name"), state)
		if r := str(f, "reason"); r != "" {
			msg += " (" + r + ")"
		}
		if state == "done" {
			msg += fmt.Sprintf(" (%s checks, %s failed)", str(f, "checks"), str(f, "failed"))
		}
	case "found":
		body := str(f, "category") + ": " + str(f, "value")
		if text := str(f, "text"); text != "" {
			body = text
		}
		msg = "+ "
		if sev := str(f, "severity"); sev != "" {
			msg += d.Value(palette.Severity, sev) + " "
		}
		msg += body
	case "count":
		msg = fmt.Sprintf("  %s: %s", str(f, "category"), str(f, "n"))
	case "warning":
		level, msg = Warn, str(f, "message")
	case "debug":
		level, msg = Debug, str(f, "message")
	default:
		return
	}
	if level < c.o.Min {
		return
	}
	fmt.Fprintln(c.o.Log, Line(d, c.o.Clock().In(c.o.Location), level, msg))
}
