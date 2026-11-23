package cli_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	_ "modernc.org/sqlite"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// harness drives cli.Execute in-process with fakes.
type harness struct {
	t                        *testing.T
	out                      string
	stages                   []run.Stage
	files                    []output.File  // nil means the default files
	signals                  chan os.Signal // nil means the run takes no signals
	stdoutTTY                bool
	stderrTTY                bool
	stdoutWidth, stderrWidth int // the terminal width each stream reports; 0 means none
	loc                      *time.Location
	eopts                    egress.Options
	now                      time.Time
	version                  string
	env                      map[string]string // the environment cli.Execute sees; see setenv
	file                     map[string]any    // what set has put in the default config file
	stdin                    io.Reader         // nil means an empty one
	stdinTTY                 bool              // whether stdin is a terminal, as nyx setup asks
	winW, winH               int               // the window size nyx setup draws in; 0 means none
	cwd                      string            // the working directory nyx reports; "" means the process's
	getwdPanicAfter          int               // when positive, the call of Getwd after this many panics, to force a panic in nyx setup
	getwdCalls               atomic.Int32
	// The threat data built into nyx for this test's runs (see builtInThreat): ipapi.is's lists
	// (abusive) and Spamhaus's (drop). When either is set, the other is empty, so a test sees only
	// the entries it gives; when neither is, the runs use the copies embedded in the binary.
	// threatBuiltIn, when set, is the whole built-in copy, and abusive and drop are ignored.
	abusive       *abusive.Snapshot
	drop          *spamhaus.Lists
	threatBuiltIn *threatdata.BuiltIn

	stdout, stderr bytes.Buffer
	rec            recorder // the events of the last call, as cli.Deps.Events delivers them

	dbMu sync.Mutex
	dbs  map[string]*sql.DB // state databases opened by openDB, by path

	// Network canaries: anything reaching them means a request was made.
	udpHits, httpHits, tcpHits atomic.Int32
}

func newHarness(t *testing.T, stages ...run.Stage) *harness {
	t.Helper()
	// The run sees only this environment, never the process's, so a developer's shell cannot
	// change a result and tests can run in parallel.
	cfgHome := t.TempDir()
	env := map[string]string{"TERM": "xterm", "XDG_CONFIG_HOME": cfgHome, "HOME": cfgHome}
	// A user who has set nyx up has a config file, so a run does not hint at nyx setup. A test of
	// that hint removes it.
	if err := os.MkdirAll(filepath.Join(cfgHome, "nyx"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgHome, "nyx", "config.yaml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, out: t.TempDir(), stages: stages, now: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC), loc: time.UTC, env: env}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			h.udpHits.Add(1)
		}
	}()
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.httpHits.Add(1) }))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.tcpHits.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { pc.Close(); hs.Close(); ln.Close() })
	h.eopts = egress.Options{
		ResolverAddrs:  []string{pc.LocalAddr().String()},
		DNSTimeout:     200 * time.Millisecond,
		ConnectTimeout: 300 * time.Millisecond,
		BannerWait:     50 * time.Millisecond,
		HTTPTimeout:    time.Second,
	}
	return h
}

func (h *harness) deps() cli.Deps {
	return cli.Deps{
		Stages:        h.stages,
		Files:         h.files,
		Egress:        h.eopts,
		Stdout:        &h.stdout,
		Stderr:        &h.stderr,
		StdoutIsTTY:   func() bool { return h.stdoutTTY },
		StderrIsTTY:   func() bool { return h.stderrTTY },
		StdoutWidth:   func() int { return h.stdoutWidth },
		StderrWidth:   func() int { return h.stderrWidth },
		Location:      h.loc,
		Clock:         func() time.Time { return h.now },
		Version:       h.version,
		Signals:       h.signals,
		Env:           h.environ(),
		NoFsync:       true,
		Events:        &h.rec,
		Stdin:         h.stdin,
		StdinIsTTY:    func() bool { return h.stdinTTY },
		WindowSize:    func() (int, int) { return h.winW, h.winH },
		Getwd:         h.getwd,
		ThreatBuiltIn: h.builtInThreat(),
	}
}

// builtInThreat is the built-in copy of the threat data the runs see, as the fields abusive, drop and
// threatBuiltIn describe; nil means the embedded copies. A list the test does not give is empty and
// dated the day before the clock, so it is neither stale nor newer than a test's downloaded copy
// dated after it.
func (h *harness) builtInThreat() *threatdata.BuiltIn {
	if h.threatBuiltIn != nil {
		return h.threatBuiltIn
	}
	if h.abusive == nil && h.drop == nil {
		return nil
	}
	day := h.now.Add(-24 * time.Hour)
	b := &threatdata.BuiltIn{Ipapi: *abSnapshotOn(day.Format(time.DateOnly), day.Format(time.DateOnly), nil, nil),
		Spamhaus: *dropListsAt(h.t, day, nil, nil)}
	if h.abusive != nil {
		b.Ipapi = *h.abusive
	}
	if h.drop != nil {
		b.Spamhaus = *h.drop
	}
	return b
}

func (h *harness) getwd() (string, error) {
	if n := h.getwdCalls.Add(1); h.getwdPanicAfter > 0 && int(n) > h.getwdPanicAfter {
		panic("forced panic in Getwd")
	}
	if h.cwd != "" {
		return h.cwd, nil
	}
	return os.Getwd()
}

// setenv sets a variable in the environment of the runs that follow. To nyx, "" is the same as
// unset.
func (h *harness) setenv(name, val string) { h.env[name] = val }

// set puts a setting, named by its dotted key (keys.shodan, archive.max_urls), in the default config
// file of the runs that follow, which it rewrites; nil removes it. It replaces whatever the file held.
func (h *harness) set(key string, val any) {
	h.t.Helper()
	if h.file == nil {
		h.file = map[string]any{}
	}
	parts := strings.Split(key, ".")
	m := h.file
	for _, p := range parts[:len(parts)-1] {
		next, ok := m[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[p] = next
		}
		m = next
	}
	if val == nil {
		delete(m, parts[len(parts)-1])
	} else {
		m[parts[len(parts)-1]] = val
	}
	data, err := yaml.Marshal(h.file)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(h.configFile(), data, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// setKey sets keys.<source> in the default config file, as set does; "" removes it.
func (h *harness) setKey(source, val string) {
	h.t.Helper()
	if val == "" {
		h.set("keys."+source, nil)
		return
	}
	h.set("keys."+source, val)
}

// configFile is the default config file of the runs that follow.
func (h *harness) configFile() string {
	return filepath.Join(h.env["XDG_CONFIG_HOME"], "nyx", "config.yaml")
}

func (h *harness) environ() []string {
	env := make([]string, 0, len(h.env))
	for k, v := range h.env {
		env = append(env, k+"="+v)
	}
	return env
}

// exec runs nyx recon with --output-dir pointing at the temp dir.
func (h *harness) exec(args ...string) int {
	return h.execCtx(context.Background(), args...)
}

func (h *harness) execCtx(ctx context.Context, args ...string) int {
	h.t.Helper()
	return h.execRootCtx(ctx, append([]string{"recon", "--output-dir", h.out}, args...)...)
}

// execRoot runs nyx with exactly args, for the tests of the command tree
// itself: no command and no --output-dir are added.
func (h *harness) execRoot(args ...string) int {
	h.t.Helper()
	return h.execRootCtx(context.Background(), args...)
}

func (h *harness) execRootCtx(ctx context.Context, args ...string) int {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	h.rec.reset()
	return cli.Execute(ctx, args, h.deps())
}

// failure is the one error a failed call writes to stderr, in either mode.
type failure struct {
	msg, code string
	hint      string // "" when there is none
	input     any    // nil when there is none
	transient bool
	targets   []string // in human mode, a partial result's "<input>: <message> (<CODE>)" lines
}

// humanErrorLine is the error line of human mode: "error: <message> (<CODE>)".
var humanErrorLine = regexp.MustCompile(`^error: (.*) \(([A-Z_]+)\)$`)

// failed asserts that the last call failed as the contract says: the exit
// code, an empty stdout, and exactly one error on stderr, which it returns. In
// human mode the error is the last lines of stderr, after any log lines; under
// --json (jsonMode) it is one compact line with exactly the five keys, in
// order, and the only thing on stderr besides DEBUG lines.
func (h *harness) failed(code, want int, jsonMode bool) failure {
	h.t.Helper()
	if code != want {
		h.t.Fatalf("exit %d, want %d\nstdout %q\nstderr %q", code, want, h.stdout.String(), h.stderr.String())
	}
	if h.stdout.Len() != 0 {
		h.t.Errorf("stdout is not empty on exit %d: %q", code, h.stdout.String())
	}
	return h.theError(jsonMode)
}

// theError is the one error on stderr (see failed), with no check of stdout.
func (h *harness) theError(jsonMode bool) failure {
	h.t.Helper()
	var lines []string
	for l := range strings.SplitSeq(strings.TrimRight(h.stderr.String(), "\n"), "\n") {
		if !logLayout.MatchString(l) {
			lines = append(lines, l)
		}
	}
	if !jsonMode {
		var f failure
		n := 0
		for _, l := range lines {
			switch {
			case strings.HasPrefix(l, "error: ") && n == 1 && f.code == "PARTIAL":
				// A partial result's per-target lines follow its error.
				if !humanErrorLine.MatchString(l) {
					h.t.Fatalf("target line %q is not \"error: <input>: <message> (<CODE>)\"", l)
				}
				f.targets = append(f.targets, strings.TrimPrefix(l, "error: "))
			case strings.HasPrefix(l, "error: "):
				n++
				m := humanErrorLine.FindStringSubmatch(l)
				if m == nil {
					h.t.Fatalf("error line %q is not \"error: <message> (<CODE>)\"", l)
				}
				f.msg, f.code = m[1], m[2]
			case strings.HasPrefix(l, "hint: ") && n == 1 && f.targets == nil:
				f.hint = strings.TrimPrefix(l, "hint: ")
			case l == "retry: may succeed after a wait" && n == 1 && f.targets == nil:
				f.transient = true
			default:
				h.t.Errorf("stderr holds a line that is not part of the error: %q", l)
			}
		}
		if n != 1 {
			h.t.Fatalf("stderr holds %d errors, want 1:\n%s", n, h.stderr.String())
		}
		return f
	}
	if len(lines) != 1 {
		h.t.Fatalf("stderr holds %d lines, want the one JSON error:\n%s", len(lines), h.stderr.String())
	}
	var e struct {
		Error     *string `json:"error"`
		Code      *string `json:"code"`
		Hint      *string `json:"hint"`
		Input     any     `json:"input"`
		Transient *bool   `json:"transient"`
	}
	dec := json.NewDecoder(strings.NewReader(lines[0]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil || e.Error == nil || e.Code == nil || e.Transient == nil {
		h.t.Fatalf("stderr is not the JSON error: %q (%v)", lines[0], err)
	}
	// Encoded again, the error is the same line only when it was compact and
	// held its keys once each, in the struct's order.
	var again bytes.Buffer
	enc := json.NewEncoder(&again)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil || strings.TrimSuffix(again.String(), "\n") != lines[0] {
		h.t.Errorf("JSON error is not compact with the keys error,code,hint,input,transient in order: %s", lines[0])
	}
	f := failure{msg: *e.Error, code: *e.Code, input: e.Input, transient: *e.Transient}
	if e.Hint != nil {
		f.hint = *e.Hint
	}
	return f
}

// inputOf is the list of failing values the error's input holds for name.
func (f failure) inputOf(name string) []string {
	m, _ := f.input.(map[string]any)
	list, _ := m[name].([]any)
	out := []string{}
	for _, v := range list {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

// hasInput reports whether the error's input names the argument at all.
func (f failure) hasInput(name string) bool {
	m, _ := f.input.(map[string]any)
	_, ok := m[name]
	return ok
}

// untouched fails if the call created anything under the output directory or
// reached a network canary.
func (h *harness) untouched() {
	h.t.Helper()
	if entries, _ := os.ReadDir(h.out); len(entries) != 0 {
		h.t.Errorf("the call created %d entries in the output directory", len(entries))
	}
	if h.network() != 0 {
		h.t.Error("the call made network contact")
	}
}

func (h *harness) network() int32 { return h.udpHits.Load() + h.httpHits.Load() + h.tcpHits.Load() }

func (h *harness) eng(name string) string { return filepath.Join(h.out, name) }

func (h *harness) readOut(name, file string) string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.out, name, file))
	if os.IsNotExist(err) {
		return "" // a file with no rows is not written
	}
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

type event map[string]any

func (e event) str(k string) string { s, _ := e[k].(string); return s }
func (e event) num(k string) int    { f, _ := e[k].(float64); return int(f) }

// recorder is the tap cli.Deps.Events gives a test. It writes each event as the JSON line the
// event once was on stdout, so a reader sees what a JSON consumer would: a number is a float64.
// A recorder that kept the maps would let every comparison of a count against zero pass.
type recorder struct {
	mu    sync.Mutex
	lines []string
	gen   int // bumped by every Emit and reset, so events knows when its parse is stale

	parsed    []event // events' last parse of lines
	parsedGen int
	parsedOut int // the length of stdout parsed with it
	parsedOK  bool
}

func (r *recorder) Emit(ev report.Event) {
	m := map[string]any{"type": ev.Type}
	maps.Copy(m, ev.Fields)
	b, err := json.Marshal(m)
	if err != nil {
		b, _ = json.Marshal(map[string]any{"type": "warning", "message": "cannot encode " + ev.Type + " event"})
	}
	r.mu.Lock()
	r.lines = append(r.lines, string(b))
	r.gen++
	r.mu.Unlock()
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.lines = nil
	r.gen++
	r.mu.Unlock()
}

// events are the events of the last call, parsed from the tap's JSON lines, then the summary event
// that the envelope on stdout makes (see summaryOf), when stdout holds one. The parse is kept
// until another event arrives, the recorder is reset or stdout changes length, so callers that ask
// in a loop parse once; each gets its own slice.
func (h *harness) events() []event {
	h.t.Helper()
	r := &h.rec
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.parsedOK || r.parsedGen != r.gen || r.parsedOut != h.stdout.Len() {
		evs := jsonLines(h.t, strings.Join(r.lines, "\n"))
		if env, ok := tryEnvelope(h.stdout.String()); ok {
			evs = append(evs, summaryOf(env))
		}
		r.parsed, r.parsedGen, r.parsedOut, r.parsedOK = evs, r.gen, h.stdout.Len(), true
	}
	return slices.Clone(r.parsed)
}

// tryEnvelope parses s as the one-line envelope of a recon --json run.
func tryEnvelope(s string) (report.Envelope, bool) {
	var env report.Envelope
	if !strings.HasPrefix(s, `{"data":`) || strings.Count(s, "\n") != 1 || json.Unmarshal([]byte(s), &env) != nil {
		return env, false
	}
	return env, true
}

// summaryOf is the summary of an envelope as a map, in the shape the summary event had: counts,
// failed and deferred as objects keyed by name, a candidate's sources joined with ";", a finding's
// missing detail as "", and the changes as counts keyed by kind then change.
func summaryOf(env report.Envelope) event {
	d := env.Data
	totals, failed, deferred := map[string]any{}, map[string]any{}, map[string]any{}
	for _, c := range d.Counts {
		totals[c.Category] = float64(c.N)
	}
	for _, c := range d.FailedChecks {
		failed[c.Stage] = float64(c.N)
	}
	for _, c := range d.Deferred {
		deferred[c.Stage] = float64(c.N)
	}
	rows := func(fs []report.FindingRow) []any {
		out := []any{}
		for _, f := range fs {
			detail := ""
			if f.Detail != nil {
				detail = *f.Detail
			}
			out = append(out, map[string]any{"category": f.Category, "severity": f.Severity, "target": f.Target, "detail": detail})
		}
		return out
	}
	cands := []any{}
	for _, c := range d.Candidates {
		cands = append(cands, map[string]any{"kind": c.Kind, "value": c.Value, "sources": strings.Join(c.Sources, ";"),
			"evidence_count": float64(c.EvidenceCount), "confidence": c.Confidence, "promote": c.Promote})
	}
	notes := []any{}
	for _, n := range d.Notes {
		notes = append(notes, n)
	}
	sum := event{"type": "summary", "totals": totals, "failed": failed, "deferred": deferred, "findings": rows(d.Findings),
		"candidates": cands, "unconfirmed_risky_ports": float64(d.UnconfirmedRiskyPorts), "notes": notes}
	if ch := d.Changes; ch != nil {
		counts := map[string]any{}
		for _, c := range ch.Counts {
			byChange, _ := counts[c.Kind].(map[string]any)
			if byChange == nil {
				byChange = map[string]any{}
				counts[c.Kind] = byChange
			}
			byChange[c.Change] = float64(c.N)
		}
		sum["changes"] = map[string]any{"counts": counts, "findings": rows(ch.Findings)}
	}
	return sum
}

// jsonLines parses s as JSON lines, failing on anything else.
func jsonLines(t *testing.T, s string) []event {
	t.Helper()
	var out []event
	for line := range strings.SplitSeq(strings.TrimSpace(s), "\n") {
		if line == "" {
			continue
		}
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("stdout line is not JSON: %q (%v)", line, err)
		}
		out = append(out, e)
	}
	return out
}

// logLine is one line the run wrote to stderr in the plain layout.
type logLine struct{ time, level, msg string }

// logLayout is the start of a plain log line: "HH:MM:SS | LEVEL | ".
var logLayout = regexp.MustCompile(`^(\d\d:\d\d:\d\d) \| (DEBUG|INFO |WARN |ERROR|CRIT ) \| `)

// logLines parses stderr's plain log lines. A line wrapped on a terminal, or a message of several
// lines, has continuation lines indented to the message column (19 cells, or 21 once escapes are
// removed from a coloured one); each is folded into the line before it, joined by a space, so the
// message reads as it was written. A line in another form (the error and its hint) is skipped.
func (h *harness) logLines() []logLine {
	var out []logLine
	last := false // the previous line was a log line or a continuation of one
	for l := range strings.SplitSeq(h.stderr.String(), "\n") {
		if m := logLayout.FindStringSubmatch(l); m != nil {
			out = append(out, logLine{m[1], strings.TrimSpace(m[2]), l[len(m[0]):]})
			last = true
			continue
		}
		if cont, ok := continuation(l); ok && last {
			out[len(out)-1].msg += " " + cont
			continue
		}
		last = false
	}
	return out
}

// continuation is the text of a line indented to the message column (19 or 21 cells, after
// removing escapes), and whether it is one.
func continuation(l string) (string, bool) {
	l = stripSGR(l)
	for _, indent := range []int{19, 21} {
		if rest, ok := strings.CutPrefix(l, strings.Repeat(" ", indent)); ok && rest != "" && rest[0] != ' ' {
			return rest, true
		}
	}
	return "", false
}

// logMsgs are the messages of the log lines of one level.
func (h *harness) logMsgs(level string) []string {
	var out []string
	for _, l := range h.logLines() {
		if l.level == level {
			out = append(out, l.msg)
		}
	}
	return out
}

// debugLines are the messages of the DEBUG lines on stderr.
func (h *harness) debugLines() []string { return h.logMsgs("DEBUG") }

// checkFailure is a check the last call's run failed, as the debug event the
// runner emits for it reads: "<stage> check <key> failed: <error>".
type checkFailure struct{ stage, key, err string }

// failedChecks are the checks of a stage (of every stage for "") that the last
// call's run failed.
func (h *harness) failedChecks(stage string) []checkFailure {
	var out []checkFailure
	for _, m := range h.messages("debug", " failed: ") {
		st, rest, ok := strings.Cut(m, " check ")
		key, err, ok2 := strings.Cut(rest, " failed: ")
		if ok && ok2 && (stage == "" || st == stage) {
			out = append(out, checkFailure{st, key, err})
		}
	}
	return out
}

// lines are the lines of an engagement output file, none for a missing or empty file.
func (h *harness) lines(eng, name string) []string {
	s := strings.TrimSpace(h.readOut(eng, name))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// table parses an engagement's CSV file into rows keyed by column name: nil when
// the file is absent or has only its header.
func (h *harness) table(eng, name string) []map[string]string {
	h.t.Helper()
	recs := csvRows(h.t, h.readOut(eng, name))
	if len(recs) == 0 {
		return nil
	}
	var out []map[string]string
	for _, r := range recs[1:] {
		m := map[string]string{}
		for i, c := range recs[0] {
			m[c] = r[i]
		}
		out = append(out, m)
	}
	return out
}

// summaryEvent is the run's one summary event.
func (h *harness) summaryEvent() event {
	h.t.Helper()
	sums := ofType(h.events(), "summary")
	if len(sums) != 1 {
		h.t.Fatalf("want one summary event, got %d\n%s", len(sums), h.stdout.String())
	}
	return sums[0]
}

// total is the run's summary total for a category, 0 when it has none.
func (h *harness) total(category string) int {
	h.t.Helper()
	totals, _ := h.summaryEvent()["totals"].(map[string]any)
	n, _ := totals[category].(float64)
	return int(n)
}

func ofType(evs []event, typ string) []event {
	var out []event
	for _, e := range evs {
		if e.str("type") == typ {
			out = append(out, e)
		}
	}
	return out
}

func stageEvents(evs []event, name string) []event {
	var out []event
	for _, e := range ofType(evs, "stage") {
		if e.str("name") == name {
			out = append(out, e)
		}
	}
	return out
}

func lastState(evs []event, name string) event {
	se := stageEvents(evs, name)
	if len(se) == 0 {
		return nil
	}
	return se[len(se)-1]
}

// openDB is the engagement's state database, opened on first use and closed when
// the test ends. A read sees what the runs since have committed, and an idle
// connection holds no lock, so the same handle serves the whole test.
func (h *harness) openDB(name string) *sql.DB {
	h.t.Helper()
	path := filepath.Join(h.out, name, ".nyx", "state.db")
	h.dbMu.Lock()
	defer h.dbMu.Unlock()
	if db, ok := h.dbs[path]; ok {
		return db
	}
	if h.dbs == nil {
		h.dbs = map[string]*sql.DB{}
	}
	db := openDB(h.t, path)
	h.dbs[path] = db
	return db
}

func openDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func queryStrings(t *testing.T, db *sql.DB, q string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(q, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func (h *harness) inputs(name, kind string) []string {
	return queryStrings(h.t, h.openDB(name), "SELECT value FROM inputs WHERE kind=?", kind)
}

func (h *harness) completed(name, stage string) []string {
	return queryStrings(h.t, h.openDB(name), "SELECT key FROM checks WHERE stage=?", stage)
}

func (h *harness) meta(name, key string) (string, bool) {
	v := queryStrings(h.t, h.openDB(name), "SELECT value FROM meta WHERE key=?", key)
	if len(v) == 0 {
		return "", false
	}
	return v[0], true
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
