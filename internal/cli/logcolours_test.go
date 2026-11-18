package cli_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

const esc = "\x1b"

// anyLayout is a log line of either layout, once its escapes are removed.
var anyLayout = regexp.MustCompile(`^\d\d:\d\d:\d\d [|│] {1,2}(DEBUG|INFO|WARN|ERROR|CRIT) {1,3}[|│] `)

// colourAt makes the terminal the given depth for the harness's streams.
func colourAt(t *testing.T, h *harness, d palette.Depth) {
	t.Helper()
	h.stdoutTTY, h.stderrTTY = true, true
	switch d {
	case palette.TrueColor:
		h.setenv("COLORTERM", "truecolor")
	case palette.Color256:
		h.setenv("TERM", "xterm-256color")
	}
}

// finder is a stage that records the observations once.
func finder(name string, observations ...run.Observation) *testkit.Stage {
	return &testkit.Stage{StageName: name, Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return testkit.Keys("c", 1) },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			return observations, nil
		}}
}

func findingObs(key, severity string) run.Observation {
	return obs("finding", key, "category", "exposed", "severity", severity, "target", "https://a.com/"+key, "detail", "d"+key)
}

func someFindings() *testkit.Stage {
	return finder("s", obs("hostname", "www.a.com"), findingObs("h", "high"), findingObs("m", "medium"), findingObs("l", "low"))
}

// failingCheck is a stage with three checks, the second of which fails.
func failingCheck(msg string) *testkit.Stage {
	return &testkit.Stage{StageName: "mixed", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return testkit.Keys("m", 3) },
		RunFn: func(_ context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
			if c.Key == "m001" {
				return nil, errors.New(msg)
			}
			return []run.Observation{obs("hostname", c.Key+".a.com")}, nil
		}}
}

func targetStage(name string) *testkit.Stage {
	return &testkit.Stage{StageName: name, Kind: run.Target, ChecksFn: func(run.View) []run.Check { return testkit.Keys("t", 1) }}
}

// summaryOnly says stdout holds the summary and nothing else.
func summaryOnly(t *testing.T, h *harness) {
	t.Helper()
	out := h.stdout.String()
	if !strings.HasPrefix(out, "Summary\n") {
		t.Fatalf("stdout does not start with the summary:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if logLayout.MatchString(l) || strings.HasPrefix(l, "nyx ") || strings.HasPrefix(l, "+ ") || strings.HasPrefix(l, "error:") {
			t.Errorf("a log line on stdout: %q", l)
		}
	}
}

// With a completed run stdout is the summary; the log is on stderr.
func TestLog_StreamsOfACompletedRun(t *testing.T) {
	t.Parallel()
	h := newHarness(t, someFindings())
	if code := h.exec("a.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	summaryOnly(t, h)
	err := h.stderr.String()
	for _, want := range []string{"| INFO  | nyx a.com  ", "| INFO  | s              running", "| INFO  | s              done (1 checks, 0 failed)",
		"| INFO  | + host: www.a.com", "| INFO  |   hosts: 1"} {
		if !strings.Contains(err, want) {
			t.Errorf("stderr lacks %q:\n%s", want, err)
		}
	}
	if strings.Contains(err, "Summary") {
		t.Errorf("the summary is on stderr:\n%s", err)
	}
}

// A run with no summary writes nothing to stdout, and ends with its own line on stderr.
func TestLog_RunsWithoutASummaryWriteNothingToStdout(t *testing.T) {
	t.Parallel()
	t.Run("error", func(t *testing.T) {
		h := newHarness(t, noop())
		if code := h.exec(); code != 2 {
			t.Fatalf("exit %d", code)
		}
		if h.stdout.Len() != 0 || !strings.HasPrefix(h.stderr.String(), "error: no inputs") {
			t.Errorf("stdout %q, stderr %q", h.stdout.String(), h.stderr.String())
		}
	})
	t.Run("netblock limit", func(t *testing.T) {
		h := newHarness(t, noop())
		if code := h.exec("--cidr", "10.0.0.0/16", "--netblock-limit", "1000"); code != 2 {
			t.Fatalf("exit %d\n%s", code, h.stderr.String())
		}
		if h.stdout.Len() != 0 || !strings.Contains(h.stderr.String(), "error: in-scope IPv4 netblocks cover 65536 addresses") {
			t.Errorf("stdout %q, stderr %q", h.stdout.String(), h.stderr.String())
		}
	})
	t.Run("interrupted", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return testkit.Keys("c", 2) },
			RunFn: func(ctx context.Context, _ run.Check, _ egress.Clients) ([]run.Observation, error) {
				cancel()
				<-ctx.Done()
				return nil, ctx.Err()
			}}
		h := newHarness(t, st)
		if code := h.execCtx(ctx, "a.com", "--concurrency", "1"); code != 130 {
			t.Fatalf("exit %d", code)
		}
		if h.stdout.Len() != 0 {
			t.Errorf("stdout %q", h.stdout.String())
		}
		if f := h.theError(false); f.code != "INTERRUPTED" || !strings.Contains(f.hint, "completed work is saved") {
			t.Errorf("error = %+v", f)
		}
	})
}

// On a coloured stderr only the error: prefix of the closing line is styled.
func TestLog_ErrorLineColour(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	colourAt(t, h, palette.TrueColor)
	h.exec()
	want := "\x1b[38;2;240;138;146merror:\x1b[0m no inputs"
	got := h.stderr.String()
	if !strings.HasPrefix(got, want) || strings.Contains(got[len(want):], esc) {
		t.Errorf("stderr = %q, want a line starting %q and no other escape", got, want)
	}
	// Plain on a terminal that is not coloured: no escape at all.
	h = newHarness(t, noop())
	h.stderrTTY = true
	h.setenv("NO_COLOR", "1")
	h.exec()
	if got := h.stderr.String(); strings.Contains(got, esc) || !strings.HasPrefix(got, "error: no inputs") {
		t.Errorf("stderr = %q", got)
	}
}

// Every log line has the layout, in the local time zone.
func TestLog_LineLayoutAndTimeZone(t *testing.T) {
	t.Parallel()
	h := newHarness(t, someFindings())
	h.loc = time.FixedZone("AEDT", 11*3600)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(h.stderr.String()), "\n")
	if len(lines) < 5 {
		t.Fatalf("stderr = %q", lines)
	}
	for _, l := range lines {
		if !logLayout.MatchString(l) {
			t.Errorf("not a log line: %q", l)
		}
		if !strings.HasPrefix(l, "20:00:00 | ") { // 09:00 UTC
			t.Errorf("time is not in the configured zone: %q", l)
		}
	}
}

// Warnings are WARN lines with no flag; a failed stage is ERROR; a check failure is DEBUG only.
func TestLog_Levels(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	warner := &testkit.Stage{StageName: "warner", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			n := calls.Add(1)
			v.Warn("technology detection is off")
			v.Warn("seen %d passes", n)
			return testkit.Keys("w", 1)
		},
		RunFn: func(ctx context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
			run.Warnf(ctx, "result for %s was truncated", c.Key)
			return nil, nil
		}}
	quota := &testkit.Stage{StageName: "quota", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return testkit.Keys("q", 2) },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			return nil, fmt.Errorf("429: %w", run.ErrQuota)
		}}
	failing := &testkit.Stage{StageName: "failing", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return testkit.Keys("f", 2) },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			return nil, errors.New("source unavailable")
		}}
	h := newHarness(t, warner, quota, failing)
	if code := h.exec("a.com", "--concurrency", "1"); code != 7 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	if calls.Load() < 2 {
		t.Fatalf("Checks ran %d times; the test needs a repeated pass", calls.Load())
	}
	warns := h.logMsgs("WARN")
	count := func(sub string) (n int) {
		for _, w := range warns {
			if strings.Contains(w, sub) {
				n++
			}
		}
		return n
	}
	if count("technology detection is off") != 1 {
		t.Errorf("a warning raised on every pass is written once: %q", warns)
	}
	if got := count("seen "); got != int(calls.Load()) {
		t.Errorf("a warning whose text changes is written again: %d lines for %d passes: %q", got, calls.Load(), warns)
	}
	if count("result for w000 was truncated") != 1 || count("quota: quota spent or key rejected; 2 checks will be retried next run") != 1 {
		t.Errorf("Warnf and quota warnings: %q", warns)
	}
	// A stage whose every check failed is shown as failed, at ERROR.
	if msgs := h.logMsgs("ERROR"); len(msgs) != 2 || !strings.HasPrefix(msgs[0], "quota          failed") || !strings.HasPrefix(msgs[1], "failing        failed") {
		t.Errorf("ERROR lines = %q", msgs)
	}
	for _, w := range warns {
		if strings.Contains(w, "check") && strings.Contains(w, "failed:") {
			t.Errorf("a check failure is a WARN line: %q", w)
		}
	}
	if len(h.debugLines()) != 0 {
		t.Errorf("DEBUG lines without --debug: %q", h.debugLines())
	}
	for _, l := range h.logLines() {
		if strings.HasPrefix(l.msg, "+ ") && l.level != "INFO" {
			t.Errorf("found line at %s", l.level)
		}
	}
}

// A check that fails among several: the rest complete, the stage line and the
// summary count it, and its line appears only with --debug, as DEBUG.
func TestLog_FailedCheckIsDebugOnly(t *testing.T) {
	t.Parallel()
	h := newHarness(t, failingCheck("boom"))
	if code := h.exec("a.com"); code != 7 {
		t.Fatal(h.stderr.String())
	}
	if strings.Contains(h.stderr.String(), "m001") || strings.Contains(h.stdout.String(), "m001") {
		t.Errorf("the failure is shown without --debug:\n%s", h.stderr.String())
	}
	if !strings.Contains(h.stderr.String(), "| mixed          done (3 checks, 1 failed)") {
		t.Errorf("stage line:\n%s", h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "Failed checks (retried on the next run; --debug shows each failure)\n  mixed            1") {
		t.Errorf("summary:\n%s", h.stdout.String())
	}
	if got := h.readOut("a.com", "subdomains.txt"); !strings.Contains(got, "m000.a.com") || !strings.Contains(got, "m002.a.com") {
		t.Errorf("the other checks completed: %q", got)
	}

	if code := h.exec("-e", "a.com", "--debug"); code != 7 {
		t.Fatal(h.stderr.String())
	}
	if d := h.debugLines(); len(d) != 1 || d[0] != "mixed check m001 failed: boom" {
		t.Errorf("DEBUG lines = %q", d)
	}
	for _, w := range h.logMsgs("WARN") {
		t.Errorf("WARN line %q", w)
	}
}

// The authorisation warning names the stages left out, once, before any stage line.
func TestLog_AuthorisationWarning(t *testing.T) {
	t.Parallel()
	const tail = "; --authorised confirms authorisation"
	mk := func() []run.Stage {
		return []run.Stage{finder("src"), targetStage("probe"), targetStage("crawl2")}
	}
	warned := func(h *harness) []string {
		var out []string
		for _, w := range h.logMsgs("WARN") {
			if strings.HasPrefix(w, "not authorised") {
				out = append(out, w)
			}
		}
		return out
	}

	t.Run("names the stages, after the header and before any stage line", func(t *testing.T) {
		h := newHarness(t, mk()...)
		if code := h.exec("a.com"); code != 0 {
			t.Fatal(h.stderr.String())
		}
		if got := warned(h); len(got) != 1 || got[0] != "not authorised, so these stages are left out: probe, crawl2"+tail {
			t.Fatalf("warnings = %q", got)
		}
		lines := h.logLines()
		if !strings.HasPrefix(lines[0].msg, "nyx a.com") || lines[1].level != "WARN" || !strings.HasPrefix(lines[2].msg, "src ") {
			t.Errorf("order: %v", lines[:3])
		}
	})
	t.Run("a stage left out by --skip is not named", func(t *testing.T) {
		h := newHarness(t, mk()...)
		h.exec("a.com", "--skip", "crawl2")
		if got := warned(h); len(got) != 1 || got[0] != "not authorised, so these stages are left out: probe"+tail {
			t.Errorf("warnings = %q", got)
		}
		if !strings.Contains(h.stderr.String(), "crawl2         not-configured (skipped)") {
			t.Errorf("the skipped stage's line:\n%s", h.stderr.String())
		}
	})
	t.Run("no line when nothing is left out for lack of authorisation", func(t *testing.T) {
		for name, args := range map[string][]string{
			"passive":    {"a.com", "--passive"},
			"authorised": {"a.com", "--authorised"},
			"all skip":   {"a.com", "--skip", "probe", "--skip", "crawl2"},
		} {
			h := newHarness(t, mk()...)
			h.exec(args...)
			if got := warned(h); len(got) != 0 {
				t.Errorf("%s: warnings = %q", name, got)
			}
		}
	})
	t.Run("an interrupted run still shows it", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		first := &testkit.Stage{StageName: "src", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return testkit.Keys("c", 1) },
			RunFn: func(ctx context.Context, _ run.Check, _ egress.Clients) ([]run.Observation, error) {
				cancel()
				<-ctx.Done()
				return nil, ctx.Err()
			}}
		h := newHarness(t, first, targetStage("probe"))
		if code := h.execCtx(ctx, "a.com"); code != 130 {
			t.Fatalf("exit %d", code)
		}
		if got := warned(h); len(got) != 1 {
			t.Errorf("warnings = %q", got)
		}
	})
	t.Run("every unauthorised run shows it; --authorised removes it", func(t *testing.T) {
		h := newHarness(t, mk()...)
		h.exec("a.com")
		h.exec("-e", "a.com")
		if got := warned(h); len(got) != 1 {
			t.Errorf("second run: warnings = %q", got)
		}
		h.exec("-e", "a.com", "--authorised")
		if got := warned(h); len(got) != 0 {
			t.Errorf("after --authorised: warnings = %q", got)
		}
	})
	t.Run("a warning event under --json", func(t *testing.T) {
		h := newHarness(t, mk()...)
		h.exec("a.com", "--json")
		var got []string
		for _, e := range ofType(h.events(), "warning") {
			got = append(got, e.str("message"))
		}
		if len(got) != 1 || got[0] != "not authorised, so these stages are left out: probe, crawl2"+tail {
			t.Errorf("warning events = %q", got)
		}
	})
}

// With the default registry the warning names exactly the stages whose line
// reads not-configured (no authorisation).
func TestLog_AuthorisationWarningMatchesTheStageLines(t *testing.T) {
	t.Parallel()
	w := newWorldWith(t, "takeover", "sensitive-paths")
	if code := w.run("example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var want []string
	for _, e := range ofType(w.h.events(), "stage") {
		if e.str("state") == "not-configured" && e.str("reason") == "no authorisation" && !slices.Contains(want, e.str("name")) {
			want = append(want, e.str("name"))
		}
	}
	if len(want) < 3 {
		t.Fatalf("stages left out = %v", want)
	}
	msgs := messages(w, "warning", "not authorised")
	if len(msgs) != 1 || msgs[0] != "not authorised, so these stages are left out: "+strings.Join(want, ", ")+"; --authorised confirms authorisation" {
		t.Errorf("warning = %q for stages %v", msgs, want)
	}
}

// --quiet, --debug and the flags that are gone.
func TestLog_Flags(t *testing.T) {
	t.Parallel()
	stages := func() []run.Stage {
		return []run.Stage{
			&testkit.Stage{StageName: "warns", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { v.Warn("careful"); return testkit.Keys("w", 1) }},
			failingCheck("boom"),
		}
	}
	levels := func(h *harness) string {
		seen := map[string]bool{}
		for _, l := range h.logLines() {
			seen[l.level] = true
		}
		var out []string
		for _, l := range []string{"DEBUG", "INFO", "WARN", "ERROR"} {
			if seen[l] {
				out = append(out, l)
			}
		}
		return strings.Join(out, ",")
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "INFO,WARN"},
		{[]string{"--quiet"}, "WARN"},
		{[]string{"-q"}, "WARN"},
		{[]string{"--debug"}, "DEBUG,INFO,WARN"},
	} {
		h := newHarness(t, stages()...)
		if code := h.exec(append([]string{"a.com"}, c.args...)...); code != 7 {
			t.Fatalf("%v: exit %d\n%s", c.args, code, h.stderr.String())
		}
		if got := levels(h); got != c.want {
			t.Errorf("%v: levels %s, want %s\n%s", c.args, got, c.want, h.stderr.String())
		}
		summaryOnly(t, h) // the summary is printed whatever the level
	}

	h := newHarness(t, stages()...)
	if code := h.exec("a.com", "--quiet", "--debug"); code != 2 || h.stdout.Len() != 0 || !strings.HasPrefix(h.stderr.String(), "error: ") {
		t.Errorf("--quiet --debug: exit %d, stdout %q, stderr %q", code, h.stdout.String(), h.stderr.String())
	}
	if code := h.exec("a.com", "--verbose"); code != 2 || !strings.Contains(h.stderr.String(), "unknown flag: --verbose") {
		t.Errorf("--verbose: exit %d, stderr %q", code, h.stderr.String())
	}

	// Neither is a setting.
	h = newHarness(t, stages()...)
	h.setenv("NYX_QUIET", "1")
	h.setenv("NYX_DEBUG", "1")
	if code := h.exec("a.com"); code != 7 {
		t.Fatal(h.stderr.String())
	}
	if got := levels(h); got != "INFO,WARN" {
		t.Errorf("NYX_QUIET and NYX_DEBUG changed the levels: %s", got)
	}
	for _, key := range []string{"quiet", "debug"} {
		cfg := writeFile(t, t.TempDir(), "config.yaml", key+": true\n")
		h := newHarness(t, stages()...)
		if code := h.exec("a.com", "--config", cfg); code != 2 || !strings.Contains(h.stderr.String(), key) {
			t.Errorf("%s in a config file: exit %d, stderr %q", key, code, h.stderr.String())
		}
	}
}

// Header, stage and count messages keep their text; found lines carry the severity badge.
func TestLog_FoundLinesPlain(t *testing.T) {
	t.Parallel()
	h := newHarness(t, someFindings())
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	var found []string
	for _, l := range h.logLines() {
		if strings.HasPrefix(l.msg, "+ ") {
			found = append(found, l.msg)
		}
	}
	for _, want := range []string{
		"+ host: www.a.com",
		"+ high     finding exposed: https://a.com/h",
		"+ medium   finding exposed: https://a.com/m",
		"+ low      finding exposed: https://a.com/l",
	} {
		if !slices.Contains(found, want) {
			t.Errorf("missing %q in %q", want, found)
		}
	}
	if strings.Contains(h.stderr.String(), "[high]") || strings.Contains(h.stdout.String(), "[high]") {
		t.Error("the [severity] suffix is back")
	}
	if want := "nyx a.com  1 roots, 0 orgs, 0 asns, 0 cidrs, 0 exclusions"; h.logLines()[0].msg != want {
		t.Errorf("header = %q, want %q", h.logLines()[0].msg, want)
	}
}

// The badge has the palette's style at each depth, an unknown severity gets the
// DEBUG style, and the only escapes in a coloured line are the chrome, the level
// badge and the severity badge.
func TestLog_FoundLinesColoured(t *testing.T) {
	t.Parallel()
	st := finder("s", obs("hostname", "www.a.com"), findingObs("h", "high"), findingObs("m", "medium"), findingObs("l", "low"), findingObs("w", "weird"))
	for _, d := range []palette.Depth{palette.TrueColor, palette.Color256, palette.Color16} {
		h := newHarness(t, st)
		colourAt(t, h, d)
		if code := h.exec("a.com"); code != 0 {
			t.Fatal(h.stderr.String())
		}
		out := h.stderr.String()
		for _, sev := range []string{"high", "medium", "low", "weird"} {
			badge := d.Value(palette.Severity, sev)
			if !strings.Contains(out, "│ \x1b[0m+ "+badge+" finding exposed: https://a.com/"+sev[:1]) {
				t.Errorf("depth %d: no %s badge in\n%q", d, sev, out)
			}
		}
		if strings.Contains(out, "[") && strings.Contains(out, "[high]") {
			t.Errorf("depth %d: brackets", d)
		}
		// Remove the chrome, the level badge and the severity badges; no escape is left.
		rest := out
		for _, sev := range []string{"high", "medium", "low", "weird"} {
			rest = strings.ReplaceAll(rest, d.Value(palette.Severity, sev), "")
		}
		for _, l := range []string{"DEBUG", "INFO", "WARN", "ERROR"} {
			rest = strings.ReplaceAll(rest, d.Badge(palette.Level, l), "")
		}
		rest = strings.ReplaceAll(rest, d.Text(palette.Chrome, "SEPARATOR", " │ "), "")
		for _, ln := range strings.Split(rest, "\n") {
			if len(ln) >= 8 && strings.Contains(ln, esc) {
				ts := ln[:strings.Index(ln, "m")+1+8+len("\x1b[0m")]
				if rest := strings.Replace(ln, ts, "", 1); strings.Contains(rest, esc) {
					t.Errorf("depth %d: an escape in the message of %q", d, ln)
				}
			}
		}
	}
	// The DEBUG style is what an unknown severity takes (24-bit values).
	h := newHarness(t, st)
	colourAt(t, h, palette.TrueColor)
	h.exec("a.com")
	if !strings.Contains(h.stderr.String(), "\x1b[38;2;169;177;198;48;2;42;47;58m weird    \x1b[0m") {
		t.Errorf("unknown severity is not in the DEBUG style:\n%q", h.stderr.String())
	}
}

// The summary is printed with --quiet, its findings carry badges, its headings
// are bold on a coloured stdout and nothing else is styled.
func TestLog_Summary(t *testing.T) {
	t.Parallel()
	h := newHarness(t, someFindings(), failingCheck("boom"))
	if code := h.exec("a.com", "--quiet"); code != 7 {
		t.Fatal(h.stderr.String())
	}
	summaryOnly(t, h)
	out := h.stdout.String()
	for _, want := range []string{"Findings (high and medium)\n  high     exposed https://a.com/h - dh\n  medium   exposed https://a.com/m - dm\n",
		"Failed checks (retried on the next run; --debug shows each failure)\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[high]") || strings.Contains(out, "(retried on the next run)") || strings.Contains(out, "low ") {
		t.Errorf("summary:\n%s", out)
	}

	h = newHarness(t, someFindings(), failingCheck("boom"))
	colourAt(t, h, palette.TrueColor)
	h.stderrTTY = false
	h.exec("a.com")
	out = h.stdout.String()
	if !strings.HasPrefix(out, "\x1b[1mSummary\x1b[0m\n") || !strings.Contains(out, "\x1b[1mFindings (high and medium)\x1b[0m\n") {
		t.Errorf("headings are not bold:\n%q", out)
	}
	rest := out
	for _, s := range []string{palette.TrueColor.Value(palette.Severity, "high"), palette.TrueColor.Value(palette.Severity, "medium"), "\x1b[1m", "\x1b[0m"} {
		rest = strings.ReplaceAll(rest, s, "")
	}
	if strings.Contains(rest, esc) {
		t.Errorf("more than the headings and badges is styled:\n%q", rest)
	}
	if strings.Contains(h.stderr.String(), esc) {
		t.Errorf("stderr is not a terminal here, yet it has an escape:\n%q", h.stderr.String())
	}
}

// stdout and stderr are coloured separately, and only on a terminal.
func TestLog_ColourDecision(t *testing.T) {
	t.Parallel()
	run1 := func(t *testing.T, stdout, stderr bool, env map[string]string) *harness {
		h := newHarness(t, someFindings())
		h.setenv("COLORTERM", "truecolor")
		for k, v := range env {
			h.setenv(k, v)
		}
		h.stdoutTTY, h.stderrTTY = stdout, stderr
		if code := h.exec("a.com"); code != 0 {
			t.Fatal(h.stderr.String())
		}
		return h
	}
	h := run1(t, true, false, nil) // nyx example.com 2> run.log
	if strings.Contains(h.stderr.String(), esc) || !strings.Contains(h.stdout.String(), "\x1b[1mSummary") {
		t.Errorf("redirected log: stderr %q, stdout %q", h.stderr.String(), h.stdout.String())
	}
	h = run1(t, false, true, nil) // nyx example.com > summary.txt
	if !strings.Contains(h.stderr.String(), "\x1b[38;2;124;129;145m") || strings.Contains(h.stdout.String(), esc) {
		t.Errorf("redirected summary: stderr %q, stdout %q", h.stderr.String(), h.stdout.String())
	}
	for name, env := range map[string]map[string]string{
		"NO_COLOR":    {"NO_COLOR": "1"},
		"dumb":        {"TERM": "dumb"},
		"FORCE_COLOR": {"FORCE_COLOR": "1", "CLICOLOR_FORCE": "1"},
	} {
		tty := name != "FORCE_COLOR" // the forcing variables are tried on a pipe
		h := run1(t, tty, tty, env)
		if strings.Contains(h.stdout.String()+h.stderr.String(), esc) {
			t.Errorf("%s: an escape byte\n%q", name, h.stdout.String()+h.stderr.String())
		}
	}
}

// The depth variables choose the depth only on a terminal.
func TestLog_ColourDepth(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		d    palette.Depth
		env  map[string]string
		want string
	}{
		{palette.TrueColor, map[string]string{"COLORTERM": "24bit"}, "\x1b[38;2;143;179;255;48;2;31;44;77m INFO  "},
		{palette.Color256, map[string]string{"TERM": "xterm-256color"}, "\x1b[38;5;111;48;5;236m INFO  "},
		{palette.Color16, map[string]string{"TERM": "xterm"}, "\x1b[94;40m INFO  "},
	} {
		h := newHarness(t, noop())
		for k, v := range c.env {
			h.setenv(k, v)
		}
		h.stderrTTY = true
		h.exec("a.com")
		if !strings.Contains(h.stderr.String(), c.want) {
			t.Errorf("depth %d: stderr %q lacks %q", c.d, h.stderr.String(), c.want)
		}
	}
	h := newHarness(t, noop())
	h.setenv("COLORTERM", "truecolor")
	h.setenv("TERM", "xterm-256color")
	h.exec("a.com") // not a terminal
	if strings.Contains(h.stdout.String()+h.stderr.String(), esc) {
		t.Error("the depth variables turned colour on")
	}
}

// Under --json stdout is the one envelope with or without --debug and --quiet, warnings are in
// meta.warnings with no flag, and stderr carries only DEBUG lines and the error.
func TestLog_JSON(t *testing.T) {
	t.Parallel()
	const key = "sekret-key-4242"
	mk := func() []run.Stage {
		warns := &testkit.Stage{StageName: "warns", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { v.Warn("careful"); return testkit.Keys("w", 1) }}
		bad := &testkit.Stage{StageName: "bad", Kind: run.ThirdParty,
			ChecksFn: func(run.View) []run.Check { return testkit.Keys("b", 1) },
			RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
				return nil, errors.New("GET /x?key=" + key + " failed")
			}}
		return []run.Stage{warns, bad, someFindings()}
	}
	var base string
	for i, args := range [][]string{{}, {"--debug"}, {"--quiet"}} {
		h := newHarness(t, mk()...)
		h.setenv("NYX_KEYS_FAKE", key)
		f := h.partial(h.exec(append([]string{"a.com", "--json"}, args...)...), true)
		if f.msg != "1 checks failed: bad 1" {
			t.Errorf("%v: error = %+v", args, f)
		}
		env := h.envelope()
		got := strings.ReplaceAll(h.stdout.String(), h.out, "OUT")
		if i == 0 {
			base = got
			if len(env.Meta.Warnings) != 1 || env.Meta.Warnings[0] != "careful" {
				t.Errorf("a warning needs no flag to be in meta.warnings: %q", env.Meta.Warnings)
			}
		} else if got != base {
			t.Errorf("%v: stdout differs from the default run:\n got %q\nwant %q", args, got, base)
		}
		if slices.Contains(args, "--debug") {
			if d := h.debugLines(); len(d) != 1 || d[0] != "bad check b000 failed: GET /x?key=**** failed" {
				t.Errorf("DEBUG lines = %q", d)
			}
		} else if len(h.debugLines()) != 0 {
			t.Errorf("%v: DEBUG lines without --debug: %q", args, h.debugLines())
		}
		for _, l := range h.logLines() {
			if l.level != "DEBUG" {
				t.Errorf("%v: a %s line on stderr under --json: %q", args, l.level, l.msg)
			}
		}
		if strings.Contains(h.stdout.String()+h.stderr.String(), key) {
			t.Errorf("%v: the key leaked", args)
		}
	}
	// stderr under --json --debug is coloured by the same rule as any stream.
	h := newHarness(t, mk()...)
	colourAt(t, h, palette.TrueColor)
	h.exec("a.com", "--json", "--debug")
	if !strings.Contains(h.stderr.String(), "\x1b[38;2;169;177;198;48;2;42;47;58m DEBUG ") || strings.Contains(h.stdout.String(), esc) {
		t.Errorf("stderr %q", h.stderr.String())
	}
	// An error is the one JSON error on stderr, and stdout is empty.
	h = newHarness(t, mk()...)
	if f := h.failed(h.exec("--json", "--debug"), 2, true); !strings.HasPrefix(f.msg, "no inputs") {
		t.Errorf("error = %+v", f)
	}
}

// Target-supplied text and secrets never reach either stream as an escape or a key.
func TestLog_MessageHandling(t *testing.T) {
	t.Parallel()
	const key = "sekret-key-4242"
	evil := "x\x1b[2J\x1b]0;pwn\x07y\u202ez\nnext\r"
	long := strings.Repeat("w", 800)
	st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			v.Warn("warned %s %s", evil, key)
			v.Warn("%s", long)
			return testkit.Keys("c", 2)
		},
		RunFn: func(ctx context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
			if c.Key == "c001" {
				return nil, errors.New("failed " + evil + " " + key)
			}
			run.Warnf(ctx, "inside %s", evil)
			return []run.Observation{obs("hostname", "x.a.com"), findingObs("h", "high"),
				obs("finding", "e", "category", "exposed", "severity", "high", "target", evil, "detail", evil)}, nil
		}}
	for _, coloured := range []bool{false, true} {
		h := newHarness(t, st)
		h.setenv("NYX_KEYS_FAKE", key)
		if coloured {
			colourAt(t, h, palette.TrueColor)
		}
		if code := h.exec("a.com", "--debug", "--concurrency", "1"); code != 7 {
			t.Fatal(h.stderr.String())
		}
		all := h.stdout.String() + h.stderr.String()
		// Our own sequences are SGR; remove them, and no control byte is left.
		rest := regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(all, "")
		for _, bad := range []string{esc, "\x07", "\u202e", "\r", key} {
			if strings.Contains(rest, bad) {
				t.Errorf("coloured=%v: %q reached the output:\n%s", coloured, bad, rest)
			}
		}
		for _, l := range h.logLines() {
			if strings.Contains(l.msg, "wwww") && l.msg != long {
				t.Errorf("a long message was cut or wrapped: %d bytes", len(l.msg))
			}
		}
		if !strings.Contains(rest, strings.Repeat("w", 800)) {
			t.Errorf("coloured=%v: the long warning is not on one line", coloured)
		}
		for _, l := range strings.Split(strings.TrimSpace(h.stderr.String()), "\n") {
			// After the log, the error and its lines: the failed check makes the run partial.
			if !anyLayout.MatchString(stripSGR(l)) && !strings.HasPrefix(stripSGR(l), "error:") &&
				!strings.HasPrefix(l, "hint:") && l != "retry: may succeed after a wait" {
				t.Errorf("coloured=%v: a line outside the layout (an injected newline?): %q", coloured, l)
			}
		}
	}
}

// sgr is one SGR escape sequence.
var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

// stripSGR removes the SGR sequences from a line.
func stripSGR(s string) string { return sgr.ReplaceAllString(s, "") }

// --palette prints every table through the formatter and touches nothing.
func TestLog_Palette(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.exec("--palette"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	out := h.stdout.String()
	for _, c := range palette.Categories() {
		for _, l := range palette.Labels(c) {
			if !strings.Contains(out, l) {
				t.Errorf("sheet lacks %s %s", c, l)
			}
		}
	}
	for _, g := range palette.Groups() {
		for _, n := range palette.Names(g) {
			if !strings.Contains(out, n) {
				t.Errorf("sheet lacks %s %s", g, n)
			}
		}
	}
	levels := 0
	for _, l := range strings.Split(out, "\n") {
		if logLayout.MatchString(l) {
			levels++
		}
	}
	if levels != 6 { // five levels and the first line of the two-line message
		t.Errorf("%d log lines in the sheet, want 6:\n%s", levels, out)
	}
	if !strings.Contains(out, "\n"+strings.Repeat(" ", 19)+"continued") || strings.Contains(out, esc) {
		t.Errorf("plain sheet:\n%q", out)
	}
	if h.stderr.Len() != 0 || h.network() != 0 {
		t.Errorf("stderr %q, network %d", h.stderr.String(), h.network())
	}
	if entries, _ := os.ReadDir(h.out); len(entries) != 0 {
		t.Errorf("--palette created %v", entries)
	}

	// Inputs, a missing scope and a broken config are ignored.
	bad := writeFile(t, t.TempDir(), "config.yaml", "not: [valid\n")
	if code := h.exec("--palette", "a.com", "--org", "Acme", "--config", bad); code != 0 || h.stdout.String() != out {
		t.Errorf("with inputs: exit %d, same sheet = %v", code, h.stdout.String() == out)
	}
	if entries, _ := os.ReadDir(h.out); len(entries) != 0 {
		t.Errorf("--palette with inputs created %v", entries)
	}

	// Coloured it follows the colour rule, and the continuation is at 21.
	colourAt(t, h, palette.TrueColor)
	h.exec("--palette")
	col := h.stdout.String()
	if !strings.Contains(col, esc) || !strings.Contains(stripSGR(col), "\n"+strings.Repeat(" ", 21)+"continued") {
		t.Errorf("coloured sheet:\n%q", col)
	}
	h.exec("--palette", "--json")
	if strings.Contains(h.stdout.String(), esc) {
		t.Error("under --json the sheet is uncoloured")
	}

	// It is not in --help.
	h.exec("--help")
	if strings.Contains(h.stdout.String(), "palette") {
		t.Error("--palette is listed in --help")
	}
}

// --help describes the new flags and the streams they write to, and not the
// removed one; the README, not --help, describes the console in full.
func TestLog_Help(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.exec("--help"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	help := h.stdout.String()
	for _, want := range []string{"--quiet", "-q", "--debug", "stderr", "stdout"} {
		if !strings.Contains(help, want) {
			t.Errorf("--help lacks %q", want)
		}
	}
	for _, bad := range []string{"--verbose", "--palette", "Console:"} {
		if strings.Contains(help, bad) {
			t.Errorf("--help names %q", bad)
		}
	}
}

// The otx and anubis stages are gone; what they found stays.
func TestLog_OTXAndAnubisAreRemoved(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"otx", "anubis"} {
		for _, flag := range []string{"--redo", "--skip"} {
			h := newHarness(t, cli.DefaultDeps().Stages...)
			if code := h.exec("--passive", flag, name, "example.com"); code != 2 || !strings.Contains(h.stderr.String(), "unknown stage") {
				t.Errorf("%s %s: exit %d, stderr %q", flag, name, code, h.stderr.String())
			}
		}
	}
	h := newHarness(t, cli.DefaultDeps().Stages...)
	if topic := h.stagesHelp(); stageRow(topic, "otx") != "" || stageRow(topic, "anubis") != "" {
		t.Errorf("help stages lists them:\n%s", topic)
	}

	w := newWorld(t)
	otx := w.serve("otx.alienvault.com", func(rw http.ResponseWriter, _ *http.Request) { http.NotFound(rw, nil) })
	anubis := w.serve("jldc.me", func(rw http.ResponseWriter, _ *http.Request) { http.NotFound(rw, nil) })
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if n := len(otx.requestLog()) + len(anubis.requestLog()); n != 0 {
		t.Errorf("%d requests to the removed sources", n)
	}

	// An engagement that holds their results keeps them.
	h = newHarness(t, finder("otx", obs("hostname", "old.a.com")))
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	h.stages = []run.Stage{noop()}
	if code := h.exec("-e", "a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if got := h.lines("a.com", "subdomains.txt"); !slices.Contains(got, "old.a.com") {
		t.Errorf("subdomains.txt = %v", got)
	}
}
