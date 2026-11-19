package cli_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/engagement"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// The error has one exact layout in each mode.
func TestContract_ErrorLayout(t *testing.T) {
	t.Parallel()
	const msg = `invalid domain "co.uk": it is a public suffix, not a registrable domain`
	h := newHarness(t, noop())
	h.failed(h.exec("co.uk"), 2, false)
	if got, want := h.stderr.String(), "error: "+msg+" (INVALID_INPUT)\nhint: nyx recon --help\n"; got != want {
		t.Errorf("human error:\n got %q\nwant %q", got, want)
	}
	h.failed(h.exec("co.uk", "--json"), 2, true)
	if got, want := h.stderr.String(), `{"error":"invalid domain \"co.uk\": it is a public suffix, not a registrable domain","code":"INVALID_INPUT","hint":"nyx recon --help","input":{"domain":["co.uk"]},"transient":false}`+"\n"; got != want {
		t.Errorf("JSON error:\n got %s\nwant %s", got, want)
	}

	// A character HTML would escape is written as it is.
	h.failed(h.exec("a<b>&c.com", "--json"), 2, true)
	if !strings.Contains(h.stderr.String(), `"input":{"domain":["a<b>&c.com"]}`) {
		t.Errorf("JSON error escapes HTML: %s", h.stderr.String())
	}

	// A locked engagement has its own code and is worth retrying; its hint says what to do and
	// no input is at fault, so the input is null.
	if code := h.exec("a.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	eng, err := engagement.Open(h.eng("a.com"), engagement.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	f := h.failed(h.exec("-e", "a.com", "--json"), 1, true)
	if f.code != "LOCKED" || !f.transient {
		t.Errorf("%+v", f)
	}
	if !strings.HasSuffix(h.stderr.String(), `,"code":"LOCKED","hint":"another run holds this engagement; wait for it to finish, or use another -e","input":null,"transient":true}`+"\n") {
		t.Errorf("hint, input and transient: %s", h.stderr.String())
	}
	f = h.failed(h.exec("-e", "a.com"), 1, false)
	if f.hint != "another run holds this engagement; wait for it to finish, or use another -e" || f.code != "LOCKED" || !f.transient {
		t.Errorf("%+v", f)
	}
}

// --json applies even when the arguments fail to parse, wherever it is.
func TestContract_JSONModeWhenParsingFails(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"recon", "--bogus", "--json"},
		{"--json", "recon", "--bogus"},
		{"-J", "recon", "a.com", "--bogus"},
		{"recon", "-qJ", "--bogus"},
		{"recon", "--json=true", "--bogus"},
		{"recon", "export", "--bogus", "-J"},
	} {
		h := newHarness(t, noop())
		f := h.failed(h.execRoot(args...), 2, true)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "--bogus") || !slices.Equal(f.inputOf("flag"), []string{"--bogus"}) {
			t.Errorf("nyx %v: %+v", args, f)
		}
		h.untouched()
	}
	// --json=false and a --json after -- leave the error in human mode.
	for _, args := range [][]string{{"recon", "--json=false", "--bogus"}, {"recon", "--bogus", "--", "--json"}} {
		h := newHarness(t, noop())
		h.failed(h.execRoot(args...), 2, false)
	}
}

// A recon --json run that fails once it has started writes nothing to stdout: the failure is the
// error on stderr, and there are no event lines to keep. A run that ends writes the one envelope.
func TestContract_FailedRunWritesNothingToStdout(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	h.failed(h.exec("--json", "--cidr", "10.0.0.0/16", "--netblock-limit", "1000"), 2, true)
	if f := h.theError(true); f.code != "INVALID_INPUT" {
		t.Errorf("%+v", f)
	}
	if len(ofType(h.events(), "run_start")) != 1 {
		t.Error("the run started, so the tap saw its run_start event")
	}
	// A successful run ends with the envelope and exit code 0.
	h = newHarness(t, noop())
	if code := h.exec("--json", "a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	h.envelope()
}

// An API key never reaches the error, in either mode, from the environment or
// the config file, also when the configuration fails to load.
func TestContract_KeysAreMaskedInTheError(t *testing.T) {
	t.Parallel()
	const envKey, fileKey = "envsecret4242", "filesecret777"
	for _, jsonMode := range []bool{false, true} {
		for _, broken := range []bool{false, true} {
			h := newHarness(t, noop())
			h.setenv("NYX_KEYS_FAKE", envKey)
			cfg := writeFile(t, t.TempDir(), "config.yaml", "keys:\n  other: "+fileKey+"\n")
			args := []string{"--config", cfg, "--asn", envKey, "--cidr", fileKey}
			if broken {
				args = append(args, "--concurrency", "abc")
			}
			if jsonMode {
				args = append(args, "--json")
			}
			f := h.failed(h.exec(args...), 2, jsonMode)
			all := h.stderr.String()
			if strings.Contains(all, envKey) || strings.Contains(all, fileKey) {
				t.Errorf("json %v, broken config %v: a key reached stderr: %s", jsonMode, broken, all)
			}
			if !strings.Contains(f.msg, "invalid ASN") || !strings.Contains(f.msg, "****") {
				t.Errorf("json %v, broken config %v: %+v", jsonMode, broken, f)
			}
		}
	}
}

// Terminal-acting characters in an error are stripped in human mode.
func TestContract_TerminalCharactersStripped(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	h.failed(h.exec("a\x1b[2Jb\x07\u202e.com"), 2, false)
	if s := h.stderr.String(); strings.ContainsAny(s, "\x1b\x07\u202e") {
		t.Errorf("stderr = %q", s)
	}
}

// Every problem with the values and the settings is reported in one error,
// and nothing is created or contacted.
func TestContract_EveryProblemInOneError(t *testing.T) { //nolint:paralleltest // it changes the working directory, which a parallel test cannot
	for _, jsonMode := range []bool{false, true} {
		h := newHarness(t, defaultStageList()...)
		cwd := emptyDir(t)
		missing := filepath.Join(t.TempDir(), "absent.txt")
		args := []string{"--concurrency", "abc", "--redo", "nope", "--skip", "resolve", "bad_domain.com",
			"-d", missing, "--quiet", "--debug"}
		if jsonMode {
			args = append(args, "--json")
		}
		f := h.failed(h.exec(args...), 2, jsonMode)
		for _, want := range []string{`concurrency: invalid value "abc": not an integer`, `"nope"`, `"resolve" cannot be skipped`,
			`"bad_domain.com"`, missing, "--quiet", "--debug"} {
			if !strings.Contains(f.msg, want) {
				t.Errorf("json %v: the error does not name %q: %s", jsonMode, want, f.msg)
			}
		}
		if !strings.Contains(f.hint, "resolve") == strings.Contains(f.hint, "asn,") {
			t.Errorf("json %v: the hint does not give the valid stages: %q", jsonMode, f.hint)
		}
		if jsonMode {
			for name, want := range map[string]string{"concurrency": "abc", "redo": "nope", "skip": "resolve", "domain": "bad_domain.com", "domains-file": missing} {
				if got := f.inputOf(name); !slices.Contains(got, want) {
					t.Errorf("input[%s] = %v, want %q in it", name, got, want)
				}
			}
			if !f.hasInput("quiet") {
				t.Errorf("input does not name --quiet: %v", f.input)
			}
		}
		h.untouched()
		cwd()
	}

	// A config file problem is reported with a flag's.
	h := newHarness(t, noop())
	cfg := writeFile(t, t.TempDir(), "config.yaml", "concurency: 3\n")
	f := h.failed(h.exec("a.com", "--config", cfg, "--rate-dns", "-1"), 2, false)
	if !strings.Contains(f.msg, "concurency") || !strings.Contains(f.msg, "rate.dns") {
		t.Errorf("%+v", f)
	}
	h.untouched()
	// So is a config file that cannot be read.
	f = h.failed(h.exec("a.com", "--config", filepath.Join(t.TempDir(), "absent.yaml"), "--rate-dns", "-1"), 2, false)
	if !strings.Contains(f.msg, "absent.yaml") || !strings.Contains(f.msg, "rate.dns") {
		t.Errorf("%+v", f)
	}
	h.untouched()

	// export reports a missing -e with an unknown --kind.
	h = newHarness(t, noop())
	f = h.failed(h.exportExec("--kind", "nope", "--output", filepath.Join(t.TempDir(), "no", "x.jsonl"), "--json"), 2, true)
	if !strings.Contains(f.msg, "-e") || !strings.Contains(f.msg, `"nope"`) || !strings.Contains(f.msg, "--output") ||
		!slices.Contains(f.inputOf("kind"), "nope") || !f.hasInput("engagement") || !strings.Contains(f.hint, "finding") {
		t.Errorf("%+v", f)
	}
	h.untouched()
}

// recon -e with no inputs for an engagement that does not exist creates
// nothing, whether its directory is absent or present and empty; the same
// call gives the same error again.
func TestContract_NewEngagementWithoutInputsCreatesNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	f := h.failed(h.exec("-e", "fresh"), 3, false)
	if !strings.Contains(f.msg, "fresh") || f.code != "NOT_FOUND" {
		t.Errorf("%+v", f)
	}
	h.untouched()
	if again := h.failed(h.exec("-e", "fresh"), 3, false); !reflect.DeepEqual(again, f) {
		t.Errorf("the second call differs: %+v", again)
	}

	if err := os.Mkdir(h.eng("fresh"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.failed(h.exec("-e", "fresh"), 3, false)
	if entries, _ := os.ReadDir(h.eng("fresh")); len(entries) != 0 {
		t.Errorf("the call created %d entries in the empty engagement directory", len(entries))
	}
	// An engagement that exists resumes as before.
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if code := h.exec("-e", "a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
}

// Over the netblock limit is a usage error: the total, a hint that is the same
// call with --allow-large-netblocks and without --redo, the outputs rendered,
// and the hint runs.
func TestContract_NetblockLimit(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		before, after []string
	}{
		{nil, []string{"--redo", "asn"}},
		{[]string{"--json"}, []string{"--redo=asn"}},
		{[]string{"-q"}, nil},
	} {
		prefix := "10.0.0.0/22" // 1024 addresses
		later := &testkit.Stage{StageName: "later", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return testkit.Keys("a", 1) }}
		h := newHarness(t, newASN(), later)
		asnServer(t, h, &prefix)
		args := append(slices.Clone(c.before), "recon", "--output-dir", h.out, "--asn", "64500", "--netblock-limit", "1000")
		args = append(args, c.after...)
		jsonMode := slices.Contains(args, "--json")
		code := h.execRoot(args...)
		if code != 2 {
			t.Fatalf("%v: exit %d\n%s", args, code, h.stderr.String())
		}
		if !jsonMode && h.stdout.Len() != 0 {
			t.Errorf("%v: stdout %q", args, h.stdout.String())
		}
		f := h.theError(jsonMode)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "1024") || !strings.Contains(f.msg, "1000") {
			t.Errorf("%v: %+v", args, f)
		}
		want := "nyx " + strings.Join(append(slices.Clone(c.before), "recon", "--allow-large-netblocks", "--output-dir", h.out, "--asn", "64500", "--netblock-limit", "1000"), " ")
		if f.hint != want {
			t.Errorf("%v: hint\n got %q\nwant %q", args, f.hint, want)
		}
		if _, err := os.Stat(filepath.Join(h.eng("as64500"), "scope.csv")); err != nil {
			t.Errorf("%v: the outputs were not rendered", args)
		}
		if len(later.Executed()) != 0 {
			t.Errorf("%v: a later stage ran", args)
		}
		if code := h.execRoot(shellSplit(t, f.hint)...); code != 0 || len(later.Executed()) != 1 {
			t.Errorf("%v: running the hint: exit %d, stderr %q", args, code, h.stderr.String())
		}
	}
}

// A signal that arrives before export writes leaves stdout empty, and the
// error is INTERRUPTED with the signal's code.
func TestContract_SignalBeforeExportWrites(t *testing.T) {
	t.Parallel()
	for sig, want := range map[syscall.Signal]int{syscall.SIGINT: 130, syscall.SIGTERM: 143, syscall.SIGHUP: 129} {
		w := newExportWorld(t)
		w.h.signals = make(chan os.Signal, 1)
		w.h.signals <- sig
		f := w.h.failed(w.h.exportExec("-e", "a.com"), want, false)
		if f.code != "INTERRUPTED" || f.transient {
			t.Errorf("%s: %+v", sig, f)
		}
	}
}

// A context the caller cancels is SIGINT, and recon's hint says the completed
// work is saved.
func TestContract_CancelledContextIsAnInterrupt(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return testkit.Keys("c", 2) },
			RunFn: func(ctx context.Context, _ run.Check, _ egress.Clients) ([]run.Observation, error) {
				cancel()
				<-ctx.Done()
				return nil, ctx.Err()
			}}
		h := newHarness(t, st)
		args := []string{"a.com", "--concurrency", "1"}
		if jsonMode {
			args = append(args, "--json")
		}
		code := h.execCtx(ctx, args...)
		if code != 130 {
			t.Fatalf("exit %d", code)
		}
		f := h.theError(jsonMode)
		if f.code != "INTERRUPTED" || f.msg != "interrupted by SIGINT" || !strings.Contains(f.hint, "completed work is saved") {
			t.Errorf("%+v", f)
		}
		if !jsonMode && h.stdout.Len() != 0 {
			t.Errorf("stdout %q", h.stdout.String())
		}
		if len(h.logMsgs("WARN")) != 0 {
			t.Errorf("the interrupt is still a warning: %q", h.logMsgs("WARN"))
		}
	}
	// A deadline is not an interrupt.
	h := newHarness(t, &testkit.Stage{StageName: "slow", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return testkit.Keys("c", 1) },
		RunFn: func(ctx context.Context, _ run.Check, _ egress.Clients) ([]run.Observation, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}})
	dctx, dcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer dcancel()
	if code := h.execCtx(dctx, "a.com"); code == 130 || code == 0 {
		t.Errorf("a deadline exited %d", code)
	}
}

// boomFile is an output file whose rows panic.
func boomFile() output.File {
	return output.File{Name: "boom.csv", Format: output.CSV, Columns: []string{"x"},
		Rows: func(output.Snapshot) []output.Row { panic("row boom") }}
}

// A panic on the way to the exit is an unexpected failure: exit 1, its stack
// only under --debug, and the engagement is not left locked.
func TestContract_PanicIsAnUnexpectedFailure(t *testing.T) {
	t.Parallel()
	for _, debug := range []bool{false, true} {
		h := newHarness(t, noop())
		h.files = append(output.Default(), boomFile())
		args := []string{"a.com"}
		if debug {
			args = append(args, "--debug")
		}
		code := h.exec(args...)
		if code != 1 {
			t.Fatalf("debug %v: exit %d\n%s", debug, code, h.stderr.String())
		}
		if h.stdout.Len() != 0 {
			t.Errorf("debug %v: stdout %q", debug, h.stdout.String())
		}
		stderr := h.stderr.String()
		lines := strings.Split(strings.TrimRight(stderr, "\n"), "\n")
		hasStack := strings.Contains(stderr, "goroutine ") && strings.Contains(stderr, ".go:")
		if hasStack != debug {
			t.Errorf("debug %v: a stack on stderr: %v\n%s", debug, hasStack, stderr)
		}
		last := lines[len(lines)-1]
		if debug {
			if last != "error: unexpected failure: row boom (UNEXPECTED_ERROR)" {
				t.Errorf("the error is not the last line: %q", last)
			}
		} else if f := h.theError(false); f.code != "UNEXPECTED_ERROR" || f.msg != "unexpected failure: row boom" || f.hint != "add --debug for the stack trace" {
			t.Errorf("%+v", f)
		}
		// Not locked: the next run opens it.
		h.files = nil
		if code := h.exec("-e", "a.com"); code != 0 {
			t.Errorf("debug %v: the next run: exit %d\n%s", debug, code, h.stderr.String())
		}
	}
	// In JSON mode too; the event lines written before it stay on stdout.
	h := newHarness(t, noop())
	h.files = append(output.Default(), boomFile())
	if code := h.exec("a.com", "--json"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if f := h.theError(true); f.code != "UNEXPECTED_ERROR" {
		t.Errorf("%+v", f)
	}
}

// A panic inside one check is that check's failure: the run carries on, the
// other checks complete, and the panicking ones are retried next run.
func TestContract_PanicInACheckFailsOnlyThatCheck(t *testing.T) {
	t.Parallel()
	panics := map[string]bool{"c001": true, "c003": true, "c005": true}
	var armed = true
	st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return testkit.Keys("c", 6) },
		RunFn: func(_ context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
			if armed && panics[c.Key] {
				panic("check boom " + c.Key)
			}
			return []run.Observation{obs("hostname", c.Key+".a.com")}, nil
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--concurrency", "1", "--debug"); code != 7 {
		t.Fatalf("exit %d, want 7: a panicking check is a failed check\n%s", code, h.stderr.String())
	}
	if got := h.completed("a.com", "s"); !slices.Equal(got, []string{"c000", "c002", "c004"}) {
		t.Errorf("completed = %v", got)
	}
	debug := strings.Join(h.debugLines(), "\n")
	if !strings.Contains(debug, "s check c001 failed: panic: check boom c001") || !strings.Contains(debug, "goroutine ") {
		t.Errorf("DEBUG lines lack the panic and its stack:\n%s", debug)
	}
	armed = false
	st.Reset()
	if code := h.exec("-e", "a.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got := sorted(st.Executed()); !slices.Equal(got, []string{"c001", "c003", "c005"}) {
		t.Errorf("retried %v", got)
	}

	// A panic while a stage lists its checks fails the enumeration, and the run
	// carries on to the next stage.
	enum := &testkit.Stage{StageName: "enum", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { panic("enum boom") }}
	after := &testkit.Stage{StageName: "after", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return testkit.Keys("a", 1) }}
	h = newHarness(t, enum, after)
	if code := h.exec("a.com", "--json"); code != 7 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	if len(after.Executed()) != 1 {
		t.Error("the next stage did not run")
	}
	if s := lastState(h.events(), "enum"); s.str("state") != "failed" {
		t.Errorf("enum = %v", s)
	}
}

// No command prompts: on a terminal and without --authorised a target stage is
// not-configured (no authorisation) with the warning, and nothing reaches the
// target; --authorised stores the acknowledgement for later runs.
func TestContract_NoPrompt(t *testing.T) {
	t.Parallel()
	st := ackStage()
	h := newHarness(t, st)
	h.stdoutTTY, h.stderrTTY = true, true
	h.setenv("NO_COLOR", "1") // terminals, with plain lines to read
	if code := h.exec("a.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	if strings.Contains(h.stderr.String(), "[y/N]") || strings.Contains(h.stderr.String(), "Confirm") {
		t.Errorf("a prompt: %q", h.stderr.String())
	}
	if !slices.ContainsFunc(h.logLines(), func(l logLine) bool { return strings.Contains(l.msg, "not-configured (no authorisation)") }) {
		t.Errorf("the stage is not not-configured (no authorisation):\n%s", h.stderr.String())
	}
	if w := h.logMsgs("WARN"); len(w) != 1 || !strings.Contains(w[0], "--authorised") {
		t.Errorf("WARN lines %q", w)
	}
	if len(st.Executed()) != 0 || h.network() != 0 {
		t.Errorf("the target stage ran: %v", st.Executed())
	}
	if code := h.exec("-e", "a.com", "--authorised"); code != 0 || len(st.Executed()) != 3 {
		t.Fatalf("--authorised: exit %d, executed %v", code, st.Executed())
	}
	st.Reset()
	if code := h.exec("-e", "a.com", "b.com"); code != 0 || !slices.Equal(st.Executed(), []string{"r:b.com"}) {
		t.Errorf("a later run without --authorised: exit %d, executed %v", code, st.Executed())
	}
}

// A .env file in the working directory changes nothing.
func TestContract_DotEnvIsNotLoaded(t *testing.T) {
	keyed := &testkit.Stage{StageName: "keyed", Kind: run.ThirdParty, ChecksFn: func(run.View) []run.Check { return testkit.Keys("k", 1) },
		ConfiguredFn: func(e run.Env) (bool, string) {
			if e.Settings.Keys["fake"].Reveal() == "" {
				return false, "no key"
			}
			return true, ""
		}}
	h := newHarness(t, keyed)
	dir := t.TempDir()
	t.Chdir(dir)
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	writeFile(t, dir, ".env", "NYX_OUTPUT_DIR="+elsewhere+"\nNYX_KEYS_FAKE=dotenvkey\n")
	if code := h.exec("a.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	if _, err := os.Stat(elsewhere); err == nil {
		t.Error("the .env output directory was used")
	}
	if len(keyed.Executed()) != 0 {
		t.Error("the .env key was used")
	}
	if _, err := os.Stat(filepath.Join(h.out, "a.com", ".nyx", "state.db")); err != nil {
		t.Error("the engagement is not under --output-dir")
	}
}
