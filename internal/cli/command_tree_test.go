package cli_test

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rafaelh/nyx/internal/kinds"
)

// exitCodesLine is the last line of every help text.
const exitCodesLine = "Exit codes: 0 success, 1 system error, 2 usage error, 3 not found, 7 partial result, 130/143/129 interrupted (SIGINT/SIGTERM/SIGHUP)"

// emptyDir makes an empty directory the working directory, and returns a check
// that nothing was created in it.
func emptyDir(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	return func() {
		t.Helper()
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Errorf("the call created %d entries in the working directory", len(entries))
		}
	}
}

// A call in the form nyx took before it had commands exits 2 with the caller's
// own arguments as the hint, recon inserted, and does nothing else.
func TestTree_OldFormCallsGetTheCorrectedCommand(t *testing.T) { //nolint:paralleltest // it changes the working directory, which a parallel test cannot
	cases := []struct {
		args     []string
		hint     string
		argument string
	}{
		{[]string{"example.com"}, "nyx recon example.com", "example.com"},
		{[]string{"-e", "acme"}, "nyx recon -e acme", "-e"},
		{[]string{"--passive", "example.com"}, "nyx recon --passive example.com", "--passive"},
		{[]string{"--json", "example.com"}, "nyx recon --json example.com", "example.com"},
		{[]string{"export", "-e", "acme"}, "nyx recon export -e acme", "export"},
		// recon here is the value of -e, not the command.
		{[]string{"-e", "recon"}, "nyx recon -e recon", "-e"},
		{[]string{"--org", "Acme Pty", "it's.example.com"}, `nyx recon --org 'Acme Pty' 'it'\''s.example.com'`, "--org"},
		{[]string{"-q", "--engagement=acme", "--debug"}, "nyx recon -q --engagement=acme --debug", "--engagement=acme"},
		// cve also takes --config and --timeout; a first positional with a dot is still a domain.
		{[]string{"--config", "c.yaml", "example.com"}, "nyx recon --config c.yaml example.com", "--config"},
		{[]string{"--timeout", "30m", "example.com"}, "nyx recon --timeout 30m example.com", "--timeout"},
	}
	for _, c := range cases {
		for _, jsonMode := range []bool{false, true} {
			args, hint, ok := oldFormInMode(c.args, c.hint, jsonMode)
			if !ok {
				continue
			}
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				checkOldFormCall(t, args, hint, c.argument, jsonMode)
			})
		}
	}
}

// oldFormInMode is an old-form call and its hint in JSON mode or not: --json
// is added when jsonMode asks for it. ok is false for a call that already
// passes --json when jsonMode does not, as the call is in JSON mode whatever
// jsonMode says.
func oldFormInMode(args []string, hint string, jsonMode bool) (_ []string, _ string, ok bool) {
	switch {
	case slices.Contains(args, "--json"):
		return args, hint, jsonMode
	case jsonMode:
		return append(slices.Clone(args), "--json"), hint + " --json", true
	}
	return args, hint, true
}

// checkOldFormCall checks that an old-form call is a usage error with the
// corrected command as its hint, names the argument under --json, touches
// nothing, and gives the same error when repeated.
func checkOldFormCall(t *testing.T, args []string, hint, argument string, jsonMode bool) {
	t.Helper()
	h := newHarness(t, noop())
	cwd := emptyDir(t)
	f := h.failed(h.execRoot(args...), 2, jsonMode)
	if f.code != "INVALID_INPUT" || f.hint != hint {
		t.Errorf("code %s, hint %q; want INVALID_INPUT and %q", f.code, f.hint, hint)
	}
	if !strings.Contains(f.msg, "command") {
		t.Errorf("the message does not say nyx takes a command: %q", f.msg)
	}
	if jsonMode {
		if got := f.inputOf("argument"); len(got) != 1 || got[0] != argument {
			t.Errorf("input = %v, want the argument %q", f.input, argument)
		}
	}
	h.untouched()
	cwd()
	// The same call again gives the same error.
	if again := h.failed(h.execRoot(args...), 2, jsonMode); fmt.Sprint(again) != fmt.Sprint(f) {
		t.Errorf("a second call differs: %+v, then %+v", f, again)
	}
}

// A bare nyx, nyx --help and nyx help print the same help and exit 0; help
// <command> is that command's --help.
func TestTree_HelpIsBareNyxAndTheHelpCommand(t *testing.T) { //nolint:paralleltest // it changes the working directory, which a parallel test cannot
	h := newHarness(t, noop())
	cwd := emptyDir(t)
	if code := h.execRoot("--help"); code != 0 || h.stderr.Len() != 0 {
		t.Fatalf("--help: exit %d, stderr %q", code, h.stderr.String())
	}
	want := h.stdout.String()
	if !strings.HasPrefix(want, "Examples:\n") {
		t.Fatalf("the root help does not open with examples:\n%s", want)
	}
	for _, args := range [][]string{{}, {"help"}, {"-h"}, {"--json"}, {"-q", "--help"}, {"help", "--json"}} {
		if code := h.execRoot(args...); code != 0 || h.stdout.String() != want || h.stderr.Len() != 0 {
			t.Errorf("nyx %v: exit %d, stderr %q, and its stdout is the root help: %v", args, code, h.stderr.String(), h.stdout.String() == want)
		}
	}
	for _, c := range [][2][]string{
		{{"help", "recon"}, {"recon", "--help"}},
		{{"help", "recon", "export"}, {"recon", "export", "--help"}},
	} {
		if code := h.execRoot(c[1]...); code != 0 {
			t.Fatalf("nyx %v: exit %d", c[1], code)
		}
		own := h.stdout.String()
		if code := h.execRoot(c[0]...); code != 0 || h.stdout.String() != own {
			t.Errorf("nyx %v (exit %d) is not what nyx %v prints", c[0], code, c[1])
		}
	}
	h.untouched()
	cwd()
}

// A first word that is no command is a usage error that names the commands,
// and prints no help.
func TestTree_UnknownCommand(t *testing.T) { //nolint:paralleltest // it changes the working directory, which a parallel test cannot
	for _, jsonMode := range []bool{false, true} {
		for _, args := range [][]string{{"frob"}, {"frob", "example.com"}, {"help", "frob"}} {
			h := newHarness(t, noop())
			cwd := emptyDir(t)
			if jsonMode {
				args = append(slices.Clone(args), "--json")
			}
			f := h.failed(h.execRoot(args...), 2, jsonMode)
			if f.code != "INVALID_INPUT" || f.hint != "nyx --help" || !strings.Contains(f.msg, `"frob"`) {
				t.Errorf("nyx %v: %+v", args, f)
			}
			if args[0] == "frob" && !strings.Contains(f.msg, "recon") {
				t.Errorf("nyx %v: the message does not name the commands: %q", args, f.msg)
			}
			if jsonMode && args[0] == "frob" {
				if got := f.inputOf("command"); len(got) != 1 || got[0] != "frob" {
					t.Errorf("nyx %v: input = %v", args, f.input)
				}
			}
			if all := h.stdout.String() + h.stderr.String(); strings.Contains(all, "Examples:") || strings.Contains(all, "Exit codes:") {
				t.Errorf("nyx %v printed the help:\n%s", args, all)
			}
			h.untouched()
			cwd()
		}
	}
}

// exampleLines are the lines of the examples block a help text opens with.
func exampleLines(t *testing.T, help string) []string {
	t.Helper()
	block, _, _ := strings.Cut(strings.TrimPrefix(help, "Examples:\n"), "\n\n")
	if !strings.HasPrefix(help, "Examples:\n") || block == "" {
		t.Fatalf("the help does not open with examples:\n%s", help)
	}
	return strings.Split(block, "\n")
}

// lastLine is the last line of a help text.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

// The root help is the whole reference: examples that pass --json (nyx setup's is the exception), every
// command with its everyday flags, an example and the values of its fixed-set
// flags, and the exit codes; recon's tuning settings are only in recon's own.
func TestTree_RootHelpIsTheWholeReference(t *testing.T) {
	t.Parallel()
	h := newHarness(t, defaultStageList()...)
	if code := h.execRoot("--help"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	help := h.stdout.String()
	for _, l := range exampleLines(t, help) {
		if strings.TrimSpace(l) == "nyx setup" {
			continue // an editor on a terminal: --json changes only its error, so its example has none
		}
		if !strings.HasPrefix(strings.TrimSpace(l), "nyx ") || !strings.Contains(l, "--json") {
			t.Errorf("example %q is not a nyx call that passes --json", l)
		}
	}
	wants := []string{
		// Every command of the tree, each with one example.
		"nyx recon [domain...] [flags]", "nyx recon export -e <engagement> [flags]", "nyx help",
		"Example: nyx recon ", "Example: nyx recon export ",
		// recon's everyday flags.
		"-d, --domains-file", "--org", "--asn", "--cidr", "-x, --exclude", "--exclude-file", "-e, --engagement",
		"--passive", "--authorised", "--redo", "--skip", "--allow-large-netblocks", "--config", "--output-dir",
		// The shared flags, and where they may go.
		"-J, --json", "-q, --quiet", "--debug", "before the command",
		// export's flags.
		"--output ", "--current", "--kind",
		"--version", "-h, --help",
		// Where the rest of recon's flags are.
		"nyx recon --help",
		// The help topics.
		"nyx help stages", "nyx help findings",
	}
	for _, s := range h.stages {
		wants = append(wants, s.Name())
	}
	for _, k := range kinds.All() {
		wants = append(wants, k.Name)
	}
	for _, want := range append(wants, "input", "exclusion") {
		if !strings.Contains(help, want) {
			t.Errorf("the root help lacks %q", want)
		}
	}
	// The stages --skip refuses are named as such.
	if !strings.Contains(help, "resolve, wildcard, ipowner, providerranges") {
		t.Error("the root help does not name the stages --skip refuses")
	}
	if got := lastLine(help); got != exitCodesLine {
		t.Errorf("the root help ends with %q, want the exit codes", got)
	}
	if strings.Contains(help, "palette") {
		t.Error("the root help lists the hidden --palette")
	}

	// A tuning setting is in recon's help and not in the root's.
	if code := h.exec("--help"); code != 0 {
		t.Fatalf("recon --help: exit %d", code)
	}
	recon := h.stdout.String()
	for _, tuning := range []string{"--rate-per-host", "--concurrency", "--crawl-depth", "--ports"} {
		if strings.Contains(help, tuning) || !strings.Contains(recon, tuning) {
			t.Errorf("%s: in the root help %v, in recon's help %v; want false and true",
				tuning, strings.Contains(help, tuning), strings.Contains(recon, tuning))
		}
	}
}

// Each command's own help opens with examples and ends with the exit codes.
func TestTree_CommandHelpOpensWithExamplesAndEndsWithExitCodes(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	for _, args := range [][]string{{"recon", "--help"}, {"recon", "export", "--help"}, {"recon", "-h"}} {
		if code := h.execRoot(args...); code != 0 || h.stderr.Len() != 0 {
			t.Fatalf("nyx %v: exit %d, stderr %q", args, code, h.stderr.String())
		}
		help := h.stdout.String()
		for _, l := range exampleLines(t, help) {
			if !strings.HasPrefix(strings.TrimSpace(l), "nyx recon") {
				t.Errorf("nyx %v: example %q is not a call of the command", args, l)
			}
		}
		if strings.Count(help, "Examples:") != 1 {
			t.Errorf("nyx %v: the examples are printed %d times", args, strings.Count(help, "Examples:"))
		}
		if got := lastLine(help); got != exitCodesLine {
			t.Errorf("nyx %v ends with %q, want the exit codes", args, got)
		}
		for _, want := range []string{"Usage:", "Flags:", "--json", "--quiet", "--debug"} {
			if !strings.Contains(help, want) {
				t.Errorf("nyx %v lacks %q", args, want)
			}
		}
	}
}

// reconWithFlags runs recon for a.com with the given arguments before and
// after the command, and returns its exit code.
func reconWithFlags(h *harness, before, after []string) int {
	args := append(slices.Clone(before), "recon", "--output-dir", h.out, "a.com")
	return h.execRoot(append(args, after...)...)
}

// --json, --quiet and --debug are taken before and after the command, by
// every command.
func TestTree_SharedFlagsBeforeAndAfterTheCommand(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		flag  string
		check func(t *testing.T, h *harness)
	}{
		{"--json", func(t *testing.T, h *harness) {
			// The failed check makes the run partial: stdout is the one envelope, and stderr is the
			// error and nothing else.
			h.envelope()
			if f := h.theError(true); f.code != "PARTIAL" || len(h.logLines()) != 0 {
				t.Errorf("stderr is not the one error: %q", h.stderr.String())
			}
		}},
		{"-J", func(t *testing.T, h *harness) {
			h.envelope()
		}},
		{"--quiet", func(t *testing.T, h *harness) {
			if len(h.logMsgs("INFO")) != 0 || !strings.HasPrefix(h.stdout.String(), "Summary\n") {
				t.Errorf("INFO lines %q, stdout %q", h.logMsgs("INFO"), h.stdout.String())
			}
		}},
		{"-q", func(t *testing.T, h *harness) {
			if len(h.logMsgs("INFO")) != 0 {
				t.Errorf("INFO lines %q", h.logMsgs("INFO"))
			}
		}},
		{"--debug", func(t *testing.T, h *harness) {
			if len(h.debugLines()) != 1 || len(h.logMsgs("INFO")) == 0 {
				t.Errorf("DEBUG lines %q", h.debugLines())
			}
		}},
	} {
		for _, before := range []bool{true, false} {
			h := newHarness(t, failingCheck("boom"))
			var code int
			if before {
				code = reconWithFlags(h, []string{c.flag}, nil)
			} else {
				code = reconWithFlags(h, nil, []string{c.flag})
			}
			if code != 7 { // failingCheck's failed check makes the run partial
				t.Fatalf("%s (before the command: %v): exit %d\n%s", c.flag, before, code, h.stderr.String())
			}
			c.check(t, h)
		}
	}

	checkExportTakesSharedFlags(t)

	// --json with --debug is allowed: the DEBUG line is on stderr.
	h := newHarness(t, failingCheck("boom"))
	if code := reconWithFlags(h, []string{"--json"}, []string{"--debug"}); code != 7 || len(h.debugLines()) != 1 {
		t.Errorf("--json --debug: exit %d, DEBUG lines %q", code, h.debugLines())
	}
}

// checkExportTakesSharedFlags checks that export takes the shared flags in
// both places too, and that they do not change what it writes.
func checkExportTakesSharedFlags(t *testing.T) {
	t.Helper()
	w := newExportWorld(t)
	plain := export(w.h, "-e", "a.com")
	if plain.code != 0 || plain.stdout == "" {
		t.Fatalf("export: exit %d, stderr %q", plain.code, plain.stderr)
	}
	for _, flag := range []string{"--json", "-J", "--quiet", "-q", "--debug"} {
		for _, args := range [][]string{
			{flag, "recon", "export", "--output-dir", w.h.out, "-e", "a.com"},
			{"recon", "export", "--output-dir", w.h.out, "-e", "a.com", flag},
			{"recon", flag, "export", "--output-dir", w.h.out, "-e", "a.com"},
		} {
			if code := w.h.execRoot(args...); code != 0 || w.h.stdout.String() != plain.stdout || w.h.stderr.Len() != 0 {
				t.Errorf("nyx %v: exit %d, stderr %q, same lines: %v", args, code, w.h.stderr.String(), w.h.stdout.String() == plain.stdout)
			}
		}
	}
}

// --quiet with --debug is a usage error on every command.
func TestTree_QuietWithDebugIsAUsageError(t *testing.T) { //nolint:paralleltest // it changes the working directory, which a parallel test cannot
	for _, args := range [][]string{
		{"recon", "a.com", "--quiet", "--debug"},
		{"-q", "--debug", "recon", "a.com"},
		{"recon", "export", "-e", "a.com", "-q", "--debug"},
		{"--debug", "recon", "export", "-e", "a.com", "--quiet"},
		// Help, the topics and the version are refused too, and print nothing.
		{"-q", "--debug"},
		{"--help", "-q", "--debug"},
		{"--version", "--quiet", "--debug"},
		{"help", "-q", "--debug"},
		{"help", "recon", "-q", "--debug"},
		{"recon", "--help", "-q", "--debug"},
		{"recon", "export", "-h", "--quiet", "--debug"},
		{"findings", "-q", "--debug"},
		{"help", "stages", "--debug", "--quiet"},
	} {
		h := newHarness(t, noop())
		cwd := emptyDir(t)
		f := h.failed(h.execRoot(args...), 2, false)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "--quiet") || !strings.Contains(f.msg, "--debug") {
			t.Errorf("nyx %v: %+v", args, f)
		}
		h.untouched()
		cwd()
	}
}

// None of the shared flags is a setting: no environment variable and no config
// key sets one.
func TestTree_SharedFlagsAreNotSettings(t *testing.T) {
	t.Parallel()
	h := newHarness(t, failingCheck("boom"))
	h.setenv("NYX_JSON", "1")
	h.setenv("NYX_QUIET", "1")
	h.setenv("NYX_DEBUG", "1")
	if code := h.exec("a.com"); code != 7 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if !strings.HasPrefix(h.stdout.String(), "Summary\n") || len(h.logMsgs("INFO")) == 0 || len(h.debugLines()) != 0 {
		t.Errorf("an environment variable changed the output:\nstdout %q\nstderr %q", h.stdout.String(), h.stderr.String())
	}
	for _, key := range []string{"json", "quiet", "debug"} {
		h := newHarness(t, noop())
		cfg := writeFile(t, t.TempDir(), "config.yaml", key+": true\n")
		f := h.failed(h.exec("a.com", "--config", cfg), 2, false)
		if !strings.Contains(f.msg, key) {
			t.Errorf("config key %s: %+v", key, f)
		}
		h.untouched()
	}
}

// Any other flag before the command is a usage error whose hint is the same
// call with the command moved to the front.
func TestTree_FlagBeforeTheCommand(t *testing.T) { //nolint:paralleltest // it changes the working directory, which a parallel test cannot
	for _, c := range []struct {
		args  []string
		hint  string
		flags []string
	}{
		{[]string{"--passive", "recon", "a.com"}, "nyx recon --passive a.com", []string{"--passive"}},
		{[]string{"--json", "-e", "acme", "--passive", "recon", "b c.com"}, "nyx recon --json -e acme --passive 'b c.com'", []string{"-e", "--passive"}},
		{[]string{"--org=Acme Pty", "recon"}, "nyx recon '--org=Acme Pty'", []string{"--org=Acme Pty"}},
		{[]string{"-e", "a.com", "recon", "export"}, "nyx recon -e a.com export", []string{"-e"}},
	} {
		h := newHarness(t, noop())
		cwd := emptyDir(t)
		jsonMode := slices.Contains(c.args, "--json")
		f := h.failed(h.execRoot(c.args...), 2, jsonMode)
		if f.code != "INVALID_INPUT" || f.msg != "flags follow the command" || f.hint != c.hint {
			t.Errorf("nyx %v: %+v, want the hint %q", c.args, f, c.hint)
		}
		if jsonMode && !slices.Equal(f.inputOf("flag"), c.flags) {
			t.Errorf("nyx %v: input = %v, want the flags %v", c.args, f.input, c.flags)
		}
		h.untouched()
		cwd()
	}
}

// A flag must be spelt in full; --authorized is the one alias.
func TestTree_FlagsAreSpeltInFull(t *testing.T) { //nolint:paralleltest // it changes the working directory, which a parallel test cannot
	for _, c := range []struct {
		args       []string
		flag, hint string
	}{
		{[]string{"recon", "a.com", "--pass"}, "--pass", "nyx recon --help"},
		{[]string{"recon", "a.com", "--authoris"}, "--authoris", "nyx recon --help"},
		{[]string{"recon", "a.com", "--jso"}, "--jso", "nyx recon --help"},
		{[]string{"recon", "export", "-e", "a.com", "--cur"}, "--cur", "nyx recon export --help"},
	} {
		h := newHarness(t, noop())
		cwd := emptyDir(t)
		f := h.failed(h.execRoot(append(c.args, "--json")...), 2, true)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "unknown flag: "+c.flag) || f.hint != c.hint {
			t.Errorf("nyx %v: %+v", c.args, f)
		}
		if got := f.inputOf("flag"); len(got) != 1 || got[0] != c.flag {
			t.Errorf("nyx %v: input = %v", c.args, f.input)
		}
		h.untouched()
		cwd()
	}
	st := ackStage()
	h := newHarness(t, st)
	if code := h.exec("a.com", "--authorized"); code != 0 || len(st.Executed()) != 3 {
		t.Errorf("--authorized: exit %d, executed %v", code, st.Executed())
	}
}

// Every HTTP request carries the version as its User-Agent, to a third-party
// source and to a target alike.
func TestTree_UserAgentIsTheVersion(t *testing.T) {
	t.Parallel()
	for version, want := range map[string]string{"v1.2.3": "nyx/v1.2.3", "": "nyx/devel"} {
		t.Run(want, func(t *testing.T) {
			t.Parallel()
			x := newWeb(t)
			x.h.version = version
			x.names("www.example.com")
			x.host("www.example.com", "203.0.113.10")
			var mu sync.Mutex
			var seen []string
			x.plain("203.0.113.10", 80, func(rw http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen = append(seen, r.UserAgent())
				mu.Unlock()
				page("hello")(rw, r)
			})
			if code := x.run(); code != 0 {
				t.Fatalf("exit %d", code)
			}
			reqs := x.requests("crt.sh")
			if len(reqs) == 0 || len(seen) == 0 {
				t.Fatalf("version %q: the source saw %d requests and the target %d", version, len(reqs), len(seen))
			}
			for _, r := range reqs {
				if got := r.Header.Get("User-Agent"); got != want {
					t.Errorf("version %q: a third-party request carried the User-Agent %q, want %q", version, got, want)
				}
			}
			for _, got := range seen {
				if got != want {
					t.Errorf("version %q: the target saw the User-Agent %q, want %q", version, got, want)
				}
			}
		})
	}
}
