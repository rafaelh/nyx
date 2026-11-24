package cli_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// The topic's old name is unknown: it exits 2 as any unknown help topic does, and the commands
// its error lists have procedures and not the old name.
func TestProceduresTopic_OldNameIsUnknown(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonMode), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, helpProcedures()...)
			f := h.failed(h.execRoot(jsonArgs(jsonMode, "help", "stages")...), 2, jsonMode)
			if f.code != "INVALID_INPUT" {
				t.Errorf("code = %s, want INVALID_INPUT: %+v", f.code, f)
			}
			_, list, ok := strings.Cut(f.msg, "the commands are ")
			if !ok || !strings.HasPrefix(f.msg, `unknown command "stages"`) {
				t.Fatalf("message = %q, want the unknown command and the list of commands", f.msg)
			}
			commands := strings.Split(list, ", ")
			if !slices.Contains(commands, "procedures") || slices.Contains(commands, "stages") {
				t.Errorf("commands = %q, want procedures and not the old name", commands)
			}
			h.untouched()
		})
	}
}

// recon's flags describe their values in the new words.
func TestProceduresTopic_FlagDescriptions(t *testing.T) {
	t.Parallel()
	h := newHarness(t, helpProcedures()...)
	if code := h.execRoot("recon", "--help"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	help := strings.Join(strings.Fields(h.stdout.String()), " ")
	for _, want := range []string{
		"--redo string Re-perform every job of one procedure (see nyx help procedures)",
		"Procedure to turn off for this run (",
		"see nyx help procedures)",
		"Workers per procedure",
		"each failed job (recon)",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("recon --help lacks %q:\n%s", want, h.stdout.String())
		}
	}
}

// The failed-jobs error, the per-procedure console line and the summary's heading say
// "procedure" and "job".
func TestProceduresTopic_FailedJobsInTheNewWords(t *testing.T) {
	t.Parallel()
	h := newHarness(t, erring("alpha", 2, errors.New("boom")), erring("beta", 1, errors.New("boom")), finder("gamma"))
	f := h.partial(h.exec("a.com"), false)
	if f.msg != "3 jobs failed: alpha 2, beta 1" {
		t.Errorf("message = %q, want %q", f.msg, "3 jobs failed: alpha 2, beta 1")
	}
	var lines []string
	for _, m := range h.logMsgs("INFO") {
		lines = append(lines, strings.Join(strings.Fields(m), " "))
	}
	if !slices.Contains(lines, "gamma done (1 jobs, 0 failed)") {
		t.Errorf("INFO lines = %q, want gamma done (1 jobs, 0 failed)", lines)
	}
	if !strings.Contains(h.stdout.String(), "Failed jobs (retried on the next run; --debug shows each failure)") {
		t.Errorf("summary:\n%s", h.stdout.String())
	}
}

// The setup Skip tab lists the procedures --skip accepts, with what each does, and its problems
// name an unknown or required procedure in the new words.
func TestProceduresTopic_SetupSkipTabListsProcedures(t *testing.T) {
	t.Parallel()
	h := newHarness(t, helpProcedures()...)
	h.stdinTTY, h.stdoutTTY, h.winW, h.winH = true, true, 120, 30
	h.cwd = t.TempDir()
	path := writeFile(t, t.TempDir(), "nyx.yaml", "skip: [crtsh, nosuchproc, resolve]\n")
	if code := h.setup([]string{"--config", path}, keyTab, keyTab, "q", "d"); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	if got := readFileOrEmpty(t, path); got != "skip: [crtsh, nosuchproc, resolve]\n" {
		t.Errorf("the file changed: %q", got)
	}
	out := h.stdout.String()
	for _, want := range []string{
		"crtsh", "Subdomains from certificate transparency logs (crt.sh)",
		"httpprobe", "ports",
		`unknown procedure "nosuchproc" for --skip or the skip setting`,
		`procedure "resolve" cannot be skipped: other procedures' safety depends on it`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the Skip tab does not show %q", want)
		}
	}
}
