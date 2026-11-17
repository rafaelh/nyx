package cli_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/run"
)

// stagesHelp is the output of nyx help stages.
func (h *harness) stagesHelp() string {
	h.t.Helper()
	if code := h.execRoot("help", "stages"); code != 0 {
		h.t.Fatalf("help stages: exit %d, stderr %q", code, h.stderr.String())
	}
	return h.stdout.String()
}

// stageRow is the row of the stages topic for stage, or "" when it has none.
func stageRow(topic, stage string) string {
	for line := range strings.SplitSeq(topic, "\n") {
		if f := strings.Fields(line); len(f) > 0 && strings.TrimSuffix(f[0], "*") == stage {
			return line
		}
	}
	return ""
}

// --help is coloured on a terminal, with the same words in the same order as
// the plain help, and plain when stdout is not a terminal, under NO_COLOR and
// under --json.
func TestHelp_Colour(t *testing.T) {
	t.Parallel()
	help := func(tty bool, env map[string]string, args ...string) string {
		t.Helper()
		h := newHarness(t, noop())
		if tty {
			colourAt(t, h, palette.TrueColor)
		}
		for k, v := range env {
			h.setenv(k, v)
		}
		if code := h.execRoot(args...); code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", args, code, h.stderr.String())
		}
		return h.stdout.String()
	}

	// The root help is coloured by the same rules.
	rootPlain, rootColoured := help(false, nil, "--help"), help(true, nil, "--help")
	if strings.Contains(rootPlain, "\x1b") || !strings.Contains(rootColoured, "\x1b[1mExamples:\x1b[0m") ||
		!strings.Contains(rootColoured, "--passive\x1b[0m") || sgr.ReplaceAllString(rootColoured, "") != rootPlain {
		t.Errorf("root help colour:\n%s", rootColoured)
	}

	plain, coloured := help(false, nil, "recon", "--help"), help(true, nil, "recon", "--help")
	if strings.Contains(plain, "\x1b") {
		t.Error("help to a pipe is coloured")
	}
	for _, want := range []string{"\x1b[1mFlags:\x1b[0m", "\x1b[1mConfiguration:\x1b[0m", "--passive\x1b[0m", "\x1b[1mExamples:\x1b[0m",
		"\x1b[38;2;124;129;145m (e.g.: 37,53,79-81,443)\x1b[0m",
		"line \x1b[38;2;124;129;145m(# comments allowed)\x1b[0m", "name \x1b[38;2;124;129;145m(repeatable)\x1b[0m"} {
		if !strings.Contains(coloured, want) {
			t.Errorf("coloured help lacks %q", want)
		}
	}
	// Removing the colour leaves the plain text, but for the width of the
	// findings table's severity badges.
	stripped := sgr.ReplaceAllString(coloured, "")
	if strings.Join(strings.Fields(stripped), " ") != strings.Join(strings.Fields(plain), " ") {
		t.Error("coloured help differs from the plain help in more than colour and spacing")
	}
	for line := range strings.SplitSeq(stripped, "\n") {
		if !strings.Contains(plain, line) && !strings.Contains(line, "  high ") && !strings.Contains(line, "  medium ") && !strings.Contains(line, "  low ") {
			t.Errorf("coloured help line not in the plain help: %q", line)
		}
	}

	// The findings topic is coloured too, its severities as badges.
	if got := help(true, nil, "help", "findings"); !strings.Contains(got, " high     \x1b[0m") {
		t.Errorf("findings topic severities are not badges:\n%s", got)
	}
	if got := help(false, nil, "help", "findings"); strings.Contains(got, "\x1b") {
		t.Error("findings topic to a pipe is coloured")
	}
	if got := help(true, nil, "--help", "--json"); strings.Contains(got, "\x1b") {
		t.Error("help under --json is coloured")
	}
	if got := help(true, nil, "recon", "export", "--help"); !strings.Contains(got, "\x1b[1mKinds accepted by --kind:\x1b[0m") ||
		!strings.Contains(got, "this kind \x1b[38;2;124;129;145m(repeatable)\x1b[0m;") {
		t.Errorf("export help is not coloured:\n%s", got)
	}
	if got := help(true, map[string]string{"NO_COLOR": "1"}, "recon", "--help"); got != plain {
		t.Error("help under NO_COLOR differs from the plain help")
	}
}

// nyx help stages lists every registered stage in run order with whom it
// contacts and what it does, marks the stages --skip refuses, and the stage
// list is not in recon --help.
func TestHelp_StagesTopic(t *testing.T) {
	t.Parallel()
	stages := defaultStageList()
	h := newHarness(t, stages...)
	topic := h.stagesHelp()
	last := -1
	for _, s := range stages {
		row := stageRow(topic, s.Name())
		if row == "" {
			t.Errorf("%s is not listed", s.Name())
			continue
		}
		if at := strings.Index(topic, row); at < last {
			t.Errorf("%s is out of run order", s.Name())
		} else {
			last = at
		}
		contact := "third party"
		if s.Contact() == run.Target {
			contact = "target"
		}
		f := strings.Fields(strings.Replace(row, contact, "", 1))
		if !strings.Contains(row, "  "+contact+"  ") || len(f) < 3 {
			t.Errorf("%s: row %q lacks its contact (%s) or what it does", s.Name(), row, contact)
		}
		unskippable := slices.Contains([]string{"resolve", "wildcard", "ipowner", "providerranges"}, s.Name())
		if starred := strings.HasPrefix(strings.TrimSpace(row), s.Name()+"*"); starred != unskippable {
			t.Errorf("%s: marked * = %v, want %v", s.Name(), starred, unskippable)
		}
	}
	for _, want := range []string{"--passive", "--redo", "--skip", "keys.<KEY>"} {
		if !strings.Contains(topic, want) {
			t.Errorf("help stages lacks %q", want)
		}
	}

	if code := h.exec("--help"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	help := h.stdout.String()
	if strings.Contains(help, "Stages accepted by --redo") || strings.Contains(help, "sensitive-paths, ports") {
		t.Error("--help still lists the stages")
	}
	if !strings.Contains(help, "see nyx help stages") {
		t.Error("recon --help does not point to nyx help stages")
	}
	if code := h.execRoot("--help"); code != 0 || !strings.Contains(h.stdout.String(), "nyx help stages") {
		t.Error("the root help does not list nyx help stages")
	}

	// On a terminal a target stage's contact is in the warning colour, and
	// removing the colour leaves the plain table.
	colourAt(t, h, palette.TrueColor)
	coloured := h.stagesHelp()
	if !strings.Contains(coloured, "\x1b[38;2;236;208;143mtarget\x1b[0m") {
		t.Errorf("target contact is not coloured:\n%s", coloured)
	}
	if sgr.ReplaceAllString(coloured, "") != topic {
		t.Error("the coloured topic differs from the plain one in more than colour")
	}
}
