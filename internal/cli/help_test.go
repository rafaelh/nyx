package cli_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/run"
)

// proceduresHelp is the output of nyx help procedures.
func (h *harness) proceduresHelp() string {
	h.t.Helper()
	if code := h.execRoot("help", "procedures"); code != 0 {
		h.t.Fatalf("help procedures: exit %d, stderr %q", code, h.stderr.String())
	}
	return h.stdout.String()
}

// procedureRow is the row of the procedures topic for procedure, or "" when it has none.
func procedureRow(topic, procedure string) string {
	for line := range strings.SplitSeq(topic, "\n") {
		if f := strings.Fields(line); len(f) > 0 && strings.TrimSuffix(f[0], "*") == procedure {
			return line
		}
	}
	return ""
}

// Help uses terminal colour/layout only when appropriate. NO_COLOR keeps layout; JSON uses
// plain output. Separate goldens pin non-terminal text.
func TestHelp_Colour(t *testing.T) {
	t.Parallel()
	d := palette.TrueColor
	heading := func(s string) string { return d.BoldText(palette.Semantic, "info", s) }
	muted := func(s string) string { return d.Text(palette.Semantic, "muted", s) }

	// The root help is coloured by the same rules.
	rootPlain, rootColoured := helpOff(t, "--help"), helpOn(t, d, 300, "--help")
	if strings.Contains(rootPlain, "\x1b") || !strings.Contains(rootColoured, heading("Examples:")+"\n") ||
		!strings.Contains(rootColoured, d.Text(palette.Semantic, "info", "--passive")) {
		t.Errorf("root help colour:\n%s", rootColoured)
	}

	plain, coloured := helpOff(t, "recon", "--help"), helpOn(t, d, 300, "recon", "--help")
	if strings.Contains(plain, "\x1b") {
		t.Error("help to a pipe is coloured")
	}
	for _, want := range []string{heading("Flags:"), heading("Configuration:"), heading("Examples:"), heading("Usage:"),
		d.Text(palette.Semantic, "info", "--passive"), muted(" (e.g.: 37,53,79-81,443)"), "line " + muted("(# comments allowed)"),
		"name " + muted("(repeatable)"), muted(" string")} {
		if !strings.Contains(coloured, want) {
			t.Errorf("coloured help lacks %q", want)
		}
	}
	// An example's nyx call is in the example colour, and its indent and label are not.
	example := func(s string) string { return d.Text(palette.Semantic, "example", s) }
	for _, want := range []string{"\n  " + example("nyx recon example.com --json --timeout 30m") + "\n"} {
		if !strings.Contains(coloured, want) {
			t.Errorf("recon --help lacks the coloured example %q", want)
		}
	}
	if want := "\n  Example: " + example("nyx cve CVE-2021-44228 CVE-2024-3094 --json") + "\n"; !strings.Contains(rootColoured, want) {
		t.Errorf("root help lacks the coloured example %q", want)
	}
	// Removing styles preserves help content apart from width-dependent paragraph reflow.
	words := func(s string) []string { return strings.Fields(sgr.ReplaceAllString(s, "")) }
	if !slices.Equal(words(coloured), strings.Fields(plain)) {
		t.Error("coloured help differs from the plain help in more than colour and layout")
	}

	// Findings help uses severity badges.
	if got := helpOn(t, d, 80, "help", "findings"); !strings.Contains(got, d.Value(palette.Severity, "high")) {
		t.Errorf("findings topic severities are not badges:\n%s", got)
	}
	if got := helpOff(t, "help", "findings"); strings.Contains(got, "\x1b") {
		t.Error("findings topic to a pipe is coloured")
	}
	if got := helpOn(t, d, 80, "--help", "--json"); strings.Contains(got, "\x1b") {
		t.Error("help under --json is coloured")
	}
	if got := helpOn(t, d, 300, "recon", "export", "--help"); !strings.Contains(got, d.Bold("Kinds accepted by --kind:")) || !strings.Contains(got, "this kind "+muted("(repeatable)")+";") {
		t.Errorf("export help is not coloured:\n%s", got)
	}
	if got := helpOn(t, palette.None, 300, "recon", "--help"); strings.Contains(got, "\x1b") || strings.Join(strings.Fields(got), " ") != strings.Join(strings.Fields(plain), " ") {
		t.Error("help under NO_COLOR differs from the plain help in more than layout")
	}
}

// First-positional help acts as --help after subcommands/flag values, but stays literal after
// other arguments or --.
func TestHelp_HelpWord(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ args, same []string }{
		{[]string{"recon", "help"}, []string{"help", "recon"}},
		{[]string{"recon", "export", "help"}, []string{"help", "recon", "export"}},
		{[]string{"recon", "help", "export"}, []string{"help", "recon", "export"}},
		{[]string{"recon", "-e", "help", "help"}, []string{"help", "recon"}},
		{[]string{"cve", "help"}, []string{"help", "cve"}},
		{[]string{"ip", "--json", "help"}, []string{"help", "ip"}},
		{[]string{"help", "help"}, []string{"help"}},
	} {
		if got, want := helpOff(t, tc.args...), helpOff(t, tc.same...); got != want {
			t.Errorf("%v is not the help of %v:\n%s", tc.args, tc.same, got)
		}
	}
	for _, args := range [][]string{{"recon", "--", "help"}, {"ip", "--", "help"}, {"recon", "example.com", "help"}} {
		h := newHarness(t, noop())
		if code := h.execRoot(args...); code != 2 || strings.Contains(h.stdout.String(), "Usage:") {
			t.Errorf("%v: exit %d, stdout %q, want a usage error", args, code, h.stdout.String())
		}
	}
}

// helpOff is a help screen written to a stream that is not a terminal.
func helpOff(t *testing.T, args ...string) string {
	t.Helper()
	h := newHarness(t, noop())
	if code := h.execRoot(args...); code != 0 {
		t.Fatalf("%v: exit %d, stderr %q", args, code, h.stderr.String())
	}
	return h.stdout.String()
}

// The procedures topic follows registry order and marks required procedures; recon help omits the full
// list.
func TestHelp_ProceduresTopic(t *testing.T) {
	t.Parallel()
	procedures := defaultProcedureList()
	h := newHarness(t, procedures...)
	topic := h.proceduresHelp()
	last := -1
	for _, s := range procedures {
		row := procedureRow(topic, s.Name())
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
			t.Errorf("help procedures lacks %q", want)
		}
	}

	if code := h.exec("--help"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	help := h.stdout.String()
	if strings.Contains(help, "Procedures accepted by --redo") || strings.Contains(help, "sensitive-paths, ports") {
		t.Error("--help still lists the procedures")
	}
	if !strings.Contains(help, "see nyx help procedures") {
		t.Error("recon --help does not point to nyx help procedures")
	}
	if code := h.execRoot("--help"); code != 0 || !strings.Contains(h.stdout.String(), "nyx help procedures") {
		t.Error("the root help does not list nyx help procedures")
	}

	// Terminal procedures tables warn-colour target contact; detailed layout is tested
	// separately.
	colourAt(t, h, palette.TrueColor)
	coloured := h.proceduresHelp()
	if !strings.Contains(coloured, palette.TrueColor.Text(palette.Semantic, "warning", "target")) {
		t.Errorf("target contact is not coloured:\n%s", coloured)
	}
	for _, s := range procedures {
		if !strings.Contains(sgr.ReplaceAllString(coloured, ""), s.Name()) {
			t.Errorf("%s is missing from the coloured topic", s.Name())
		}
	}
}
