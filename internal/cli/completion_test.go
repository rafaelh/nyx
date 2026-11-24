package cli_test

import (
	"slices"
	"strings"
	"testing"
)

// completions asks nyx for the completions of args, as a completion script does, and returns
// the candidates and the directive line.
func completions(t *testing.T, h *harness, args ...string) (cands []string, directive string) {
	t.Helper()
	if code := h.execRoot(append([]string{"__complete"}, args...)...); code != 0 {
		t.Fatalf("__complete %q: exit %d, stderr %q", args, code, h.stderr.String())
	}
	lines := strings.Split(strings.TrimRight(h.stdout.String(), "\n"), "\n")
	for _, l := range lines[:len(lines)-1] {
		name, _, _ := strings.Cut(l, "\t") // drop the description
		cands = append(cands, name)
	}
	return cands, lines[len(lines)-1]
}

// nyx completion prints the script for bash or zsh on stdout, without a terminal's margin and
// whatever the output mode, and writes and contacts nothing.
func TestCompletion_PrintsTheScript(t *testing.T) {
	t.Parallel()
	for shell, head := range map[string]string{"bash": "# bash completion V2 for nyx", "zsh": "#compdef nyx"} {
		for _, extra := range [][]string{nil, {"--json"}, {"-q"}} {
			h := newHarness(t, noop())
			h.stdoutTTY = true
			args := append([]string{"completion", shell}, extra...)
			if code := h.execRoot(args...); code != 0 || h.stderr.Len() != 0 {
				t.Fatalf("nyx %v: exit %d, stderr %q", args, code, h.stderr.String())
			}
			if !strings.HasPrefix(h.stdout.String(), head) {
				t.Errorf("nyx %v does not start with %q:\n%.200s", args, head, h.stdout.String())
			}
			if !strings.Contains(h.stdout.String(), "__complete") {
				t.Errorf("nyx %v: the script does not ask nyx for completions", args)
			}
			h.untouched()
		}
	}
}

// Anything but one supported shell is a usage error that names the shells.
func TestCompletion_NeedsOneSupportedShell(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{}, {"fish"}, {"powershell"}, {"bash", "zsh"}} {
		for _, jsonMode := range []bool{false, true} {
			h := newHarness(t, noop())
			call := append([]string{"completion"}, args...)
			if jsonMode {
				call = append(call, "--json")
			}
			f := h.failed(h.execRoot(call...), 2, jsonMode)
			if f.code != "INVALID_INPUT" || f.hint != "nyx completion --help" || !strings.Contains(f.msg, "bash") || !strings.Contains(f.msg, "zsh") {
				t.Errorf("nyx %v: %+v", call, f)
			}
			if jsonMode && len(args) > 0 {
				if got := f.inputOf("argument"); !slices.Equal(got, args) {
					t.Errorf("nyx %v: input %v", call, f.input)
				}
			}
			h.untouched()
		}
	}
}

// A completion request is answered by Cobra, not refused as an unknown command, and offers the
// commands, the shared flags and every value a flag takes from a fixed list.
func TestCompletion_OffersCommandsFlagsAndValues(t *testing.T) {
	t.Parallel()
	h := newHarness(t, helpStages()...)
	for _, c := range []struct {
		args          []string
		want, without []string
		directive     string
	}{
		{[]string{""}, []string{"recon", "cve", "ip", "setup", "completion", "help"}, []string{"__complete"}, ":4"},
		{[]string{"recon", ""}, []string{"export"}, nil, ":4"},
		{[]string{"recon", "--"}, []string{"--json", "--quiet", "--redo", "--skip", "--passive"}, []string{"--palette"}, ":4"},
		{[]string{"recon", "--redo", ""}, []string{"crtsh", "resolve", "ports"}, nil, ":4"},
		// --skip leaves out the stages it refuses, and offers none.
		{[]string{"recon", "--skip", ""}, []string{"crtsh", "ports", "none"}, []string{"resolve", "wildcard", "providerranges"}, ":4"},
		{[]string{"recon", "--output-dir", ""}, nil, nil, ":16"},
		{[]string{"recon", "export", "--kind", ""}, []string{"finding", "hostname", "input", "exclusion"}, nil, ":4"},
		// A comma-separated list continues after what is typed, without what it already has.
		{[]string{"cve", "--fields", ""}, []string{"id", "cvss_score", "all"}, nil, ":6"},
		{[]string{"cve", "--fields", "id,cvss_s"}, []string{"id,cvss_score"}, []string{"id,id"}, ":6"},
		// ip's active-only fields come with --active.
		{[]string{"ip", "--fields", ""}, []string{"asn", "all"}, []string{"tls", "web"}, ":6"},
		{[]string{"ip", "--active", "--fields", ""}, []string{"asn", "tls", "web"}, nil, ":6"},
		{[]string{"help", ""}, []string{"recon", "findings", "stages", "completion"}, []string{"help"}, ":4"},
		{[]string{"help", "recon", ""}, []string{"export"}, nil, ":4"},
		{[]string{"completion", ""}, []string{"bash", "zsh"}, []string{"fish", "powershell"}, ":4"},
	} {
		got, directive := completions(t, h, c.args...)
		for _, w := range c.want {
			if !slices.ContainsFunc(got, func(g string) bool { return g == w || strings.HasPrefix(w, "--") && strings.HasPrefix(g, w) }) {
				t.Errorf("%q: %q is not offered: %q", c.args, w, got)
			}
		}
		for _, w := range c.without {
			if slices.Contains(got, w) {
				t.Errorf("%q: %q is offered: %q", c.args, w, got)
			}
		}
		if directive != c.directive {
			t.Errorf("%q: directive %s, want %s", c.args, directive, c.directive)
		}
		if h.stderr.Len() != 0 {
			t.Errorf("%q: stderr %q", c.args, h.stderr.String())
		}
	}
	h.untouched()
}

// The root help leaves completion out: setup's help points to it, and it has its own.
func TestCompletion_OnlySetupsHelpPointsToIt(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	help := func(args ...string) string {
		t.Helper()
		if code := h.execRoot(args...); code != 0 {
			t.Fatalf("nyx %v: exit %d, stderr %q", args, code, h.stderr.String())
		}
		return h.stdout.String()
	}
	if root := help("--help"); strings.Contains(root, "completion") {
		t.Errorf("the root help mentions completion:\n%s", root)
	}
	if setup := help("setup", "--help"); !strings.Contains(setup, "source <(nyx completion zsh)") || !strings.Contains(setup, "nyx completion --help") {
		t.Errorf("setup's help does not say how to turn on completion:\n%s", setup)
	}
	if own := help("help", "completion"); !strings.HasPrefix(own, "Examples:\n  nyx completion zsh") {
		t.Errorf("nyx help completion:\n%s", own)
	}
}

// A completion request reads no config file: a broken one changes nothing and prints no hint.
func TestCompletion_ReadsNoConfig(t *testing.T) {
	t.Parallel()
	h := newHarness(t, helpStages()...)
	cfg := writeFile(t, t.TempDir(), "config.yaml", "not: [valid\n")
	got, _ := completions(t, h, "recon", "--config", cfg, "--redo", "")
	if !slices.Contains(got, "crtsh") || h.stderr.Len() != 0 {
		t.Errorf("with a broken config: %q, stderr %q", got, h.stderr.String())
	}
	h.untouched()
}
