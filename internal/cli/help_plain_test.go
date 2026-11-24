package cli_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// helpStages supplies stable representative stage names so golden help does not change with
// every registry addition.
func helpStages() []run.Stage {
	st := func(name string, kind run.Contact) run.Stage { return &testkit.Stage{StageName: name, Kind: kind} }
	return []run.Stage{
		st("crtsh", run.ThirdParty), st("shodan", run.ThirdParty), st("providerranges", run.ThirdParty),
		st("resolve", run.ThirdParty), st("wildcard", run.ThirdParty), st("httpprobe", run.Target), st("ports", run.Target),
	}
}

// helpScreens are every help screen: the root help, each command's own help, help's own and the
// two topics.
var helpScreens = []struct {
	name string
	args []string
}{
	{"root", []string{"--help"}},
	{"recon", []string{"recon", "--help"}},
	{"export", []string{"recon", "export", "--help"}},
	{"cve", []string{"cve", "--help"}},
	{"setup", []string{"setup", "--help"}},
	{"completion", []string{"completion", "--help"}},
	{"help", []string{"help", "--help"}},
	{"findings", []string{"help", "findings"}},
	{"stages", []string{"help", "stages"}},
}

// Plain help goldens preserve non-terminal text independently of colour environment variables.
func TestHelp_PlainJoin(t *testing.T) {
	t.Parallel()
	for _, s := range helpScreens {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			goldenPlain(t, "help-"+s.name, func(tune func(*harness)) (*harness, string) {
				h := newHarness(t, helpStages()...)
				tune(h)
				if code := h.execRoot(s.args...); code != 0 {
					t.Fatalf("%v: exit %d, stderr %q", s.args, code, h.stderr.String())
				}
				return h, h.stdout.String()
			})
		})
	}
}

// Under --json help is not laid out, even on a terminal: it is the text of a stream that is not.
func TestHelp_JSONOnTerminalIsPlain(t *testing.T) {
	t.Parallel()
	for _, s := range helpScreens {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			plain := newHarness(t, helpStages()...)
			if code := plain.execRoot(s.args...); code != 0 {
				t.Fatal(plain.stderr.String())
			}
			h := newHarness(t, helpStages()...)
			colourAt(t, h, palette.TrueColor)
			h.setenv("COLUMNS", "70")
			if code := h.execRoot(append([]string{"--json"}, s.args...)...); code != 0 {
				t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
			}
			if got, want := h.stdout.String(), plain.stdout.String(); got != want {
				t.Errorf("help under --json on a terminal differs from the plain help\n got: %q\nwant: %q", got, want)
			}
		})
	}
}
