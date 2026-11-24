package cli_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/threatdata"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
)

// CLI update tests focus on output/outcomes; threatdata tests cover individual acceptance
// rules.

// tdFiveRequests are the requests of one whole update, each list asked for once, in order within
// each source.
var tdFiveRequests = []string{
	threatdata.SpamhausHost + " GET " + tdPathV4,
	threatdata.SpamhausHost + " GET " + tdPathV6,
	threatdata.SpamhausHost + " GET " + tdPathASN,
	threatdata.IpapiHost + " GET " + tdPathNetworks,
	threatdata.IpapiHost + " GET " + tdPathASNs,
}

// updatedBoth checks an envelope in which both sources were updated.
func updatedBoth(t *testing.T, w *threatWorld) {
	t.Helper()
	env := w.h.threatEnvelope()
	if got := env.outcomes(); got != "spamhaus=updated ipapi.is=updated" {
		t.Errorf("outcomes %s, want both updated", got)
	}
	for _, f := range []string{tdSpamhausData, tdIpapiData} {
		if !tdExists(w.path(f)) {
			t.Errorf("%s was not written in %s", f, w.dir())
		}
	}
}

// Updates work without terminals or readable config and leave config files untouched.
func TestThreatUpdate_RunsWithoutATerminalOrAConfigFile(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		config *string // the default config file's text; nil for none
		args   []string
	}{
		{"stdin and stdout are not terminals", new(""), nil},
		{"no config file", nil, nil},
		{"a config file that does not parse", new("keys: [\n"), nil},
		{"a config file with an unknown key and a bad value", new("bogus: 1\nconcurrency: abc\n"), nil},
		{"--config names a missing file", new(""), []string{"--config", "MISSING"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			runsWithoutAConfig(t, c.config, c.args)
		})
	}
}

// runsWithoutAConfig verifies updates succeed independently of missing/invalid config
// arguments.
func runsWithoutAConfig(t *testing.T, config *string, args []string) {
	t.Helper()
	w := newThreatWorld(t)
	if w.h.stdinTTY || w.h.stdoutTTY {
		t.Fatal("the harness's stdin and stdout must not be terminals")
	}
	if config == nil {
		if err := os.Remove(w.h.configFile()); err != nil {
			t.Fatal(err)
		}
	} else if err := os.WriteFile(w.h.configFile(), []byte(*config), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "nowhere", "nyx.yaml")
	args = slices.Clone(args)
	if i := slices.Index(args, "MISSING"); i >= 0 {
		args[i] = missing
	}
	if code := w.update(append(args, "--json")...); code != 0 {
		t.Fatalf("exit %d, want 0\nstdout %s\nstderr %s", code, w.h.stdout.String(), w.h.stderr.String())
	}
	updatedBoth(t, w)
	want := "<absent>"
	if config != nil {
		want = *config
	}
	if got := readFileOrEmpty(t, w.h.configFile()); got != want {
		t.Errorf("the config file is now %q, want %q", got, want)
	}
	if tdExists(filepath.Dir(missing)) {
		t.Error("the update created the directory of the --config file")
	}
}

// On a terminal the update still never opens the editor: it writes its lines and exits.
func TestThreatUpdate_NeverOpensTheEditor(t *testing.T) {
	t.Parallel()
	w := newThreatWorldOn(t, setupHarness(t))
	w.h.stdin = &sequence{chunks: []string{"q"}} // an editor that opened would quit at once
	if code := w.update(); code != 0 {
		t.Fatalf("exit %d, want 0\nstderr %s", code, w.h.stderr.String())
	}
	out := w.h.stdout.String()
	if strings.Contains(out, "\x1b[?1049h") || strings.Contains(out, "Settings") {
		t.Errorf("the editor opened:\n%q", out)
	}
	for _, l := range tdListNames {
		w.h.threatLine(l)
	}
}

// An argument exits 2, as nyx setup does, and nothing is sent.
func TestThreatUpdate_AnArgumentExitsTwo(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonMode), func(t *testing.T) {
			t.Parallel()
			w := newThreatWorld(t)
			f := w.h.failed(w.update(jsonArgs(jsonMode, "x")...), 2, jsonMode)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "argument") {
				t.Errorf("error %+v, want INVALID_INPUT about the argument", f)
			}
			if r := w.requests(); len(r) != 0 {
				t.Errorf("requests %v, want none", r)
			}
			if tdExists(w.dir()) {
				t.Error("the threat-data directory was created")
			}
		})
	}
}

// nyx setup --help lists the flag and says what it does, and so does the root help's setup entry.
func TestThreatUpdate_HelpListsTheFlag(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	flagLine := regexp.MustCompile(`(?m)^\s+--update-threat-data\b(.*)$`)
	for _, args := range [][]string{{"setup", "--help"}, {"--help"}} {
		if code := h.execRoot(args...); code != 0 {
			t.Fatalf("nyx %v: exit %d", args, code)
		}
		out := h.stdout.String()
		if i := strings.Index(out, "setup flags:"); len(args) == 1 && i >= 0 {
			out = out[i:]
		}
		m := flagLine.FindStringSubmatch(out)
		if m == nil {
			t.Errorf("nyx %v does not list --update-threat-data:\n%s", args, out)
			continue
		}
		if !strings.Contains(strings.ToLower(m[1]), "threat data") {
			t.Errorf("nyx %v: the flag's line %q does not say it updates the threat data", args, m[0])
		}
	}
}

// One update makes five source requests without touching DNS/HTTP/TCP target canaries.
func TestThreatUpdate_SendsOneRequestPerList(t *testing.T) {
	t.Parallel()
	w := newThreatWorld(t)
	if code := w.update("--json"); code != 0 {
		t.Fatalf("exit %d, want 0\nstderr %s", code, w.h.stderr.String())
	}
	if got := w.requests(); !slices.Equal(got, tdFiveRequests) {
		t.Errorf("requests\n got %v\nwant %v", got, tdFiveRequests)
	}
	if n := w.h.network(); n != 0 {
		t.Errorf("the harness's target canaries saw %d contacts", n)
	}
}

// A failing drop_v4 stops Spamhaus's other requests, with no retry, while ipapi.is is still asked
// for both lists.
func TestThreatUpdate_AFailureStopsItsSource(t *testing.T) {
	t.Parallel()
	w := newThreatWorld(t)
	w.fail(threatdata.Spamhaus, http.StatusInternalServerError)
	if code := w.update("--json"); code != 7 {
		t.Fatalf("exit %d, want 7\nstderr %s", code, w.h.stderr.String())
	}
	if got := w.sh.requests(); !slices.Equal(got, []string{"GET " + tdPathV4}) {
		t.Errorf("Spamhaus saw %v, want drop_v4 once", got)
	}
	if got := w.ip.requests(); !slices.Equal(got, []string{"GET " + tdPathNetworks, "GET " + tdPathASNs}) {
		t.Errorf("ipapi.is saw %v, want both lists", got)
	}
	if n := w.h.network(); n != 0 {
		t.Errorf("the harness's target canaries saw %d contacts", n)
	}
}

// Rejected downloads preserve prior bytes/mode and explain shrink counts and recovery guidance.
func TestThreatUpdate_ARefusedListLeavesTheFile(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name     string
		v4       func(w *threatWorld) []byte
		stops    bool     // the source's later lists are not asked for
		inReason []string // words the source's reason holds
	}{
		{"a row that does not parse", func(w *threatWorld) []byte {
			f := tdDropFile(tdV4Row, w.d2, 5, 80)
			return append([]byte("{not json\n"), f...)
		}, true, nil},
		{"a list under half the copy in use", func(w *threatWorld) []byte {
			return tdDropFile(tdV4Row, w.d2, 5, 30)
		}, false, []string{"half", "30", "80", "a newer build of nyx"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newThreatWorld(t)
			w.placeDownloaded()
			if err := os.Chmod(w.path(tdSpamhausData), 0o640); err != nil { // a mode the update would not give it
				t.Fatal(err)
			}
			before := tdSnapshot(t, w.path(tdSpamhausData))
			w.sh.set(tdPathV4, tdOK(c.v4(w)))
			if code := w.update("--json"); code != 7 {
				t.Fatalf("exit %d, want 7\nstderr %s", code, w.h.stderr.String())
			}
			tdUnchanged(t, w.path(tdSpamhausData), before)
			env := w.h.threatEnvelope()
			s := env.source(t, threatdata.Spamhaus)
			if s.Outcome != "failed" || s.Error == nil || s.Error.Code != "UPSTREAM_ERROR" || s.Error.Transient {
				t.Fatalf("Spamhaus %+v error %+v, want failed with UPSTREAM_ERROR, not transient", s, s.Error)
			}
			for _, word := range c.inReason {
				if !strings.Contains(s.Error.Error, word) {
					t.Errorf("the reason %q does not say %q", s.Error.Error, word)
				}
			}
			if c.stops && (w.sh.count(tdPathV6) != 0 || w.sh.count(tdPathASN) != 0) {
				t.Errorf("Spamhaus saw %v after the refused drop_v4", w.sh.requests())
			}
			if l := env.list(t, spamhaus.ListV4); l.OldUpdated != l.NewUpdated || l.NewUpdated != tdStamp(w.d1) {
				t.Errorf("drop_v4 %+v, want the downloaded copy of %s still in use", l, tdStamp(w.d1))
			}
		})
	}
}

// Only newer lists replace active data, including mixed-version source bundles.
func TestThreatUpdate_AlreadyCurrent(t *testing.T) {
	t.Parallel()
	t.Run("every list", func(t *testing.T) {
		t.Parallel()
		w := newThreatWorld(t)
		w.current()
		if code := w.update(); code != 0 {
			t.Fatalf("exit %d, want 0\nstderr %s", code, w.h.stderr.String())
		}
		for _, l := range tdListNames {
			if line := w.h.threatLine(l); !strings.HasSuffix(line, "already current") {
				t.Errorf("line %q does not end with already current", line)
			}
		}
		for _, f := range []string{tdSpamhausData, tdIpapiData} {
			if tdExists(w.path(f)) {
				t.Errorf("%s was written for lists that are already current", f)
			}
		}
		if code := w.update("--json"); code != 0 {
			t.Fatalf("exit %d, want 0 (the second update an hour later)", code)
		}
	})
	t.Run("one newer list of three", func(t *testing.T) {
		t.Parallel()
		w := newThreatWorld(t)
		f := tdSpamhausAt(w.d0, 0)
		f.v4 = tdDropFile(tdV4Row, w.d2, 5, 80)
		w.serveSpamhaus(f)
		if code := w.update(); code != 0 {
			t.Fatalf("exit %d, want 0\nstderr %s", code, w.h.stderr.String())
		}
		if line := w.h.threatLine(spamhaus.ListV4); !strings.Contains(line, tdStamp(w.d0)+" -> "+tdStamp(w.d2)) {
			t.Errorf("drop_v4's line %q does not give its old and new dates", line)
		}
		for _, l := range []string{spamhaus.ListV6, spamhaus.ListASN} {
			if line := w.h.threatLine(l); !strings.HasSuffix(line, "already current") {
				t.Errorf("line %q does not end with already current", line)
			}
		}
		if !tdExists(w.path(tdSpamhausData)) {
			t.Error("the updated source's data file was not written")
		}
	})
}

// Responses start a one-hour cooldown; skipped updates report both contact and next-eligible
// times.
func TestThreatUpdate_WithinTheHourSendsNothing(t *testing.T) {
	t.Parallel()
	w := newThreatWorld(t)
	if code := w.update("--json"); code != 0 {
		t.Fatalf("first update: exit %d\nstderr %s", code, w.h.stderr.String())
	}
	first := w.h.now
	w.h.now = first.Add(59 * time.Minute)
	if code := w.update("--json"); code != 0 {
		t.Fatalf("second update: exit %d, want 0 (skipped counts as success)\nstderr %s", code, w.h.stderr.String())
	}
	if got := w.requests(); !slices.Equal(got, tdFiveRequests) {
		t.Errorf("after the second update the hosts saw %v, want only the first update's five", got)
	}
	env := w.h.threatEnvelope()
	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		s := env.source(t, name)
		if s.Outcome != "skipped" || tdStr(s.LastContacted) != tdStamp(first) || tdStr(s.NextUpdate) != tdStamp(first.Add(time.Hour)) {
			t.Errorf("%s: outcome %s, last_contacted %s, next_update %s; want skipped, %s, %s", name, s.Outcome,
				tdStr(s.LastContacted), tdStr(s.NextUpdate), tdStamp(first), tdStamp(first.Add(time.Hour)))
		}
	}
	if code := w.update(); code != 0 {
		t.Fatalf("third update: exit %d", code)
	}
	for _, l := range tdListNames {
		if line := w.h.threatLine(l); !strings.Contains(line, "skipped: last contacted ") || !strings.Contains(line, "; can be updated after ") {
			t.Errorf("line %q does not say when it was last contacted and when it can be updated", line)
		}
	}
	w.h.now = first.Add(time.Hour)
	if code := w.update("--json"); code != 0 {
		t.Fatalf("an hour later: exit %d\nstderr %s", code, w.h.stderr.String())
	}
	if got := len(w.requests()); got != 2*len(tdFiveRequests) {
		t.Errorf("an hour later the hosts have seen %d requests, want %d", got, 2*len(tdFiveRequests))
	}
}

// Concurrent updates serialise per source so the second skips and each list is requested once.
func TestThreatUpdate_TwoAtOnce(t *testing.T) {
	t.Parallel()
	w := newThreatWorld(t)
	other := newHarness(t)
	other.env["XDG_CONFIG_HOME"], other.env["HOME"] = w.h.env["XDG_CONFIG_HOME"], w.h.env["HOME"]
	other.eopts, other.threatBuiltIn, other.now = w.h.eopts, w.h.threatBuiltIn, w.h.now
	releaseV4 := w.sh.hold(t, tdPathV4)
	releaseNets := w.ip.hold(t, tdPathNetworks)

	codes := make([]int, 2)
	var wg sync.WaitGroup
	wg.Go(func() { codes[0] = w.h.execRootCtx(t.Context(), "setup", "--update-threat-data", "--json") })
	if !w.sh.asked(tdPathV4) || !w.ip.asked(tdPathNetworks) {
		releaseV4()
		releaseNets()
		wg.Wait()
		t.Fatalf("the first update never asked for both sources' first lists: %v (exit %d, stderr %s)", w.requests(), codes[0], w.h.stderr.String())
	}
	wg.Go(func() { codes[1] = other.execRootCtx(t.Context(), "setup", "--update-threat-data", "--json") })
	time.Sleep(300 * time.Millisecond) // the second is now waiting on the locks
	if n := w.sh.count(tdPathV4) + w.ip.count(tdPathNetworks); n != 2 {
		t.Errorf("while the first update held the sources, the first lists were asked for %d times, want 2", n)
	}
	releaseV4()
	releaseNets()
	wg.Wait()
	if codes[0] != 0 || codes[1] != 0 {
		t.Fatalf("exits %v, want 0 and 0\nfirst stderr %s\nsecond stderr %s", codes, w.h.stderr.String(), other.stderr.String())
	}
	for _, p := range []string{tdPathV4, tdPathV6, tdPathASN} {
		if n := w.sh.count(p); n != 1 {
			t.Errorf("%s was asked for %d times, want once", p, n)
		}
	}
	for _, p := range []string{tdPathNetworks, tdPathASNs} {
		if n := w.ip.count(p); n != 1 {
			t.Errorf("%s was asked for %d times, want once", p, n)
		}
	}
	if got := w.h.threatEnvelope().outcomes(); got != "spamhaus=updated ipapi.is=updated" {
		t.Errorf("the first update: %s, want both updated", got)
	}
	if got := other.threatEnvelope().outcomes(); got != "spamhaus=skipped ipapi.is=skipped" {
		t.Errorf("the second update: %s, want both skipped", got)
	}
}

// The downloaded copy is kept under $XDG_CONFIG_HOME/nyx/threat-data, else ~/.config/nyx/threat-data,
// whatever --config says.
func TestThreatUpdate_TheDirectory(t *testing.T) {
	t.Parallel()
	t.Run("XDG_CONFIG_HOME first", func(t *testing.T) {
		t.Parallel()
		w := newThreatWorld(t)
		home := t.TempDir()
		w.h.setenv("HOME", home)
		if code := w.update(); code != 0 {
			t.Fatalf("exit %d\nstderr %s", code, w.h.stderr.String())
		}
		if !tdExists(filepath.Join(w.h.env["XDG_CONFIG_HOME"], "nyx", "threat-data", tdSpamhausData)) {
			t.Error("nothing was written under $XDG_CONFIG_HOME/nyx/threat-data")
		}
		if tdExists(filepath.Join(home, ".config")) {
			t.Error("something was written under $HOME/.config")
		}
	})
	t.Run("HOME else", func(t *testing.T) {
		t.Parallel()
		w := newThreatWorld(t)
		home := t.TempDir()
		w.h.setenv("XDG_CONFIG_HOME", "")
		w.h.setenv("HOME", home)
		if code := w.update(); code != 0 {
			t.Fatalf("exit %d\nstderr %s", code, w.h.stderr.String())
		}
		for _, f := range []string{tdSpamhausData, tdIpapiData} {
			if !tdExists(filepath.Join(home, ".config", "nyx", "threat-data", f)) {
				t.Errorf("%s was not written under ~/.config/nyx/threat-data", f)
			}
		}
	})
	t.Run("--config does not move it", func(t *testing.T) {
		t.Parallel()
		w := newThreatWorld(t)
		elsewhere := t.TempDir()
		cfg := writeFile(t, elsewhere, "nyx.yaml", "concurrency: 7\n")
		if code := w.update("--config", cfg); code != 0 {
			t.Fatalf("exit %d\nstderr %s", code, w.h.stderr.String())
		}
		if !tdExists(w.path(tdSpamhausData)) {
			t.Error("nothing was written in the default threat-data directory")
		}
		if entries, _ := os.ReadDir(elsewhere); len(entries) != 1 {
			t.Errorf("the --config file's directory holds %d entries, want only the file", len(entries))
		}
	})
}

// With neither XDG_CONFIG_HOME nor HOME set the update exits 2 and says why, with or without
// --config, sending nothing.
func TestThreatUpdate_NowhereToKeepTheData(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range []bool{false, true} {
		for _, withConfig := range []bool{false, true} {
			t.Run(fmt.Sprintf("json=%v --config=%v", jsonMode, withConfig), func(t *testing.T) {
				t.Parallel()
				w := newThreatWorld(t)
				w.h.setenv("XDG_CONFIG_HOME", "")
				w.h.setenv("HOME", "")
				var args []string
				if withConfig {
					args = []string{"--config", writeFile(t, t.TempDir(), "nyx.yaml", "")}
				}
				f := w.h.failed(w.update(jsonArgs(jsonMode, args...)...), 2, jsonMode)
				if !strings.Contains(f.msg, "nowhere to keep threat data") || !strings.Contains(f.msg, "neither XDG_CONFIG_HOME nor HOME is set") {
					t.Errorf("error %+v does not say why", f)
				}
				if r := w.requests(); len(r) != 0 {
					t.Errorf("requests %v, want none", r)
				}
			})
		}
	}
}

// Golden human output pins per-list transitions/counts/status and source credit.
func TestPlain_ThreatUpdate(t *testing.T) {
	t.Parallel()
	// Spamhaus: drop_v4 is newer, the others are already current. ipapi.is: skipped.
	updatedAndSkipped := func(tune func(*harness)) (*harness, string) {
		w := newThreatWorld(t)
		tune(w.h)
		f := tdSpamhausAt(w.d0, 0)
		f.v4 = tdDropFile(tdV4Row, w.d2, 5, 80)
		w.serveSpamhaus(f)
		w.skipped(threatdata.Ipapi)
		if code := w.update(); code != 0 {
			t.Fatalf("exit %d, want 0\nstderr %s", code, w.h.stderr.String())
		}
		return w.h, w.h.stdout.String()
	}
	// Spamhaus fails on drop_v4; ipapi.is is updated.
	failedAndUpdated := func(tune func(*harness)) (*harness, string) {
		w := newThreatWorld(t)
		tune(w.h)
		w.fail(threatdata.Spamhaus, http.StatusInternalServerError)
		if code := w.update(); code != 7 {
			t.Fatalf("exit %d, want 7\nstderr %s", code, w.h.stderr.String())
		}
		return w.h, w.h.stdout.String()
	}

	h, _ := updatedAndSkipped(func(*harness) {})
	d0 := h.now.AddDate(0, 0, -20)
	checkThreatLines(t, h, map[string]string{
		spamhaus.ListV4:         "^spamhaus\\s+drop_v4\\s+" + regexp.QuoteMeta(tdStamp(d0)+" -> "+tdStamp(d0.AddDate(0, 0, 2))) + "\\s+80 entries \\(\\+5, -5\\)$",
		spamhaus.ListV6:         "^spamhaus\\s+drop_v6\\b.*already current$",
		spamhaus.ListASN:        "^spamhaus\\s+asndrop\\b.*already current$",
		threatdata.ListNetworks: "^ipapi\\.is\\s+networks\\b.*skipped: last contacted .+; can be updated after .+$",
		threatdata.ListASNs:     "^ipapi\\.is\\s+asns\\b.*skipped: last contacted .+; can be updated after .+$",
	})
	h, _ = failedAndUpdated(func(*harness) {})
	checkThreatLines(t, h, map[string]string{
		spamhaus.ListV4:         "^spamhaus\\s+drop_v4\\b.*failed: .*HTTP 500",
		spamhaus.ListV6:         "^spamhaus\\s+drop_v6\\b.*failed",
		spamhaus.ListASN:        "^spamhaus\\s+asndrop\\b.*failed",
		threatdata.ListNetworks: "^ipapi\\.is\\s+networks\\s+" + regexp.QuoteMeta(tdDay(d0)+" -> "+tdDay(d0.AddDate(0, 0, 2))) + "\\s+80 entries \\(\\+5, -5\\)$",
		threatdata.ListASNs:     "^ipapi\\.is\\s+asns\\s+" + regexp.QuoteMeta(tdDay(d0)+" -> "+tdDay(d0.AddDate(0, 0, 2))) + "\\s+20 entries \\(\\+5, -5\\)$",
	})

	goldenPlain(t, "threat-update", updatedAndSkipped)
	goldenPlain(t, "threat-update-failed", failedAndUpdated)
}

// checkThreatLines verifies exactly five ordered list lines followed by credit.
func checkThreatLines(t *testing.T, h *harness, want map[string]string) {
	t.Helper()
	lines := h.threatLines()
	if len(lines) != len(tdListNames)+1 {
		t.Errorf("the output has %d lines, want one per list and the credit:\n%s", len(lines), h.stdout.String())
		return
	}
	for i, l := range tdListNames {
		if !regexp.MustCompile(want[l]).MatchString(lines[i]) {
			t.Errorf("line %d is %q, want it to match %s", i+1, lines[i], want[l])
		}
	}
	if last := lines[len(lines)-1]; last != tdCreditLine {
		t.Errorf("the last line is %q, want %q", last, tdCreditLine)
	}
}

// The output goes to stdout, and --quiet leaves it as it is.
func TestThreatUpdate_QuietPrintsTheOutput(t *testing.T) {
	t.Parallel()
	outputs := map[bool]string{}
	for _, quiet := range []bool{false, true} {
		w := newThreatWorld(t)
		var args []string
		if quiet {
			args = append(args, "--quiet")
		}
		if code := w.update(args...); code != 0 {
			t.Fatalf("quiet=%v: exit %d\nstderr %s", quiet, code, w.h.stderr.String())
		}
		outputs[quiet] = w.h.stdout.String()
		if got := w.h.threatLines(); len(got) != len(tdListNames)+1 || got[len(got)-1] != tdCreditLine {
			t.Errorf("quiet=%v: stdout is not the five lines and the credit:\n%s", quiet, w.h.stdout.String())
		}
	}
	if outputs[true] != outputs[false] {
		t.Errorf("--quiet changed the output:\n%q\nwithout it:\n%q", outputs[true], outputs[false])
	}
}

// tdArrange makes a source end with an outcome.
var tdArrange = map[string]func(w *threatWorld, source string){
	"updated": func(*threatWorld, string) {},
	"current": func(w *threatWorld, source string) {
		if source == threatdata.Spamhaus {
			w.serveSpamhaus(tdSpamhausAt(w.d0, 0))
		} else {
			w.serveIpapi(w.d0, 0)
		}
	},
	"skipped": func(w *threatWorld, source string) { w.skipped(source) },
	"failed":  func(w *threatWorld, source string) { w.fail(source, http.StatusInternalServerError) },
}

// The exit codes: 0 when no source failed, 7 when one did, whatever the other did.
func TestThreatUpdate_ExitCodes(t *testing.T) {
	t.Parallel()
	outcomes := []string{"updated", "current", "skipped", "failed"}
	for _, a := range outcomes {
		for _, b := range outcomes {
			if a == "failed" && b == "failed" {
				continue // exit 1: TestThreatUpdate_BothFailed
			}
			t.Run(fmt.Sprintf("spamhaus %s, ipapi.is %s", a, b), func(t *testing.T) {
				t.Parallel()
				exitCodeOf(t, a, b)
			})
		}
	}
}

// exitCodeOf checks the exit code and the error of an update in which Spamhaus ends with outcome a
// and ipapi.is with b.
func exitCodeOf(t *testing.T, a, b string) {
	t.Helper()
	want := 0
	if a == "failed" || b == "failed" {
		want = 7
	}
	w := newThreatWorld(t)
	tdArrange[a](w, threatdata.Spamhaus)
	tdArrange[b](w, threatdata.Ipapi)
	code := w.update("--json")
	if code != want {
		t.Fatalf("exit %d, want %d\nstdout %s\nstderr %s", code, want, w.h.stdout.String(), w.h.stderr.String())
	}
	env := w.h.threatEnvelope()
	if got, wantOut := env.outcomes(), "spamhaus="+a+" ipapi.is="+b; got != wantOut {
		t.Errorf("outcomes %s, want %s", got, wantOut)
	}
	if want == 0 {
		if w.h.stderr.Len() != 0 {
			t.Errorf("stderr %q on exit 0", w.h.stderr.String())
		}
		return
	}
	f := w.h.theError(true)
	if f.code != "PARTIAL" {
		t.Errorf("code %s, want PARTIAL: %+v", f.code, f)
	}
	failed := threatdata.Spamhaus
	if b == "failed" {
		failed = threatdata.Ipapi
	}
	if next := w.h.now.Add(time.Hour); !strings.Contains(f.hint, failed) || !strings.Contains(f.hint, next.Format("15:04")) {
		t.Errorf("hint %q does not say when %s can next be updated (%s)", f.hint, failed, tdStamp(next))
	}
}

// In human mode a partial result writes the lines and a PARTIAL error that names the failed source
// and its reason.
func TestThreatUpdate_PartialInHumanMode(t *testing.T) {
	t.Parallel()
	w := newThreatWorld(t)
	w.fail(threatdata.Ipapi, http.StatusInternalServerError)
	if code := w.update(); code != 7 {
		t.Fatalf("exit %d, want 7\nstderr %s", code, w.h.stderr.String())
	}
	if lines := w.h.threatLines(); len(lines) != len(tdListNames)+1 {
		t.Errorf("stdout is not the five lines and the credit:\n%s", w.h.stdout.String())
	}
	f := w.h.threatFailure(false)
	if f.code != "PARTIAL" {
		t.Errorf("code %s, want PARTIAL", f.code)
	}
	if !slices.ContainsFunc(f.targets, func(l string) bool {
		return strings.HasPrefix(l, threatdata.Ipapi+": ") && strings.Contains(l, "HTTP 500") && strings.HasSuffix(l, "(UPSTREAM_ERROR)")
	}) {
		t.Errorf("the error's lines %v do not give ipapi.is's reason and code", f.targets)
	}
}

// bothFailed is a case of an update in which both sources fail.
type bothFailed struct {
	name      string
	arrange   func(w *threatWorld)
	code      string
	transient bool
	reasons   []string                      // what the error says of the sources' reasons
	whenNext  func(w *threatWorld) []string // what the hint says of when they can next be updated
}

// Total update failure returns a shared code or UPSTREAM_ERROR with empty stdout, source
// reasons and cooldown-aware hints. Transience follows network/timeout/rate-limit failures.
func TestThreatUpdate_BothFailed(t *testing.T) {
	t.Parallel()
	nextHour := func(w *threatWorld) []string { return []string{w.h.now.Add(time.Hour).Format("15:04")} }
	for _, c := range []bothFailed{
		{"no response from either", func(w *threatWorld) {
			w.unreachable(threatdata.Spamhaus)
			w.unreachable(threatdata.Ipapi)
		}, "NETWORK_ERROR", true, []string{"connection refused"}, func(*threatWorld) []string { return []string{"now"} }},
		{"HTTP 500 from both", func(w *threatWorld) {
			w.fail(threatdata.Spamhaus, http.StatusInternalServerError)
			w.fail(threatdata.Ipapi, http.StatusInternalServerError)
		}, "UPSTREAM_ERROR", false, []string{"HTTP 500"}, nextHour},
		{"429 from both", func(w *threatWorld) {
			w.fail(threatdata.Spamhaus, http.StatusTooManyRequests)
			w.fail(threatdata.Ipapi, http.StatusTooManyRequests)
		}, "RATE_LIMITED", true, nil, nextHour},
		{"different codes", func(w *threatWorld) {
			w.fail(threatdata.Spamhaus, http.StatusInternalServerError)
			w.unreachable(threatdata.Ipapi)
		}, "UPSTREAM_ERROR", true, []string{"HTTP 500", "connection refused"}, func(w *threatWorld) []string {
			return append(nextHour(w), "now")
		}},
		{"different codes, neither of them UPSTREAM_ERROR", func(w *threatWorld) {
			w.unreachable(threatdata.Spamhaus)
			w.fail(threatdata.Ipapi, http.StatusTooManyRequests)
		}, "UPSTREAM_ERROR", true, []string{"connection refused"}, func(w *threatWorld) []string {
			return append(nextHour(w), "now")
		}},
	} {
		for _, jsonMode := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s json=%v", c.name, jsonMode), func(t *testing.T) {
				t.Parallel()
				checkBothFailed(t, c, jsonMode)
			})
		}
	}
}

func checkBothFailed(t *testing.T, c bothFailed, jsonMode bool) {
	t.Helper()
	w := newThreatWorld(t)
	c.arrange(w)
	code := w.update(jsonArgs(jsonMode)...)
	if code != 1 {
		t.Fatalf("exit %d, want 1\nstdout %s\nstderr %s", code, w.h.stdout.String(), w.h.stderr.String())
	}
	if w.h.stdout.Len() != 0 {
		t.Errorf("stdout is not empty on exit 1: %q", w.h.stdout.String())
	}
	f := w.h.threatFailure(jsonMode)
	if f.code != c.code || f.transient != c.transient {
		t.Errorf("error %+v, want %s with transient %v", f, c.code, c.transient)
	}
	all := w.h.stderr.String()
	for _, r := range c.reasons {
		if !strings.Contains(all, r) {
			t.Errorf("the error does not give the reason %q:\n%s", r, all)
		}
	}
	for _, s := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		if !strings.Contains(f.hint, s) {
			t.Errorf("hint %q does not name %s", f.hint, s)
		}
	}
	for _, when := range c.whenNext(w) {
		if !strings.Contains(f.hint, when) {
			t.Errorf("hint %q does not say %q for when a source can next be updated", f.hint, when)
		}
	}
}

// Unwritable storage fails both sources before requests and preserves previous copies.
func TestThreatUpdate_AnUnwritableDirectory(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	w := newThreatWorld(t)
	w.placeDownloaded()
	before := map[string]tdSnap{tdSpamhausData: tdSnapshot(t, w.path(tdSpamhausData)), tdIpapiData: tdSnapshot(t, w.path(tdIpapiData))}
	if err := os.Chmod(w.dir(), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(w.dir(), 0o700) })
	f := w.h.failed(w.update("--json"), 1, true)
	if f.code != "UNEXPECTED_ERROR" || !strings.Contains(w.h.stderr.String(), "permission denied") {
		t.Errorf("error %+v, want UNEXPECTED_ERROR that says permission denied", f)
	}
	if r := w.requests(); len(r) != 0 {
		t.Errorf("requests %v, want none", r)
	}
	for name, b := range before {
		tdUnchanged(t, w.path(name), b)
	}
}
