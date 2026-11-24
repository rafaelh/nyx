package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// defaultConfig locates the harness's pre-created empty config; absence tests remove it
// explicitly.
func defaultConfig(h *harness) string {
	return filepath.Join(h.env["XDG_CONFIG_HOME"], "nyx", "config.yaml")
}

func removeDefaultConfig(t *testing.T, h *harness) string {
	t.Helper()
	p := defaultConfig(h)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	return p
}

// hintLines are the lines of stderr that suggest nyx setup.
func hintLines(h *harness) []string {
	var out []string
	for l := range strings.SplitSeq(h.stderr.String(), "\n") {
		if strings.Contains(l, "nyx setup") {
			out = append(out, l)
		}
	}
	return out
}

func wantHint(t *testing.T, h *harness, path string) {
	t.Helper()
	want := "hint: no config file at " + path + "; run nyx setup to store API keys and settings"
	if got := hintLines(h); len(got) != 1 || got[0] != want {
		t.Errorf("hint lines %q, want exactly %q\nstderr:\n%s", got, want, h.stderr.String())
	}
}

func wantNoHint(t *testing.T, h *harness) {
	t.Helper()
	if got := hintLines(h); len(got) != 0 {
		t.Errorf("unexpected hint %q", got)
	}
}

// Missing-default hints add one stderr line without changing recon/CVE results.
func TestNoSetupHint_PrintedWhenTheDefaultFileIsAbsent(t *testing.T) {
	t.Parallel()
	t.Run("recon", func(t *testing.T) {
		t.Parallel()
		with := newHarness(t, noop())
		if code := with.exec("example.com", "--json"); code != 0 {
			t.Fatalf("exit %d: %s", code, with.stderr.String())
		}
		wantNoHint(t, with) // the file exists: nothing to suggest
		without := newHarness(t, noop())
		path := removeDefaultConfig(t, without)
		if code := without.exec("example.com"); code != 0 {
			t.Fatalf("exit %d: %s", code, without.stderr.String())
		}
		wantHint(t, without, path)
		if strings.Contains(without.stderr.String(), "error:") {
			t.Errorf("the hint is not an error:\n%s", without.stderr.String())
		}
	})
	t.Run("cve", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		nvd := newNVD(t, h)
		id := nvd.fixture("rejected.json")
		path := removeDefaultConfig(t, h)
		if code := h.cveRun(false, id); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		wantHint(t, h, path)
	})
}

// The hint changes nothing but stderr: the exit code, stdout and the events are as they are when
// the file exists.
func TestNoSetupHint_ChangesNothingElse(t *testing.T) {
	t.Parallel()
	have := newHarness(t, noop())
	haveCode := have.exec("example.com")
	haveOut, haveEvents := have.stdout.String(), have.events()

	absent := newHarness(t, noop())
	removeDefaultConfig(t, absent)
	absentCode := absent.exec("example.com")
	if absentCode != haveCode {
		t.Errorf("exit %d with no file, %d with one", absentCode, haveCode)
	}
	if absent.stdout.String() != haveOut {
		t.Errorf("stdout differs:\n%q\n%q", absent.stdout.String(), haveOut)
	}
	if got := absent.events(); len(got) != len(haveEvents) {
		t.Errorf("%d events with no file, %d with one", len(got), len(haveEvents))
	}
}

// It is not printed under --json or --quiet, with --config, or on a usage error.
func TestNoSetupHint_NotPrinted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		run  func(h *harness) int
	}{
		{"recon --json", func(h *harness) int { return h.exec("example.com", "--json") }},
		{"recon --quiet", func(h *harness) int { return h.exec("example.com", "--quiet") }},
		{"recon --config", func(h *harness) int {
			return h.exec("example.com", "--config", writeFile(t, t.TempDir(), "c.yaml", ""))
		}},
		{"recon no inputs", func(h *harness) int { return h.exec() }},
		{"recon bad flag", func(h *harness) int { return h.exec("example.com", "--no-such-flag") }},
		{"recon bad value", func(h *harness) int { return h.exec("example.com", "--concurrency", "abc") }},
		{"cve --json", func(h *harness) int { return h.cveRun(true, "CVE-2021-44228") }},
		{"cve --quiet", func(h *harness) int { return h.cveRun(false, "CVE-2021-44228", "--quiet") }},
		{"cve --config", func(h *harness) int {
			return h.cveRun(false, "CVE-2021-44228", "--config", writeFile(t, t.TempDir(), "c.yaml", ""))
		}},
		{"cve bad id", func(h *harness) int { return h.cveRun(false, "not-an-id") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, noop())
			nvd := newNVD(t, h)
			nvd.entry("CVE-2021-44228")
			removeDefaultConfig(t, h)
			c.run(h)
			wantNoHint(t, h)
		})
	}
}

// recon export reads an engagement that already exists, so it never suggests setup.
func TestNoSetupHint_NotPrintedByExport(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.exec("example.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	removeDefaultConfig(t, h)
	h.execRoot("recon", "export", "-e", "example.com", "--output-dir", h.out)
	wantNoHint(t, h)
}

// The default path is unknown when neither XDG_CONFIG_HOME nor HOME is set: there is nothing to
// suggest writing.
func TestNoSetupHint_NotPrintedWithoutADefaultPath(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	h.setenv("XDG_CONFIG_HOME", "")
	h.setenv("HOME", "")
	if code := h.exec("example.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	wantNoHint(t, h)
}
