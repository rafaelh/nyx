package cli_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
)

// The keys a script sends to the terminal. Each is what the terminal sends for one key press.
const (
	keyDown  = "\x1b[B"
	keyEnter = "\r"
	keyCtrlS = "\x13"
	keyCtrlC = "\x03"
	keyEsc   = "\x1b"
	keyTab   = "\t"
)

// setupHarness is a harness whose stdin and stdout are a terminal of 100 by 30 cells, and whose
// stdin is the keys the script sends.
func setupHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	h.stdinTTY, h.stdoutTTY, h.winW, h.winH = true, true, 100, 30
	h.cwd = t.TempDir()
	return h
}

// setup runs nyx setup with args, sending keys as the user's key presses.
func (h *harness) setup(args []string, keys ...string) int {
	h.t.Helper()
	h.stdin = &sequence{chunks: keys}
	return h.execRootTimeout(append([]string{"setup"}, args...)...)
}

// execRootTimeout is execRoot, except that a call that never ends fails the test after a while
// instead of hanging it: the interrupt it is ended with is what the test then sees.
func (h *harness) execRootTimeout(args ...string) int {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	code := h.execRootCtx(ctx, args...)
	if ctx.Err() != nil {
		h.t.Fatalf("nyx %v did not finish; exit %d, stdout %q", args, code, h.stdout.String())
	}
	return code
}

// loaded is the config at path as nyx recon reads it, with nothing from the environment.
func loaded(t *testing.T, path string) config.Settings {
	t.Helper()
	s, err := config.Load(nil, path, config.Env{"HOME=" + t.TempDir()})
	if err != nil {
		t.Fatalf("the saved file does not load: %v", err)
	}
	return s
}

func readFileOrEmpty(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "<absent>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// typed is the keys that edit the key on row n (counting from 0) of the Keys tab to value.
func typedKey(row int, value string) []string {
	keys := slices.Repeat([]string{keyDown}, row)
	return append(keys, keyEnter, value, keyEnter)
}

// The root help lists setup with an example, and nyx setup --help works when nothing is a terminal.
func TestSetup_HelpListsTheCommand(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if code := h.execRoot("--help"); code != 0 || !strings.Contains(h.stdout.String(), "nyx setup") ||
		!strings.Contains(h.stdout.String(), "  Example: nyx setup") && !strings.Contains(h.stdout.String(), "nyx setup --config") {
		t.Errorf("root help (exit %d) does not list nyx setup with an example:\n%s", code, h.stdout.String())
	}
	if code := h.execRoot("setup", "--help"); code != 0 || !strings.Contains(h.stdout.String(), "nyx setup") {
		t.Errorf("nyx setup --help piped: exit %d\n%s", code, h.stdout.String())
	}
	if h.stderr.Len() != 0 {
		t.Errorf("stderr %q", h.stderr.String())
	}
}

// jsonArgs is args, with --json when jsonMode asks for it.
func jsonArgs(jsonMode bool, args ...string) []string {
	if jsonMode {
		return append(args, "--json")
	}
	return args
}

// An argument exits 2 before anything is drawn.
func TestSetup_ArgumentExitsTwo(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonMode), func(t *testing.T) {
			t.Parallel()
			h := setupHarness(t)
			f := h.failed(h.setup(jsonArgs(jsonMode, "x")), 2, jsonMode)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "argument") {
				t.Errorf("error %+v", f)
			}
		})
	}
}

// With no --config and neither XDG_CONFIG_HOME nor HOME set there is no file to edit: exit 2, which
// says to pass --config.
func TestSetup_NoPathExitsTwo(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonMode), func(t *testing.T) {
			t.Parallel()
			h := setupHarness(t)
			h.setenv("HOME", "")
			h.setenv("XDG_CONFIG_HOME", "")
			f := h.failed(h.setup(jsonArgs(jsonMode)), 2, jsonMode)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.msg+f.hint, "--config") {
				t.Errorf("error %+v: it should say to pass --config", f)
			}
		})
	}
}

// Without a terminal on stdin or stdout exit 2 is INVALID_INPUT, naming the file and saying to edit
// it by hand, as the usual JSON error under --json. The file is not created.
func TestSetup_NoTerminalExitsTwo(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name          string
		stdin, stdout bool
	}{{"stdin is not a terminal", false, true}, {"stdout is not a terminal", true, false}, {"neither is", false, false}} {
		for _, jsonMode := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s json=%v", c.name, jsonMode), func(t *testing.T) {
				t.Parallel()
				h := setupHarness(t)
				h.stdinTTY, h.stdoutTTY = c.stdin, c.stdout
				path := filepath.Join(t.TempDir(), "nyx.yaml")
				f := h.failed(h.setup(jsonArgs(jsonMode, "--config", path)), 2, jsonMode)
				if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, path) {
					t.Errorf("error %+v: it should name the config file %s", f, path)
				}
				if !strings.Contains(f.hint, "edit "+path+" by hand") || !strings.Contains(f.hint, "docs/configuration.md") {
					t.Errorf("hint %q should say to edit the file by hand", f.hint)
				}
				if _, err := os.Stat(path); err == nil {
					t.Error("setup created the file")
				}
			})
		}
	}
}

// The checks run in order: an argument, then no path, then no terminal.
func TestSetup_ExitsTwoInOrder(t *testing.T) {
	t.Parallel()
	h := setupHarness(t)
	h.setenv("HOME", "")
	h.setenv("XDG_CONFIG_HOME", "")
	h.stdinTTY = false
	f := h.failed(h.setup([]string{"x"}), 2, false)
	if !strings.Contains(f.msg, "argument") {
		t.Errorf("an argument is reported first: %+v", f)
	}
	f = h.failed(h.setup(nil), 2, false)
	if !strings.Contains(f.msg+f.hint, "--config") {
		t.Errorf("no path is reported before no terminal: %+v", f)
	}
}

// A file that cannot be read or parsed, or holds an unknown key, exits 2 with every problem recon
// reports for the file and the file's full path, before the UI opens. The environment is not read.
func TestSetup_FileProblemsExitTwo(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		body string // "" for a directory in its place
		want []string
	}{
		{"unparseable", "keys: [\n", nil},
		{"unknown key", "bogus: 1\n", []string{"bogus"}},
		{"unknown key and a bad value", "bogus: 1\nconcurrency: abc\n", []string{"bogus", "concurrency"}},
		{"unreadable", "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := setupHarness(t)
			dir := t.TempDir()
			path := filepath.Join(dir, "nyx.yaml")
			if c.body == "" {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFile(t, dir, "nyx.yaml", c.body)
			}
			h.setenv("NYX_CONCURRENCY", "0") // an invalid variable adds no problem
			f := h.failed(h.setup([]string{"--config", path}), 2, false)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, path) {
				t.Errorf("error %+v: it should name %s", f, path)
			}
			for _, w := range c.want {
				if !strings.Contains(f.msg, w) {
					t.Errorf("message %q does not report %q", f.msg, w)
				}
			}
			if strings.Contains(f.msg, "NYX_CONCURRENCY") || strings.Contains(f.msg, `"0"`) {
				t.Errorf("the environment was read: %q", f.msg)
			}
			if h.stdout.Len() != 0 {
				t.Errorf("stdout %q: the UI opened", h.stdout.String())
			}
		})
	}
}

// With nothing to change, setup writes nothing, exits 0 and leaves the terminal as it found it;
// a missing file is not created. NYX_* variables and NVD_API_KEY are not read: they neither show
// nor stop it.
func TestSetup_QuitWithNoChangeWritesNothing(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ name, body string }{{"missing", ""}, {"existing", "concurrency: 7\n"}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := setupHarness(t)
			path := filepath.Join(t.TempDir(), "nyx.yaml")
			if c.body != "" {
				writeFile(t, filepath.Dir(path), "nyx.yaml", c.body)
			}
			h.setenv("NYX_CONCURRENCY", "abc")
			h.setenv("NYX_KEYS_SHODAN", "env-shodan-key-1234")
			h.setenv("NVD_API_KEY", "env-nvd-key-5678")
			want := readFileOrEmpty(t, path)
			if code := h.setup([]string{"--config", path}, "q"); code != 0 {
				t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
			}
			if got := readFileOrEmpty(t, path); got != want {
				t.Errorf("the file changed:\n%q\n%q", want, got)
			}
			out := h.stdout.String()
			if strings.Contains(out, "env-shodan-key") || strings.Contains(out, "env-nvd-key") {
				t.Error("a key from the environment is on screen")
			}
			if c.body != "" && !strings.Contains(out, "7") {
				t.Error("the file's concurrency is not shown")
			}
			if strings.Contains(out, "abc") {
				t.Error("NYX_CONCURRENCY changed what is shown")
			}
			if h.stderr.Len() != 0 {
				t.Errorf("stderr %q", h.stderr.String())
			}
		})
	}
}

// assertNoKeyBeyondItsEnd fails when the screen or stderr holds more of key than its last 4 characters.
func assertNoKeyBeyondItsEnd(t *testing.T, h *harness, key string) {
	t.Helper()
	for name, text := range map[string]string{"stdout": h.stdout.String(), "stderr": h.stderr.String()} {
		if strings.Contains(text, key[:len(key)-4]) || strings.Contains(text, key) {
			t.Errorf("%s shows more of the key than its last 4 characters", name)
		}
	}
}

// Through the real Program: a key is entered, saved and quit. The file holds the key trimmed,
// recon reads it, and nothing of it but its last four characters reaches the screen or stderr.
func TestSetup_EditSaveAndQuit(t *testing.T) {
	t.Parallel()
	for _, debug := range []bool{false, true} {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			h := setupHarness(t)
			path := filepath.Join(t.TempDir(), "nested", "nyx.yaml")
			const key = "sh0dan-KEY-abcdefghijklmnop-WXYZ"
			args := []string{"--config", path}
			if debug {
				args = append(args, "--debug")
			}
			keys := append(typedKey(1, "  "+key+"  "), keyCtrlS, "q")
			if code := h.setup(args, keys...); code != 0 {
				t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
			}
			if got := loaded(t, path).Keys["shodan"].Reveal(); got != key {
				t.Errorf("saved key %q, want %q", got, key)
			}
			assertNoKeyBeyondItsEnd(t, h, key)
			if !strings.Contains(h.stdout.String(), "WXYZ") {
				t.Error("the key's last 4 characters are not shown")
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("file mode %v, %v: want 0600", info, err)
			}
			if d, err := os.Stat(filepath.Dir(path)); err != nil || d.Mode().Perm() != 0o700 {
				t.Errorf("the created directory is %v, %v: want 0700", d, err)
			}
		})
	}
}

// A key entered and saved without a test is shown and recorded as not tested, dated by the clock,
// and the record does not stop nyx recon reading the file.
func TestSetup_EnteredKeyIsRecordedAsNotTested(t *testing.T) {
	t.Parallel()
	h := setupHarness(t)
	path := filepath.Join(t.TempDir(), "nyx.yaml")
	const key = "sh0dan-KEY-abcdefghijklmnop-WXYZ"
	if code := h.setup([]string{"--config", path}, append(typedKey(1, key), keyCtrlS, "q")...); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	got := readFileOrEmpty(t, path)
	if !strings.Contains(got, "key_tests:\n  shodan:\n    result: not tested\n    date: \"2026-11-01\"\n    key: ") {
		t.Errorf("the file does not record the key as not tested on the clock's day:\n%s", got)
	}
	if !strings.Contains(h.stdout.String(), "not tested") {
		t.Error("the entered key is not shown as not tested")
	}
	if loaded(t, path).Keys["shodan"].Reveal() != key {
		t.Error("the key did not load back")
	}
}

// Discarding leaves the file as it was and exits 0; so does going back, then discarding.
func TestSetup_DiscardLeavesTheFile(t *testing.T) {
	t.Parallel()
	h := setupHarness(t)
	dir := t.TempDir()
	path := writeFile(t, dir, "nyx.yaml", "# mine\nconcurrency: 7\n")
	keys := append(typedKey(0, "a-key-that-is-not-kept"), "q", "d")
	if code := h.setup([]string{"--config", path}, keys...); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	if got := readFileOrEmpty(t, path); got != "# mine\nconcurrency: 7\n" {
		t.Errorf("the file changed: %q", got)
	}
}

// A save keeps everything else in the file, and a later nyx cve with no NVD_API_KEY sends the nvd
// key setup saved, exactly as typed.
func TestSetup_SavedNVDKeyIsUsedByCVE(t *testing.T) {
	t.Parallel()
	h := setupHarness(t)
	nvd := newNVD(t, h)
	id := nvd.fixture("rejected.json")
	dir := filepath.Join(h.env["XDG_CONFIG_HOME"], "nyx")
	writeFile(t, dir, "config.yaml", "# my config\nconcurrency: 7 # workers\n")
	const key = `nvd: "key" #1 -0x10 yes é` // characters that are special in YAML
	if code := h.setup(nil, append(typedKey(8, key), keyCtrlS, "q")...); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	got := readFileOrEmpty(t, filepath.Join(dir, "config.yaml"))
	for _, want := range []string{"# my config", "concurrency: 7 # workers"} {
		if !strings.Contains(got, want) {
			t.Errorf("the save lost %q:\n%s", want, got)
		}
	}
	h.stdoutTTY, h.stdin = false, nil
	if code := h.cveRun(true, id); code != 0 {
		t.Fatalf("cve exit %d: %s", code, h.stderr.String())
	}
	if keys := nvd.apiKeys(); !slices.Equal(keys, []string{key}) {
		t.Errorf("the NVD received %q, want %q", keys, key)
	}
}

// An interrupt that arrives before setup has drawn anything exits with the signal's code and leaves
// the file as it was.
func TestSetup_SignalLeavesTheFile(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		sig  os.Signal
		want int
	}{{os.Interrupt, 130}, {sigTerm, 143}, {sigHup, 129}} {
		t.Run(c.sig.String(), func(t *testing.T) {
			t.Parallel()
			h := setupHarness(t)
			path := writeFile(t, t.TempDir(), "nyx.yaml", "concurrency: 7\n")
			h.signals = make(chan os.Signal, 2)
			h.signals <- c.sig
			keys := append(typedKey(0, "a-key-never-saved"), keyCtrlS)
			code := h.setup([]string{"--config", path}, keys...)
			if code != c.want {
				t.Fatalf("exit %d, want %d (stderr %q)", code, c.want, h.stderr.String())
			}
			if got := readFileOrEmpty(t, path); got != "concurrency: 7\n" {
				t.Errorf("the file changed: %q", got)
			}
		})
	}
}

var (
	sigTerm os.Signal = syscall.SIGTERM
	sigHup  os.Signal = syscall.SIGHUP
)

// sequence is a terminal input that hands each chunk of key presses over on its own read and runs
// the hook of a chunk before it does, so that something can change between two key presses.
type sequence struct {
	chunks []string
	before map[int]func()
	next   int
}

func (s *sequence) Read(p []byte) (int, error) {
	if s.next >= len(s.chunks) {
		return 0, io.EOF
	}
	// The editor draws about every 17 ms, so each chunk gets its own frame; a lone escape is given
	// time to be told from the start of a longer sequence before the next chunk follows it.
	if s.next > 0 {
		pause := 40 * time.Millisecond
		if s.chunks[s.next-1] == keyEsc {
			pause = 300 * time.Millisecond
		}
		time.Sleep(pause)
	}
	if f := s.before[s.next]; f != nil {
		f()
	}
	n := copy(p, s.chunks[s.next])
	s.next++
	return n, nil
}

// An edit while the file changed on disk does not write until the user chooses: reload drops the
// edits, overwrite writes them over what is there now, and going back writes nothing.
func TestSetup_ChangedFileAsksBeforeWriting(t *testing.T) {
	t.Parallel()
	const key = "changed-file-key-0123456789"
	for _, c := range []struct {
		name, choice string
		wantKey      bool
	}{{"reload", "r", false}, {"overwrite", "o", true}, {"back", keyEsc, false}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := setupHarness(t)
			dir := t.TempDir()
			path := writeFile(t, dir, "nyx.yaml", "concurrency: 7\n")
			external := "concurrency: 7\nrate:\n  dns: 12\n"
			chunks := append(typedKey(1, key), keyCtrlS, c.choice, keyCtrlC, "d")
			h.stdin = &sequence{chunks: chunks, before: map[int]func(){
				len(chunks) - 4: func() { writeFile(t, dir, "nyx.yaml", external) }, // before ctrl+s
			}}
			if code := h.execRootTimeout("setup", "--config", path); code != 0 {
				t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
			}
			got := readFileOrEmpty(t, path)
			if has := strings.Contains(got, key); has != c.wantKey {
				t.Errorf("the key was saved: %v, want %v\n%s", has, c.wantKey, got)
			}
			if !strings.Contains(got, "dns: 12") {
				t.Errorf("what was written to the file outside setup is lost:\n%s", got)
			}
		})
	}
}

// A save that fails leaves setup open with the edits, says why and where, and leaves the file as
// it was.
func TestSetup_FailedSaveKeepsTheEdits(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	h := setupHarness(t)
	dir := t.TempDir()
	path := writeFile(t, dir, "nyx.yaml", "concurrency: 7\n")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	const key = "unsaved-key-0123456789-ABCD"
	keys := append(typedKey(1, key), keyCtrlS, "q", "d")
	if code := h.setup([]string{"--config", path}, keys...); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	if got := readFileOrEmpty(t, path); got != "concurrency: 7\n" {
		t.Errorf("the file changed: %q", got)
	}
	out := h.stdout.String()
	if !strings.Contains(out, "Could not save: ") || !strings.Contains(out, "File: "+path) || !strings.Contains(out, "permission denied") {
		t.Errorf("the screen does not give the reason and the path:\n%q", out)
	}
	if !strings.Contains(out, "Save, discard") && !strings.Contains(strings.ToLower(out), "unsaved") {
		t.Errorf("setup closed instead of staying open with the edits:\n%q", out)
	}
}

// A value in the file that recon would refuse opens marked invalid, and saving is blocked until it
// is fixed or cleared.
func TestSetup_InvalidValueBlocksSaving(t *testing.T) {
	t.Parallel()
	h := setupHarness(t)
	dir := t.TempDir()
	path := writeFile(t, dir, "nyx.yaml", "concurrency: abc\nskip: [crtsh, nosuchstage, resolve]\n")
	keys := append(typedKey(1, "a-key-that-cannot-be-saved"), keyCtrlS, keyTab, keyCtrlS, "q", "d")
	if code := h.setup([]string{"--config", path}, keys...); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	if got := readFileOrEmpty(t, path); strings.Contains(got, "a-key-that") {
		t.Errorf("a file with invalid values was saved: %q", got)
	}
	out := h.stdout.String()
	for _, want := range []string{"not an integer"} {
		if !strings.Contains(out, want) {
			t.Errorf("the screen does not show %q", want)
		}
	}
}

// Keys never reach the screen, stderr or an error, even when the editor panics: the failure is
// UNEXPECTED_ERROR with the terminal given back, and --debug adds a stack with no key in it.
func TestSetup_PanicLeaksNoKey(t *testing.T) {
	t.Parallel()
	const fileKey, typedKey1 = "file-key-ABCDEFGHIJKLMNOP-1234", "typed-key-ZYXWVUTSRQPONM-9876"
	for _, debug := range []bool{false, true} {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := writeFile(t, dir, "nyx.yaml", "keys:\n  virustotal: "+fileKey+"\n  extra: unknown-source-key-QWERTYUIOP\n")
			// How often opening the file asks for the working directory: the panic is the call after.
			probe := setupHarness(t)
			if code := probe.setup([]string{"--config", path}, "q"); code != 0 {
				t.Fatalf("probe exit %d: %s", code, probe.stderr.String())
			}
			h := setupHarness(t)
			h.getwdPanicAfter = int(probe.getwdCalls.Load())
			args := []string{"--config", path}
			if debug {
				args = append(args, "--debug")
			}
			keys := append(typedKey(1, typedKey1), keyTab, keyEnter, "relative/dir", keyEnter)
			code := h.setup(args, keys...)
			if code != 1 {
				t.Fatalf("exit %d, want 1\nstderr %q", code, h.stderr.String())
			}
			if !strings.Contains(h.stderr.String(), "UNEXPECTED_ERROR") || !strings.Contains(h.stderr.String(), "forced panic") {
				t.Errorf("stderr %q", h.stderr.String())
			}
			if debug && !strings.Contains(h.stderr.String(), "goroutine") {
				t.Error("--debug adds no stack")
			}
			for name, text := range map[string]string{"stdout": h.stdout.String(), "stderr": h.stderr.String()} {
				for _, k := range []string{fileKey, typedKey1, "unknown-source-key-QWERTYUIOP"} {
					if strings.Contains(text, k[:len(k)-4]) {
						t.Errorf("%s holds more of the key %q than its last 4 characters", name, k[len(k)-4:])
					}
				}
			}
		})
	}
}
