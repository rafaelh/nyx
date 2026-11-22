package configedit_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/configedit"
	"github.com/rafaelh/nyx/internal/setup"
)

func (w *world) save(snap setup.Snapshot, e setup.Edits) setup.Snapshot {
	w.t.Helper()
	out, err := w.store.Save(snap, e)
	if err != nil {
		w.t.Fatalf("Save: %v", err)
	}
	return out
}

func (w *world) contents() string {
	w.t.Helper()
	return read(w.t, w.path)
}

func TestStore_SaveChangesOnlyTheEditedValuesAndReadsTheFileBack(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new(`# my nyx config

output_dir: /data # engagements
concurrency: 4
keys:
  # rotate monthly
  shodan: old # shodan
  foo: 'unknown source' # not listed
rate:
  dns: 20
`))
	snap := w.open()
	out := w.save(snap, setup.Edits{
		Set:   map[string]string{"keys.shodan": "new-key", "keys.github": "gh", "rate.per_host": "2.5"},
		Clear: []string{"concurrency", "rate.dns"},
		Skip:  []string{"dns", "ports"},
	})
	want := `# my nyx config

output_dir: /data # engagements
keys:
  # rotate monthly
  shodan: new-key # shodan
  foo: 'unknown source' # not listed
  github: gh
rate:
  per_host: "2.5"
skip:
  - dns
  - ports
`
	if got := w.contents(); got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
	if out.Keys["shodan"].Value != "new-key" || out.Keys["github"].Value != "gh" || out.Settings["rate.per_host"].Text != "2.5" ||
		out.Settings["concurrency"].Set || !slices.Equal(out.Skip, []string{"dns", "ports"}) {
		t.Errorf("the snapshot read back = %+v", out)
	}
	if m := mode(t, w.path); m != 0o600 {
		t.Errorf("mode = %o, want an existing 0644 file tightened to 600", m)
	}
}

func TestStore_SaveClearsAnEmptyBlockAndAnEmptySkipList(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("keys:\n  shodan: a\nskip: [dns]\nconcurrency: 3\n"))
	w.save(w.open(), setup.Edits{Clear: []string{"keys.shodan"}, Skip: []string{}})
	if got := w.contents(); got != "concurrency: 3\n" {
		t.Errorf("file = %q", got)
	}
}

func TestStore_SaveCreatesAMissingFileAndItsDirectories(t *testing.T) {
	t.Parallel()
	w := newWorld(t, nil)
	w.path = filepath.Join(w.home, ".config", "nyx", "config.yaml")
	w.opts.Path = w.path
	w.store = configedit.NewStore(w.opts)
	snap := w.open()
	out := w.save(snap, setup.Edits{Set: map[string]string{"keys.shodan": "k"}})
	if got := w.contents(); got != "keys:\n  shodan: k\n" {
		t.Errorf("file = %q", got)
	}
	if m := mode(t, w.path); m != 0o600 {
		t.Errorf("file mode = %o", m)
	}
	for _, d := range []string{filepath.Join(w.home, ".config"), filepath.Dir(w.path)} {
		if m := mode(t, d); m != 0o700 {
			t.Errorf("%s mode = %o", d, m)
		}
	}
	if out.Keys["shodan"].Value != "k" {
		t.Errorf("read back %+v", out.Keys["shodan"])
	}
}

// A file that keeps a source setup does not list is left alone, byte for byte, by a save.
func TestStore_SaveLeavesUnknownKeySourcesUntouched(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("keys:\n  foo: \"tricky: 'value' # not a comment\" # mine\n  bar: 0x1F\n  shodan: a\n"))
	w.save(w.open(), setup.Edits{Set: map[string]string{"keys.shodan": "b"}})
	got := w.contents()
	for _, line := range []string{"  foo: \"tricky: 'value' # not a comment\" # mine\n", "  bar: 0x1F\n", "  shodan: b\n"} {
		if !strings.Contains(got, line) {
			t.Errorf("lost %q in:\n%s", line, got)
		}
	}
	snap := w.open()
	if _, ok := snap.Keys["foo"]; ok || len(snap.Keys) != 9 {
		t.Errorf("keys = %v", snap.Keys)
	}
}

func TestStore_SaveFixesCaseVariants(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("Concurrency: 5\nconcurrency: 6\nKeys:\n  Shodan: a\nkeys:\n  shodan: b\n  github: g\n"))
	snap := w.open()
	if snap.Settings["concurrency"].Problem == "" || snap.Keys["shodan"].Problem == "" {
		t.Fatalf("not marked invalid: %+v", snap.Settings["concurrency"])
	}
	out := w.save(snap, setup.Edits{Set: map[string]string{"concurrency": "9", "keys.shodan": "z"}})
	if got, want := w.contents(), "Concurrency: \"9\"\nKeys:\n  Shodan: z\n  github: g\n"; got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
	if p := out.Settings["concurrency"].Problem + out.Keys["shodan"].Problem + out.Keys["github"].Problem; p != "" {
		t.Errorf("still marked invalid: %q", p)
	}
}

// Every key and path is stored exactly as entered, whatever characters it holds, and a run reads
// back what setup showed.
func TestStore_SaveRoundTripsAwkwardKeysAndPaths(t *testing.T) {
	t.Parallel()
	awkward := []string{
		"a: b", "x #y", `q"uote'`, "-lead", "yes", "0123", "0x10", "héllo 日本語 🔑", "tab\there", "1e3", "null", "~tilde", "*star", "{brace}", "a,b",
		"multi\nline", "back\\slash", "  spaced  ", "", strings.Repeat("long ", 40),
	}
	w := newWorld(t, nil)
	edits := setup.Edits{Set: map[string]string{}}
	for i, n := range sourceNames {
		v := awkward[i%len(awkward)]
		if v == "" {
			v = "nonempty"
		}
		edits.Set["keys."+n] = v
	}
	// Paths: the files exist, under names full of what YAML cares about.
	odd := ": #'\" -yes 0123 0x10 é\tz"
	words := filepath.Join(w.cwd, "w"+odd)
	paths := filepath.Join(w.cwd, "p"+odd)
	if err := os.WriteFile(words, []byte("www\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths, []byte("- path: '/x'\n  signature: 'y'\n  severity: high\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"output_dir": filepath.Join(w.cwd, "o"+odd), "wordlist": words, "sensitive_paths": paths,
		"concurrency": "0123", "rate.per_host": "0.5", "rate.per_source": "007", "rate.dns": "1e2"} {
		got, err := w.store.Check(k, v)
		if err != nil {
			t.Fatalf("Check(%s, %q): %v", k, v, err)
		}
		edits.Set[k] = got
	}
	snap := w.save(w.open(), edits)

	loaded, err := config.Load(nil, w.path, config.Env{"HOME=" + w.home})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	for n, v := range edits.Set {
		if key, ok := strings.CutPrefix(n, "keys."); ok {
			if got := loaded.Keys[key].Reveal(); got != v {
				t.Errorf("keys.%s: a run reads %q, want %q", key, got, v)
			}
			if got := snap.Keys[key].Value.Reveal(); got != v {
				t.Errorf("keys.%s: setup shows %q, want %q", key, got, v)
			}
		}
	}
	if loaded.OutputDir != edits.Set["output_dir"] || loaded.Wordlist != words || loaded.SensitivePaths != paths {
		t.Errorf("paths: %q %q %q", loaded.OutputDir, loaded.Wordlist, loaded.SensitivePaths)
	}
	if loaded.Concurrency != 123 || loaded.Rate.PerHost != 0.5 || loaded.Rate.PerSource != 7 || loaded.Rate.DNS != 100 {
		t.Errorf("numbers: %d %+v", loaded.Concurrency, loaded.Rate)
	}
	for _, k := range []string{"output_dir", "wordlist", "sensitive_paths"} {
		if got := snap.Settings[k]; got.Text != edits.Set[k] || got.Problem != "" {
			t.Errorf("setup shows %s = %+v, want %q", k, got, edits.Set[k])
		}
	}
	if got := snap.Settings["concurrency"].Text; got != "123" {
		t.Errorf("setup shows concurrency %q; a run uses 123", got)
	}
}

// Save refuses to write over a file that changed since the snapshot, and writes nothing.
func TestStore_SaveReturnsErrConflictWhenTheFileChanged(t *testing.T) {
	t.Parallel()
	edit := setup.Edits{Set: map[string]string{"keys.shodan": "mine"}}
	conflict := func(t *testing.T, w *world, snap setup.Snapshot, changed string) {
		t.Helper()
		w.write(changed)
		_, err := w.store.Save(snap, edit)
		if !errors.Is(err, setup.ErrConflict) {
			t.Errorf("Save error = %v, want ErrConflict", err)
		}
		if got := w.contents(); got != changed {
			t.Errorf("the changed file was written: %q", got)
		}
		if got := names(t, w.dir); !slices.Equal(got, []string{"config.yaml"}) {
			t.Errorf("directory holds %v", got)
		}
	}
	t.Run("after open", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, new("concurrency: 4\n"))
		conflict(t, w, w.open(), "concurrency: 5\n")
	})
	t.Run("after save", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, new("concurrency: 4\n"))
		snap := w.save(w.open(), setup.Edits{Set: map[string]string{"concurrency": "6"}})
		conflict(t, w, snap, "concurrency: 7\n")
	})
	t.Run("after reload", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, new("concurrency: 4\n"))
		w.open()
		w.write("concurrency: 5\n")
		snap := w.open()
		conflict(t, w, snap, "concurrency: 8\n")
	})
	t.Run("a file that appeared", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, nil)
		conflict(t, w, w.open(), "concurrency: 5\n")
	})
	t.Run("a file that went", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, new("concurrency: 4\n"))
		snap := w.open()
		if err := os.Remove(w.path); err != nil {
			t.Fatal(err)
		}
		if _, err := w.store.Save(snap, edit); !errors.Is(err, setup.ErrConflict) {
			t.Errorf("Save error = %v", err)
		}
		if _, err := os.Stat(w.path); err == nil {
			t.Error("the file was created")
		}
	})
	t.Run("an unreadable file", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, new("concurrency: 4\n"))
		snap := w.open()
		if err := os.Remove(w.path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(w.path, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := w.store.Save(snap, edit); err == nil {
			t.Error("Save wrote over a directory")
		}
	})
}

// Rewriting the same bytes is not a change.
func TestStore_SaveIsNotAConflictWhenTheBytesAreTheSame(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("concurrency: 4\n"))
	snap := w.open()
	w.write("concurrency: 4\n")
	w.save(snap, setup.Edits{Set: map[string]string{"keys.shodan": "mine"}})
	// And a second save from what the first returned.
	snap = w.open()
	w.save(snap, setup.Edits{Set: map[string]string{"keys.github": "gh"}})
	if got := w.contents(); !strings.Contains(got, "shodan: mine") || !strings.Contains(got, "github: gh") {
		t.Errorf("file = %q", got)
	}
}

func TestStore_OverwriteAppliesTheEditsToTheFileAsItIsNow(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("concurrency: 4\n"))
	w.open()
	w.write("# changed elsewhere\nconcurrency: 5\nrate:\n  dns: 3\n")
	out, err := w.store.Overwrite(setup.Edits{Set: map[string]string{"keys.shodan": "mine"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := w.contents(), "# changed elsewhere\nconcurrency: 5\nrate:\n  dns: 3\nkeys:\n  shodan: mine\n"; got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
	if out.Keys["shodan"].Value != "mine" || out.Settings["concurrency"].Text != "5" {
		t.Errorf("snapshot = %+v", out)
	}
	// The returned snapshot is current: a Save from it is not a conflict.
	w.save(out, setup.Edits{Clear: []string{"keys.shodan"}})
}

func TestStore_OverwriteReplacesAFileThatCannotBeOpened(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{"unparseable": "keys: [unclosed\n", "unknown key": "concurency: 3\nkeys:\n  shodan: a\n", "two documents": "a: 1\n---\nb: 2\n"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, &body)
			out, err := w.store.Overwrite(setup.Edits{Set: map[string]string{"concurrency": "9"}})
			if err != nil {
				t.Fatal(err)
			}
			if out.Settings["concurrency"].Text != "9" {
				t.Errorf("snapshot = %+v", out.Settings["concurrency"])
			}
			if w.contents() != "concurrency: \"9\"\n" {
				t.Errorf("file = %q", w.contents())
			}
		})
	}
}

// A failed save leaves the file as it was and the error shows the reason and the path, but no key.
func TestStore_ASaveThatFailsLeavesTheFileAndNamesNoKey(t *testing.T) {
	t.Parallel()
	const secret = "SECRET-KEY-0123456789"
	w := newWorld(t, new("concurrency: 4\n"), func(o *configedit.StoreOptions) {
		o.Rename = func(oldpath, newpath string) error {
			return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: syscall.EXDEV}
		}
	})
	snap := w.open()
	_, err := w.store.Save(snap, setup.Edits{Set: map[string]string{"keys.shodan": secret}})
	if err == nil || errors.Is(err, setup.ErrConflict) {
		t.Fatalf("Save error = %v", err)
	}
	if !strings.Contains(err.Error(), w.path) || !strings.Contains(err.Error(), syscall.EXDEV.Error()) || strings.Contains(err.Error(), secret) {
		t.Errorf("error = %q", err)
	}
	if got := w.contents(); got != "concurrency: 4\n" {
		t.Errorf("file = %q", got)
	}
	if got := names(t, w.dir); !slices.Equal(got, []string{"config.yaml"}) {
		t.Errorf("directory holds %v", got)
	}
	// Overwrite fails the same way.
	if _, err := w.store.Overwrite(setup.Edits{Set: map[string]string{"keys.shodan": secret}}); err == nil || strings.Contains(err.Error(), secret) {
		t.Errorf("Overwrite error = %v", err)
	}
}

func TestStore_ASaveIntoAReadOnlyDirectoryFailsWithReasonAndPath(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	w := newWorld(t, new("concurrency: 4\n"))
	snap := w.open()
	if err := os.Chmod(w.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(w.dir, 0o700) })
	_, err := w.store.Save(snap, setup.Edits{Set: map[string]string{"keys.shodan": "k"}})
	if err == nil || !strings.Contains(err.Error(), w.path) || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %v", err)
	}
	if got := w.contents(); got != "concurrency: 4\n" {
		t.Errorf("file = %q", got)
	}
}

func TestStore_SaveThroughASymlinkUpdatesTheTarget(t *testing.T) {
	t.Parallel()
	w := newWorld(t, nil)
	real := filepath.Join(w.home, "dotfiles", "nyx.yaml")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, []byte("concurrency: 4\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link(t, real, w.path)
	snap := w.open()
	if snap.Settings["concurrency"].Text != "4" {
		t.Fatalf("not read through the link: %+v", snap.Settings["concurrency"])
	}
	w.save(snap, setup.Edits{Set: map[string]string{"keys.shodan": "k"}})
	if got, err := os.Readlink(w.path); err != nil || got != real {
		t.Errorf("link = %q, %v", got, err)
	}
	if got := read(t, real); got != "concurrency: 4\nkeys:\n  shodan: k\n" {
		t.Errorf("target = %q", got)
	}
}

// Setup edits with no changes need not touch the file at all.
func TestStore_SaveWithNoEditsKeepsTheBytes(t *testing.T) {
	t.Parallel()
	body := "# c\n\n\nconcurrency: 4\n\nkeys: {shodan: a}\n"
	w := newWorld(t, &body)
	w.save(w.open(), setup.Edits{})
	if got := w.contents(); got != body {
		t.Errorf("file = %q", got)
	}
}

// A lone "~" is the home directory, not YAML's null.
func TestStore_ATildeAloneIsStoredAsTheHomeDirectory(t *testing.T) {
	t.Parallel()
	w := newWorld(t, nil)
	out := w.save(w.open(), setup.Edits{Set: map[string]string{"output_dir": "~", "keys.shodan": "~"}})
	loaded, err := config.Load(nil, w.path, config.Env{"HOME=" + w.home})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.OutputDir != w.home || loaded.Keys["shodan"].Reveal() != "~" {
		t.Errorf("a run reads output_dir %q and key %q", loaded.OutputDir, loaded.Keys["shodan"].Reveal())
	}
	if got := out.Settings["output_dir"]; got.Text != "~" || !got.Set || got.Problem != "" || got.Relative != "" {
		t.Errorf("setup shows %+v", got)
	}
}
