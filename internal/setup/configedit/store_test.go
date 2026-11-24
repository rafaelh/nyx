package configedit_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/setup"
	"github.com/rafaelh/nyx/internal/setup/configedit"
)

// The store does everything of a setup.Backend except Test.
var _ interface {
	Info() setup.Info
	Open() (setup.Snapshot, error)
	Check(key, value string) (string, error)
	Save(snap setup.Snapshot, edits setup.Edits) (setup.Snapshot, error)
	Overwrite(edits setup.Edits) (setup.Snapshot, error)
} = (*configedit.Store)(nil)

var sourceNames = []string{"securitytrails", "shodan", "virustotal", "whoisxml", "censys", "chaos", "github", "certspotter", "nvd"}

func skipEntry(name string) string {
	switch name {
	case "dns", "ports", "email", "web":
		return ""
	case "resolve":
		return fmt.Sprintf("procedure %q cannot be skipped: other procedures' safety depends on it", name)
	}
	return fmt.Sprintf("unknown procedure %q for --skip or the skip setting", name)
}

// world is a config file in a temp directory, and a store over it.
type world struct {
	t     *testing.T
	dir   string // holds the config file
	path  string
	home  string
	cwd   string // the directory setup "runs from"
	store *configedit.Store
	opts  configedit.StoreOptions
}

func newWorld(t *testing.T, body *string, mod ...func(*configedit.StoreOptions)) *world {
	t.Helper()
	w := &world{t: t, dir: t.TempDir(), home: t.TempDir(), cwd: t.TempDir()}
	w.path = filepath.Join(w.dir, "config.yaml")
	if body != nil {
		w.write(*body)
	}
	w.opts = configedit.StoreOptions{
		Path:       w.path,
		Env:        config.Env{"HOME=" + w.home},
		Procedures: []setup.Procedure{{Name: "dns", Does: "d"}, {Name: "ports", Does: "p"}, {Name: "email", Does: "e"}},
		SkipEntry:  skipEntry,
		Getwd:      func() (string, error) { return w.cwd, nil },
		NoFsync:    true,
	}
	for _, n := range sourceNames {
		w.opts.Sources = append(w.opts.Sources, setup.Source{Name: n, Turns: "turns " + n})
	}
	for _, m := range mod {
		m(&w.opts)
	}
	w.store = configedit.NewStore(w.opts)
	return w
}

// yamlFor is a config file that sets key to the string val, written by hand rather than by the
// editor under test.
func yamlFor(key, val string) string {
	if section, name, ok := strings.Cut(key, "."); ok {
		return section + ":\n  " + name + ": " + strconv.Quote(val) + "\n"
	}
	return key + ": " + strconv.Quote(val) + "\n"
}

func (w *world) write(body string) {
	w.t.Helper()
	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(w.path, []byte(body), 0o644); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) open() setup.Snapshot {
	w.t.Helper()
	snap, err := w.store.Open()
	if err != nil {
		w.t.Fatalf("Open: %v", err)
	}
	return snap
}

func (w *world) openErr() *setup.FileError {
	w.t.Helper()
	_, err := w.store.Open()
	fe, ok := errors.AsType[*setup.FileError](err)
	if !ok {
		w.t.Fatalf("Open error = %v, want a *setup.FileError", err)
	}
	return fe
}

// problems indexes config.Check diagnostics by setting key.
func problems(t *testing.T, body, path string, env config.Env) clierr.Problems {
	t.Helper()
	_, err := config.Check([]byte(body), path, env)
	var p clierr.Problems
	if err != nil && !errors.As(err, &p) {
		t.Fatalf("Check error %v is not Problems", err)
	}
	return p
}

func messageFor(p clierr.Problems, key string) string {
	for _, q := range p {
		if q.Name == key {
			return q.Message
		}
	}
	return ""
}

func TestStore_InfoGivesTheAbsolutePathAndWhatTheFileCanHold(t *testing.T) {
	t.Parallel()
	w := newWorld(t, nil)
	info := w.store.Info()
	if info.Path != w.path || len(info.Sources) != 9 || info.Sources[1].Name != "shodan" || len(info.Procedures) != 3 {
		t.Errorf("Info = %+v", info)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relPath, err := filepath.Rel(cwd, w.path)
	if err != nil {
		t.Fatal(err)
	}
	rel := configedit.NewStore(configedit.StoreOptions{Path: relPath})
	if got := rel.Info().Path; got != w.path {
		t.Errorf("a relative path is shown as %q, want %q", got, w.path)
	}
}

func TestStore_AMissingFileIsDefaults(t *testing.T) {
	t.Parallel()
	for name, mod := range map[string]func(w *world){
		"in an existing directory": func(w *world) {},
		"under directories that do not exist": func(w *world) {
			w.path = filepath.Join(w.home, ".config", "nyx", "config.yaml")
			w.opts.Path = w.path
			w.store = configedit.NewStore(w.opts)
		},
		"a dangling symlink": func(w *world) {
			link(t, filepath.Join(w.dir, "nowhere.yaml"), w.path)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, nil)
			mod(w)
			snap := w.open()
			if snap.Token == nil || snap.Token != w.open().Token {
				t.Errorf("Token = %v: an absent file should give the same token each time", snap.Token)
			}
			for _, n := range sourceNames {
				if ks, ok := snap.Keys[n]; !ok || ks.Value != "" || ks.Problem != "" {
					t.Errorf("Keys[%s] = %+v", n, ks)
				}
			}
			for _, k := range setup.SettingKeys {
				v, ok := snap.Settings[k]
				if !ok || v.Set || v.Text != "" || v.Problem != "" || v.Default != config.DefaultText(k) {
					t.Errorf("Settings[%s] = %+v", k, v)
				}
			}
			if want := "Relative: resolves against the directory nyx runs from, e.g. " + w.cwd; snap.Settings["output_dir"].Relative != want {
				t.Errorf("output_dir Relative = %q, want %q", snap.Settings["output_dir"].Relative, want)
			}
			if len(snap.Skip) != 0 || len(snap.SkipProblems) != 0 || snap.SkipListProblem != "" {
				t.Errorf("skip = %+v", snap)
			}
		})
	}
}

// The values shown are the ones the loader decodes, so a reader sees what a run uses.
func TestStore_OpenShowsTheDecodedValues(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new(`# my config
concurrency: 0x10
rate:
  per_host: 2.50
  per_source: 010
  dns: 1e2
keys:
  shodan: abc123
  github: 0123
  nvd: ""
  foo: unknown source
output_dir: ~/engagements
sensitive_paths: ""
`))
	snap := w.open()
	for key, want := range map[string]setup.Value{
		"concurrency":     {Text: "16", Set: true, Default: "10"},
		"rate.per_host":   {Text: "2.5", Set: true, Default: "5"},
		"rate.per_source": {Text: "8", Set: true, Default: "1"},
		"rate.dns":        {Text: "100", Set: true, Default: "50"},
		"output_dir":      {Text: "~/engagements", Set: true, Default: "."},
		"wordlist":        {Default: config.BuiltinWordlistLabel()},
		"sensitive_paths": {Set: true, Default: config.BuiltinSensitivePathsLabel()},
	} {
		if got := snap.Settings[key]; got != want {
			t.Errorf("Settings[%s] = %+v, want %+v", key, got, want)
		}
	}
	if got := snap.Keys["shodan"]; got.Value != "abc123" || got.Problem != "" {
		t.Errorf("shodan = %+v", got)
	}
	if got := snap.Keys["github"].Value; got != "83" {
		t.Errorf("an unquoted 0123 is read as %q by the loader, so is shown as that", got)
	}
	if got := snap.Keys["nvd"]; got.Value != "" || got.Problem != "" {
		t.Errorf("an empty key = %+v", got)
	}
	if _, listed := snap.Keys["foo"]; listed || len(snap.Keys) != 9 {
		t.Errorf("an unknown source is listed: %v", snap.Keys)
	}
}

func TestStore_OpenMarksRelativePaths(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("output_dir: out/sub\nwordlist: words.txt\nsensitive_paths: ~/paths.yaml\n"))
	snap := w.open()
	if got, want := snap.Settings["output_dir"].Relative, "Relative: resolves against the directory nyx runs from, e.g. "+filepath.Join(w.cwd, "out/sub"); got != want {
		t.Errorf("output_dir Relative = %q, want %q", got, want)
	}
	if got, want := snap.Settings["wordlist"].Relative, "Relative: resolves against the directory nyx runs from, e.g. "+filepath.Join(w.cwd, "words.txt"); got != want {
		t.Errorf("wordlist Relative = %q, want %q", got, want)
	}
	if got := snap.Settings["sensitive_paths"].Relative; got != "" {
		t.Errorf("a ~/ path is not relative: %q", got)
	}
	w2 := newWorld(t, new("output_dir: /abs/out\n"))
	if got := w2.open().Settings["output_dir"].Relative; got != "" {
		t.Errorf("an absolute path is not relative: %q", got)
	}
}

// Invalid values open marked invalid, with the message nyx recon gives for the file.
func TestStore_OpenMarksInvalidValuesWithReconsMessages(t *testing.T) {
	t.Parallel()
	body := "concurrency: abc\nrate:\n  dns: -1\n  per_host: 3\nwordlist: /no/such/wordlist.txt\nsensitive_paths: /no/such/paths.yaml\noutput_dir: \"\"\n"
	w := newWorld(t, &body)
	snap := w.open()
	probs := problems(t, body, w.path, w.opts.Env)
	for _, key := range []string{"concurrency", "rate.dns", "wordlist", "sensitive_paths", "output_dir"} {
		want := messageFor(probs, key)
		if want == "" {
			t.Fatalf("config.Check has no problem for %s", key)
		}
		if got := snap.Settings[key]; got.Problem != want || !got.Set {
			t.Errorf("Settings[%s] = %+v, want problem %q", key, got, want)
		}
	}
	if got := snap.Settings["concurrency"].Text; got != "abc" {
		t.Errorf("an invalid value keeps its text for editing: %q", got)
	}
	if got := snap.Settings["rate.per_host"]; got.Problem != "" || got.Text != "3" {
		t.Errorf("rate.per_host = %+v", got)
	}
}

func TestStore_OpenRefusesAFileNyxReconWouldRefuse(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct{ body string }{
		"unparseable":               {"keys: [unclosed\n"},
		"unknown key":               {"concurency: 3\nrate:\n  dns: -1\n"},
		"unknown key under a block": {"keys:\n  shodan: abc\nrate:\n  fast: 1\n"},
		"a block that is a string":  {"keys: abc\n"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, &c.body)
			fe := w.openErr()
			if fe.Path != w.path {
				t.Errorf("Path = %q, want %q", fe.Path, w.path)
			}
			var want []string
			for _, p := range problems(t, c.body, w.path, w.opts.Env) {
				want = append(want, p.Message)
			}
			if len(want) == 0 || !slices.Equal(fe.Problems, want) {
				t.Errorf("problems = %q, want %q", fe.Problems, want)
			}
			// A problem the file has besides the fatal one is in the set too.
			if name == "unknown key" && !strings.Contains(strings.Join(fe.Problems, "\n"), "rate.dns") {
				t.Errorf("the whole problem set is not given: %q", fe.Problems)
			}
		})
	}
}

func TestStore_OpenReportsSkipProblemsWithAFatalFile(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("concurency: 3\nskip: [foo, dns]\n"))
	fe := w.openErr()
	if !slices.Contains(fe.Problems, skipEntry("foo")) || slices.Contains(fe.Problems, skipEntry("dns")) {
		t.Errorf("problems = %q", fe.Problems)
	}
}

func TestStore_OpenRefusesAFileItCannotRead(t *testing.T) {
	t.Parallel()
	w := newWorld(t, nil)
	if err := os.MkdirAll(w.path, 0o755); err != nil { // a directory where the file should be
		t.Fatal(err)
	}
	fe := w.openErr()
	want := config.FileReadMessage(w.path, &os.PathError{Op: "read", Path: w.path, Err: errors.New("is a directory")})
	if len(fe.Problems) != 1 || fe.Problems[0] != want || fe.Path != w.path {
		t.Errorf("FileError = %+v, want one problem %q", fe, want)
	}
}

// A key in a file that fails to decode is never in the message about it.
func TestStore_AFileErrorNeverHoldsAKey(t *testing.T) {
	t.Parallel()
	const secret = "SECRET-KEY-0123456789"
	for name, body := range map[string]string{
		"a list for a key":    "keys:\n  shodan: [" + secret + "]\n",
		"a block for a key":   "keys:\n  shodan:\n    x: " + secret + "\n",
		"with an unknown key": "nope: 1\nkeys:\n  shodan: " + secret + "\n",
		"a bad setting":       "concurrency: " + secret + "\nkeys:\n  shodan: " + secret + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, &body)
			snap, err := w.store.Open()
			text := fmt.Sprintf("%v %+v", err, snap)
			if fe, ok := errors.AsType[*setup.FileError](err); ok {
				text += strings.Join(fe.Problems, "\n")
			}
			for _, s := range []setup.KeyState{snap.Keys["shodan"]} {
				text += s.Problem
			}
			for _, v := range snap.Settings {
				text += v.Problem
			}
			if strings.Contains(strings.ReplaceAll(text, "****", ""), secret) && name != "a bad setting" {
				t.Errorf("a key is in the output: %s", text)
			}
		})
	}
}

func TestStore_CaseVariantsShowAsTheSettingAndTwoVariantsAreInvalid(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("Concurrency: 5\nKeys:\n  Shodan: abc\nRate:\n  PER_HOST: 3\n"))
	snap := w.open()
	if got := snap.Settings["concurrency"]; got.Text != "5" || got.Problem != "" || !got.Set {
		t.Errorf("concurrency = %+v", got)
	}
	if got := snap.Keys["shodan"]; got.Value != "abc" || got.Problem != "" {
		t.Errorf("shodan = %+v", got)
	}
	if got := snap.Settings["rate.per_host"]; got.Text != "3" || got.Problem != "" {
		t.Errorf("rate.per_host = %+v", got)
	}

	w = newWorld(t, new("Concurrency: 5\nconcurrency: 6\nkeys:\n  Shodan: a\n  shodan: b\n  github: g\n"))
	snap = w.open()
	if got, want := snap.Settings["concurrency"].Problem, "set twice in the file, as `Concurrency` and `concurrency`"; got != want {
		t.Errorf("concurrency problem = %q, want %q", got, want)
	}
	if got, want := snap.Keys["shodan"].Problem, "set twice in the file, as `keys.Shodan` and `keys.shodan`"; got != want {
		t.Errorf("shodan problem = %q, want %q", got, want)
	}
	if got := snap.Keys["github"].Problem; got != "" {
		t.Errorf("an unambiguous key beside them is marked: %q", got)
	}
	// A whole block spelled twice makes every setting in it ambiguous.
	w = newWorld(t, new("Keys:\n  shodan: a\nkeys:\n  github: b\nRate:\n  dns: 3\nrate:\n  per_host: 4\n"))
	snap = w.open()
	if got, want := snap.Keys["shodan"].Problem, "set twice in the file, as `Keys` and `keys`"; got != want {
		t.Errorf("shodan problem = %q, want %q", got, want)
	}
	if got, want := snap.Settings["rate.dns"].Problem, "set twice in the file, as `Rate` and `rate`"; got != want {
		t.Errorf("rate.dns problem = %q, want %q", got, want)
	}
	if got := snap.Settings["concurrency"].Problem; got != "" {
		t.Errorf("concurrency is marked: %q", got)
	}
}

func TestStore_OpenReadsSkipAsNyxReconDoes(t *testing.T) {
	t.Parallel()
	type want struct {
		skip     []string
		problems []setup.SkipProblem
		list     bool
	}
	for body, c := range map[string]want{
		"skip: [dns, foo, resolve]\n":   {[]string{"dns"}, []setup.SkipProblem{{Entry: "foo", Message: skipEntry("foo")}, {Entry: "resolve", Message: skipEntry("resolve")}}, false},
		"skip: DNS,ports\n":             {[]string{"dns", "ports"}, nil, false},
		"skip: none\n":                  {nil, nil, false},
		"skip: [None]\n":                {nil, nil, false},
		"skip: [none, dns]\n":           {[]string{"dns"}, nil, true},
		"skip: [DNS, dns, ' Ports ']\n": {[]string{"dns", "ports"}, nil, false},
		"skip: foo,dns\n":               {[]string{"dns"}, []setup.SkipProblem{{Entry: "foo", Message: skipEntry("foo")}}, false},
		"Skip: [email]\n":               {[]string{"email"}, nil, false},
		"skip:\n":                       {nil, nil, false},
		"skip: []\n":                    {nil, nil, false},
		"concurrency: 4\n":              {nil, nil, false},
		"skip: [dns, '', ports]\n":      {[]string{"dns", "ports"}, nil, false},
	} {
		w := newWorld(t, &body)
		snap := w.open()
		if !slices.Equal(snap.Skip, c.skip) || !slices.Equal(snap.SkipProblems, c.problems) {
			t.Errorf("%q: Skip = %v, problems = %v; want %v, %v", body, snap.Skip, snap.SkipProblems, c.skip, c.problems)
		}
		wantList := ""
		if c.list {
			wantList = messageFor(problems(t, body, w.path, w.opts.Env), "skip")
			if wantList == "" {
				t.Fatalf("config.Check has no skip problem for %q", body)
			}
		}
		if snap.SkipListProblem != wantList {
			t.Errorf("%q: SkipListProblem = %q, want %q", body, snap.SkipListProblem, wantList)
		}
	}
}

// NYX_* variables and NVD_API_KEY change nothing that is shown, and an invalid one does not stop setup.
func TestStore_IgnoresNYXVariablesAndTheNVDKey(t *testing.T) {
	t.Parallel()
	body := "concurrency: 7\nkeys:\n  shodan: filekey\noutput_dir: ~/out\n"
	clean := newWorld(t, &body).open()
	dirty := newWorld(t, &body, func(o *configedit.StoreOptions) {
		o.Env = append(slices.Clone(o.Env), "NYX_CONCURRENCY=abc", "NYX_KEYS_SHODAN=envkey", "NYX_KEYS_NVD=x", "NYX_OUTPUT_DIR=/elsewhere", "NVD_API_KEY=y", "NYX_SKIP=dns")
	}).open()
	if dirty.Settings["concurrency"].Text != "7" || dirty.Settings["concurrency"].Problem != "" ||
		dirty.Keys["shodan"].Value != "filekey" || dirty.Keys["nvd"].Value != "" || dirty.Settings["output_dir"].Text != "~/out" ||
		len(dirty.Skip) != 0 {
		t.Errorf("dirty env changed what is shown: %+v", dirty)
	}
	if clean.Settings["concurrency"] != dirty.Settings["concurrency"] || clean.Keys["shodan"] != dirty.Keys["shodan"] {
		t.Error("clean and dirty differ")
	}
}

// HOME stays, so ~ in a path is the home directory, and a wordlist under it is read.
func TestStore_KeepsHomeForTilde(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("wordlist: ~/words.txt\n"))
	if err := os.WriteFile(filepath.Join(w.home, "words.txt"), []byte("www\nmail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := w.open().Settings["wordlist"]; got.Problem != "" || got.Text != "~/words.txt" {
		t.Errorf("wordlist = %+v", got)
	}
}

// Flag YAML values whose loader interpretation differs from the editor's view, including
// literal dotted keys.
func TestStore_ASettingThatDoesNotReadBackAsShownIsInvalid(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("rate.per_host: 9\nrate:\n  dns: 3\n"))
	snap := w.open()
	if got := snap.Settings["rate.per_host"]; got.Problem == "" {
		t.Errorf("rate.per_host = %+v, want it marked invalid", got)
	}
	if got := snap.Settings["rate.dns"]; got.Problem != "" || got.Text != "3" {
		t.Errorf("rate.dns = %+v", got)
	}
	// Editing it leaves a file that reads back as entered.
	out := w.save(snap, setup.Edits{Set: map[string]string{"rate.per_host": "2"}})
	if got := out.Settings["rate.per_host"]; got.Text != "2" {
		t.Errorf("after the edit rate.per_host = %+v", got)
	}
}

// Valueless settings remain unset under loader rules.
func TestStore_ASettingWithNoValueIsNotSet(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("concurrency:\noutput_dir:\nkeys:\n  shodan:\n"))
	snap := w.open()
	if got := snap.Settings["concurrency"]; got.Set || got.Problem != "" || got.Text != "" {
		t.Errorf("concurrency = %+v", got)
	}
	if got := snap.Settings["output_dir"]; got.Set || got.Problem != "" || got.Relative == "" {
		t.Errorf("output_dir = %+v", got)
	}
	if got := snap.Keys["shodan"]; got.Value != "" || got.Problem != "" {
		t.Errorf("shodan = %+v", got)
	}
}

func checkCases(t *testing.T) (w *world, wordlistOK, pathsOK string) {
	t.Helper()
	w = newWorld(t, nil)
	wordlistOK = filepath.Join(w.cwd, "words.txt")
	pathsOK = filepath.Join(w.cwd, "paths.yaml")
	if err := os.WriteFile(wordlistOK, []byte("www\nmail\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathsOK, []byte("- path: '/x'\n  signature: 'y'\n  severity: high\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.home, "words.txt"), []byte("www\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return w, wordlistOK, pathsOK
}

// A bad value is rejected with the exact message config.Check gives for the file that would hold it.
func TestStore_CheckRejectsABadValueWithReconsMessage(t *testing.T) {
	t.Parallel()
	w, _, _ := checkCases(t)
	for _, c := range []struct{ key, value string }{
		{"concurrency", "abc"}, {"concurrency", "0"}, {"concurrency", "-3"}, {"concurrency", "1.5"}, {"concurrency", "0x10"},
		{"rate.per_host", "abc"}, {"rate.per_host", "0"}, {"rate.per_host", "-1"},
		{"rate.per_source", "fast"}, {"rate.per_source", "0"},
		{"rate.dns", "x"}, {"rate.dns", "-0.5"},
		{"wordlist", "/no/such/wordlist.txt"}, {"wordlist", w.cwd}, {"wordlist", "~/missing.txt"},
		{"sensitive_paths", "/no/such/paths.yaml"}, {"sensitive_paths", filepath.Join(w.cwd, "words.txt")},
	} {
		_, err := w.store.Check(c.key, c.value)
		if err == nil {
			t.Errorf("Check(%s, %q) accepted it", c.key, c.value)
			continue
		}
		// The message config.Check gives for a file that holds exactly what would be stored.
		want := messageFor(problems(t, yamlFor(c.key, c.value), w.path, w.opts.Env), c.key)
		if want == "" {
			t.Errorf("config.Check has no problem for %s=%q", c.key, c.value)
		} else if err.Error() != want {
			t.Errorf("Check(%s, %q) = %q, want %q", c.key, c.value, err.Error(), want)
		}
	}
}

func TestStore_CheckAcceptsAGoodValueAndReturnsWhatToStore(t *testing.T) {
	t.Parallel()
	w, wordlistOK, pathsOK := checkCases(t)
	for _, c := range []struct{ key, value, want string }{
		{"concurrency", "12", "12"}, {"concurrency", " 12 ", " 12 "},
		{"rate.per_host", "0.5", "0.5"}, {"rate.per_source", "3", "3"}, {"rate.dns", "100", "100"},
		{"output_dir", "/abs/out", "/abs/out"},
		{"output_dir", "out", filepath.Join(w.cwd, "out")},
		{"output_dir", "./out/../x/", filepath.Join(w.cwd, "x")},
		{"output_dir", "~", "~"}, {"output_dir", "~/eng", "~/eng"}, {"output_dir", "~other/eng", filepath.Join(w.cwd, "~other/eng")},
		{"wordlist", wordlistOK, wordlistOK},
		{"wordlist", "words.txt", filepath.Join(w.cwd, "words.txt")}, // read where it will be stored
		{"wordlist", "~/words.txt", "~/words.txt"},
		{"sensitive_paths", pathsOK, pathsOK},
		{"sensitive_paths", "paths.yaml", filepath.Join(w.cwd, "paths.yaml")},
		{"keys.shodan", "  odd key  ", "  odd key  "}, // stored exactly as given
		{"keys.nvd", "a: b # c", "a: b # c"},
	} {
		got, err := w.store.Check(c.key, c.value)
		if err != nil || got != c.want {
			t.Errorf("Check(%s, %q) = %q, %v; want %q", c.key, c.value, got, err, c.want)
		}
	}
}

func TestStore_CheckIgnoresProblemsOfOtherSettings(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("concurrency: abc\nwordlist: /no/such\n"))
	w.open()
	if got, err := w.store.Check("output_dir", "/x"); err != nil || got != "/x" {
		t.Errorf("Check = %q, %v", got, err)
	}
	if _, err := w.store.Check("concurrency", "5"); err != nil {
		t.Errorf("a good value for a setting that is invalid in the file: %v", err)
	}
}

func TestStore_CheckRefusesInvalidUTF8WithoutEchoingIt(t *testing.T) {
	t.Parallel()
	w, _, _ := checkCases(t)
	for _, key := range []string{"keys.shodan", "output_dir", "wordlist", "concurrency"} {
		_, err := w.store.Check(key, "SECRETab\xffcd")
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("Check(%s) error = %v", key, err)
		}
	}
}
