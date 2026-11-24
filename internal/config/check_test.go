package config_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
)

// Check gives what Load gives for the same file, with no flags: the same settings and the same
// problems, in the same order.
func TestCheck_AgreesWithLoad(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"empty":            "",
		"comment only":     "# nothing here\n",
		"valid":            "concurrency: 0x10\nrate:\n  per_host: 2.5\nkeys:\n  shodan: abc\nskip: [dns]\n",
		"bad number":       "concurrency: abc\nrate:\n  dns: -1\n",
		"unknown key":      "concurency: 3\nkeys:\n  shodan: filekey\n",
		"unparseable":      "keys: [unclosed\n",
		"skip with none":   "skip: [none, dns]\n",
		"missing wordlist": "wordlist: /no/such/wordlist.txt\n",
		"empty output_dir": "output_dir: \"\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := writeFile(t, body)
			env := config.Env{"HOME=" + t.TempDir()}
			want, wantErr := config.Load(nil, path, env)
			got, gotErr := config.Check([]byte(body), path, env)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("settings differ:\n got %+v\nwant %+v", got, want)
			}
			if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
				t.Errorf("error = %v, want %v", gotErr, wantErr)
			}
			if wantErr != nil {
				var gp, wp clierr.Problems
				if !errors.As(gotErr, &gp) || !errors.As(wantErr, &wp) || !reflect.DeepEqual(gp, wp) {
					t.Errorf("problems = %#v, want %#v", gp, wp)
				}
			}
		})
	}
}

// Check returns file settings independently of supplied environment values.
func TestCheck_IgnoresSettingVariables(t *testing.T) {
	t.Parallel()
	s, err := config.Check([]byte("concurrency: 2\n"), "c.yaml", config.Env{"NYX_CONCURRENCY=3", "NYX_KEYS_SHODAN=envkey", "NVD_API_KEY=n"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Concurrency != 2 || len(s.Keys) != 0 {
		t.Errorf("a variable was read: concurrency=%d keys=%v", s.Concurrency, s.Keys)
	}
}

// A file that fails to parse is a problem named config, which names the path.
func TestCheck_ParseProblemNamesThePath(t *testing.T) {
	t.Parallel()
	_, err := config.Check([]byte("keys: [unclosed\n"), "/x/c.yaml", nil)
	var probs clierr.Problems
	if !errors.As(err, &probs) || len(probs) == 0 || probs[0].Name != "config" || !strings.Contains(probs[0].Message, "/x/c.yaml") {
		t.Errorf("got %#v", err)
	}
}

func TestDefaultText(t *testing.T) {
	t.Parallel()
	for key, want := range map[string]string{
		"output_dir":      ".",
		"concurrency":     "10",
		"rate.per_host":   "5",
		"rate.per_source": "1",
		"rate.dns":        "50",
		"wordlist":        config.BuiltinWordlistLabel(),
		"sensitive_paths": config.BuiltinSensitivePathsLabel(),
		"unknown":         "",
	} {
		if got := config.DefaultText(key); got != want {
			t.Errorf("DefaultText(%q) = %q, want %q", key, got, want)
		}
	}
}

func TestExpandHome(t *testing.T) {
	t.Parallel()
	env := config.Env{"HOME=/home/u"}
	for in, want := range map[string]string{
		"~": "/home/u", "~/x": "/home/u/x", "~other/x": "~other/x", "rel/x": "rel/x", "/abs": "/abs", "": "",
	} {
		if got := config.ExpandHome(in, env); got != want {
			t.Errorf("ExpandHome(%q) = %q, want %q", in, got, want)
		}
	}
	if got := config.ExpandHome("~/x", nil); got != "~/x" {
		t.Errorf("without a home: %q", got)
	}
}

// FileReadMessage is the text Load gives for a config file it could not read.
func TestFileReadMessage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := os.ReadFile(filepath.Join(dir, "absent.yaml"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "absent.yaml")
	_, loadErr := config.Load(nil, p, nil)
	want := "config file " + p + ": no such file or directory"
	if got := config.FileReadMessage(p, err); got != want || loadErr == nil || loadErr.Error() != want {
		t.Errorf("FileReadMessage = %q, Load = %v, want %q", got, loadErr, want)
	}
}
