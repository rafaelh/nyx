package config_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/config"
)

// Entry format, defaults and matching.
func TestSensitivePathEntries(t *testing.T) {
	t.Parallel()
	file := writeFile(t, `
- path: /.git/config
  signature: '\[core\]'
  severity: high
- path: /backup.zip
  magic: 504b0304
  status: 206
- path: /both
  signature: 'world'
  magic: '68656c'
`)
	s, err := load(t, nil, "", "--sensitive-paths", file)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range s.SensitivePathEntries {
		got = append(got, e.Path)
	}
	if !slices.Equal(got, []string{"/.git/config", "/backup.zip", "/both"}) {
		t.Fatalf("entries = %+v", s.SensitivePathEntries)
	}
	git, zip, both := s.SensitivePathEntries[0], s.SensitivePathEntries[1], s.SensitivePathEntries[2]
	if git.Status != 200 || git.Severity != "high" || zip.Severity != "medium" || zip.Status != 206 {
		t.Errorf("defaults: %+v %+v", git, zip)
	}
	if sig, ok := git.Match(200, []byte("[core]\n\trepositoryformatversion = 0")); !ok || sig == "" {
		t.Error("signature should match")
	}
	if _, ok := git.Match(200, []byte("<html>catch-all page</html>")); ok {
		t.Error("a catch-all 200 must not match")
	}
	if _, ok := git.Match(404, []byte("[core]")); ok {
		t.Error("wrong status must not match")
	}
	if _, ok := zip.Match(206, []byte{0x50, 0x4b, 0x03, 0x04, 0x00}); !ok {
		t.Error("magic prefix should match")
	}
	if _, ok := zip.Match(206, []byte{0x00, 0x50, 0x4b, 0x03, 0x04}); ok {
		t.Error("magic is a prefix match only")
	}
	if _, ok := both.Match(200, []byte("hello world")); !ok {
		t.Error("both hold")
	}
	if _, ok := both.Match(200, []byte("hello there")); ok {
		t.Error("when both are given, the signature must hold too")
	}
	if _, ok := both.Match(200, []byte("say world")); ok {
		t.Error("when both are given, the magic must hold too")
	}
	if git.Hash() == zip.Hash() || len(git.Hash()) != 8 {
		t.Errorf("hashes: %q %q", git.Hash(), zip.Hash())
	}
}

// Invalid entries fail validation (exit 2 in the CLI).
func TestSensitivePathValidation(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"plain string":      "- /admin\n",
		"no signature":      "- path: /admin\n",
		"relative path":     "- path: admin/.env\n  signature: x\n",
		"bad regex":         "- path: /a\n  signature: '(['\n",
		"bad magic":         "- path: /a\n  magic: zz\n",
		"bad severity":      "- path: /a\n  signature: x\n  severity: critical\n",
		"bad status":        "- path: /a\n  signature: x\n  status: 99\n",
		"missing path":      "- signature: x\n",
		"not a list":        "path: /a\n",
		"unknown field":     "- path: /a\n  signature: x\n  sig: y\n",
		"empty magic bytes": "- path: /a\n  magic: ''\n",
	}
	for name, body := range cases {
		_, err := load(t, nil, "", "--sensitive-paths", writeFile(t, body))
		if err == nil || !strings.Contains(err.Error(), "sensitive_paths") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestDKIMSelectors(t *testing.T) {
	t.Parallel()
	sel := config.DKIMSelectors()
	for _, want := range []string{"google", "selector1", "selector2", "k1", "k2", "default", "dkim", "mail", "s1", "s2", "smtp", "mandrill"} {
		if !slices.Contains(sel, want) {
			t.Errorf("selector %q missing", want)
		}
	}
	if config.DKIMSelectorHash() == "" || len(config.DKIMSelectorHash()) != 8 {
		t.Errorf("hash = %q", config.DKIMSelectorHash())
	}
}
