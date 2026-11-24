package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/dnsname"
)

// The built-in wordlist is big enough to use without a list of one's own, and
// every entry is something a permutation can use.
func TestBuiltinWordlist(t *testing.T) {
	t.Parallel()
	s, err := load(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	words := s.WordlistWords
	if len(words) < 2000 || len(words) > 5000 {
		t.Fatalf("built-in wordlist has %d entries, want 2000 to 5000", len(words))
	}
	seen := map[string]bool{}
	for _, w := range words {
		if w != strings.ToLower(w) {
			t.Errorf("%q is not lower case", w)
		}
		if !dnsname.ValidLabel(w) {
			t.Errorf("%q is not a valid DNS label", w)
		}
		if seen[w] {
			t.Errorf("%q is listed twice", w)
		}
		seen[w] = true
	}
	// Most common first: the per-seed cap takes words from the front.
	for i, want := range []string{"www", "mail", "ns2", "ns1"} {
		if words[i] != want {
			t.Errorf("word %d = %q, want %q", i, words[i], want)
		}
	}
	if got := config.BuiltinWordlistLabel(); got != fmt.Sprintf("built-in (%d entries)", len(words)) {
		t.Errorf("label = %q", got)
	}
}

// The wordlist's source and licence are credited in the file itself.
func TestBuiltinWordlistAttribution(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("builtin/wordlist.txt")
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := strings.Cut(string(b), "\n\n")
	for _, want := range []string{"SecLists", "MIT", "Daniel Miessler", "subdomains-top1million-5000"} {
		if !strings.Contains(header, want) {
			t.Errorf("wordlist header does not mention %q:\n%s", want, header)
		}
	}
	for line := range strings.SplitSeq(header, "\n") {
		if !strings.HasPrefix(line, "#") {
			t.Errorf("header line %q is not a comment", line)
		}
	}
}

// docs/lists-and-limits.md credits SecLists, says what a run costs, and gives the request
// formula for the sensitive paths.
func TestDocsStateListsAndVolume(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "lists-and-limits.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	s, err := load(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"SecLists", "MIT",
		fmt.Sprintf("%d lookups per root", len(s.WordlistWords)),
		"services × entries", "sensitive_path_max_requests", "permutations.max_names",
		fmt.Sprintf("%d entries", len(s.SensitivePathEntries)),
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("docs/lists-and-limits.md does not mention %q", want)
		}
	}
}

// sampleName encodes paths for fixtures and renames tilde/.DS_Store cases that Git would
// otherwise ignore. This ensures fixtures exist after checkout, not only locally.
func sampleName(path string) string {
	name := strings.ReplaceAll(strings.TrimPrefix(path, "/"), "/", "__")
	if name == ".DS_Store" {
		return "dot-DS_Store"
	}
	return strings.ReplaceAll(name, "~", "-tilde")
}

func sample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "sensitive", name))
	if err != nil {
		t.Fatalf("sample missing: %v", err)
	}
	return b
}

// Built-in signatures need explicit severity and realistic positive samples without matching
// generic success/404 pages.
func TestBuiltinSensitivePathsSamples(t *testing.T) {
	t.Parallel()
	s, err := load(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	entries := s.SensitivePathEntries
	if len(entries) < 150 {
		t.Fatalf("built-in sensitive paths: %d entries, want at least 150", len(entries))
	}
	raw, err := os.ReadFile("builtin/sensitive_paths.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var rawEntries []map[string]any
	if err := yaml.Unmarshal(raw, &rawEntries); err != nil {
		t.Fatal(err)
	}
	if len(rawEntries) != len(entries) {
		t.Fatalf("%d raw entries, %d parsed", len(rawEntries), len(entries))
	}
	generic, soft404 := sample(t, "_generic-200.html"), sample(t, "_soft-404.html")
	seen, seenSample := map[string]bool{}, map[string]string{}
	for i, e := range entries {
		if seen[e.Path] {
			t.Errorf("%s is listed twice", e.Path)
		}
		seen[e.Path] = true
		// Reject case-only fixture names that collapse on case-insensitive filesystems
		// but differ on Linux.
		if other, ok := seenSample[strings.ToLower(sampleName(e.Path))]; ok {
			t.Errorf("%s and %s have samples whose names differ only in case", other, e.Path)
		}
		seenSample[strings.ToLower(sampleName(e.Path))] = e.Path
		if sev, _ := rawEntries[i]["severity"].(string); sev != "high" && sev != "medium" && sev != "low" {
			t.Errorf("%s: severity %q is not explicit (high, medium or low)", e.Path, sev)
		}
		body := sample(t, sampleName(e.Path))
		if _, ok := e.Match(e.Status, body); !ok {
			t.Errorf("%s: does not match its sample", e.Path)
		}
		if _, ok := e.Match(e.Status+1, body); ok {
			t.Errorf("%s: matches its sample under the wrong status", e.Path)
		}
		if _, ok := e.Match(200, generic); ok {
			t.Errorf("%s: matches a generic 200 page", e.Path)
		}
		if _, ok := e.Match(200, soft404); ok {
			t.Errorf("%s: matches a soft 404", e.Path)
		}
		if _, ok := e.Match(404, soft404); ok {
			t.Errorf("%s: matches a 404 page", e.Path)
		}
	}
	if got := config.BuiltinSensitivePathsLabel(); got != fmt.Sprintf("built-in (%d entries)", len(entries)) {
		t.Errorf("label = %q", got)
	}
}

// Every sample belongs to an entry, so a removed entry leaves nothing behind.
func TestSensitiveSamplesHaveEntries(t *testing.T) {
	t.Parallel()
	s, err := load(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"_generic-200.html": true, "_soft-404.html": true}
	for _, e := range s.SensitivePathEntries {
		want[sampleName(e.Path)] = true
	}
	files, err := os.ReadDir(filepath.Join("testdata", "sensitive"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if !want[f.Name()] {
			t.Errorf("sample %s belongs to no entry", f.Name())
		}
	}
}

// Pin existing path hashes because changing them reruns checks and disconnects previously
// stored hits.
var goldenEntries = []string{
	"/.git/config|eb95cb36",
	"/.git/HEAD|82193961",
	"/.env|af1fcec4",
	"/.aws/credentials|cec353cf",
	"/.htpasswd|fc51f1f5",
	"/wp-config.php.bak|a01438d9",
	"/.svn/entries|57e4114a",
	"/.hg/hgrc|70a2119c",
	"/.DS_Store|3726b3b2",
	"/server-status|20465484",
	"/server-info|4cf91c54",
	"/phpinfo.php|872a54c5",
	"/info.php|872a54c5",
	"/actuator/env|e93c71f3",
	"/actuator/heapdump|4ba95696",
	"/.npmrc|cf2a6649",
	"/.docker/config.json|e4a42bad",
	"/id_rsa|fd3134f5",
	"/backup.zip|500b5a03",
	"/backup.tar.gz|bbb9b6b8",
	"/backup.sql|00a6c0c2",
	"/dump.sql|00a6c0c2",
	"/WEB-INF/web.xml|ab5a08d0",
}

func TestBuiltinSensitivePathsKeepExistingEntries(t *testing.T) {
	t.Parallel()
	s, err := load(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, e := range s.SensitivePathEntries {
		have[e.Path+"|"+e.Hash()] = true
	}
	for _, g := range goldenEntries {
		if !have[g] {
			t.Errorf("existing entry %s is gone or changed", g)
		}
	}
}

// sensitive_path_max_requests is a top-level key, not part of the sensitive_paths file setting.
func TestSensitivePathMaxRequestsIsNotNested(t *testing.T) {
	t.Parallel()
	if _, err := load(t, nil, writeFile(t, "sensitive_paths:\n  max_requests: 5\n")); err == nil {
		t.Error("max_requests must not be accepted nested under sensitive_paths")
	}
}

// --permutations-max stays the per-seed cap and does not touch the per-run one.
func TestPermutationsMaxIsStillPerSeed(t *testing.T) {
	t.Parallel()
	if s, err := load(t, nil, "", "--permutations-max", "11"); err != nil || s.Permutations.MaxPerSeed != 11 || s.Permutations.MaxNames != 200000 {
		t.Errorf("%+v %v", s.Permutations, err)
	}
}

// A custom wordlist or sensitive-path file replaces the built-in list outright.
func TestCustomListsReplaceBuiltin(t *testing.T) {
	t.Parallel()
	wl := writeFile(t, "alpha\nbeta\n")
	sp := writeFile(t, "- path: /x\n  signature: 'x'\n")
	s, err := load(t, nil, "", "--wordlist", wl, "--sensitive-paths", sp)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.WordlistWords) != 2 || len(s.SensitivePathEntries) != 1 {
		t.Errorf("%d words, %d entries", len(s.WordlistWords), len(s.SensitivePathEntries))
	}
}
