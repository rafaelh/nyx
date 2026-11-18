package config_test

import (
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/config"
)

// Permutations are on by default, and --no-permutations or the config file turns them off.
func TestPermutationsEnabled(t *testing.T) {
	t.Parallel()
	if s, err := load(t, nil, ""); err != nil || !s.Permutations.Enabled {
		t.Errorf("default: %+v %v", s.Permutations, err)
	}
	if s, err := load(t, nil, "", "--no-permutations"); err != nil || s.Permutations.Enabled {
		t.Errorf("--no-permutations: %+v %v", s.Permutations, err)
	}
	if s, err := load(t, nil, writeFile(t, "permutations:\n  enabled: false\n")); err != nil || s.Permutations.Enabled {
		t.Errorf("file: %+v %v", s.Permutations, err)
	}
}

// A custom wordlist replaces the built-in one, and its content changes the hash.
func TestWordlistContentAndHash(t *testing.T) {
	t.Parallel()
	sa, err := load(t, nil, "", "--wordlist", writeFile(t, "# comment\nalpha\nbeta\n"))
	if err != nil {
		t.Fatal(err)
	}
	sb, _ := load(t, nil, "", "--wordlist", writeFile(t, "alpha\nbeta\ngamma\n"))
	if strings.Join(sa.WordlistWords, ",") != "alpha,beta" {
		t.Errorf("words = %v", sa.WordlistWords)
	}
	if config.ListHash(sa.WordlistWords) == config.ListHash(sb.WordlistWords) {
		t.Error("different wordlists must have different hashes")
	}
}
