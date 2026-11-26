package cli_test

import (
	"strings"
	"testing"
)

// The user guide describes name guessing: a "## Name guessing" section names the
// wordlist, variants, learned names, parent names and the existence rule, and the configuration
// lists the permutations settings and the learned-names cap.
func TestNameGuessing_DocsSayWhatItDoes(t *testing.T) {
	t.Parallel()
	docs := docsText(t)
	for _, want := range []string{
		"permutations.enabled", "--no-permutations",
		"permutations.max_per_seed", "--permutations-max",
		"permutations.max_names", "--permutations-max-names",
		"learned_names.max_names", "--learned-names-max-names",
	} {
		if !strings.Contains(docs, want) {
			t.Errorf("the docs do not mention %q", want)
		}
	}
	if !strings.Contains(docs, "\n## Name guessing\n") {
		t.Fatal(`the docs have no "## Name guessing" section`)
	}
	section, _ := docsSection(t, "\n## Name guessing\n")
	flat := flatWords(section)
	for _, want := range []string{"wordlist", "variant", "learned name", "learned-names", "parent name", "ipv6"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the Name guessing section does not mention %q", want)
		}
	}
	if docUnit(section, "guessed name", "cname", "a address") == "" {
		t.Error("the Name guessing section has no sentence saying a guessed name counts only with a CNAME or an A address")
	}
}
