package shodan

import (
	"os"
	"strings"
	"testing"
)

// The README lists the favicon hashes that are never pivoted, so adding one to
// the built-in list without documenting it fails here.
func TestREADMEListsEveryDefaultFavicon(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := defaultFavicons["0"]; !ok {
		t.Error("the empty file's hash (0) is not on the list")
	}
	for hash, what := range defaultFavicons {
		if !strings.Contains(string(b), "`"+hash+"`") {
			t.Errorf("README.md does not list the default favicon `%s` (%s)", hash, what)
		}
	}
}
