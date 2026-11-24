package shodan

import (
	"os"
	"strings"
	"testing"
)

// Keep default favicon exclusions documented whenever hashes are added.
func TestDocsListEveryDefaultFavicon(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../docs/web.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := defaultFavicons["0"]; !ok {
		t.Error("the empty file's hash (0) is not on the list")
	}
	for hash, what := range defaultFavicons {
		if !strings.Contains(string(b), "`"+hash+"`") {
			t.Errorf("docs/web.md does not list the default favicon `%s` (%s)", hash, what)
		}
	}
}
