package web

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

const scriptOrigin = "https://a.example.com"

func TestExtractEndpoints(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		body string
		want []string
	}{
		// What is recorded.
		"a quoted path": {`fetch("/api/v1/users")`, []string{"https://a.example.com/api/v1/users"}},
		"single quotes": {`get('/api/v1/users')`, []string{"https://a.example.com/api/v1/users"}},
		"backticks":     {"get(`/api/v1/users`)", []string{"https://a.example.com/api/v1/users"}},
		"a path is joined to the script's own origin": {`"/x1"`, []string{"https://a.example.com/x1"}},
		"two characters is long enough":               {`"/a"`, []string{"https://a.example.com/a"}},
		"a query is kept and a fragment dropped":      {`"/search?q=1&r=2#top"`, []string{"https://a.example.com/search?q=1&r=2"}},
		"a protocol-relative reference takes the script's scheme": {
			`x="//api.example.com/v2"`, []string{"https://api.example.com/v2"}},
		"an absolute https URL": {`u="https://api.example.com/v1/items"`, []string{"https://api.example.com/v1/items"}},
		"an absolute http URL":  {`u='http://legacy.example.com/a'`, []string{"http://legacy.example.com/a"}},
		"an absolute URL inside a longer string": {
			`m="see https://docs.example.com/guide for details"`, []string{"https://docs.example.com/guide"}},
		"a dot directory that is not just an extension": {`"/.well-known/openid-configuration"`, []string{"https://a.example.com/.well-known/openid-configuration"}},
		"an out-of-scope host is the stage's to drop":   {`"https://cdn.example.net/lib.js"`, []string{"https://cdn.example.net/lib.js"}},
		"order of appearance, and each URL once": {
			`a("/b/1");a("https://api.example.com/z");a("/a/1");a("/b/1");a("//api.example.com/y")`,
			[]string{"https://a.example.com/b/1", "https://api.example.com/z", "https://a.example.com/a/1", "https://api.example.com/y"}},
		"minified, on one line": {
			`!function(){var e="/api/a",t={u:"/api/b"};n.get(e).then(function(){return n.post("/api/c",t)})}()`,
			[]string{"https://a.example.com/api/a", "https://a.example.com/api/b", "https://a.example.com/api/c"}},
		"an apostrophe in a comment does not hide what follows": {
			"// don't stop\nfetch(\"/api/after\")", []string{"https://a.example.com/api/after"}},

		// What is not.
		"an extension alone":               {`"/.js"`, nil},
		"an extension alone, any case":     {`"/.JSON" '/.map'`, nil},
		"a regular expression":             {`s.replace(/\d+/g,"")`, nil},
		"a regular expression in a string": {`new RegExp("/\\d+/g")`, nil},
		"a slash and a space":              {`"/ "`, nil},
		"a path with whitespace":           {`"/a b" "/tab\there"`, nil},
		"a comment-like host":              {`"//comment"`, nil},
		"an empty first segment":           {`"//" "///x"`, nil},
		"a single slash":                   {`"/"`, nil},
		"a backslash":                      {`"/a\\b"`, nil},
		"a template placeholder":           {"`/api/${id}/x` \"/api/{{id}}\"", nil},
		"a placeholder in an absolute URL's host": {
			"`https://${env}.example.com/x` `https://api-${env}.example.com` \"https://api.{{domain}}/x\" `http://${h}`", nil},
		"escaped slashes in a quoted path": {`"\/api\/v1"`, nil},
		"an absolute URL is cut at a placeholder": {
			"\"https://api.example.com/v1/${id}\" `https://b.example.com/{{v}}/x` \"https://c.example.com?q=${q}\"",
			[]string{"https://api.example.com/v1/", "https://b.example.com/", "https://c.example.com/?q="}},
		"an escaped absolute URL": {
			`{"api":"https:\/\/api.example.com\/v1\/items","x":"HTTP:\/\/b.example.com"}`,
			[]string{"https://api.example.com/v1/items", "http://b.example.com/"}},
		"a relative path":    {`"api/v1/users" "./x" "../y"`, nil},
		"a mime type":        {`"text/html" "application/json"`, nil},
		"other schemes":      {`"ftp://files.example.com/x" "javascript:void(0)" "mailto:a@example.com"`, nil},
		"a host with no dot": {`"http://localhost/x" "//intranet/y"`, nil},
		"nothing":            {``, nil},
	} {
		t.Run(name, func(t *testing.T) {
			got := ExtractEndpoints([]byte(tc.body), scriptOrigin)
			if !slices.Equal(got, tc.want) {
				t.Errorf("ExtractEndpoints(%q) =\n  %q\nwant\n  %q", tc.body, got, tc.want)
			}
		})
	}
}

// Cover extraction examples for accepted and rejected endpoints.
func TestExtractEndpoints_SpecificationExamples(t *testing.T) {
	t.Parallel()
	body := `a("/api/v1/users"); b("//api.example.com/v2"); c("/.js"); d(s.match(/\d+/g)); e("/ "); f("//comment")`
	want := []string{"https://a.example.com/api/v1/users", "https://api.example.com/v2"}
	if got := ExtractEndpoints([]byte(body), scriptOrigin); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The extractor returns everything it finds; the 500 cap belongs to the stage.
// A large body is read in one pass.
func TestExtractEndpoints_ManyURLs(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for i := range 2000 {
		fmt.Fprintf(&b, "x(\"/api/%d\");", i)
	}
	got := ExtractEndpoints([]byte(b.String()), scriptOrigin)
	if len(got) != 2000 || got[0] != "https://a.example.com/api/0" || got[1999] != "https://a.example.com/api/1999" {
		t.Errorf("got %d URLs, first %q", len(got), got[:min(1, len(got))])
	}
}

// A port in the origin is kept for a path, and the default port is not added.
func TestExtractEndpoints_OriginPort(t *testing.T) {
	t.Parallel()
	got := ExtractEndpoints([]byte(`"/api/a" "//api.example.com/b"`), "http://a.example.com:8080")
	want := []string{"http://a.example.com:8080/api/a", "http://api.example.com/b"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
