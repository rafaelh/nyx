package dnsname_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
)

// With cut, an escape that the text ends inside counts as reaching the end, as the name might
// have gone on through it; an escape that is whole does not.
func TestHostnamesIn_CutInsideAnEscape(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		`api.example.com%`, `api.example.com%2`, `api.example.com\`, `api.example.com\u00`,
		`api.example.com\u{2`, `api.example.com\x2`, `api.example.com\1`, `api.example.com&`,
		`api.example.com&#`, `api.example.com&#x`, `api.example.com&#32`, `api.example.com&am`, `api.example.com&amp;`,
	} {
		if got := hostnamesIn(t, text, true); got != nil {
			t.Errorf("HostnamesIn(%q, true) = %q, want nothing", text, got)
		}
	}
	for _, text := range []string{
		`api.example.com%20`, `api.example.com\n`, `api.example.com\032`, `api.example.com&#32;`,
		`api.example.com%zz`, `api.example.com\u{2F}`,
	} {
		if got := hostnamesIn(t, text, true); !slices.Equal(got, []string{"api.example.com"}) {
			t.Errorf("HostnamesIn(%q, true) = %q, want api.example.com", text, got)
		}
	}
}

// A \u or \x without its digits is not an escape and rejects the run, as any other letter after
// a backslash does; a backslash and fewer than three digits takes the digits.
func TestHostnamesIn_BrokenEscapes(t *testing.T) {
	t.Parallel()
	api := []string{"api.example.com"}
	checkHostnames(t, []hostnameCase{
		{`C:\users\api.example.com`, nil},
		{`\xzzapi.example.com`, nil},
		{`\u{}api.example.com`, api}, // the closing brace separates
		{`api.example.com\u{}`, nil}, // the rejecting \u touches the name
		{`x.\u{1234567}.example.com`, []string{"example.com"}},
		{`\u{110000} api.example.com`, api},
		{`\12api.example.com`, api},
		{`%zzapi.example.com`, []string{"zzapi.example.com"}},
		{`%2zapi.example.com`, []string{"2zapi.example.com"}},
		{`api.example.com&#;www.example.com`, []string{"api.example.com", "www.example.com"}},
		{`api.example.com&amp www.example.com`, []string{"api.example.com", "www.example.com"}},
		{`\ü.example.com`, nil},
		{"\\\xfc.example.com", nil},
	})
}

// A combining diacritic belongs to the letter before it, so the decomposed form of a Latin
// letter rejects the name it touches as the composed form does; after a separator it separates.
func TestHostnamesIn_CombiningMarks(t *testing.T) {
	t.Parallel()
	api := []string{"api.example.com"}
	checkHostnames(t, []hostnameCase{
		{"bücher.shop.example.com", nil},
		{`bücher.shop.example.com`, nil},
		{"bu&#x308;cher.shop.example.com", nil},
		{"api.example.coḿ", nil},
		{"́api.example.com", api},
		{"中゙api.example.com", api},
		{"api.example.com.́ www.example.com", []string{"api.example.com", "www.example.com"}},
		{"❤️api.example.com", api},
	})
}

// No prefix of a text full of escapes, read with or without cut, panics or gives a name whose
// labels are not valid.
func TestHostnamesIn_EveryPrefix(t *testing.T) {
	t.Parallel()
	text := `a%2%252F\u{\u00\x\0\12\123&#&#x&#x2F&amp;#&amp&am\\\\%\ü\` + "\xfc\xe4\xb8 b.c-d.e..f_g\u00fc-h.i\n"
	for i := range len(text) + 1 {
		for _, cut := range []bool{false, true} {
			for h := range dnsname.HostnamesIn(text[:i], cut) {
				if len(h) > 253 || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || !strings.Contains(h, ".") ||
					slices.ContainsFunc(strings.Split(h, "."), func(l string) bool { return !dnsname.ValidLabel(l) }) {
					t.Errorf("prefix %q gives %q", text[:i], h)
				}
			}
		}
	}
}

// Hyphens at the ends of a run are trimmed like dots, so a name pressed against an HTML comment's
// dashes is read; a hyphen inside a label stays, and an invalid label within a run still gives
// nothing.
func TestHostnamesIn_HyphensAtTheEnds(t *testing.T) {
	t.Parallel()
	api := []string{"api.example.com"}
	checkHostnames(t, []hostnameCase{
		{"<!--api.example.com-->", api},
		{"--api.example.com", api},
		{"api.example.com-", api},
		{"-.api.example.com.-", api},
		{"<!--api-dev.example.com-->", []string{"api-dev.example.com"}},
		{"api.-example.com", nil},
		{"api.example-.com", nil},
	})
	if got := hostnamesIn(t, "<!--api.example.com--", true); got != nil {
		t.Errorf("HostnamesIn(cut text ending in a run of hyphens) = %q, want nothing", got)
	}
}
