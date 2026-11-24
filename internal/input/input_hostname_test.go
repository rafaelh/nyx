package input_test

import (
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/input"
)

func TestParseHostname(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in          string
		singleLabel bool
		want        string // empty expectation denotes rejection
	}{
		{"www.example.com", false, "www.example.com"},
		{"  WWW.Example.COM. ", false, "www.example.com"},
		{"münchen.example", false, "xn--mnchen-3ya.example"},
		{"a-b.example", false, "a-b.example"},
		// Lookup hostnames allow public suffixes even though scope domains reject them.
		{"co.uk", false, "co.uk"},
		{"example.com", false, "example.com"},
		{"github.io", false, "github.io"},
		// Single-label names require explicit allowance.
		{"intranet", false, ""},
		{"intranet", true, "intranet"},
		{"Intranet.", true, "intranet"},
		{"com", true, "com"},
		{"com", false, ""},
		// Reject digit/dot-only values as probable address typos.
		{"123", true, ""},
		{"1.2.3", false, ""},
		{"1.2.3.4", false, ""},
		{"1.2.3.4.5", false, ""},
		{"1..2", false, ""},
		{"123.abc", false, "123.abc"},
		// Cover address literals and malformed labels.
		{"::1", true, ""},
		{"2001:db8::1", false, ""},
		{"", false, ""},
		{"   ", true, ""},
		{"a b.example", false, ""},
		{"a/b.example", false, ""},
		{"a:80.example", false, ""},
		{"user@example.com", false, ""},
		{"*.example.com", false, ""},
		{"_srv.example.com", false, ""},
		{"-a.example.com", false, ""},
		{"a-.example.com", false, ""},
		{"a..example.com", false, ""},
		{strings.Repeat("a", 64) + ".example.com", false, ""},
		{strings.Repeat("a.", 130) + "com", false, ""},
	} {
		got, err := input.ParseHostname(tc.in, tc.singleLabel)
		if tc.want == "" {
			if err == nil {
				t.Errorf("ParseHostname(%q, %v) = %q, want an error", tc.in, tc.singleLabel, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ParseHostname(%q, %v) = %q, %v; want %q", tc.in, tc.singleLabel, got, err, tc.want)
		}
	}
}

// Hostname/domain parsing shares normalisation for every accepted domain.
func TestParseHostname_AgreesWithParseDomain(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"example.com", "WWW.Example.com.", "münchen.example", "a.b.c.example.org", "xn--mnchen-3ya.example"} {
		d, derr := input.ParseDomain(s)
		h, herr := input.ParseHostname(s, false)
		if derr != nil || herr != nil || d != h {
			t.Errorf("%q: ParseDomain = %q, %v; ParseHostname = %q, %v", s, d, derr, h, herr)
		}
	}
}

func TestParseHostname_ErrorNamesTheInput(t *testing.T) {
	t.Parallel()
	_, err := input.ParseHostname("a b.example", false)
	if err == nil || !strings.Contains(err.Error(), `"a b.example"`) || !strings.Contains(err.Error(), "hostname") {
		t.Errorf("error = %v, want it to name the input and say hostname", err)
	}
	_, err = input.ParseDomain("a b.example")
	if err == nil || !strings.Contains(err.Error(), "invalid domain") {
		t.Errorf("ParseDomain error = %v, want it to keep saying domain", err)
	}
}

func TestBareHost(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want string // empty expectation denotes no recognised wrapper
	}{
		{"https://example.com", "example.com"},
		{"https://example.com/", "example.com"},
		{"http://Example.com:8080/a/b?q=1#f", "example.com"},
		{"ftp://user:pw@example.com/x", "example.com"},
		{"https://1.2.3.4:443/x", "1.2.3.4"},
		{"https://[2001:db8::1]:8443/x", "2001:db8::1"},
		{"https://[2001:db8::1]/", "2001:db8::1"},
		{"  https://example.com/x  ", "example.com"},
		{"example.com:80", "example.com"},
		{"EXAMPLE.com:443", "example.com"},
		{"1.2.3.4:22", "1.2.3.4"},
		{"example.com:8080/path", "example.com"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[::1]:80", "::1"},
		{"intranet:8080", "intranet"},
		// Bare names/addresses have no wrapper to remove.
		{"example.com", ""},
		{"1.2.3.4", ""},
		{"2001:db8::1", ""},
		{"::1", ""},
		{"2001:db8::1:80", ""}, // IPv6 literal without a port wrapper
		{"10.0.0.0/8", ""},
		{"example.com/path", ""},
		{"example.com:", ""},
		{"example.com:http", ""},
		{"example.com:99999", ""},
		{"example.com:0", ""},
		{":80", ""},
		{"https://", ""},
		{"https:///path", ""},
		{"[::1", ""},
		{"", ""},
		{"a b:80", ""},
	} {
		got, ok := input.BareHost(tc.in)
		if tc.want == "" {
			if ok {
				t.Errorf("BareHost(%q) = %q, true; want not recognised", tc.in, got)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("BareHost(%q) = %q, %v; want %q, true", tc.in, got, ok, tc.want)
		}
	}
}

func TestCleanName(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"WWW.Example.com.":   "www.example.com",
		"*.example.com":      "example.com",
		"*.WWW.Example.com.": "www.example.com",
		"1.2.3.4":            "",
		"https://x.example/": "",
		"com":                "",
	} {
		if got := input.CleanName(in); got != want {
			t.Errorf("CleanName(%q) = %q, want %q", in, got, want)
		}
	}
}
