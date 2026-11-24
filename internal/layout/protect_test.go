package layout_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/layout"
)

func TestProtected(t *testing.T) {
	t.Parallel()
	yes := []string{
		"https://example.com/a/b?c=d",
		"ftp://x",
		"git+ssh://host/repo",
		"someone@example.com",
		"192.0.2.10",
		"2001:db8::1",
		"::1",
		"192.0.2.0/24",
		"2001:db8::/32",
		"example.com",
		"a.b.example.co.uk",
		"*.example.com",
		"EXAMPLE.com",
		"example.com.",
		"example.com,",
		"(example.com)",
		`"https://example.com/x",`,
		"<someone@example.com>",
		"[2001:db8::1]",
		"example.com;",
		// Protect address/hostname targets carrying ports.
		"198.51.100.7:21",
		"[2001:db8::1]:3389",
		"([2001:db8::1]:3389),",
		"www.example.com:8443",
		// Pin harmless short tokens that happen to match hostname syntax.
		"e.g",
		"2.4.41",
	}
	for _, w := range yes {
		if !layout.Protected(w) {
			t.Errorf("Protected(%q) = false, want true", w)
		}
	}
	no := []string{
		"",
		"word",
		"...",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"://x",
		"http://",
		"1http://x",
		"@example.com",
		"a@b@example.com",
		"someone@localhost",
		"foo-bar",
		"a/b/c",
		"-a.example.com",
		"a-.example.com",
		"a..example.com",
		".example.com",
		"exa mple.com",
		"a_b.example.com",
		"*example.com",
		"*.",
		"999",
		"example.com:http",
		"word:8443",
	}
	for _, w := range no {
		if layout.Protected(w) {
			t.Errorf("Protected(%q) = true, want false", w)
		}
	}
}
