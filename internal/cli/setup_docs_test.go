package cli_test

import (
	"strings"
	"testing"
)

// Keep setup commands, errors, hints, config precedence and key-test source hosts documented.
func TestSetup_DocsDescribeTheCommand(t *testing.T) {
	t.Parallel()
	docs := docsText(t)
	commands, _ := docsSection(t, "## Commands")
	if !strings.Contains(commands, "**`nyx setup`") {
		t.Error("the command list does not name nyx setup")
	}
	flat := flatWords(docs)
	for _, want := range []string{
		"run nyx setup to store api keys and settings", // the hint's text
		"what setup shows and saves is what nyx reads",
		"a key test may spend a query",
		"no prompts, no stdin",
	} {
		if want == "no prompts, no stdin" {
			if strings.Contains(flat, want) {
				t.Errorf("the docs still say %q, which nyx setup makes untrue", want)
			}
			continue
		}
		if !strings.Contains(flat, want) {
			t.Errorf("the docs do not say %q", want)
		}
	}
	boundary, _ := docsSection(t, "## Passive boundary")
	for _, host := range []string{"api.securitytrails.com", "api.shodan.io", "www.virustotal.com", "user.whoisxmlapi.com",
		"api.platform.censys.io", "dns.projectdiscovery.io", "api.github.com", "api.certspotter.com", "services.nvd.nist.gov"} {
		if !strings.Contains(boundary, host) {
			t.Errorf("the passive boundary does not list the key-test host %s", host)
		}
	}
}
