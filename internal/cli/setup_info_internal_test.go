package cli

import (
	"slices"
	"strings"
	"testing"
)

// Key descriptions derive required/optional procedures, with explicit Cert Spotter and NVD wording.
func TestKeyTurnsOn(t *testing.T) {
	t.Parallel()
	procedures := defaultProcedures()
	got := map[string]string{}
	for _, s := range setupSources(procedures) {
		got[s.Name] = s.Turns
	}
	if len(got) != 9 {
		t.Fatalf("%d sources: %v", len(got), got)
	}
	for source, wants := range map[string][]string{
		"securitytrails": {"securitytrails", "dnshistory", "nsreverse", "adds to reverseip"},
		"shodan":         {"shodan", "shodan-dns", "shodan-host", "identifier-pivot"},
		"virustotal":     {"virustotal"},
		"whoisxml":       {"whoisxml"},
		"censys":         {"censys"},
		"chaos":          {"Turns on chaos"},
		"github":         {"github"},
		"certspotter":    {"Adds to certspotter", "also works without a key"},
		"nvd":            {"Increases cve requests from 5 per 30 seconds to 50"},
	} {
		for _, w := range wants {
			if !strings.Contains(got[source], w) {
				t.Errorf("%s: %q does not say %q", source, got[source], w)
			}
		}
	}
	if strings.Contains(got["virustotal"], "without a key") {
		t.Errorf("only Cert Spotter works without a key: %q", got["virustotal"])
	}
}

// The procedures offered to skip are the registry's, without the ones other procedures depend on.
func TestSetupProceduresLeaveOutTheUnskippable(t *testing.T) {
	t.Parallel()
	var names []string
	for _, s := range setupProcedures(defaultProcedures()) {
		names = append(names, s.Name)
		if s.Does == "" {
			t.Errorf("stage %s has no description", s.Name)
		}
	}
	for _, u := range unskippable {
		if slices.Contains(names, u) {
			t.Errorf("%s is offered but cannot be skipped", u)
		}
	}
	if !slices.Contains(names, "crtsh") {
		t.Errorf("skippable stages are missing: %v", names)
	}
	if want := len(defaultProcedures()) - len(unskippable); len(names) != want {
		t.Errorf("%d stages offered, want %d", len(names), want)
	}
}
