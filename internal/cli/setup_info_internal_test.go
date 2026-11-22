package cli

import (
	"slices"
	"strings"
	"testing"
)

// Each source says what its key turns on, from the stages that name it; Cert Spotter says it works
// without one and the NVD's line is fixed.
func TestKeyTurnsOn(t *testing.T) {
	t.Parallel()
	stages := defaultStages()
	got := map[string]string{}
	for _, s := range setupSources(stages) {
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
		"chaos":          {"chaos"},
		"github":         {"github"},
		"certspotter":    {"adds to certspotter", "also works without a key"},
		"nvd":            {"nyx cve: 50 requests per 30 s instead of 5"},
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

// The stages offered to skip are the registry's, without the ones other stages depend on.
func TestSetupStagesLeaveOutTheUnskippable(t *testing.T) {
	t.Parallel()
	var names []string
	for _, s := range setupStages(defaultStages()) {
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
	if want := len(defaultStages()) - len(unskippable); len(names) != want {
		t.Errorf("%d stages offered, want %d", len(names), want)
	}
}
