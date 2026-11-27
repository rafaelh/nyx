package cli_test

import (
	"slices"
	"strings"
	"testing"
)

// The user guide's pages on the passive boundary, candidates, output, configuration and sources
// describe promotion by address.

// The passive boundary says that candidate hostnames and roots are looked up through the public
// resolvers and never contacted.
func TestInNetblockDocs_PassiveBoundarySaysCandidatesAreOnlyLookedUp(t *testing.T) {
	t.Parallel()
	section, _ := docsSection(t, "\n## Passive boundary\n")
	if docUnit(section, "candidate hostnames", "roots", "looked up", "public", "resolvers", "never contacted") == "" {
		t.Error("the Passive boundary section has no sentence saying that candidate hostnames and roots are looked up " +
			"through the public resolvers and never contacted")
	}
}

// candidates.md lists the in-netblock source, and the procedure declares it, so that
// TestCandidates_DocsListEverySource requires it too.
func TestInNetblockDocs_CandidatesPageListsTheSource(t *testing.T) {
	t.Parallel()
	if !slices.Contains(realFamilies.Sources(), "in-netblock") {
		t.Errorf("no procedure declares the candidate source in-netblock: %v", realFamilies.Sources())
	}
	if got := realFamilies.Of("in-netblock"); got != "in-netblock" {
		t.Errorf("the family of in-netblock = %q, want a family of its own", got)
	}
	if !strings.Contains(docPage(t, "candidates.md"), "`in-netblock`") {
		t.Error("docs/candidates.md does not list the candidate source `in-netblock`")
	}
}

// output.md says that scope.csv has hostname rows for the names in scope by address.
func TestInNetblockDocs_OutputNamesTheHostnameRowsOfScope(t *testing.T) {
	t.Parallel()
	section, _ := docsSection(t, "\n## Output files\n")
	found := docUnit(section, "scope.csv", "hostname", "address") != ""
	for line := range strings.SplitSeq(section, "\n") {
		if strings.Contains(line, "scope.csv") && strings.Contains(line, "hostname") && strings.Contains(line, "address") {
			found = true
		}
	}
	if !found {
		t.Error("the Output files section does not say that scope.csv lists the hostnames in scope by address")
	}
}

// configuration.md lists the three settings, each with its flag and its default.
func TestInNetblockDocs_ConfigurationListsTheSettings(t *testing.T) {
	t.Parallel()
	section, _ := docsSection(t, "\n## Configuration\n")
	for _, want := range [][]string{
		{"`in_netblock.enabled`", "`--no-in-netblock`"},
		{"`in_netblock.max_lookups`", "`--in-netblock-max-lookups`", "1,000"},
		{"`in_netblock.max_names_per_address`", "`--in-netblock-max-names-per-address`", "100"},
	} {
		if docUnit(section, want...) == "" {
			t.Errorf("the Configuration section has no sentence with %q", want)
		}
	}
}

// sources.md and candidates.md no longer say that a candidate is never resolved, or that a
// hostname reverse IP finds never enters scope on its own.
func TestInNetblockDocs_NoPageSaysACandidateIsNeverResolved(t *testing.T) {
	t.Parallel()
	pages := map[string]string{
		"sources.md":    flatWords(docPage(t, "sources.md")),
		"candidates.md": flatWords(docPage(t, "candidates.md")),
	}
	for name, text := range pages {
		for _, stale := range []string{"no candidate root is resolved", "no candidate is resolved", "no candidate hostname is resolved"} {
			if strings.Contains(text, stale) {
				t.Errorf("docs/%s still says %q", name, stale)
			}
		}
	}
	reverse, _ := docsSection(t, "\n## Reverse IP\n")
	if strings.Contains(flatWords(reverse), "enters scope on its own") {
		t.Error("the Reverse IP section still says that nothing it finds enters scope on its own")
	}
	if strings.Contains(pages["candidates.md"], "enters scope on its own") {
		t.Error("docs/candidates.md still says that nothing enters scope on its own")
	}
}
