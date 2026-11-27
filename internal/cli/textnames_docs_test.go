package cli_test

import (
	"strings"
	"testing"
)

// The user guide has a section on the hostnames read from responses: that they are taken from
// anywhere in a response and from banners, the cap of 1,000 per web service and what is said past
// 10,000, that a root added later needs --redo, and that the reading is off under --passive.
func TestTextNames_DocsDescribeHostnamesInResponses(t *testing.T) {
	t.Parallel()
	section, _ := docsSection(t, "\n## Hostnames in responses\n")
	flat := flatWords(section)
	for _, want := range []string{"anywhere", "banner", "1,000", "more than 10,000", "--redo", "--passive"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the Hostnames in responses section does not mention %q", want)
		}
	}
}

// The passive boundary says that hostnames are read from the responses and banners nyx has
// already received, and that reading them sends nothing.
func TestTextNames_PassiveBoundarySaysReadingSendsNothing(t *testing.T) {
	t.Parallel()
	section, _ := docsSection(t, "\n## Passive boundary\n")
	if docUnit(section, "hostname", "banner", "sends nothing") == "" {
		t.Error("the Passive boundary section has no sentence saying that reading hostnames from responses and banners sends nothing")
	}
}
