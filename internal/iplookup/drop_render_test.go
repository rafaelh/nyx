package iplookup

import (
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/spamhaus"
)

// Missing DROP metadata leaves no stray punctuation or spacing.
func TestRender_DropBlankFieldsLeaveNoGaps(t *testing.T) {
	t.Parallel()
	rec := Record{Address: "34.68.34.70", Hostnames: []string{}, Kind: "public",
		DropNetworks: []spamhaus.NetworkMatch{{CIDR: "34.68.34.64/27", SBLID: "SBL1", Updated: dropV4Date}},
		DropASN:      []spamhaus.ASNMatch{{ASN: 64050, Updated: dropASNDate}}}
	got := renderTo(t, []Record{rec}, "drop_networks,drop_asn", false, stream(false, palette.None, 200))
	for _, want := range []string{"- 34.68.34.64/27: SBL1, updated " + dropV4Date, "- AS64050: updated " + dropASNDate} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("no line %q in:\n%s", want, got)
		}
	}
}
