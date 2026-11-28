package output

import (
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/recon/analysis/findings"
	"github.com/rafaelh/nyx/internal/recon/kinds"
)

// findingsFile uses findings-owned columns/rows with the shared CSV writer.
func findingsFile(f findings.File) File {
	return File{Name: f.Name, Format: CSV, Columns: f.Columns, Rows: func(s Snapshot) []Row {
		var rows []Row
		for _, r := range f.Rows(findings.Listing{Records: s.Records, Storage: s.Storage}) {
			rows = append(rows, recordRow(r.Record, r.Cells...))
		}
		return rows
	}}
}

var emailPostureColumns = []string{"root", "mx", "spf", "spf_lookups", "dmarc", "dmarc_policy", "dkim_selectors", "mta_sts", "mx_self_hosted"}

// emailPostureRows lists the email posture evidence of each in-scope root.
func emailPostureRows(s Snapshot) []Row {
	var rows []Row
	vis := s.vis()
	for _, r := range s.of(kinds.EmailPosture) {
		if !vis.Shown(kinds.EmailPosture, r) {
			continue
		}
		a := kinds.EmailPosture.Attrs(r)
		lookups := strconv.Itoa(a.SPFLookups)
		if !r.Current { // a record no longer current has lost its count
			lookups = ""
		}
		rows = append(rows, recordRow(r, r.Key, a.MX, a.SPF, lookups, a.DMARC, a.DMARCPolicy, a.DKIMSelectors, a.MTASTS,
			selfHostedMX(s, a.MX)))
	}
	return rows
}

// selfHostedMX filters a semicolon-separated host list to self-hosted mail servers. Non-current
// records have no hosts to filter.
func selfHostedMX(s Snapshot, mx string) string {
	var own []string
	for h := range strings.SplitSeq(mx, ";") {
		if h != "" && s.Inv.SelfHosted(h, s.Scope) {
			own = append(own, h)
		}
	}
	return strings.Join(own, ";")
}
