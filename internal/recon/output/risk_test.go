package output_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/output"
	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/scope"
)

// The findings files' columns and rows are tested in the findings package;
// TestDefaultRegistry checks that they are registered.

// snapshot shows recs under the scope of example.com and 198.51.100.0/24, less the exclusions.
func snapshot(recs map[string][]store.Record, exclusions ...input.Exclusion) output.Snapshot {
	inv := inventory.New(inventory.Data{}, provider.Default())
	sc := scope.New(scope.Config{Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions: exclusions})
	return output.Snapshot{Today: "2026-11-01", Records: recs, Scope: sc, Inv: inv, Vis: kinds.NewVisibility(sc, inv)}
}

func file(t *testing.T, name string) output.File {
	t.Helper()
	for _, f := range output.Default() {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no file %s", name)
	return output.File{}
}

func srec(kind, key string, current bool, kv ...any) store.Record {
	a := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		a[kv[i].(string)] = kv[i+1]
	}
	return store.Record{Kind: kind, Key: key, Current: current, Attrs: a, FirstSeen: "2026-10-01", LastSeen: "2026-11-01"}
}

func cellMap(f output.File, r output.Row) map[string]string {
	m := map[string]string{}
	for i, c := range f.Columns {
		m[c] = r.Cells[i]
	}
	return m
}

// email-posture.csv has one row per in-scope root.
func TestEmailPostureFile(t *testing.T) {
	t.Parallel()
	snap := snapshot(map[string][]store.Record{"email_posture": {
		srec("email_posture", "example.com", true, "mx", "mail.example.com", "spf", "v=spf1 -all", "spf_lookups", 3.0,
			"dmarc", "v=DMARC1; p=none", "dmarc_policy", "none", "dkim_selectors", "google;k1", "mta_sts", "absent"),
		srec("email_posture", "other.org", true, "spf", "v=spf1 -all"),
	}})
	f := file(t, "email-posture.csv")
	if !slices.Equal(f.Columns, []string{"root", "mx", "spf", "spf_lookups", "dmarc", "dmarc_policy", "dkim_selectors", "mta_sts", "mx_self_hosted"}) {
		t.Errorf("columns = %v", f.Columns)
	}
	rows := f.Rows(snap)
	if len(rows) != 1 {
		t.Fatalf("rows = %v", rows)
	}
	got := cellMap(f, rows[0])
	if got["root"] != "example.com" || got["spf_lookups"] != "3" || got["dkim_selectors"] != "google;k1" || got["dmarc_policy"] != "none" || got["mta_sts"] != "absent" || got["mx_self_hosted"] != "mail.example.com" {
		t.Errorf("row = %v", got)
	}
}

// A findings file is written with the dates of the record each row lists.
func TestFindingsFileRows(t *testing.T) {
	t.Parallel()
	snap := snapshot(map[string][]store.Record{"finding": {
		srec("finding", "email|spf-missing|example.com", false),
	}})
	rows := file(t, "risk-email.csv").Rows(snap)
	if len(rows) != 1 || rows[0].Current || rows[0].FirstSeen != "2026-10-01" || rows[0].LastSeen != "2026-11-01" {
		t.Errorf("rows = %+v", rows)
	}
	if got := cellMap(file(t, "risk-email.csv"), rows[0]); got["root"] != "example.com" || got["type"] != "spf-missing" {
		t.Errorf("row = %v", got)
	}
}

// Candidate/exclusion rows match summary placement, deduplicating excluded values and ignoring
// invalid CIDRs.
func TestCandidateExcludedFilesMatchTotals(t *testing.T) {
	t.Parallel()
	x, err := input.ParseExclusion("bad.example.com")
	if err != nil {
		t.Fatal(err)
	}
	recs := map[string][]store.Record{
		"hostname": {srec("hostname", "www.example.com", true), srec("hostname", "www.other.org", true),
			srec("hostname", "bad.example.com", false)},
		"root":     {srec("root", "other.org", true)},
		"netblock": {srec("netblock", "198.51.100.0/24", true), srec("netblock", "203.0.113.0/24", true), srec("netblock", "not-a-prefix", true)},
		"excluded": {srec("excluded", "bad.example.com", true, "reason", "guard"), srec("excluded", "192.0.2.1", true, "reason", "guard")},
	}
	snap := snapshot(recs, x)
	totals := snap.Vis.Totals(recs)
	current := func(name string) (n int, values []string) {
		for _, r := range file(t, name).Rows(snap) {
			if r.Current {
				n++
			}
			values = append(values, r.Cells[0]+"/"+r.Cells[len(r.Cells)-1])
		}
		return n, values
	}
	if n, v := current("candidates.csv"); n != totals[kinds.Candidates] || n != 3 {
		t.Errorf("candidates.csv current rows = %d %v, totals = %d", n, v, totals[kinds.Candidates])
	}
	if n, v := current("excluded.csv"); n != totals[kinds.Excluded] || n != 2 || len(v) != 2 {
		t.Errorf("excluded.csv current rows = %d %v, totals = %d", n, v, totals[kinds.Excluded])
	}
}
