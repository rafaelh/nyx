package cve

import (
	"slices"
	"strings"
	"testing"
)

var allNames = []string{"id", "status", "published", "last_modified", "description", "cvss_version", "cvss_score",
	"cvss_severity", "cvss_vector", "cvss_source", "weaknesses", "affected_products", "references"}

func TestFields_NamesAreTheRecordsKeysInOrder(t *testing.T) {
	t.Parallel()
	if got := FieldNames(); !slices.Equal(got, allNames) {
		t.Errorf("FieldNames() = %v", got)
	}
	if got, want := ValidFields(), "valid fields: "+strings.Join(allNames, ", ")+", or all"; got != want {
		t.Errorf("ValidFields() = %q, want %q", got, want)
	}
}

// The selection keeps the table's order whatever order it was given in, always
// has id, ignores empty names and accepts all.
func TestFields_Select(t *testing.T) {
	t.Parallel()
	score, sev := 9.8, "CRITICAL"
	rec := Record{ID: "CVE-2024-0001", CVSSScore: &score, CVSSSeverity: &sev, Weaknesses: []string{}, AffectedProducts: []AffectedProduct{}, References: []Reference{}}
	for _, c := range []struct{ spec, want string }{
		{"cvss_score", `{"id":"CVE-2024-0001","cvss_score":9.8}`},
		{"id,cvss_score", `{"id":"CVE-2024-0001","cvss_score":9.8}`},
		{" cvss_severity , cvss_score,,id ", `{"id":"CVE-2024-0001","cvss_score":9.8,"cvss_severity":"CRITICAL"}`},
		{"description,references", `{"id":"CVE-2024-0001","description":null,"references":[]}`},
		{"", `{"id":"CVE-2024-0001"}`},
		{"all", encode(t, rec)},
		{"cvss_score,all", encode(t, rec)},
	} {
		f, unknown := Select(c.spec)
		if unknown != nil {
			t.Errorf("Select(%q): unknown %q", c.spec, unknown)
			continue
		}
		if got := encode(t, f.Project(rec)); got != c.want {
			t.Errorf("Select(%q) projects to %s, want %s", c.spec, got, c.want)
		}
		if !f.Has("id") {
			t.Errorf("Select(%q) does not have id", c.spec)
		}
	}
}

func TestFields_UnknownNames(t *testing.T) {
	t.Parallel()
	if _, unknown := Select("cvss_score,bogus, severity ,all"); !slices.Equal(unknown, []string{"bogus", "severity"}) {
		t.Fatalf("Select's unknown names = %q, want bogus and severity", unknown)
	}
}

func TestFields_Has(t *testing.T) {
	t.Parallel()
	f, unknown := Select("cvss_score")
	if unknown != nil {
		t.Fatal(unknown)
	}
	for name, want := range map[string]bool{"id": true, "cvss_score": true, "cvss_severity": false, "bogus": false} {
		if f.Has(name) != want {
			t.Errorf("Has(%q) = %v", name, !want)
		}
	}
}
