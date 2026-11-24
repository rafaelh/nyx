package findings_test

import (
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/recon/analysis/findings"
	"github.com/rafaelh/nyx/internal/recon/store"
)

// Origin keys identify the pair independently of confirmation and decode to a readable
// host/address target.
func TestOriginExposure_KeyIsStableBetweenPossibleAndConfirmed(t *testing.T) {
	t.Parallel()
	possible := findings.Finding{Category: findings.OriginExposure, Type: "possible", Target: "www.example.com -> 203.0.113.20"}
	confirmed := findings.Finding{Category: findings.OriginExposure, Type: "confirmed", Target: "www.example.com -> 203.0.113.20"}
	const want = "origin-exposure|www.example.com|203.0.113.20"
	if possible.Key() != want || confirmed.Key() != want {
		t.Errorf("keys = %q, %q; want %q for both", possible.Key(), confirmed.Key(), want)
	}
	cat, typ, target := findings.ParseKey(want)
	if cat != findings.OriginExposure || typ != "" || target != "www.example.com -> 203.0.113.20" {
		t.Errorf("ParseKey = %q %q %q", cat, typ, target)
	}
	// An IPv6 address keeps its colons.
	f := findings.Finding{Category: findings.OriginExposure, Target: "www.example.com -> 2001:db8::5"}
	if _, _, target := findings.ParseKey(f.Key()); target != f.Target {
		t.Errorf("IPv6 target = %q", target)
	}
}

func TestOriginExposure_Severities(t *testing.T) {
	t.Parallel()
	if got := findings.Severity(findings.OriginExposure, "confirmed"); got != findings.Medium {
		t.Errorf("confirmed = %q, want medium", got)
	}
	if got := findings.Severity(findings.OriginExposure, "possible"); got != findings.Low {
		t.Errorf("possible = %q, want low", got)
	}
	if got := findings.Severity(findings.OriginExposure, "other"); got != "" {
		t.Errorf("an unknown type = %q", got)
	}
	var documented []string
	for _, r := range findings.SeverityTable() {
		if r.Category == findings.OriginExposure {
			documented = append(documented, r.Type)
		}
	}
	if len(documented) != 2 {
		t.Errorf("the severity table lists %v, want confirmed and possible", documented)
	}
}

// risk-origin-exposure.csv has one row per hostname and address, and a pair no longer derived
// keeps its hostname and address from its key.
func TestOriginExposure_File(t *testing.T) {
	t.Parallel()
	f := file(t, "risk-origin-exposure.csv")
	want := []string{"severity", "hostname", "provider", "address", "found_by", "confirmed_by", "confirmed"}
	if !slices.Equal(f.Columns, want) {
		t.Fatalf("columns = %v, want %v", f.Columns, want)
	}
	l := findings.Listing{Records: map[string][]store.Record{"finding": {
		srec("finding", "origin-exposure|www.example.com|203.0.113.20", true,
			"category", "origin-exposure", "type", "confirmed", "severity", "medium", "target", "www.example.com -> 203.0.113.20", "detail", "d",
			"hostname", "www.example.com", "provider", "fastly", "address", "203.0.113.20", "found_by", "sibling-certificate",
			"confirmed_by", "title", "confirmed", "yes"),
		srec("finding", "origin-exposure|www.example.com|2001:db8::5", false),
	}}}
	rows := f.Rows(l)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	for k, v := range map[string]string{"severity": "medium", "hostname": "www.example.com", "provider": "fastly", "address": "203.0.113.20",
		"found_by": "sibling-certificate", "confirmed_by": "title", "confirmed": "yes"} {
		if got := cellMap(f, rows[0])[k]; got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	gone := cellMap(f, rows[1])
	if rows[1].Record.Current || gone["hostname"] != "www.example.com" || gone["address"] != "2001:db8::5" || gone["severity"] != "" {
		t.Errorf("a pair no longer derived = %v (current %v)", gone, rows[1].Record.Current)
	}
}
