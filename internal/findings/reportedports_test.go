package findings_test

import (
	"net/netip"
	"testing"

	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/provider"
)

// A risky port that only a third party reports is the same finding one severity
// step lower and unconfirmed; once nyx has opened it, the same key is at full
// severity and confirmed. A port nyx found closed is no finding.
func TestRiskyPortsReportedByAThirdParty(t *testing.T) {
	t.Parallel()
	reported := func(f *fixture) {
		f.add(rec("reported_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389.0, "banner", "rdp", "last_seen", "2026-10-30"))
	}
	t.Run("reported only", func(t *testing.T) {
		f := newFixture()
		reported(f)
		f.add(rec("reported_port", "198.51.100.5:8080", "ip", "198.51.100.5", "port", 8080.0, "banner", ""))
		got := f.derive(t)
		wantSet(t, got, "ports/risky-port=low")
		if len(got) != 1 {
			return
		}
		if x := got[0]; x.Key() != "ports|risky-port|198.51.100.5:3389" || x.Attrs["confirmed"] != "no" || x.Attrs["banner"] != "rdp" {
			t.Errorf("finding = %+v", x)
		}
	})
	t.Run("confirmed", func(t *testing.T) {
		f := newFixture()
		reported(f)
		f.add(rec("open_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389.0, "banner", "nyx banner"))
		got := f.derive(t)
		wantSet(t, got, "ports/risky-port=medium")
		if len(got) != 1 {
			return
		}
		if x := got[0]; x.Key() != "ports|risky-port|198.51.100.5:3389" || x.Attrs["confirmed"] != "yes" || x.Attrs["banner"] != "nyx banner" {
			t.Errorf("finding = %+v", x)
		}
	})
	t.Run("closed", func(t *testing.T) {
		f := newFixture()
		reported(f)
		in := f.input(t)
		in.Inv = inventory.New(inventory.Data{ClosedPorts: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.5:3389")}}, provider.Default())
		wantSet(t, derive(in))
	})
	t.Run("not eligible", func(t *testing.T) {
		f := newFixture()
		f.add(rec("reported_port", "203.0.113.9:3389", "ip", "203.0.113.9", "port", 3389.0))
		wantSet(t, f.derive(t))
	})
	t.Run("not current", func(t *testing.T) {
		f := newFixture()
		r := rec("reported_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389.0)
		r.Current = false
		f.add(r)
		wantSet(t, f.derive(t))
	})
}

func TestStepDown(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{findings.High: findings.Medium, findings.Medium: findings.Low, findings.Low: findings.Low} {
		if got := findings.StepDown(in); got != want {
			t.Errorf("StepDown(%s) = %s, want %s", in, got, want)
		}
	}
}
