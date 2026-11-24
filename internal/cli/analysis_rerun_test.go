package cli_test

import (
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// analysisWorld is an engagement "a.com" whose one procedure, seed, records evidence of a finding
// (an open RDP port in the --cidr netblock) and a candidate hostname, so that the findings and
// candidate-rank analyses both produce records.
func analysisWorld(t *testing.T) (*harness, *testkit.Procedure) {
	t.Helper()
	seed := finder("seed",
		obs("open_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389, "banner", ""),
		obs("hostname", "evil.example"))
	h := newHarness(t, seed)
	if code := h.exec("a.com", "--cidr", "198.51.100.0/24"); code != 0 {
		t.Fatalf("first run exit %d: %s", code, h.stderr.String())
	}
	db := h.openDB("a.com")
	if got := queryStrings(t, db, "SELECT key FROM records WHERE kind='finding' AND current=1"); len(got) == 0 {
		t.Fatal("precondition: the first run derived no finding")
	}
	if got := queryStrings(t, db, "SELECT key FROM records WHERE kind='candidate_rank' AND current=1"); len(got) == 0 {
		t.Fatal("precondition: the first run ranked no candidate")
	}
	return h, seed
}

// jobsRows lists the engagement's jobs table as "procedure|key".
func jobsRows(h *harness, eng string) []string {
	h.t.Helper()
	return queryStrings(h.t, h.openDB(eng), "SELECT procedure||'|'||key FROM jobs")
}

// analysisJobs lists the jobs rows named after an analysis or the guard.
func analysisJobs(h *harness, eng string) []string {
	h.t.Helper()
	var out []string
	for _, p := range run.AnalysisNames() {
		for _, k := range h.completed(eng, p) {
			out = append(out, p+"|"+k)
		}
	}
	return out
}

// analysisObservations lists the stored observations of the analyses and the guard, with the date
// each was last seen.
func analysisObservations(h *harness, eng string) []string {
	h.t.Helper()
	db := h.openDB(eng)
	var out []string
	for _, p := range run.AnalysisNames() {
		out = append(out, queryStrings(h.t, db,
			"SELECT kind||'|'||key||'|'||producer||'|'||job_key||'|'||seen FROM observations WHERE producer=?", p)...)
	}
	return out
}

// The jobs table holds only the jobs procedures performed: the analyses write no row, on the
// first run or when a second run derives their records again.
func TestAnalysisRerun_FindingsRederivedWithoutJobsRows(t *testing.T) {
	t.Parallel()
	h, seed := analysisWorld(t)
	db := h.openDB("a.com")

	if got := analysisJobs(h, "a.com"); len(got) != 0 {
		t.Errorf("after the first run, jobs rows named after an analysis: %q", got)
	}
	wantJobs := []string{}
	for _, k := range h.completed("a.com", "seed") {
		wantJobs = append(wantJobs, "seed|"+k)
	}
	if got := jobsRows(h, "a.com"); !slices.Equal(got, wantJobs) || len(got) == 0 {
		t.Errorf("after the first run, jobs = %q, want only seed's %q", got, wantJobs)
	}
	findings := queryStrings(t, db, "SELECT key FROM records WHERE kind='finding'")

	h.now = h.now.Add(48 * time.Hour)
	if code := h.exec("-e", "a.com"); code != 0 {
		t.Fatalf("second run exit %d: %s", code, h.stderr.String())
	}
	if n := len(seed.Executed()); n != 1 {
		t.Fatalf("precondition: seed's job ran %d times, want once", n)
	}
	if got := jobsRows(h, "a.com"); !slices.Equal(got, wantJobs) {
		t.Errorf("after the second run, jobs = %q, want them unchanged %q", got, wantJobs)
	}
	// The findings were derived again: still current, first seen on the first run and last seen on
	// the second.
	for _, k := range findings {
		got := queryStrings(t, db, "SELECT first_seen||'|'||last_seen||'|'||current FROM records WHERE kind='finding' AND key=?", k)
		if want := "2026-11-01|2026-11-03|1"; len(got) != 1 || got[0] != want {
			t.Errorf("finding %s after the second run = %q, want %q", k, got, want)
		}
	}
	if got := queryStrings(t, db, "SELECT key FROM records WHERE kind='finding'"); !slices.Equal(got, findings) {
		t.Errorf("findings after the second run = %q, want %q", got, findings)
	}
}

// --redo performs a procedure's jobs again and leaves the analyses' observations alone.
func TestAnalysisRerun_RedoLeavesAnalysisObservations(t *testing.T) {
	t.Parallel()
	h, seed := analysisWorld(t)
	before := analysisObservations(h, "a.com")
	if len(before) == 0 {
		t.Fatal("precondition: the analyses stored no observation")
	}

	if code := h.exec("-e", "a.com", "--redo", "seed"); code != 0 {
		t.Fatalf("redo run exit %d: %s", code, h.stderr.String())
	}
	if got := seed.Executed(); len(got) != 2 || got[0] != got[1] {
		t.Errorf("seed's jobs performed %q, want its one job performed again", got)
	}
	if after := analysisObservations(h, "a.com"); !slices.Equal(after, before) {
		t.Errorf("the analyses' observations changed with --redo seed:\nbefore %q\nafter  %q", before, after)
	}
}

// A dial egress refuses because the address is excluded records the address as excluded, under
// the guard, and adds no jobs row for the guard.
func TestAnalysisRerun_GuardWritesNoJobsRow(t *testing.T) {
	t.Parallel()
	const addr = "198.51.100.9"
	var refused atomic.Bool
	dialler := diallerProcedure(addr, &refused)
	h := newHarness(t, dialler)
	if code := h.exec("a.com", "--cidr", "198.51.100.0/24", "-x", addr+"/32", "--authorised"); code != 0 {
		t.Fatalf("run exit %d: %s", code, h.stderr.String())
	}
	if !refused.Load() {
		t.Fatal("precondition: egress did not refuse the dial to the excluded address")
	}
	db := h.openDB("a.com")
	if got := queryStrings(t, db, "SELECT key FROM records WHERE kind='excluded' AND current=1"); !slices.Contains(got, addr) {
		t.Errorf("current excluded records = %q, want %s", got, addr)
	}
	if got := queryStrings(t, db, "SELECT producer FROM observations WHERE kind='excluded' AND key=?", addr); !slices.Equal(got, []string{"guard"}) {
		t.Errorf("the excluded record's producers = %q, want the guard", got)
	}
	if got := h.completed("a.com", run.AnalysisGuard); len(got) != 0 {
		t.Errorf("jobs rows for the guard = %q, want none", got)
	}
	if got := jobsRows(h, "a.com"); !slices.Equal(got, []string{"dialler|" + addr + ":22"}) {
		t.Errorf("jobs = %q, want only dialler's job", got)
	}
}
