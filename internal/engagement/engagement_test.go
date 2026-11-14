package engagement_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rafaelh/recon/internal/engagement"
	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/store"
	"golang.org/x/sys/unix"
)

func clock() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }

func open(t *testing.T, dir string) (*engagement.Engagement, error) {
	t.Helper()
	return engagement.Open(dir, engagement.Options{Clock: clock})
}

// Empty dir adopted; non-recon dir refused naming it.
func TestOpenCreatesAndAdopts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "eng")
	e, err := open(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	if _, err := os.Stat(filepath.Join(dir, ".recon", "state.db")); err != nil {
		t.Fatal(err)
	}

	empty := t.TempDir()
	e, err = open(t, empty)
	if err != nil {
		t.Fatalf("empty dir should be adopted: %v", err)
	}
	e.Close()
}

func TestRefusesNonEngagement(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "subdomains.txt"), []byte("a.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := open(t, dir)
	var ne *engagement.NotEngagementError
	if !errors.As(err, &ne) || ne.Dir != dir {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, ".recon")); serr == nil {
		t.Error("must not create .recon in a foreign dir")
	}
}

// .recon with a lock but no DB (crash during creation) is adopted.
func TestAdoptsInterruptedCreation(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".recon"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".recon", "lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := open(t, dir)
	if err != nil {
		t.Fatalf("should adopt: %v", err)
	}
	e.Close()
}

// Live lock refuses; a released (crashed) lock does not block.
func TestLock(t *testing.T) {
	dir := t.TempDir()
	e, err := open(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = open(t, dir)
	var le *engagement.LockedError
	if !errors.As(err, &le) {
		t.Fatalf("second open: %v", err)
	}
	e.Close()
	e, err = open(t, dir)
	if err != nil {
		t.Fatalf("after close: %v", err)
	}
	e.Close()

	// Someone else holds the flock.
	f, _ := os.OpenFile(filepath.Join(dir, ".recon", "lock"), os.O_RDWR, 0)
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err = open(t, dir); !errors.As(err, &le) {
		t.Fatalf("held lock: %v", err)
	}
}

// Inputs and exclusions are merged as a union and persisted.
func TestMergeInputs(t *testing.T) {
	dir := t.TempDir()
	e, _ := open(t, dir)
	if err := e.MergeInputs(input.Parsed{Roots: []string{"a.com"}, ASNs: []string{"AS1"}, Exclusions: []string{"x.a.com"}}); err != nil {
		t.Fatal(err)
	}
	e.Close()

	e, _ = open(t, dir)
	if err := e.MergeInputs(input.Parsed{Roots: []string{"b.com"}, CIDRs: []string{"10.0.0.0/8"}, Exclusions: []string{"y.a.com"}}); err != nil {
		t.Fatal(err)
	}
	got, err := e.Inputs()
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	if len(got.Roots) != 2 || got.Roots[0] != "a.com" || got.Roots[1] != "b.com" ||
		len(got.ASNs) != 1 || len(got.CIDRs) != 1 || len(got.Exclusions) != 2 {
		t.Errorf("inputs = %+v", got)
	}
}

func TestAckAndApproval(t *testing.T) {
	e, _ := open(t, t.TempDir())
	defer e.Close()
	if e.Acked() || e.NetblockApproved() != 0 {
		t.Fatal("fresh engagement")
	}
	if err := e.SetAck(); err != nil {
		t.Fatal(err)
	}
	if err := e.SetNetblockApproved(9999); err != nil {
		t.Fatal(err)
	}
	if !e.Acked() || e.NetblockApproved() != 9999 {
		t.Error("not stored")
	}
}

// A read-only open takes no lock and creates nothing, so it works beside a run.
func TestOpenReadOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "eng")
	e, err := open(t, dir) // holds the lock
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.MergeInputs(input.Parsed{Roots: []string{"a.com"}, Exclusions: []string{"x.a.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.Store().Flush(); err != nil {
		t.Fatal(err)
	}

	ro, err := engagement.OpenReadOnly(dir)
	if err != nil {
		t.Fatalf("a read-only open must work while a run holds the lock: %v", err)
	}
	err = ro.View(func(r store.Reader) error {
		rows, err := r.Inputs()
		if in := engagement.ParseInputs(rows); err != nil || len(in.Roots) != 1 || len(in.Exclusions) != 1 {
			t.Errorf("inputs = %+v, %v", in, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ro.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	if _, err := open(t, dir); err == nil {
		t.Error("closing the read-only engagement released the run's lock, or never held it")
	}
}

func TestOpenReadOnlyCreatesNothing(t *testing.T) {
	base := t.TempDir()
	if _, err := engagement.OpenReadOnly(filepath.Join(base, "missing")); err == nil {
		t.Error("a missing directory was opened")
	}
	other := filepath.Join(base, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	hollow := filepath.Join(base, "hollow", ".recon")
	if err := os.MkdirAll(hollow, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{other, filepath.Dir(hollow)} {
		if _, err := engagement.OpenReadOnly(d); err == nil {
			t.Errorf("%s was opened", d)
		}
	}
	for _, p := range []string{"missing", "other/.recon", "hollow/.recon/lock", "hollow/.recon/state.db"} {
		if _, err := os.Stat(filepath.Join(base, p)); err == nil {
			t.Errorf("%s was created", p)
		}
	}

	// An engagement that ran and closed has no lock holder, and still gains no file.
	dir := filepath.Join(base, "done")
	e, err := open(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	before, _ := os.ReadDir(filepath.Join(dir, ".recon"))
	ro, err := engagement.OpenReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}
	ro.Close()
	after, _ := os.ReadDir(filepath.Join(dir, ".recon"))
	if len(before) != len(after) {
		t.Errorf(".recon had %d entries, now %d", len(before), len(after))
	}
}
