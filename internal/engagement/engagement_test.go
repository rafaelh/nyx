package engagement_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/engagement"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/store"
	"golang.org/x/sys/unix"
)

func clock() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }

func open(t *testing.T, dir string) (*engagement.Engagement, error) {
	t.Helper()
	return engagement.Open(dir, engagement.Options{Clock: clock})
}

// Empty dir adopted; non-nyx dir refused naming it.
func TestOpenCreatesAndAdopts(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "eng")
	e, err := open(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	if _, err := os.Stat(filepath.Join(dir, ".nyx", "state.db")); err != nil {
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
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, dir, "subdomains.txt")
	_, err := open(t, dir)
	var ne *engagement.NotEngagementError
	if !errors.As(err, &ne) || ne.Dir != dir {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, ".nyx")); serr == nil {
		t.Error("must not create .nyx in a foreign dir")
	}
}

// .nyx with a lock but no DB (crash during creation) is adopted.
func TestAdoptsInterruptedCreation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeFile(t, mkdir(t, dir, ".nyx"), "lock")
	e, err := open(t, dir)
	if err != nil {
		t.Fatalf("should adopt: %v", err)
	}
	e.Close()
}

// Live lock refuses; a released (crashed) lock does not block.
func TestLock(t *testing.T) {
	t.Parallel()
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
	f, _ := os.OpenFile(filepath.Join(dir, ".nyx", "lock"), os.O_RDWR, 0)
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	base := t.TempDir()
	if _, err := engagement.OpenReadOnly(filepath.Join(base, "missing")); err == nil {
		t.Error("a missing directory was opened")
	}
	other := filepath.Join(base, "other")
	if err := os.Mkdir(other, 0o755); err != nil {
		t.Fatal(err)
	}
	hollow := filepath.Join(base, "hollow", ".nyx")
	if err := os.MkdirAll(hollow, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{other, filepath.Dir(hollow)} {
		if _, err := engagement.OpenReadOnly(d); err == nil {
			t.Errorf("%s was opened", d)
		}
	}
	for _, p := range []string{"missing", "other/.nyx", "hollow/.nyx/lock", "hollow/.nyx/state.db"} {
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
	before, _ := os.ReadDir(filepath.Join(dir, ".nyx"))
	ro, err := engagement.OpenReadOnly(dir)
	if err != nil {
		t.Fatal(err)
	}
	ro.Close()
	after, _ := os.ReadDir(filepath.Join(dir, ".nyx"))
	if len(before) != len(after) {
		t.Errorf(".nyx had %d entries, now %d", len(before), len(after))
	}
}

func mkdir(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeFile(t *testing.T, parts ...string) string {
	t.Helper()
	p := filepath.Join(parts...)
	if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProbe(t *testing.T) {
	t.Parallel()
	base := t.TempDir()

	empty := mkdir(t, base, "empty")
	stray := mkdir(t, base, "stray")
	writeFile(t, stray, "subdomains.txt")
	regular := writeFile(t, base, "plain.txt")
	hollow := mkdir(t, base, "hollow", ".nyx")
	hollow = filepath.Dir(hollow)
	writeFile(t, hollow, ".nyx", "lock")
	done := filepath.Join(base, "done")
	e, err := open(t, done)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()

	for _, tc := range []struct {
		name string
		dir  string
		want engagement.State
	}{
		{"missing directory", filepath.Join(base, "missing"), engagement.Absent},
		{"empty directory", empty, engagement.Absent},
		{"stray file and no .nyx", stray, engagement.Foreign},
		{"regular file", regular, engagement.Foreign},
		{".nyx without a state database", hollow, engagement.Absent},
		{"closed engagement", done, engagement.Exists},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := engagement.Probe(tc.dir)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if got != tc.want {
				t.Errorf("Probe = %v, want %v", got, tc.want)
			}
		})
	}
}

// A path under a regular file cannot be read as a directory entry: that is a
// failure to read, not a missing engagement.
func TestProbeReadFailure(t *testing.T) {
	t.Parallel()
	file := writeFile(t, t.TempDir(), "plain.txt")
	if got, err := engagement.Probe(filepath.Join(file, "eng")); err == nil {
		t.Errorf("Probe through a regular file = %v, nil; want an error", got)
	}
}

// An engagement a run holds is still an engagement.
func TestProbeWhileLocked(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "eng")
	e, err := open(t, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if got, err := engagement.Probe(dir); err != nil || got != engagement.Exists {
		t.Errorf("Probe = %v, %v; want exists", got, err)
	}
}

func TestProbeCreatesNothing(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	missing := filepath.Join(base, "missing")
	empty := mkdir(t, base, "empty")
	hollow := mkdir(t, base, "hollow")
	mkdir(t, hollow, ".nyx")
	for _, d := range []string{missing, empty, hollow} {
		if _, err := engagement.Probe(d); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(missing); err == nil {
		t.Error("a missing directory was created")
	}
	if es, _ := os.ReadDir(empty); len(es) != 0 {
		t.Errorf("an empty directory gained %d entries", len(es))
	}
	if es, _ := os.ReadDir(filepath.Join(hollow, ".nyx")); len(es) != 0 {
		t.Errorf(".nyx gained %d entries", len(es))
	}
}

func TestStateString(t *testing.T) {
	t.Parallel()
	for s, want := range map[engagement.State]string{
		engagement.Exists: "exists", engagement.Foreign: "foreign", engagement.Absent: "absent",
	} {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	out := t.TempDir()
	for _, name := range []string{"zeta", "acme", "mid"} {
		e, err := open(t, filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		e.Close()
	}
	mkdir(t, out, "empty")
	foreign := mkdir(t, out, "foreign")
	writeFile(t, foreign, "subdomains.txt")
	mkdir(t, out, "hollow", ".nyx")
	writeFile(t, out, "plain.txt")

	got := engagement.List(out)
	want := []string{"acme", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("List = %v, want %v", got, want)
		}
	}
}

func TestListUnreadable(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	if got := engagement.List(filepath.Join(base, "missing")); got != nil {
		t.Errorf("List of a missing directory = %v, want none", got)
	}
	if got := engagement.List(writeFile(t, base, "plain.txt")); got != nil {
		t.Errorf("List of a regular file = %v, want none", got)
	}
	if got := engagement.List(mkdir(t, base, "empty")); len(got) != 0 {
		t.Errorf("List of an empty directory = %v, want none", got)
	}
}
