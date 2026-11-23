package threatdata_test

import (
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// lockAfterRenames is a Rename that puts each data file in place and then, once both sources'
// files are in place (or after ten seconds), makes the directory read-only, so the state write
// that follows each rename fails.
func lockAfterRenames(t *testing.T, dir string) func(oldpath, newpath string) error {
	t.Helper()
	var (
		mu      sync.Mutex
		renamed int
		both    = make(chan struct{})
		once    sync.Once
	)
	return func(oldpath, newpath string) error {
		if err := os.Rename(oldpath, newpath); err != nil {
			return err
		}
		mu.Lock()
		renamed++
		if renamed == 2 {
			close(both)
		}
		mu.Unlock()
		select {
		case <-both:
		case <-time.After(10 * time.Second):
		}
		once.Do(func() {
			if err := os.Chmod(dir, 0o500); err != nil {
				t.Errorf("making the directory read-only: %v", err)
			}
		})
		return nil
	}
}

// A download put in place whose check then can't be recorded still fails its source with
// UNEXPECTED_ERROR, but the source reports its lists as they are after the update, as the new
// copy is in use, and its reason says the data was replaced and only the check wasn't recorded.
func TestUpdate_StateWriteFailsAfterTheDataIsStored(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	w := newWorld(t)
	w.previous(0o600) // dated d1: drop_v4 0..79, networks 0..79, asns 0..19
	const newCopyright = "(c) 2027 The Spamhaus Project SLU"
	v4 := file(append(rows(v4Row, 3, 87), strings.Replace(metaLine(d2, 87), copyright, newCopyright, 1))...) // -0,1,2 +80..89
	w.serveSpamhaus(lists{v4, dropFile(v6Row, d2, 0, 20), dropFile(asnRow, d2, 0, 20)})
	w.serveIpapi(day(d2), 90, 0, 90, day(d2), 18, 2, 18)
	t.Cleanup(func() { _ = os.Chmod(w.dir, 0o700) })
	w.rename = lockAfterRenames(t, w.dir)
	r := w.update()
	w.rename = nil

	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		s := source(t, r, name)
		failedWith(t, "a failed state write after the data was stored", s, clierr.Unexpected, false, "permission denied")
		if !strings.Contains(strings.ToLower(s.Reason), "replaced") {
			t.Errorf("%s's reason %q doesn't say the data was replaced", name, s.Reason)
		}
		if !s.LastContacted.Equal(now) {
			t.Errorf("%s: last contacted %v, want %v", name, s.LastContacted, now)
		}
	}
	if s := source(t, r, threatdata.Spamhaus); s.Copyright != newCopyright || s.Terms != terms {
		t.Errorf("Spamhaus's credit %q, %q; want the new copy's %q, %q", s.Copyright, s.Terms, newCopyright, terms)
	}

	// Each list is described as it is after the update. Its outcome is not what this pins.
	want := []threatdata.ListResult{
		{List: spamhaus.ListV4, Source: threatdata.Spamhaus, OldUpdated: stamp(d1), NewUpdated: stamp(d2), OldEntries: 80, Entries: 87, Added: 10, Removed: 3},
		{List: spamhaus.ListV6, Source: threatdata.Spamhaus, OldUpdated: stamp(d1), NewUpdated: stamp(d2), OldEntries: 20, Entries: 20},
		{List: spamhaus.ListASN, Source: threatdata.Spamhaus, OldUpdated: stamp(d1), NewUpdated: stamp(d2), OldEntries: 20, Entries: 20},
		{List: threatdata.ListNetworks, Source: threatdata.Ipapi, OldUpdated: day(d1), NewUpdated: day(d2), OldEntries: 80, Entries: 90, Added: 10},
		{List: threatdata.ListASNs, Source: threatdata.Ipapi, OldUpdated: day(d1), NewUpdated: day(d2), OldEntries: 20, Entries: 18, Removed: 2},
	}
	got := slices.Clone(r.Lists)
	for i := range got {
		got[i].Outcome = ""
	}
	if !slices.Equal(got, want) {
		t.Errorf("lists (outcomes left out)\n%+v\nwant\n%+v", got, want)
	}

	// The new copy is what a reader now uses.
	s := w.load(now)
	if len(s.Warnings) != 0 {
		t.Errorf("warnings after the update: %v", s.Warnings)
	}
	if l := inUse(t, s, spamhaus.ListV4); !l.Downloaded || l.Updated != stamp(d2) || l.Entries != 87 {
		t.Errorf("drop_v4 in use: %+v, want the download dated %s with 87 entries", l, stamp(d2))
	}
	if l := inUse(t, s, threatdata.ListNetworks); !l.Downloaded || l.Updated != day(d2) || l.Entries != 90 {
		t.Errorf("networks in use: %+v, want the download dated %s with 90 entries", l, day(d2))
	}
	if l := inUse(t, s, threatdata.ListASNs); !l.Downloaded || l.Updated != day(d2) || l.Entries != 18 {
		t.Errorf("asns in use: %+v, want the download dated %s with 18 entries", l, day(d2))
	}
	if s.Copyright != newCopyright {
		t.Errorf("credit in use %q, want %q", s.Copyright, newCopyright)
	}
}
