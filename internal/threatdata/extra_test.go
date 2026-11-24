package threatdata_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/threatdata"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
	tdt "github.com/rafaelh/nyx/internal/threatdata/threatdatatest"
)

// An update that syncs its files (NoFsync unset) puts the same files in place.
func TestUpdate_SyncsWhenAsked(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	opts := w.options()
	opts.NoFsync = false
	r := threatdata.Update(context.Background(), opts)
	for _, s := range r.Sources {
		if s.Outcome != threatdata.Updated {
			t.Errorf("%s: %+v, want updated", s.Source, s)
		}
	}
	if l := inUse(t, w.load(now), spamhaus.ListV4); !l.Downloaded || l.Updated != stamp(d2) {
		t.Errorf("drop_v4 in use: %+v, want the download", l)
	}
}

// A state file that isn't JSON is no state: the source was never checked, and the next update
// writes it afresh.
func TestUpdate_AnUnreadableStateIsNoState(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	writeFile(t, w.dir, spamhausSt, []byte(`{"last_response":`), 0o600)
	old := now.AddDate(0, 0, -60)
	w.builtIn = aged(t, old, old, old, day(old), day(old))
	if s := w.load(now); len(s.Stale) != 2 || len(s.Warnings) != 0 {
		t.Errorf("with a damaged state file: stale %+v, warnings %+v; want both sources stale and no warning", s.Stale, s.Warnings)
	}
	w.serveSpamhaus(lists{tdt.GenDropFile(tdt.GenV4Row, old, 0, 80), tdt.GenDropFile(tdt.GenV6Row, old, 0, 20), tdt.GenDropFile(tdt.GenASNRow, old, 0, 20)})
	if s := source(t, w.update(), threatdata.Spamhaus); s.Outcome != threatdata.Current {
		t.Fatalf("%+v, want current", s)
	}
	sameTime(t, "last_checked", readState(t, w.dir).LastChecked, now)
}

// A last check recorded in the future is no check: it doesn't keep the stale notice away.
func TestLoad_FutureLastCheckedIsNoCheck(t *testing.T) {
	t.Parallel()
	old := now.AddDate(0, 0, -60)
	dir := t.TempDir()
	writeState(t, dir, nil, new(now.AddDate(5, 0, 0)))
	s := aged(t, old, old, old, day(now), day(now)).Load(dir, now)
	if len(s.Stale) != 1 || s.Stale[0].Source != threatdata.Spamhaus {
		t.Errorf("stale %+v, want Spamhaus", s.Stale)
	}
}

// A path that can't be a directory fails both sources before anything is sent.
func TestUpdate_NoDirectory(t *testing.T) {
	t.Parallel()
	for name, dir := range map[string]string{
		"under a file": filepath.Join(writeBlocker(t), "threat-data"),
		"no path":      "",
	} {
		w := newWorld(t)
		w.dir = dir
		r := w.update()
		for _, src := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
			failedWith(t, name, source(t, r, src), clierr.Unexpected, false)
		}
		if got := append(w.spamhaus.requests(), w.ipapi.requests()...); len(got) != 0 {
			t.Errorf("%s: the hosts saw %v, want nothing", name, got)
		}
	}
}

// writeBlocker is a regular file, which nothing can be created under.
func writeBlocker(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A lock that can't be taken fails its source alone.
func TestUpdate_UnusableLock(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	if err := os.MkdirAll(w.path("spamhaus.lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := w.update()
	failedWith(t, "a lock that is a directory", source(t, r, threatdata.Spamhaus), clierr.Unexpected, false, "lock")
	if s := source(t, r, threatdata.Ipapi); s.Outcome != threatdata.Current {
		t.Errorf("ipapi.is: %+v, want current", s)
	}
	if got := w.spamhaus.requests(); len(got) != 0 {
		t.Errorf("Spamhaus saw %v, want nothing", got)
	}
}

// cancelAfter is a client that cancels the update once a request for the URL has been answered.
type cancelAfter struct {
	inner  egress.ThirdPartyHTTP
	suffix string
	cancel context.CancelFunc
}

func (c cancelAfter) Do(ctx context.Context, r egress.ThirdPartyRequest) (egress.ThirdPartyResponse, error) {
	resp, err := c.inner.Do(ctx, r)
	if strings.HasSuffix(r.URL, c.suffix) {
		c.cancel()
	}
	return resp, err
}

// An update cancelled after its last answer arrives but before it has stored anything stores
// nothing.
func TestUpdate_CancelledBeforeStoring(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	sh, _ := w.previous(0o600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := w.options()
	opts.HTTP = cancelAfter{inner: opts.HTTP, suffix: "asndrop.json", cancel: cancel}
	r := threatdata.Update(ctx, opts)
	s := source(t, r, threatdata.Spamhaus)
	if s.Outcome != threatdata.Failed || !strings.Contains(s.Reason, "cancelled") {
		t.Errorf("%+v, want failed, cancelled", s)
	}
	unchanged(t, w.path(spamhausFile), sh)
	if l := inUse(t, w.load(now), spamhaus.ListV4); l.Updated != stamp(d1) {
		t.Errorf("drop_v4 in use: %+v, want the previous copy", l)
	}
}

// A failure in one source leaves the other's update alone, and a source that failed after its first
// list stores nothing.
func TestUpdate_SourcesAreReplacedSeparately(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	w.ipapi.set(pathASNs, reply{status: 500})
	r := w.update()
	if s := source(t, r, threatdata.Spamhaus); s.Outcome != threatdata.Updated {
		t.Errorf("Spamhaus: %+v, want updated", s)
	}
	failedWith(t, "a 500 for the ASNs page", source(t, r, threatdata.Ipapi), clierr.UpstreamError, false, "HTTP 500")
	if _, err := os.Stat(w.path(ipapiData)); !os.IsNotExist(err) {
		t.Errorf("ipapi.json: %v, want none: the networks page alone doesn't make a copy", err)
	}
	if !slices.ContainsFunc(w.load(now).Lists, func(l threatdata.List) bool { return l.Name == spamhaus.ListV4 && l.Downloaded }) {
		t.Error("the new Spamhaus copy isn't in use")
	}
}

// A request interrupted by the update's context fails the source as cancelled, not as a network
// error, and nothing marks it transient.
func TestUpdate_AnInterruptedRequestIsCancelled(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	w.spamhaus.set(pathV4, reply{status: 200, body: newerLists().v4, gate: make(chan struct{})})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if w.spamhaus.asked(pathV4) {
			cancel()
		}
	}()
	s := source(t, w.updateCtx(ctx), threatdata.Spamhaus)
	if s.Outcome != threatdata.Failed || s.Code != clierr.Unexpected || s.Transient || !strings.Contains(s.Reason, "cancelled") {
		t.Errorf("the interrupted source: %+v, want an UNEXPECTED_ERROR that says it was cancelled", s)
	}
}

// Reused lock files must not hide an unwritable update directory; fail before requests.
func TestUpdate_ADirectoryMadeReadOnlyLater(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	w := newWorld(t)
	w.serveNewer()
	w.update()
	before := len(w.spamhaus.requests()) + len(w.ipapi.requests())
	if err := os.Chmod(w.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(w.dir, 0o700) })
	w.now = now.Add(2 * time.Hour)
	r := w.update()
	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		if s := source(t, r, name); s.Outcome != threatdata.Failed || s.Code != clierr.Unexpected || !strings.Contains(s.Reason, "permission denied") {
			t.Errorf("%s: %+v, want an UNEXPECTED_ERROR that gives the reason", name, s)
		}
	}
	if after := len(w.spamhaus.requests()) + len(w.ipapi.requests()); after != before {
		t.Errorf("the read-only update sent %d requests, want none", after-before)
	}
}

// A data file that can't be put in place leaves no temporary file behind.
func TestUpdate_AFailedRenameLeavesNoTemporaryFile(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	w.previous(0o600)
	w.rename = func(string, string) error { return errors.New("injected rename failure") }
	w.update()
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("%s is left in the threat-data directory", e.Name())
		}
	}
}
