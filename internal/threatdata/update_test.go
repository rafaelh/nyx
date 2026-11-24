package threatdata_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

var (
	spamhausPaths = []string{pathV4, pathV6, pathASN}
	ipapiPaths    = []string{pathNetworks, pathASNs}
)

// gets is the requests a fake expects for the paths.
func gets(paths ...string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, "GET "+p)
	}
	return out
}

// newerLists is a Spamhaus download dated d2, with the standard entries.
func newerLists() lists {
	return lists{dropFile(v4Row, d2, 0, 80), dropFile(v6Row, d2, 0, 20), dropFile(asnRow, d2, 0, 20)}
}

// serveNewer makes both fakes answer lists dated d2, newer than every copy in use.
func (w *world) serveNewer() {
	w.serveSpamhaus(newerLists())
	w.serveIpapi(day(d2), 80, 0, 80, day(d2), 20, 0, 20)
}

// previous writes a readable downloaded copy of both sources, dated d1, with the given mode.
func (w *world) previous(mode os.FileMode) (fileSnap, fileSnap) {
	w.t.Helper()
	writeFile(w.t, w.dir, spamhausFile, bundle(dropFile(v4Row, d1, 0, 80), dropFile(v6Row, d1, 0, 20), dropFile(asnRow, d1, 0, 20)), mode)
	writeFile(w.t, w.dir, ipapiData, ipapiFile(w.t, snapshot(day(d1), 0, 80, day(d1), 0, 20)), mode)
	return snap(w.t, w.path(spamhausFile)), snap(w.t, w.path(ipapiData))
}

// failedWith fails the test unless the source failed with the code, the transient flag and a
// reason holding each of the texts.
func failedWith(t *testing.T, what string, s threatdata.SourceResult, code clierr.Code, transient bool, reason ...string) {
	t.Helper()
	if s.Outcome != threatdata.Failed || s.Code != code || s.Transient != transient {
		t.Errorf("%s: %s %s %s transient=%v (%q), want failed %s transient=%v", what, s.Source, s.Outcome, s.Code, s.Transient, s.Reason, code, transient)
	}
	if s.Reason == "" {
		t.Errorf("%s: %s failed with no reason", what, s.Source)
	}
	for _, r := range reason {
		if !strings.Contains(s.Reason, r) {
			t.Errorf("%s: %s's reason %q doesn't contain %q", what, s.Source, s.Reason, r)
		}
	}
}

// Updates GET each list once with a 30-second timeout; equal dates remain current.
func TestUpdate_AsksForEachListOnce(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	r := w.update()
	got := w.rec.seen()
	urls := w.rec.urls()
	if !slices.Equal(slices.Sorted(slices.Values(urls)), slices.Sorted(slices.Values(fiveURLs))) {
		t.Errorf("requests %v, want one for each of %v", urls, fiveURLs)
	}
	for _, s := range got {
		if s.method != "GET" {
			t.Errorf("%s was asked with %s, want GET", s.url, s.method)
		}
		if s.timeout != 30*time.Second {
			t.Errorf("%s: the request's timeout is %v, want 30s", s.url, s.timeout)
		}
		if s.deadline <= 25*time.Second || s.deadline > 30*time.Second {
			t.Errorf("%s: the request's context has %v left, want a 30s deadline of its own", s.url, s.deadline)
		}
	}
	// Each source's lists are asked for in order.
	if got := w.spamhaus.requests(); !slices.Equal(got, gets(spamhausPaths...)) {
		t.Errorf("Spamhaus saw %v, want %v", got, gets(spamhausPaths...))
	}
	if got := w.ipapi.requests(); !slices.Equal(got, gets(ipapiPaths...)) {
		t.Errorf("ipapi.is saw %v, want %v", got, gets(ipapiPaths...))
	}
	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		if s := source(t, r, name); s.Outcome != threatdata.Current {
			t.Errorf("%s: %s (%s), want current", name, s.Outcome, s.Reason)
		}
	}
}

// Verify source/list result dates, counts and added/removed totals.
func TestUpdate_ReportsEachList(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	const newCopyright = "(c) 2027 The Spamhaus Project SLU"
	v4 := file(append(rows(v4Row, 3, 87), strings.Replace(metaLine(d2, 87), copyright, newCopyright, 1))...) // -0,1,2 +80..89
	w.serveSpamhaus(lists{v4, dropFile(v6Row, d0, 0, 20), dropFile(asnRow, d0.Add(-time.Hour), 0, 20)})
	w.serveIpapi(day(d2), 90, 0, 90, day(d2), 18, 2, 18)
	r := w.update()

	if len(r.Sources) != 2 || r.Sources[0].Source != threatdata.Spamhaus || r.Sources[1].Source != threatdata.Ipapi {
		t.Fatalf("sources %+v, want Spamhaus and then ipapi.is", r.Sources)
	}
	wantSources := []threatdata.SourceResult{
		{Source: threatdata.Spamhaus, Outcome: threatdata.Updated, LastContacted: now, Copyright: newCopyright, Terms: terms},
		{Source: threatdata.Ipapi, Outcome: threatdata.Updated, LastContacted: now},
	}
	for i, want := range wantSources {
		got := r.Sources[i]
		if got.Source != want.Source || got.Outcome != want.Outcome || !got.LastContacted.Equal(want.LastContacted) ||
			!got.NextUpdate.IsZero() || got.Copyright != want.Copyright || got.Terms != want.Terms ||
			got.Code != "" || got.Reason != "" || got.Transient {
			t.Errorf("source %d = %+v\nwant %+v", i, got, want)
		}
	}
	want := []threatdata.ListResult{
		{List: spamhaus.ListV4, Source: threatdata.Spamhaus, Outcome: threatdata.Updated, OldUpdated: stamp(d0), NewUpdated: stamp(d2), OldEntries: 80, Entries: 87, Added: 10, Removed: 3},
		{List: spamhaus.ListV6, Source: threatdata.Spamhaus, Outcome: threatdata.Current, OldUpdated: stamp(d0), NewUpdated: stamp(d0), OldEntries: 20, Entries: 20},
		{List: spamhaus.ListASN, Source: threatdata.Spamhaus, Outcome: threatdata.Current, OldUpdated: stamp(d0), NewUpdated: stamp(d0), OldEntries: 20, Entries: 20},
		{List: threatdata.ListNetworks, Source: threatdata.Ipapi, Outcome: threatdata.Updated, OldUpdated: day(d0), NewUpdated: day(d2), OldEntries: 80, Entries: 90, Added: 10},
		{List: threatdata.ListASNs, Source: threatdata.Ipapi, Outcome: threatdata.Updated, OldUpdated: day(d0), NewUpdated: day(d2), OldEntries: 20, Entries: 18, Removed: 2},
	}
	if !slices.Equal(r.Lists, want) {
		t.Errorf("lists\n%+v\nwant\n%+v", r.Lists, want)
	}

	// The new copy is in use, and a list that wasn't newer is the download or the built-in one, by
	// date.
	s := w.load(now)
	if l := inUse(t, s, spamhaus.ListV4); !l.Downloaded || l.Updated != stamp(d2) || l.Entries != 87 {
		t.Errorf("drop_v4 in use: %+v", l)
	}
	if l := inUse(t, s, spamhaus.ListASN); l.Downloaded {
		t.Errorf("asndrop in use: %+v, want the built-in copy, dated later", l)
	}
	if l := inUse(t, s, threatdata.ListASNs); !l.Downloaded || l.Entries != 18 {
		t.Errorf("asns in use: %+v", l)
	}
	if s.Copyright != newCopyright {
		t.Errorf("credit in use %q, want %q", s.Copyright, newCopyright)
	}
}

// Stop a source after its first failure without retries, continue the other source and start
// cooldown on any response.
func TestUpdate_AFailureStopsItsSource(t *testing.T) {
	t.Parallel()
	malformed := file(append(append(rows(v4Row, 0, 79), `{"cidr":"10.250.0.0/24","sblid"`), metaLine(d2, 80))...)
	big := bytes.Repeat([]byte(v4Row(1)+"\n"), 10<<20/len(v4Row(1))+100)
	for _, c := range []struct {
		name      string
		src       string
		path      string
		reply     reply
		code      clierr.Code
		transient bool
		reason    []string
	}{
		{"a 500 for drop_v4", threatdata.Spamhaus, pathV4, reply{status: 500}, clierr.UpstreamError, false, []string{"HTTP 500"}},
		{"a 404 for drop_v6", threatdata.Spamhaus, pathV6, reply{status: 404}, clierr.UpstreamError, false, []string{"HTTP 404"}},
		{"a 503 for asndrop", threatdata.Spamhaus, pathASN, reply{status: 503}, clierr.UpstreamError, false, []string{"HTTP 503"}},
		{"a 500 for the networks page", threatdata.Ipapi, pathNetworks, reply{status: 500}, clierr.UpstreamError, false, []string{"HTTP 500"}},
		{"a 429 for drop_v4", threatdata.Spamhaus, pathV4, reply{status: 429, header: map[string]string{"Retry-After": "60"}}, clierr.RateLimited, true, nil},
		{"a 429 for the ASNs page", threatdata.Ipapi, pathASNs, reply{status: 429}, clierr.RateLimited, true, nil},
		{"a 301 to the same host", threatdata.Spamhaus, pathV4,
			reply{status: 301, header: map[string]string{"Location": "https://www.spamhaus.org/drop/v2/drop_v4.json"}}, clierr.UpstreamError, false,
			[]string{"redirected to https://www.spamhaus.org/drop/v2/drop_v4.json", "which nyx does not follow"}},
		{"a 302 to another host", threatdata.Ipapi, pathNetworks,
			reply{status: 302, header: map[string]string{"Location": "https://elsewhere.example/networks.html"}}, clierr.UpstreamError, false,
			[]string{"redirected to https://elsewhere.example/networks.html", "which nyx does not follow"}},
		{"a refused drop_v4", threatdata.Spamhaus, pathV4, ok(malformed), clierr.UpstreamError, false, nil},
		{"a body cut at 10 MiB", threatdata.Spamhaus, pathV4, ok(big), clierr.UpstreamError, false, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			fk, paths, other, otherPaths := w.spamhaus, spamhausPaths, w.ipapi, ipapiPaths
			if c.src == threatdata.Ipapi {
				fk, paths, other, otherPaths = w.ipapi, ipapiPaths, w.spamhaus, spamhausPaths
			}
			fk.set(c.path, c.reply)
			r := w.update()
			upTo := paths[:slices.Index(paths, c.path)+1]
			if got := fk.requests(); !slices.Equal(got, gets(upTo...)) {
				t.Errorf("%s saw %v, want %v", c.src, got, gets(upTo...))
			}
			if got := other.requests(); !slices.Equal(got, gets(otherPaths...)) {
				t.Errorf("the other source saw %v, want %v", got, gets(otherPaths...))
			}
			s := source(t, r, c.src)
			failedWith(t, c.name, s, c.code, c.transient, c.reason...)
			if !s.LastContacted.Equal(now) || !s.NextUpdate.Equal(now.Add(time.Hour)) {
				t.Errorf("last contacted %v, next update %v; want %v and an hour later", s.LastContacted, s.NextUpdate, now)
			}
			onlyFailed(t, r, c.src)
		})
	}
}

// onlyFailed fails the test unless the source's lists failed, unchanged, and the other source is
// current.
func onlyFailed(t *testing.T, r threatdata.Result, src string) {
	t.Helper()
	for _, l := range r.Lists {
		if l.Source == src && (l.Outcome != threatdata.Failed || l.OldUpdated != l.NewUpdated || l.OldEntries != l.Entries) {
			t.Errorf("list %+v, want failed and unchanged", l)
		}
	}
	for _, o := range r.Sources {
		if o.Source != src && o.Outcome != threatdata.Current {
			t.Errorf("the other source: %+v, want current", o)
		}
	}
}

// allSkipped fails the test unless both sources and all their lists were skipped, last contacted
// at contacted.
func allSkipped(t *testing.T, r threatdata.Result, contacted time.Time) {
	t.Helper()
	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		s := source(t, r, name)
		if s.Outcome != threatdata.Skipped || !s.LastContacted.Equal(contacted) || !s.NextUpdate.Equal(contacted.Add(time.Hour)) || s.Code != "" {
			t.Errorf("%s: %+v, want skipped, last contacted %v, next update an hour later", name, s, contacted)
		}
	}
	for _, l := range r.Lists {
		if l.Outcome != threatdata.Skipped || l.OldUpdated != l.NewUpdated || l.OldEntries != l.Entries || l.Added != 0 || l.Removed != 0 {
			t.Errorf("list %+v, want skipped and unchanged", l)
		}
	}
}

// Use the update's request timeout even with shorter base egress settings. No response means no
// cooldown.
func TestUpdate_Timeout(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.timeout = 1500 * time.Millisecond // above the egress HTTPTimeout of 1 s
	w.spamhaus.set(pathV4, reply{status: 200, body: newerLists().v4, stall: 3 * time.Second})
	start := time.Now()
	r := w.update()
	if took := time.Since(start); took < 1400*time.Millisecond || took > 2900*time.Millisecond {
		t.Errorf("the update took %v, want it to give up at the 1.5s timeout", took)
	}
	s := source(t, r, threatdata.Spamhaus)
	failedWith(t, "a stalled drop_v4", s, clierr.Timeout, true)
	if !s.LastContacted.IsZero() || !s.NextUpdate.IsZero() {
		t.Errorf("last contacted %v, next update %v; want neither", s.LastContacted, s.NextUpdate)
	}
	if got := w.spamhaus.requests(); !slices.Equal(got, gets(pathV4)) {
		t.Errorf("Spamhaus saw %v, want only drop_v4", got)
	}
	if st := readState(t, w.dir); st.LastResponse != nil {
		t.Errorf("last_response = %v, want none", st.LastResponse)
	}
	for _, s := range w.rec.seen() {
		if s.timeout != 1500*time.Millisecond {
			t.Errorf("%s: the request's timeout is %v, want the update's 1.5s", s.url, s.timeout)
		}
	}
}

// Network failures without responses preserve immediate retry eligibility.
func TestUpdate_NoResponse(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + ln.Addr().String()
	ln.Close()

	t.Run("a refused connection", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		w.eopts.SourceBaseURLs[threatdata.SpamhausHost] = closed
		r := w.update()
		s := source(t, r, threatdata.Spamhaus)
		failedWith(t, "a refused connection", s, clierr.NetworkError, true)
		if !s.LastContacted.IsZero() || !s.NextUpdate.IsZero() {
			t.Errorf("last contacted %v, next update %v; want neither", s.LastContacted, s.NextUpdate)
		}
		if got := w.rec.urls(); slices.Contains(got, fiveURLs[1]) {
			t.Errorf("drop_v6 was asked for after drop_v4 failed: %v", got)
		}
		if st := readState(t, w.dir); st.LastResponse != nil {
			t.Errorf("last_response = %v, want none", st.LastResponse)
		}
		w.now = now.Add(10 * time.Minute)
		r = w.update()
		if got := w.rec.urls(); !slices.Contains(got, fiveURLs[0]) {
			t.Errorf("10 minutes later, the update asked for %v; want drop_v4 again", got)
		}
		if s := source(t, r, threatdata.Spamhaus); s.Outcome == threatdata.Skipped {
			t.Errorf("10 minutes later: %+v, want it not skipped", s)
		}
	})

	t.Run("a failed DNS lookup", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		w.client = failing{err: errors.New("Get \"https://www.spamhaus.org/drop/drop_v4.json\": dial tcp: lookup www.spamhaus.org: no such host")}
		r := w.update()
		for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
			s := source(t, r, name)
			failedWith(t, "a failed lookup", s, clierr.NetworkError, true)
			if !s.LastContacted.IsZero() || !s.NextUpdate.IsZero() {
				t.Errorf("%s: last contacted %v, next update %v; want neither", name, s.LastContacted, s.NextUpdate)
			}
		}
		if got := w.rec.urls(); len(got) != 2 {
			t.Errorf("requests %v, want only each source's first", got)
		}
		w.now = now.Add(10 * time.Minute)
		w.update()
		if got := w.rec.urls(); len(got) != 2 {
			t.Errorf("10 minutes later, the update asked for %v; want each source's first list again", got)
		}
	})
}

// Any response starts an inclusive one-hour cooldown with last/next timestamps in skipped
// results.
func TestUpdate_WithinTheHourIsSkipped(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		setup func(w *world)
	}{
		{"after a 500 from each", func(w *world) {
			w.spamhaus.set(pathV4, reply{status: 500})
			w.ipapi.set(pathNetworks, reply{status: 500})
		}},
		{"after each was current", func(*world) {}},
		{"after each was updated", func(w *world) { w.serveNewer() }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			c.setup(w)
			w.update()
			before := len(w.spamhaus.requests()) + len(w.ipapi.requests())

			w.now = now.Add(time.Hour - time.Second)
			r := w.update()
			if after := len(w.spamhaus.requests()) + len(w.ipapi.requests()); after != before {
				t.Errorf("an update 59m59s later sent %d requests, want none", after-before)
			}
			if got := w.rec.seen(); len(got) != 0 {
				t.Errorf("an update 59m59s later asked for %v", got)
			}
			allSkipped(t, r, now)
			// Skipped lists report the active copy, including downloaded metadata
			// when selected.
			for i, in := range w.load(w.now).Lists {
				if l := r.Lists[i]; l.NewUpdated != in.Updated || l.Entries != in.Entries {
					t.Errorf("skipped %s: %s, %d entries; want the copy in use's %s, %d", l.List, l.NewUpdated, l.Entries, in.Updated, in.Entries)
				}
			}

			w.now = now.Add(time.Hour)
			r = w.update()
			if got := w.spamhaus.count(pathV4); got != 2 {
				t.Errorf("an hour later, drop_v4 has been asked for %d times, want 2", got)
			}
			if got := w.ipapi.count(pathNetworks); got != 2 {
				t.Errorf("an hour later, the networks page has been asked for %d times, want 2", got)
			}
			if s := source(t, r, threatdata.Spamhaus); s.Outcome == threatdata.Skipped {
				t.Errorf("an hour later: %+v, want it not skipped", s)
			}
		})
	}
}

// Clamp future contact times to now so cooldown cannot extend indefinitely.
func TestUpdate_FutureLastResponse(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	writeState(t, w.dir, new(now.AddDate(1, 0, 0)), nil)
	r := w.update()
	s := source(t, r, threatdata.Spamhaus)
	if s.Outcome != threatdata.Skipped || !s.LastContacted.Equal(now) || !s.NextUpdate.Equal(now.Add(time.Hour)) {
		t.Errorf("%+v, want skipped, last contacted now and next update in an hour", s)
	}
	sameTime(t, "last_response on disk", readState(t, w.dir).LastResponse, now)
	if got := w.spamhaus.requests(); len(got) != 0 {
		t.Errorf("Spamhaus saw %v, want nothing", got)
	}
	w.now = now.Add(59 * time.Minute)
	if s := source(t, w.update(), threatdata.Spamhaus); s.Outcome != threatdata.Skipped {
		t.Errorf("59 minutes later: %+v, want skipped", s)
	}
	w.now = now.Add(time.Hour)
	w.update()
	if got := w.spamhaus.requests(); !slices.Equal(got, gets(spamhausPaths...)) {
		t.Errorf("an hour later, Spamhaus saw %v, want %v", got, gets(spamhausPaths...))
	}
}

// Clamp future check times so stale notices cannot be hidden beyond 30 days.
func TestUpdate_FutureLastChecked(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	old := now.AddDate(0, 0, -60)
	w.builtIn = aged(t, old, old, old, day(now), day(now))
	writeState(t, w.dir, new(now.Add(-10*time.Minute)), new(now.AddDate(5, 0, 0)))
	if s := source(t, w.update(), threatdata.Spamhaus); s.Outcome != threatdata.Skipped {
		t.Fatalf("%+v, want skipped", s)
	}
	sameTime(t, "last_checked on disk", readState(t, w.dir).LastChecked, now)
	if s := w.load(now.AddDate(0, 0, 30)); slices.ContainsFunc(s.Stale, func(n threatdata.Notice) bool { return n.Source == threatdata.Spamhaus }) {
		t.Errorf("30 days later: stale %+v, want Spamhaus not among them", s.Stale)
	}
	s := w.load(now.AddDate(0, 0, 31))
	if !slices.ContainsFunc(s.Stale, func(n threatdata.Notice) bool { return n.Source == threatdata.Spamhaus }) {
		t.Errorf("31 days later: stale %+v, want Spamhaus among them", s.Stale)
	}
}

// Record responses immediately; record successful checks only after the source finishes.
func TestUpdate_RecordsTheState(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.update()
	st := readState(t, w.dir)
	sameTime(t, "last_response after a current source", st.LastResponse, now)
	sameTime(t, "last_checked after a current source", st.LastChecked, now)

	w = newWorld(t)
	w.spamhaus.set(pathV6, reply{status: 500})
	w.update()
	st = readState(t, w.dir)
	sameTime(t, "last_response after a 500", st.LastResponse, now)
	if st.LastChecked != nil {
		t.Errorf("last_checked after a 500 = %v, want none", st.LastChecked)
	}
}

// Per-source locks serialise concurrent updates so each list is requested once.
func TestUpdate_TwoAtOnce(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	gate := make(chan struct{})
	w.spamhaus.set(pathV4, reply{status: 200, body: newerLists().v4, gate: gate})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	first, second := w.options(), w.options()
	var opened sync.Once
	open := func() { opened.Do(func() { close(gate) }) }
	defer open()

	var r1, r2 threatdata.Result
	var wg sync.WaitGroup
	wg.Go(func() { r1 = threatdata.Update(ctx, first) })
	w.spamhaus.waitFor(t, pathV4)
	wg.Go(func() { r2 = threatdata.Update(ctx, second) })
	time.Sleep(300 * time.Millisecond) // the second is now waiting on Spamhaus's lock
	open()
	wg.Wait()

	if got := w.spamhaus.requests(); !slices.Equal(got, gets(spamhausPaths...)) {
		t.Errorf("Spamhaus saw %v, want each list once", got)
	}
	if got := w.ipapi.requests(); !slices.Equal(got, gets(ipapiPaths...)) {
		t.Errorf("ipapi.is saw %v, want each list once", got)
	}
	if s := source(t, r1, threatdata.Spamhaus); s.Outcome != threatdata.Updated {
		t.Errorf("the first update: %+v, want Spamhaus updated", s)
	}
	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		if s := source(t, r2, name); s.Outcome != threatdata.Skipped || !s.LastContacted.Equal(now) {
			t.Errorf("the second update: %+v, want %s skipped, last contacted by the first", s, name)
		}
	}
}

// An update waiting on a source's lock stops waiting when its context ends, and sends nothing.
func TestUpdate_LockWaitEndsWithTheContext(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	gate := make(chan struct{})
	w.spamhaus.set(pathV4, reply{status: 200, body: newerLists().v4, gate: gate})
	first, second := w.options(), w.options()
	var opened sync.Once
	open := func() { opened.Do(func() { close(gate) }) }
	defer open()

	var r1 threatdata.Result
	var wg sync.WaitGroup
	wg.Go(func() { r1 = threatdata.Update(context.Background(), first) })
	w.spamhaus.waitFor(t, pathV4)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	r2 := threatdata.Update(ctx, second)
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("the waiting update took %v to end after its context did", took)
	}
	if got := w.spamhaus.requests(); !slices.Equal(got, gets(pathV4)) {
		t.Errorf("Spamhaus saw %v, want only the first update's drop_v4", got)
	}
	s := source(t, r2, threatdata.Spamhaus)
	if s.Outcome == threatdata.Updated || s.Outcome == threatdata.Current || s.Outcome == threatdata.Skipped {
		t.Errorf("the cancelled update: %+v, want it neither done nor skipped", s)
	}
	open()
	wg.Wait()
	if s := source(t, r1, threatdata.Spamhaus); s.Outcome != threatdata.Updated {
		t.Errorf("the first update: %+v, want Spamhaus updated", s)
	}
}

// The two sources are updated at the same time.
func TestUpdate_SourcesRunConcurrently(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	gateS, gateI := make(chan struct{}), make(chan struct{})
	w.spamhaus.set(pathV4, reply{status: 200, body: newerLists().v4, gate: gateS})
	w.ipapi.set(pathNetworks, reply{status: 200, body: networksPage(day(d2), 80, 0, 80), gate: gateI})
	var both atomic.Bool
	go func() {
		defer close(gateS)
		defer close(gateI)
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			if w.spamhaus.count(pathV4) > 0 && w.ipapi.count(pathNetworks) > 0 {
				both.Store(true)
				return
			}
		}
	}()
	r := w.update()
	if !both.Load() {
		t.Error("the sources' first requests were never in flight together")
	}
	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		if s := source(t, r, name); s.Outcome != threatdata.Updated {
			t.Errorf("%s: %+v, want updated", name, s)
		}
	}
}

// Older/equal data stays unchanged while a successful check is still recorded.
func TestUpdate_AlreadyCurrent(t *testing.T) {
	t.Parallel()
	t.Run("against the built-in copy", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		// The same dates with other entries, and an older drop_v6.
		w.serveSpamhaus(lists{dropFile(v4Row, d0, 50, 80), dropFile(v6Row, d0.Add(-time.Second), 50, 20), dropFile(asnRow, d0, 50, 20)})
		w.serveIpapi(day(d0), 80, 50, 80, day(d0.AddDate(0, 0, -3)), 20, 50, 20)
		r := w.update()
		for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
			if s := source(t, r, name); s.Outcome != threatdata.Current || !s.LastContacted.Equal(now) || !s.NextUpdate.IsZero() {
				t.Errorf("%s: %+v, want current, last contacted now", name, s)
			}
		}
		for _, l := range r.Lists {
			if l.Outcome != threatdata.Current || l.OldUpdated != l.NewUpdated || l.OldEntries != l.Entries || l.Added != 0 || l.Removed != 0 {
				t.Errorf("list %+v, want current and unchanged", l)
			}
		}
		for _, name := range []string{spamhausFile, ipapiData} {
			if _, err := os.Stat(w.path(name)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s: %v, want no downloaded copy", name, err)
			}
		}
		sameTime(t, "last_checked", readState(t, w.dir).LastChecked, now)
	})
	t.Run("against a downloaded copy", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		sh, ip := w.previous(0o644)
		w.serveSpamhaus(lists{dropFile(v4Row, d1, 50, 30), dropFile(v6Row, d0, 50, 20), dropFile(asnRow, d1, 50, 20)})
		w.serveIpapi(day(d1), 80, 50, 80, day(d0), 20, 50, 20)
		r := w.update()
		for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
			if s := source(t, r, name); s.Outcome != threatdata.Current {
				t.Errorf("%s: %+v, want current", name, s)
			}
		}
		unchanged(t, w.path(spamhausFile), sh)
		unchanged(t, w.path(ipapiData), ip)
		if l := list(t, r, spamhaus.ListV4); l.OldUpdated != stamp(d1) || l.NewUpdated != stamp(d1) || l.Entries != 80 {
			t.Errorf("drop_v4: %+v, want the downloaded copy's date and count, unchanged", l)
		}
		sameTime(t, "last_checked", readState(t, w.dir).LastChecked, now)
	})
}

// Update only newer lists within a bundle, retaining other downloaded versions.
func TestUpdate_OneNewerList(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	prevV4, prevV6, prevASN := dropFile(v4Row, d1, 0, 80), dropFile(v6Row, d1, 0, 20), dropFile(asnRow, d1, 0, 20)
	writeFile(t, w.dir, spamhausFile, bundle(prevV4, prevV6, prevASN), 0o600)
	writeFile(t, w.dir, ipapiData, ipapiFile(t, snapshot(day(d1), 0, 80, day(d1), 0, 20)), 0o600)
	newV4 := dropFile(v4Row, d2, 5, 80)
	w.serveSpamhaus(lists{newV4, dropFile(v6Row, d1, 300, 20), dropFile(asnRow, d0, 300, 20)})
	w.serveIpapi(day(d2), 81, 0, 81, day(d1), 20, 300, 20)

	r := w.update()
	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		if s := source(t, r, name); s.Outcome != threatdata.Updated {
			t.Errorf("%s: %+v, want updated", name, s)
		}
	}
	for name, want := range map[string]threatdata.Outcome{
		spamhaus.ListV4: threatdata.Updated, spamhaus.ListV6: threatdata.Current, spamhaus.ListASN: threatdata.Current,
		threatdata.ListNetworks: threatdata.Updated, threatdata.ListASNs: threatdata.Current,
	} {
		if got := list(t, r, name); got.Outcome != want {
			t.Errorf("%s: %+v, want %s", name, got, want)
		}
	}
	if l := list(t, r, spamhaus.ListV4); l.Added != 5 || l.Removed != 5 || l.OldUpdated != stamp(d1) || l.NewUpdated != stamp(d2) {
		t.Errorf("drop_v4: %+v, want +5 -5 from the downloaded copy", l)
	}
	got, err := os.ReadFile(w.path(spamhausFile))
	if err != nil {
		t.Fatal(err)
	}
	if want := bundle(newV4, prevV6, prevASN); !bytes.Equal(got, want) {
		t.Errorf("the downloaded copy is\n%s\nwant the new drop_v4 and the previous drop_v6 and asndrop, as they were:\n%s", got, want)
	}
	s := w.load(now)
	if s.Abusive == nil {
		t.Fatal("no ipapi.is lists to match")
	}
	if l := inUse(t, s, threatdata.ListASNs); !l.Downloaded || l.Updated != day(d1) || len(s.Abusive.ASN(ipapiASN(0))) != 1 || len(s.Abusive.ASN(ipapiASN(300))) != 0 {
		t.Errorf("asns in use: %+v; want the previous downloaded copy", l)
	}
	if l := inUse(t, s, threatdata.ListNetworks); l.Updated != day(d2) || l.Entries != 81 {
		t.Errorf("networks in use: %+v; want the download", l)
	}
}

// A valid download replaces corrupt stored data even when no newer than embedded data, clearing
// fallback warnings.
func TestUpdate_ReplacesAnUnreadableCopy(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		date time.Time
	}{
		{"with the built-in copy's date", d0},
		{"older than the built-in copy", d0.AddDate(0, 0, -1)},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			good := bundle(dropFile(v4Row, d1, 0, 80), dropFile(v6Row, d1, 0, 20), dropFile(asnRow, d1, 0, 20))
			writeFile(t, w.dir, spamhausFile, good[:len(good)/2], 0o600)
			writeFile(t, w.dir, ipapiData, []byte(`{"networks":`), 0o600)
			if s := w.load(now); len(s.Warnings) != 2 {
				t.Fatalf("before the update: warnings %+v, want one for each source", s.Warnings)
			}
			w.serveSpamhaus(lists{dropFile(v4Row, c.date, 0, 80), dropFile(v6Row, c.date, 0, 20), dropFile(asnRow, c.date, 0, 20)})
			w.serveIpapi(day(c.date), 80, 0, 80, day(c.date), 20, 0, 20)
			r := w.update()
			for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
				if s := source(t, r, name); s.Outcome != threatdata.Updated {
					t.Errorf("%s: %+v, want updated", name, s)
				}
			}
			s := w.load(now)
			if len(s.Warnings) != 0 {
				t.Errorf("after the update: warnings %+v, want none", s.Warnings)
			}
			if c.date.Equal(d0) {
				for _, l := range s.Lists {
					if !l.Downloaded {
						t.Errorf("%s in use: %+v, want the download, of the built-in copy's date", l.Name, l)
					}
				}
			}
		})
	}
}

// Rejected data stops its source and preserves previous bytes/permissions.
func TestUpdate_Refusals(t *testing.T) {
	t.Parallel()
	endOfTomorrow := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC) // now is 2026-11-01 12:00 UTC
	v4With := func(extra ...string) []byte {
		return file(append(append(rows(v4Row, 0, 79), extra...), metaLine(d2, 79+len(extra)))...)
	}
	cases := []refusal{
		{name: "a malformed row", v4: v4With(`{"cidr":"10.250.0.0/24","sblid"`), at: pathV4},
		{name: "a row that isn't JSON", v4: v4With(`cidr=10.250.0.0/24`), at: pathV4},
		{name: "a missing cidr", v4: v4With(`{"sblid":"SBL9","rir":"arin"}`), at: pathV4},
		{name: "a missing sblid", v4: v4With(`{"cidr":"10.250.0.0/24","rir":"arin"}`), at: pathV4},
		{name: "a missing asn", asn: file(append(append(rows(asnRow, 0, 19), `{"rir":"arin","domain":"x.example","cc":"US","asname":"X"}`), metaLine(d2, 20))...), at: pathASN},
		{name: "a non-canonical CIDR", v4: v4With(`{"cidr":"10.250.0.1/24","sblid":"SBL9","rir":"arin"}`), at: pathV4},
		{name: "an IPv6 CIDR in drop_v4", v4: v4With(`{"cidr":"2001:db8:ffff::/48","sblid":"SBL9","rir":"arin"}`), at: pathV4},
		{name: "an IPv4 CIDR in drop_v6", v6: file(append(append(rows(v6Row, 0, 19), `{"cidr":"10.250.0.0/24","sblid":"SBL9","rir":"arin"}`), metaLine(d2, 20))...), at: pathV6},
		{name: "a control character in a row", v4: v4With(`{"cidr":"10.250.0.0/24","sblid":"SBL\u0007","rir":"arin"}`), at: pathV4},
		{name: "a control character in the metadata", v4: file(append(rows(v4Row, 0, 80), strings.Replace(metaLine(d2, 80), copyright, `(c) \u0007`, 1))...), at: pathV4},
		{name: "an identical pair twice", v4: v4With(v4Row(5)), at: pathV4},
		{name: "no metadata line", v4: file(rows(v4Row, 0, 80)...), at: pathV4},
		{name: "89% of the records it states", v4: file(append(rows(v4Row, 0, 89), metaLine(d2, 100))...), at: pathV4},
		{name: "zero entries", v4: file(metaLine(d2, 0)), at: pathV4, compared: true},
		{name: "under half the entries in use", v4: dropFile(v4Row, d2, 0, 39), at: pathV4, compared: true,
			reason: []string{"half", "39", "80", "a newer build of nyx"}},
		{name: "dated at the end of tomorrow", v4: dropFile(v4Row, endOfTomorrow, 0, 80), at: pathV4},
		{name: "a networks page that doesn't parse", netPage: []byte(`<html><body><p>Down for maintenance</p></body></html>`), at: pathNetworks},
		{name: "a networks page with 89% of the entries it states", netPage: networksPage(day(d2), 100, 0, 89), at: pathNetworks},
		{name: "a networks page under half the entries in use", netPage: networksPage(day(d2), 39, 0, 39), at: pathNetworks, compared: true,
			reason: []string{"half", "39", "80", "a newer build of nyx"}},
		{name: "an ASNs page with no entries", asnPage: asnsPage(day(d2), 0, 0, 0), at: pathASNs},
		{name: "a networks page dated after tomorrow", netPage: networksPage("2026-11-03", 80, 0, 80), at: pathNetworks},

		{name: "an unknown field", v4: v4With(`{"cidr":"10.250.0.0/24","sblid":"SBL9","rir":"arin","listed":"2026-10-01"}`)},
		{name: "one CIDR under two SBL IDs", v4: v4With(`{"cidr":"10.0.5.0/24","sblid":"SBL999999","rir":"ripencc"}`)},
		{name: "90% of the records it states", v4: file(append(rows(v4Row, 0, 90), metaLine(d2, 100))...)},
		{name: "exactly half the entries in use", v4: dropFile(v4Row, d2, 0, 40)},
		{name: "dated just before the end of tomorrow", v4: dropFile(v4Row, endOfTomorrow.Add(-time.Second), 0, 80)},
		{name: "a networks page dated tomorrow", netPage: networksPage("2026-11-02", 80, 0, 80)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			checkRefusal(t, c)
		})
	}
}

// refusal is a case of TestUpdate_Refusals: the lists or pages that differ from a valid download
// dated d2.
type refusal struct {
	name    string
	v4, v6  []byte
	asn     []byte
	netPage []byte
	asnPage []byte
	at      string // the path refused; "" when the download passes
	reason  []string
	// Comparison-based rejections may wait for the full source bundle, so later lists may
	// already have been requested.
	compared bool
}

// checkRefusal runs one case of TestUpdate_Refusals.
func checkRefusal(t *testing.T, c refusal) {
	t.Helper()
	w := newWorld(t)
	sh, ip := w.previous(0o644)
	n := newerLists()
	w.serveSpamhaus(lists{cmpOr(c.v4, n.v4), cmpOr(c.v6, n.v6), cmpOr(c.asn, n.asn)})
	w.ipapi.set(pathNetworks, ok(cmpOr(c.netPage, networksPage(day(d2), 80, 0, 80))))
	w.ipapi.set(pathASNs, ok(cmpOr(c.asnPage, asnsPage(day(d2), 20, 0, 20))))
	r := w.update()

	src, fk, paths, data, before := threatdata.Spamhaus, w.spamhaus, spamhausPaths, spamhausFile, sh
	if slices.Contains(ipapiPaths, c.at) || c.netPage != nil || c.asnPage != nil {
		src, fk, paths, data, before = threatdata.Ipapi, w.ipapi, ipapiPaths, ipapiData, ip
	}
	s := source(t, r, src)
	if c.at == "" {
		if s.Outcome != threatdata.Updated {
			t.Errorf("%s: %+v, want updated", src, s)
		}
		if got := snap(t, w.path(data)); got.mode.Perm() != 0o600 || bytes.Equal(got.b, before.b) {
			t.Errorf("%s: mode %v, changed=%v; want a new copy of mode 0600", data, got.mode, !bytes.Equal(got.b, before.b))
		}
		return
	}
	failedWith(t, c.name, s, clierr.UpstreamError, false, c.reason...)
	unchanged(t, w.path(data), before)
	upTo := gets(paths[:slices.Index(paths, c.at)+1]...)
	if got := fk.requests(); !slices.Equal(got, upTo) && (!c.compared || !slices.Equal(got, gets(paths...))) {
		t.Errorf("%s saw %v, want %v", src, got, upTo)
	}
	first := spamhaus.ListV4
	if src == threatdata.Ipapi {
		first = threatdata.ListNetworks
	}
	if l := w.load(now); len(l.Warnings) != 0 || !inUse(t, l, first).Downloaded {
		t.Errorf("after the refusal: %+v, warnings %v; want the previous downloaded copy in use", l.Lists, l.Warnings)
	}
}

func cmpOr(b, otherwise []byte) []byte {
	if b != nil {
		return b
	}
	return otherwise
}

// An update creates the directory for the owner alone, and every file in it is the owner's alone.
func TestUpdate_CreatesAPrivateDirectory(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	if _, err := os.Stat(w.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the directory exists before the update: %v", err)
	}
	r := w.update()
	for _, s := range r.Sources {
		if s.Outcome != threatdata.Updated {
			t.Errorf("%s: %+v, want updated", s.Source, s)
		}
	}
	fi, err := os.Stat(w.dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("the directory's mode is %v, want 0700", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, e.Name())
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s's mode is %v, want 0600", e.Name(), info.Mode().Perm())
		}
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("a temporary file is left: %s", e.Name())
		}
	}
	for _, want := range []string{spamhausFile, ipapiData, spamhausSt} {
		if !slices.Contains(names, want) {
			t.Errorf("the directory holds %v, want %s among them", names, want)
		}
	}
}

// Detect unwritable storage before requests because responses need persistent contact records.
func TestUpdate_ReadOnlyDirectory(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	w := newWorld(t)
	w.serveNewer()
	sh, ip := w.previous(0o600)
	if err := os.Chmod(w.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(w.dir, 0o700) })
	r := w.update()
	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		s := source(t, r, name)
		failedWith(t, "a read-only directory", s, clierr.Unexpected, false, "permission denied")
		if !s.LastContacted.IsZero() || !s.NextUpdate.IsZero() {
			t.Errorf("%s: last contacted %v, next update %v; want neither", name, s.LastContacted, s.NextUpdate)
		}
	}
	if got := append(w.spamhaus.requests(), w.ipapi.requests()...); len(got) != 0 {
		t.Errorf("the hosts saw %v, want nothing", got)
	}
	unchanged(t, w.path(spamhausFile), sh)
	unchanged(t, w.path(ipapiData), ip)
}

// Replacement failure preserves previous data and records the received response with an
// unexpected-error result.
func TestUpdate_StoreFailure(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	sh, ip := w.previous(0o600)
	w.rename = func(string, string) error { return errors.New("injected rename failure") }
	r := w.update()
	w.rename = nil
	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		s := source(t, r, name)
		failedWith(t, "a failed rename", s, clierr.Unexpected, false, "injected rename failure")
		if !s.LastContacted.Equal(now) || !s.NextUpdate.Equal(now.Add(time.Hour)) {
			t.Errorf("%s: last contacted %v, next update %v; want now and an hour later", name, s.LastContacted, s.NextUpdate)
		}
	}
	unchanged(t, w.path(spamhausFile), sh)
	unchanged(t, w.path(ipapiData), ip)
	sameTime(t, "last_response", readState(t, w.dir).LastResponse, now)
	if s := w.load(now); len(s.Warnings) != 0 || !inUse(t, s, spamhaus.ListV4).Downloaded || inUse(t, s, spamhaus.ListV4).Updated != stamp(d1) {
		t.Errorf("after the failure: %+v, warnings %v; want the previous copy in use", s.Lists, s.Warnings)
	}
	// Both responses were recorded, so both sources are now within the hour.
	w.now = now.Add(30 * time.Minute)
	r = w.update()
	for _, name := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
		if s := source(t, r, name); s.Outcome != threatdata.Skipped {
			t.Errorf("30 minutes later, %s: %+v, want skipped", name, s)
		}
	}
}

// An update interrupted part way through a source leaves its previous copy in place.
func TestUpdate_InterruptedLeavesThePreviousCopy(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.serveNewer()
	sh, _ := w.previous(0o600)
	w.spamhaus.set(pathV6, reply{status: 200, body: newerLists().v6, gate: make(chan struct{})})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	asked := make(chan bool, 1)
	go func() {
		asked <- w.spamhaus.asked(pathV6)
		cancel()
	}()
	r := w.updateCtx(ctx)
	if !<-asked {
		t.Fatal("drop_v6 was never asked for")
	}
	if s := source(t, r, threatdata.Spamhaus); s.Outcome == threatdata.Updated || s.Outcome == threatdata.Current {
		t.Errorf("the interrupted source: %+v, want it not done", s)
	}
	unchanged(t, w.path(spamhausFile), sh)
	if got := w.spamhaus.count(pathASN); got != 0 {
		t.Errorf("asndrop was asked for %d times after the interruption", got)
	}
}

// A temporary file an interrupted update left behind is removed by the next update of its
// source, whatever that update does.
func TestUpdate_RemovesStaleTemporaryFiles(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name  string
		setup func(w *world)
	}{
		{"an update that finds it current", func(*world) {}},
		{"an update that is skipped", func(w *world) { writeState(t, w.dir, new(now.Add(-time.Minute)), nil) }},
		{"an update that fails", func(w *world) { w.spamhaus.set(pathV4, reply{status: 500}) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			writeFile(t, w.dir, ".spamhaus-x.tmp", bundle(dropFile(v4Row, d1, 100, 80), dropFile(v6Row, d1, 100, 20), dropFile(asnRow, d1, 100, 20)), 0o600)
			c.setup(w)
			w.update()
			if _, err := os.Stat(w.path(".spamhaus-x.tmp")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf(".spamhaus-x.tmp after the update: %v, want it removed", err)
			}
		})
	}
}

// Concurrent readers see complete old/new source bundles, never partial or mixed writes.
func TestUpdate_LoadDuringUpdates(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	const versions = 12
	done := make(chan struct{})
	var reads atomic.Int64
	var wg sync.WaitGroup
	var torn atomic.Value
	wg.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			s := w.load(now)
			reads.Add(1)
			if problem := version(s); problem != "" {
				torn.Store(problem)
				return
			}
		}
	})
	for k := 1; k <= versions; k++ {
		w.serveSpamhaus(lists{dropFile(v4Row, d0.Add(time.Duration(k)*time.Hour), 0, 80+k),
			dropFile(v6Row, d0.Add(time.Duration(k)*time.Hour), 0, 20+k), dropFile(asnRow, d0.Add(time.Duration(k)*time.Hour), 0, 20+k)})
		kd := day(d0.AddDate(0, 0, k))
		w.serveIpapi(kd, 80+k, 0, 80+k, kd, 20+k, 0, 20+k)
		w.now = now.Add(time.Duration(k) * 2 * time.Hour)
		r := w.update()
		for _, s := range r.Sources {
			if s.Outcome != threatdata.Updated {
				t.Errorf("version %d: %s %+v, want updated", k, s.Source, s)
			}
		}
	}
	close(done)
	wg.Wait()
	if p := torn.Load(); p != nil {
		t.Errorf("a read during the updates: %s", p)
	}
	if reads.Load() == 0 {
		t.Error("no read ran during the updates")
	}
	if p := version(w.load(now)); p != "" {
		t.Errorf("after the updates: %s", p)
	}
}

// version checks all lists agree on their encoded fixture generation, returning a reason when
// they do not.
func version(s threatdata.Set) string {
	if len(s.Warnings) != 0 {
		return fmt.Sprintf("warnings %+v", s.Warnings)
	}
	if len(s.Lists) != 5 {
		return fmt.Sprintf("lists %+v", s.Lists)
	}
	base := []int{80, 20, 20, 80, 20}
	k := s.Lists[0].Entries - base[0]
	for i, l := range s.Lists[:3] {
		want := stamp(d0.Add(time.Duration(k) * time.Hour))
		if l.Entries-base[i] != k || l.Updated != want || l.Downloaded != (k > 0) {
			return fmt.Sprintf("Spamhaus is a mix: %+v", s.Lists[:3])
		}
	}
	k = s.Lists[3].Entries - base[3]
	for i, l := range s.Lists[3:] {
		want := day(d0.AddDate(0, 0, k))
		if l.Entries-base[3+i] != k || l.Updated != want || l.Downloaded != (k > 0) {
			return fmt.Sprintf("ipapi.is is a mix: %+v", s.Lists[3:])
		}
	}
	return ""
}
