package threatdata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/fault"
	"github.com/rafaelh/nyx/internal/sanitize"
	"github.com/rafaelh/nyx/internal/spamhaus"
)

// Options supplies update storage, data and I/O dependencies.
type Options struct {
	Dir     string                // the threat-data directory; see Dir
	HTTP    egress.ThirdPartyHTTP // a client whose sources are SpamhausHost and IpapiHost
	Now     func() time.Time      // nil means time.Now
	NoFsync bool                  // write files without syncing them to disk first
	Timeout time.Duration         // each request's; 0 means 30 s
	BuiltIn *BuiltIn              // nil means the embedded copies

	// Rename injects replacement failures in tests. Nil uses os.Rename.
	Rename func(oldpath, newpath string) error
}

// Outcome classifies source/list update results.
type Outcome string

// The outcomes, as the update's envelope gives them.
const (
	Updated Outcome = "updated" // replaced by the download
	Current Outcome = "current" // already current: the download was dated no later than the copy in use
	Skipped Outcome = "skipped" // not asked: the source answered less than an hour ago
	Failed  Outcome = "failed"
)

// Result preserves source order (Spamhaus, ipapi.is) and list order (drop_v4, drop_v6, asndrop,
// networks, asns).
type Result struct {
	Sources []SourceResult
	Lists   []ListResult
}

// SourceResult is how the update of one source ended.
type SourceResult struct {
	Source  string // Spamhaus or Ipapi
	Outcome Outcome

	// LastContacted is the response time, or the saved time for a skipped source; zero
	// means no response this update. NextUpdate is set for skipped sources and failures
	// after a response, otherwise zero.
	LastContacted, NextUpdate time.Time

	// Copyright and Terms carry sanitised post-update Spamhaus credit; ipapi.is leaves them
	// empty.
	Copyright, Terms string

	// Code/Reason/Transient describe failures with sanitised text and retryability for
	// network, timeout and rate-limit errors.
	Code      clierr.Code
	Reason    string
	Transient bool
}

// ListResult compares the active copy before and after an update. Old and new values differ
// only when a list was replaced.
type ListResult struct {
	List    string
	Source  string
	Outcome Outcome

	OldUpdated, NewUpdated string
	OldEntries, Entries    int
	Added, Removed         int
}

// Update downloads and validates five lists, replacing only newer accepted data. Sources update
// concurrently under separate directory locks; each source bundle is replaced in full or left
// unchanged.
func Update(ctx context.Context, o Options) Result {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	builtIP, _ := o.BuiltIn.ipapiSnapshot()
	srcs := []*srcRun{
		{o: &o, ctx: ctx, src: spamhausSource, op: &spamhausOps{built: o.BuiltIn.spamhausLists()}},
		{o: &o, ctx: ctx, src: ipapiSource, op: &ipapiOps{built: builtIP}},
	}
	runs := make([]sourceRun, len(srcs))
	var wg sync.WaitGroup
	for i, r := range srcs {
		wg.Go(func() { runs[i] = r.execute() })
	}
	wg.Wait()
	var res Result
	for _, r := range runs {
		res.Sources = append(res.Sources, r.source)
		res.Lists = append(res.Lists, r.lists...)
	}
	return res
}

const (
	defaultTimeout = 30 * time.Second
	// rateWindow sets the no-request interval after any response.
	rateWindow = time.Hour
	// lockPoll is how often a waiting update tries a source's lock again.
	lockPoll = 100 * time.Millisecond
)

// failure is why a source's update failed.
type failure struct {
	code   clierr.Code
	reason string
}

func unexpected(format string, args ...any) *failure {
	return &failure{clierr.Unexpected, fmt.Sprintf(format, args...)}
}

// transient reports whether a retry later may succeed.
func (f failure) transient() bool {
	return f.code == clierr.NetworkError || f.code == clierr.Timeout || f.code == clierr.RateLimited
}

// sourceRun is how the update of one source ended.
type sourceRun struct {
	source SourceResult
	lists  []ListResult
}

// source holds provider metadata, file names and list URLs.
type source struct {
	name, stem, file string
	lists, urls      []string
}

var (
	spamhausSource = source{
		name: Spamhaus, stem: stemSpamhaus, file: fileSpamhaus,
		lists: []string{spamhaus.ListV4, spamhaus.ListV6, spamhaus.ListASN},
		urls: []string{
			"https://" + SpamhausHost + "/drop/drop_v4.json",
			"https://" + SpamhausHost + "/drop/drop_v6.json",
			"https://" + SpamhausHost + "/drop/asndrop.json",
		},
	}
	ipapiSource = source{
		name: Ipapi, stem: stemIpapi, file: fileIpapi,
		lists: []string{ListNetworks, ListASNs},
		urls: []string{
			"https://" + IpapiHost + "/most-abusive-networks.html",
			"https://" + IpapiHost + "/most-abusive-asn.html",
		},
	}
)

// sourceOps abstracts source-specific parsing and bundle storage.
type sourceOps interface {
	// prepare reads the previous downloaded copy, once.
	prepare(dir string)
	// unreadable detects existing downloads unusable by Load.
	unreadable() bool
	// hasPrevious reports whether a previous downloaded copy is readable.
	hasPrevious() bool
	// before reads pre-update active metadata and credit.
	before() ([]view, string, string)
	// parse retains one downloaded list and returns its metadata.
	parse(i int, body []byte, now time.Time) (view, error)
	// after constructs the resulting active-list metadata, credit and bundle bytes using
	// the selected downloads.
	after(useDownload []bool) ([]view, string, string, []byte)
}

// srcRun is the update of one source.
type srcRun struct {
	o   *Options
	src source
	op  sourceOps
	ctx context.Context //nolint:containedctx // the run lives for one call

	st        state
	responded time.Time // when a response arrived in this run; zero until one does
}

func (r *srcRun) path(name string) string { return filepath.Join(r.o.Dir, name) }

// execute runs the steps of one source's update.
func (r *srcRun) execute() sourceRun {
	if err := os.MkdirAll(r.o.Dir, 0o700); err != nil {
		return r.fail(unexpected("cannot create the threat-data directory: %v", err))
	}
	release, f := r.lock()
	if f != nil {
		return r.fail(f)
	}
	defer release()
	r.removeTemporaryFiles()

	now := r.o.Now()
	r.st = readState(r.o.Dir, r.src.stem)
	if r.st.LastResponse != nil && r.st.LastResponse.After(now) {
		r.st.LastResponse = &now
	}
	if r.st.LastChecked != nil && r.st.LastChecked.After(now) {
		r.st.LastChecked = &now
	}
	// Persist state before requesting to verify the directory can record contact times.
	if err := r.writeState(); err != nil {
		return r.fail(unexpected("cannot write to %s: %v", r.o.Dir, err))
	}
	if last := r.st.LastResponse; last != nil && now.Before(last.Add(rateWindow)) {
		return r.skipped(*last)
	}

	r.op.prepare(r.o.Dir)
	downloads := make([]view, len(r.src.lists))
	for i, name := range r.src.lists {
		body, f := r.request(i)
		if f != nil {
			return r.fail(f)
		}
		at := r.o.Now()
		v, err := r.op.parse(i, body, at)
		if err == nil {
			err = CheckDate(name, v.date, at)
		}
		if err != nil {
			return r.fail(&failure{clierr.UpstreamError, fmt.Sprintf("%s: refused: %v", name, err)})
		}
		downloads[i] = v
	}
	return r.replace(downloads)
}

// replace waits for a complete source download before choosing and storing replacements.
func (r *srcRun) replace(downloads []view) sourceRun {
	before, copyright, terms := r.op.before()
	forced := r.op.unreadable()
	newer := make([]bool, len(downloads))
	anyNewer := false
	for i, d := range downloads {
		if err := CheckEmpty(d.Name, d.Entries); err != nil {
			return r.fail(&failure{clierr.UpstreamError, "refused: " + err.Error()})
		}
		// Treat corrupt downloads as absent so valid fetched lists can repair the
		// bundle.
		newer[i] = forced || Newer(d.date, before[i].date)
		if !newer[i] {
			continue
		}
		anyNewer = true
		if err := CheckShrink(d.Name, d.Entries, before[i].Entries); err != nil {
			return r.fail(&failure{clierr.UpstreamError, "refused: " + err.Error()})
		}
	}

	after := before
	if anyNewer {
		if r.ctx.Err() != nil {
			return r.fail(cancelled())
		}
		useDownload := make([]bool, len(downloads))
		for i := range useDownload {
			useDownload[i] = newer[i] || !r.op.hasPrevious()
		}
		var data []byte
		after, copyright, terms, data = r.op.after(useDownload)
		if err := r.writeFile(r.src.file, data); err != nil {
			return r.fail(unexpected("cannot store the downloaded %s data: %v", r.src.name, err))
		}
	}
	checked := r.o.Now()
	r.st.LastChecked = &checked
	stateErr := r.writeState()
	if stateErr != nil && !anyNewer {
		return r.fail(unexpected("cannot record the check of %s: %v", r.src.name, stateErr))
	}

	out := sourceRun{source: SourceResult{Source: r.src.name, Outcome: Current, LastContacted: r.responded, Copyright: copyright, Terms: terms}}
	if anyNewer {
		out.source.Outcome = Updated
	}
	for i := range downloads {
		l := listResult(before[i], after[i], Current)
		if newer[i] {
			l.Outcome = Updated
		}
		out.lists = append(out.lists, l)
	}
	if stateErr != nil {
		// Report the newly active data even though recording the successful check
		// failed.
		f := unexpected("the downloaded %s data was replaced, but its check could not be recorded: %v", r.src.name, stateErr)
		out.source.Outcome, out.source.Code, out.source.Reason = Failed, f.code, sanitize.Line(f.reason)
		out.source.NextUpdate = r.responded.Add(rateWindow)
	}
	return out
}

// unchanged describes a list that was left as it was.
func unchanged(v view, outcome Outcome) ListResult {
	return ListResult{List: v.Name, Source: v.Source, Outcome: outcome,
		OldUpdated: v.Updated, NewUpdated: v.Updated, OldEntries: v.Entries, Entries: v.Entries}
}

// listResult compares active copies and counts added/removed entries.
func listResult(before, after view, outcome Outcome) ListResult {
	l := unchanged(before, outcome)
	l.NewUpdated, l.Entries = after.Updated, after.Entries
	old, now := before.keys(), after.keys()
	for k := range now {
		if _, held := old[k]; !held {
			l.Added++
		}
	}
	for k := range old {
		if _, held := now[k]; !held {
			l.Removed++
		}
	}
	return l
}

// skipped reports a source still within its response cooldown.
func (r *srcRun) skipped(last time.Time) sourceRun {
	r.op.prepare(r.o.Dir)
	before, copyright, terms := r.op.before()
	out := sourceRun{source: SourceResult{Source: r.src.name, Outcome: Skipped, LastContacted: last, NextUpdate: last.Add(rateWindow),
		Copyright: copyright, Terms: terms}}
	for _, v := range before {
		out.lists = append(out.lists, unchanged(v, Skipped))
	}
	return out
}

// fail reports a source error while preserving its previous active-list metadata.
func (r *srcRun) fail(f *failure) sourceRun {
	r.op.prepare(r.o.Dir)
	before, copyright, terms := r.op.before()
	out := sourceRun{source: SourceResult{Source: r.src.name, Outcome: Failed, Copyright: copyright, Terms: terms,
		Code: f.code, Reason: sanitize.Line(f.reason), Transient: f.transient()}}
	if !r.responded.IsZero() {
		out.source.LastContacted, out.source.NextUpdate = r.responded, r.responded.Add(rateWindow)
	}
	for _, v := range before {
		out.lists = append(out.lists, unchanged(v, Failed))
	}
	return out
}

func cancelled() *failure { return unexpected("the update was cancelled") }

// lock polls cancellably for the source lock and returns its release function.
func (r *srcRun) lock() (func(), *failure) {
	f, err := os.OpenFile(r.path(r.src.stem+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, unexpected("cannot open the lock for %s: %v", r.src.name, err)
	}
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil // closing the file releases the lock
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			f.Close()
			return nil, unexpected("cannot lock %s: %v", r.src.name, err)
		}
		wait := time.NewTimer(lockPoll)
		select {
		case <-r.ctx.Done():
			wait.Stop()
			f.Close()
			return nil, unexpected("the update was cancelled while it waited for another update of %s to finish", r.src.name)
		case <-wait.C:
		}
	}
}

// removeTemporaryFiles cleans this source's interrupted writes while its lock prevents
// competing writers.
func (r *srcRun) removeTemporaryFiles() {
	entries, err := os.ReadDir(r.o.Dir)
	if err != nil {
		return
	}
	prefix := "." + r.src.stem + "-"
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".tmp") {
			_ = os.Remove(r.path(e.Name()))
		}
	}
}

// writeState writes the state file.
func (r *srcRun) writeState() error {
	b, err := json.Marshal(r.st)
	if err != nil {
		return err
	}
	return r.write(r.src.stem+".state.json", append(b, '\n'), false)
}

// writeFile exposes a crash checkpoint after sync and before the injectable rename.
func (r *srcRun) writeFile(name string, b []byte) error { return r.write(name, b, true) }

// write syncs a temporary file unless disabled, then renames it over the destination for atomic
// replacement.
func (r *srcRun) write(name string, b []byte, point bool) (err error) {
	f, err := os.CreateTemp(r.o.Dir, "."+r.src.stem+"-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if !r.o.NoFsync {
		if err = f.Sync(); err != nil {
			f.Close()
			return err
		}
	}
	if err = f.Close(); err != nil {
		return err
	}
	rename := os.Rename
	if point {
		fault.Point("threat-before-rename")
		if r.o.Rename != nil {
			rename = r.o.Rename
		}
	}
	if err = rename(tmp, r.path(name)); err != nil {
		return err
	}
	if !r.o.NoFsync {
		if d, derr := os.Open(r.o.Dir); derr == nil {
			_ = d.Sync()
			d.Close()
		}
	}
	return nil
}

// request records any HTTP response immediately because it starts the one-hour cooldown. Only a
// 200 returns list data.
func (r *srcRun) request(i int) ([]byte, *failure) {
	name := r.src.lists[i]
	ctx, cancel := context.WithTimeout(r.ctx, r.o.Timeout)
	defer cancel()
	resp, err := r.o.HTTP.Do(ctx, egress.ThirdPartyRequest{Method: "GET", URL: r.src.urls[i], Timeout: r.o.Timeout})
	if err != nil {
		if r.ctx.Err() != nil {
			return nil, cancelled()
		}
		if deadline, _ := ctx.Deadline(); !time.Now().Before(deadline) {
			return nil, &failure{clierr.Timeout, fmt.Sprintf("%s: no answer within %s", name, r.o.Timeout)}
		}
		return nil, &failure{clierr.NetworkError, fmt.Sprintf("%s: %v", name, err)}
	}
	r.responded = r.o.Now()
	r.st.LastResponse = &r.responded
	if err := r.writeState(); err != nil {
		return nil, unexpected("cannot record the response of %s: %v", r.src.name, err)
	}
	fault.Point("threat-after-response")
	switch {
	case resp.Status/100 == 3:
		return nil, &failure{clierr.UpstreamError, fmt.Sprintf("%s: redirected to %s, which nyx does not follow", name, resp.HeaderValue("Location"))}
	case resp.Status == 429:
		return nil, &failure{clierr.RateLimited, fmt.Sprintf("%s: HTTP 429, the source is rate limiting nyx", name)}
	case resp.Status != 200:
		return nil, &failure{clierr.UpstreamError, fmt.Sprintf("%s: HTTP %d", name, resp.Status)}
	case resp.Truncated:
		return nil, &failure{clierr.UpstreamError, fmt.Sprintf("%s: the answer is longer than 10 MiB", name)}
	}
	return resp.Body, nil
}

// spamhausOps is Spamhaus's source.
type spamhausOps struct {
	built spamhaus.Lists

	prepared bool
	prev     *spamhaus.Lists // the previous downloaded copy, when readable
	prevBad  bool            // a previous downloaded copy exists and is unreadable
	down     spamhaus.Lists
}

func (s *spamhausOps) unreadable() bool  { return s.prevBad }
func (s *spamhausOps) hasPrevious() bool { return s.prev != nil }

func (s *spamhausOps) prepare(dir string) {
	if s.prepared {
		return
	}
	s.prepared = true
	l, err := parseSpamhausFile(filepath.Join(dir, fileSpamhaus))
	s.prev, s.prevBad = l, err != nil
}

func (s *spamhausOps) before() ([]view, string, string) {
	use, from := spamhausInUse(s.built, s.prev)
	c, t := credit(use, s.built)
	return spamhausViews(use, from), c, t
}

func (s *spamhausOps) parse(i int, body []byte, _ time.Time) (view, error) {
	switch i {
	case 0, 1:
		l, err := spamhaus.ParseDrop(body, i == 1)
		if err != nil {
			return view{}, err
		}
		if i == 0 {
			s.down.V4 = l
			return netView(spamhaus.ListV4, l, true), nil
		}
		s.down.V6 = l
		return netView(spamhaus.ListV6, l, true), nil
	}
	l, err := spamhaus.ParseASNDrop(body)
	if err != nil {
		return view{}, err
	}
	s.down.ASNs = l
	return asnView(l, true), nil
}

func (s *spamhausOps) after(useDownload []bool) ([]view, string, string, []byte) {
	next := s.down
	if !useDownload[0] {
		next.V4 = s.prev.V4
	}
	if !useDownload[1] {
		next.V6 = s.prev.V6
	}
	if !useDownload[2] {
		next.ASNs = s.prev.ASNs
	}
	use, from := spamhausInUse(s.built, &next)
	c, t := credit(use, s.built)
	return spamhausViews(use, from), c, t, spamhaus.Bundle(next.V4.Raw, next.V6.Raw, next.ASNs.Raw)
}

// ipapiOps is ipapi.is's source.
type ipapiOps struct {
	built abusive.Snapshot

	prepared bool
	prev     *abusive.Snapshot
	prevBad  bool
	down     abusive.Snapshot
}

func (s *ipapiOps) unreadable() bool  { return s.prevBad }
func (s *ipapiOps) hasPrevious() bool { return s.prev != nil }

func (s *ipapiOps) prepare(dir string) {
	if s.prepared {
		return
	}
	s.prepared = true
	l, err := parseIpapiFile(filepath.Join(dir, fileIpapi))
	s.prev, s.prevBad = l, err != nil
}

func (s *ipapiOps) before() ([]view, string, string) {
	use, from := ipapiInUse(s.built, s.prev)
	return ipapiViews(use, from), "", ""
}

func (s *ipapiOps) parse(i int, body []byte, now time.Time) (view, error) {
	if i == 0 {
		l, err := abusive.ParseNetworksPage(body, now)
		if err != nil {
			return view{}, err
		}
		s.down.Nets = l
		return ipapiViews(abusive.Snapshot{Nets: l}, [2]bool{true, false})[0], nil
	}
	l, err := abusive.ParseASNsPage(body, now)
	if err != nil {
		return view{}, err
	}
	s.down.ASNs = l
	return ipapiViews(abusive.Snapshot{ASNs: l}, [2]bool{false, true})[1], nil
}

func (s *ipapiOps) after(useDownload []bool) ([]view, string, string, []byte) {
	next := s.down
	if !useDownload[0] {
		next.Nets = s.prev.Nets
	}
	if !useDownload[1] {
		next.ASNs = s.prev.ASNs
	}
	use, from := ipapiInUse(s.built, &next)
	return ipapiViews(use, from), "", "", abusive.Marshal(next)
}
