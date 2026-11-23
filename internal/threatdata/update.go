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

// Options is what an update needs.
type Options struct {
	Dir     string                // the threat-data directory; see Dir
	HTTP    egress.ThirdPartyHTTP // a client whose sources are SpamhausHost and IpapiHost
	Now     func() time.Time      // nil means time.Now
	NoFsync bool                  // write files without syncing them to disk first
	Timeout time.Duration         // each request's; 0 means 30 s
	BuiltIn *BuiltIn              // nil means the embedded copies
}

// Outcome is how an update ended for a source or a list.
type Outcome string

// The outcomes, as the update's envelope gives them.
const (
	Updated Outcome = "updated" // replaced by the download
	Current Outcome = "current" // already current: the download was dated no later than the copy in use
	Skipped Outcome = "skipped" // not asked: the source answered less than an hour ago
	Failed  Outcome = "failed"
)

// Result is what an update did: each source, in the order Spamhaus, ipapi.is, and each of the
// five lists, in the order drop_v4, drop_v6, asndrop, networks, asns.
type Result struct {
	Sources []SourceResult
	Lists   []ListResult
}

// SourceResult is how the update of one source ended.
type SourceResult struct {
	Source  string // Spamhaus or Ipapi
	Outcome Outcome

	// LastContacted is the last time the source sent an HTTP response, or zero when none is
	// recorded. NextUpdate is when it can next be updated: set when it was skipped, and when it
	// failed after a response; otherwise zero.
	LastContacted, NextUpdate time.Time

	// Copyright and Terms are Spamhaus's credit, as Set gives it after the update; "" for ipapi.is.
	Copyright, Terms string

	// Code, Reason and Transient describe a failure: Transient is set for NETWORK_ERROR, TIMEOUT
	// and RATE_LIMITED.
	Code      clierr.Code
	Reason    string
	Transient bool
}

// ListResult is how the update of one list ended. The Old fields describe the copy in use before
// the update and the others the copy in use after it; they are equal unless the list was replaced.
type ListResult struct {
	List    string
	Source  string
	Outcome Outcome

	OldUpdated, NewUpdated string
	OldEntries, Entries    int
	Added, Removed         int
}

// Update downloads the five lists and replaces each source's downloaded copy that passes the
// acceptance rules and is newer than the copy in use. The two sources are updated concurrently,
// each under its own lock in dir, and each is replaced as a whole or not at all.
func Update(ctx context.Context, o Options) Result {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	builtIP, _ := o.BuiltIn.ipapiSnapshot()
	ops := []sourceOps{&spamhausOps{built: o.BuiltIn.spamhausLists()}, &ipapiOps{built: builtIP}}
	runs := make([]sourceRun, len(ops))
	var wg sync.WaitGroup
	for i, op := range ops {
		wg.Go(func() { runs[i] = (&srcRun{o: &o, op: op, ctx: ctx}).execute() })
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
	// rateWindow is how long after a source's last response an update sends it nothing.
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

// sourceOps is what differs between the two sources: the lists, their formats and how the
// downloaded copy is kept.
type sourceOps interface {
	name() string
	stem() string
	listNames() []string
	urls() []string
	// prepare reads the previous downloaded copy, once.
	prepare(dir string)
	// unreadable reports whether a previous downloaded copy exists and can't be used.
	unreadable() bool
	// hasPrevious reports whether a previous downloaded copy is readable.
	hasPrevious() bool
	// before describes the lists in use, and the credit, before the update.
	before() ([]view, string, string)
	// parse reads the download of list i, keeping it, and describes it.
	parse(i int, body []byte, now time.Time) (view, error)
	// after describes the lists in use, and the credit, once the download of each list for which
	// useDownload is set replaces the previous downloaded one, and gives the data file's bytes.
	after(useDownload []bool) ([]view, string, string, []byte)
	// file is the data file's name.
	file() string
}

// srcRun is the update of one source.
type srcRun struct {
	o   *Options
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
	r.st = readState(r.o.Dir, r.op.stem())
	if r.st.LastResponse != nil && r.st.LastResponse.After(now) {
		r.st.LastResponse = &now
	}
	if r.st.LastChecked != nil && r.st.LastChecked.After(now) {
		r.st.LastChecked = &now
	}
	// Writing the state back, unchanged or with the fix above, proves the directory is writable
	// before anything is sent.
	if err := r.writeState(); err != nil {
		return r.fail(unexpected("cannot write to %s: %v", r.o.Dir, err))
	}
	if last := r.st.LastResponse; last != nil && now.Before(last.Add(rateWindow)) {
		return r.skipped(*last)
	}

	r.op.prepare(r.o.Dir)
	downloads := make([]view, len(r.op.listNames()))
	for i, name := range r.op.listNames() {
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

// replace decides, once every list of the source has arrived, which downloads replace the copy in
// use, and stores them.
func (r *srcRun) replace(downloads []view) sourceRun {
	before, copyright, terms := r.op.before()
	forced := r.op.unreadable()
	newer := make([]bool, len(downloads))
	anyNewer := false
	for i, d := range downloads {
		if err := CheckEmpty(d.Name, d.Entries); err != nil {
			return r.fail(&failure{clierr.UpstreamError, "refused: " + err.Error()})
		}
		// An unreadable copy counts as absent, so every list replaces the built-in one.
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
		if err := r.writeFile(r.op.file(), data); err != nil {
			return r.fail(unexpected("cannot store the downloaded %s data: %v", r.op.name(), err))
		}
	}
	checked := r.o.Now()
	r.st.LastChecked = &checked
	if err := r.writeState(); err != nil {
		return r.fail(unexpected("cannot record the check of %s: %v", r.op.name(), err))
	}

	out := sourceRun{source: SourceResult{Source: r.op.name(), Outcome: Current, LastContacted: r.responded, Copyright: copyright, Terms: terms}}
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
	return out
}

// unchanged describes a list that was left as it was.
func unchanged(v view, outcome Outcome) ListResult {
	return ListResult{List: v.Name, Source: v.Source, Outcome: outcome,
		OldUpdated: v.Updated, NewUpdated: v.Updated, OldEntries: v.Entries, Entries: v.Entries}
}

// listResult describes a list that went from the copy in use before to the one after, counting the
// entries that were added and removed.
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

// skipped is the result of a source that answered within the hour.
func (r *srcRun) skipped(last time.Time) sourceRun {
	before, copyright, terms := r.op.before()
	out := sourceRun{source: SourceResult{Source: r.op.name(), Outcome: Skipped, LastContacted: last, NextUpdate: last.Add(rateWindow),
		Copyright: copyright, Terms: terms}}
	for _, v := range before {
		out.lists = append(out.lists, unchanged(v, Skipped))
	}
	return out
}

// fail is the result of a source that failed. Its lists are left as they were.
func (r *srcRun) fail(f *failure) sourceRun {
	r.op.prepare(r.o.Dir)
	before, copyright, terms := r.op.before()
	out := sourceRun{source: SourceResult{Source: r.op.name(), Outcome: Failed, Copyright: copyright, Terms: terms,
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

// lock takes the source's lock, polling until the context ends: a blocking flock can't be
// cancelled. The returned function releases it.
func (r *srcRun) lock() (func(), *failure) {
	f, err := os.OpenFile(r.path(r.op.stem()+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, unexpected("cannot open the lock for %s: %v", r.op.name(), err)
	}
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil // closing the file releases the lock
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			f.Close()
			return nil, unexpected("cannot lock %s: %v", r.op.name(), err)
		}
		wait := time.NewTimer(lockPoll)
		select {
		case <-r.ctx.Done():
			wait.Stop()
			f.Close()
			return nil, unexpected("the update was cancelled while it waited for another update of %s to finish", r.op.name())
		case <-wait.C:
		}
	}
}

// removeTemporaryFiles removes what an interrupted update of this source left behind. It is safe
// because only the holder of the source's lock writes them.
func (r *srcRun) removeTemporaryFiles() {
	entries, err := os.ReadDir(r.o.Dir)
	if err != nil {
		return
	}
	prefix := "." + r.op.stem() + "-"
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
	return r.write(r.op.stem()+".state.json", append(b, '\n'), false)
}

// writeFile writes a data file, with the fault point between its sync and its rename.
func (r *srcRun) writeFile(name string, b []byte) error { return r.write(name, b, true) }

// write puts the file in place: it is written to a temporary file, synced (unless the options say
// not) and renamed over the old one, so a reader sees the old file or the whole new one.
func (r *srcRun) write(name string, b []byte, point bool) (err error) {
	f, err := os.CreateTemp(r.o.Dir, "."+r.op.stem()+"-*.tmp")
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
	if point {
		if err = fault.Err(r.ctx, "threat-before-rename"); err != nil {
			return err
		}
	}
	if err = os.Rename(tmp, r.path(name)); err != nil {
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

// request asks for list i and returns the body of a 200. A response of any status is recorded at
// once, as it starts the hour.
func (r *srcRun) request(i int) ([]byte, *failure) {
	name := r.op.listNames()[i]
	ctx, cancel := context.WithTimeout(r.ctx, r.o.Timeout)
	defer cancel()
	resp, err := r.o.HTTP.Do(ctx, egress.ThirdPartyRequest{Method: "GET", URL: r.op.urls()[i], Timeout: r.o.Timeout})
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
		return nil, unexpected("cannot record the response of %s: %v", r.op.name(), err)
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

var spamhausURLs = []string{
	"https://" + SpamhausHost + "/drop/drop_v4.json",
	"https://" + SpamhausHost + "/drop/drop_v6.json",
	"https://" + SpamhausHost + "/drop/asndrop.json",
}

func (s *spamhausOps) name() string { return Spamhaus }
func (s *spamhausOps) stem() string { return stemSpamhaus }
func (s *spamhausOps) listNames() []string {
	return []string{spamhaus.ListV4, spamhaus.ListV6, spamhaus.ListASN}
}
func (s *spamhausOps) urls() []string    { return spamhausURLs }
func (s *spamhausOps) file() string      { return fileSpamhaus }
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
	var next spamhaus.Lists
	next.V4, next.V6, next.ASNs = s.down.V4, s.down.V6, s.down.ASNs
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

var ipapiURLs = []string{
	"https://" + IpapiHost + "/most-abusive-networks.html",
	"https://" + IpapiHost + "/most-abusive-asn.html",
}

func (s *ipapiOps) name() string        { return Ipapi }
func (s *ipapiOps) stem() string        { return stemIpapi }
func (s *ipapiOps) listNames() []string { return []string{ListNetworks, ListASNs} }
func (s *ipapiOps) urls() []string      { return ipapiURLs }
func (s *ipapiOps) file() string        { return fileIpapi }
func (s *ipapiOps) unreadable() bool    { return s.prevBad }
func (s *ipapiOps) hasPrevious() bool   { return s.prev != nil }

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
