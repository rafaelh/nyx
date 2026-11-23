package threatdata_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// now is the clock of these tests. The built-in copies they use are their own (d0, 20 days
// earlier), never the embedded ones, whose dates move with each refresh.
var (
	now = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	d0  = now.AddDate(0, 0, -20) // the built-in copies' date
	d1  = d0.AddDate(0, 0, 1)    // a downloaded copy already in place
	d2  = d0.AddDate(0, 0, 2)    // a download, newer than both
)

// day is t's UTC date as ipapi.is lists are dated.
func day(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// stamp is t as a Spamhaus list's date is written.
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// The credit the generated Spamhaus files carry, as Spamhaus's own do.
const (
	copyright = "(c) 2026 The Spamhaus Project SLU"
	terms     = "https://www.spamhaus.org/drop/terms/"
)

// The paths of the five lists on their hosts, and their full URLs.
const (
	pathV4       = "/drop/drop_v4.json"
	pathV6       = "/drop/drop_v6.json"
	pathASN      = "/drop/asndrop.json"
	pathNetworks = "/most-abusive-networks.html"
	pathASNs     = "/most-abusive-asn.html"
)

var fiveURLs = []string{
	"https://www.spamhaus.org/drop/drop_v4.json",
	"https://www.spamhaus.org/drop/drop_v6.json",
	"https://www.spamhaus.org/drop/asndrop.json",
	"https://ipapi.is/most-abusive-networks.html",
	"https://ipapi.is/most-abusive-asn.html",
}

// v4Row, v6Row and asnRow are entry i of a generated list, in the format Spamhaus serves.
func v4Row(i int) string {
	return fmt.Sprintf(`{"cidr":"10.%d.%d.0/24","sblid":"SBL%d","rir":"ripencc"}`, i/256, i%256, 100000+i)
}

func v6Row(i int) string {
	return fmt.Sprintf(`{"cidr":"2001:db8:%x::/48","sblid":"SBL%d","rir":"apnic"}`, i, 200000+i)
}

func asnRow(i int) string {
	return fmt.Sprintf(`{"asn":%d,"rir":"arin","domain":"bad%d.example","cc":"US","asname":"BAD-AS-%d"}`, 64500+i, i, i)
}

// v4Addr, v6Addr and asnOf are an address entry i holds, and entry i's AS number.
func v4Addr(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("10.%d.%d.7", i/256, i%256)) }
func v6Addr(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::7", i)) }
func asnOf(i int) int         { return 64500 + i }

// rows is entries from to from+n-1 of a list.
func rows(row func(int) string, from, n int) []string {
	out := make([]string, 0, n)
	for i := from; i < from+n; i++ {
		out = append(out, row(i))
	}
	return out
}

// metaLine is a Spamhaus metadata line.
func metaLine(date time.Time, records int) string {
	return fmt.Sprintf(`{"type":"metadata","timestamp":%d,"size":1234,"records":%d,"copyright":%q,"terms":%q}`,
		date.Unix(), records, copyright, terms)
}

// file is a Spamhaus file: the lines, each ending in a newline.
func file(lines ...string) []byte {
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// dropFile is a generated list of entries from to from+n-1, dated date, that states n records.
func dropFile(row func(int) string, date time.Time, from, n int) []byte {
	return file(append(rows(row, from, n), metaLine(date, n))...)
}

// bundle is a downloaded Spamhaus copy as nyx keeps it: each file after its marker line.
func bundle(v4, v6, asn []byte) []byte { return spamhaus.Bundle(v4, v6, asn) }

// netEntry and asEntry are entry i of a generated ipapi.is list, in the snapshot format.
func netEntry(i int) abusive.NetworkEntry {
	return abusive.NetworkEntry{Rank: i + 1, Start: netip.MustParseAddr(fmt.Sprintf("172.%d.%d.0", 16+i/200, i%200)),
		End: netip.MustParseAddr(fmt.Sprintf("172.%d.%d.255", 16+i/200, i%200)), ScoreTag: "High", AbuseScore: 50, Org: fmt.Sprintf("Org %d", i), OrgType: "isp"}
}

func asEntry(i int) abusive.ASNEntry {
	return abusive.ASNEntry{Rank: i + 1, ASN: 65000 + i, ScoreTag: "High", AbuseScore: 50, Org: fmt.Sprintf("AS Org %d", i), OrgType: "isp"}
}

func netAddr(i int) netip.Addr {
	return netip.MustParseAddr(fmt.Sprintf("172.%d.%d.9", 16+i/200, i%200))
}
func ipapiASN(i int) int { return 65000 + i }

// snapshot is an ipapi.is copy of networks from..from+nn-1 and ASNs from..from+an-1.
func snapshot(netsDate string, nFrom, nn int, asnsDate string, aFrom, an int) abusive.Snapshot {
	s := abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: netsDate, Stated: nn, Entries: []abusive.NetworkEntry{}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: asnsDate, Stated: an, Entries: []abusive.ASNEntry{}},
	}
	for i := nFrom; i < nFrom+nn; i++ {
		s.Nets.Entries = append(s.Nets.Entries, netEntry(i))
	}
	for i := aFrom; i < aFrom+an; i++ {
		s.ASNs.Entries = append(s.ASNs.Entries, asEntry(i))
	}
	return s
}

// ipapiFile is a downloaded ipapi.is copy as nyx keeps it: the snapshot file's JSON.
func ipapiFile(t *testing.T, s abusive.Snapshot) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// headerOrg is the organisation column's header as ipapi.is spells it.
const headerOrg = "Organization" //nolint:misspell // the page's own spelling

func pageDate(d string) string {
	t, _ := time.Parse(time.DateOnly, d)
	return t.Format("January 2, 2006")
}

// networksPage is ipapi.is's most-abusive networks page, dated d, stating stated entries and
// listing networks from..from+n-1.
func networksPage(d string, stated, from, n int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><span>Data last updated on <strong>%s</strong></span><p>The table lists the <strong>%d</strong> most abusive networks on the Internet.</p>`, pageDate(d), stated)
	b.WriteString(`<table><thead><tr><th>Rank</th><th>Network</th><th>Num Hosts</th><th>Score Tag</th><th>Abuse Score</th><th>` + headerOrg + `</th><th>Type</th></tr></thead><tbody>`)
	for i := from; i < from+n; i++ {
		e := netEntry(i)
		fmt.Fprintf(&b, `<tr><td>%d</td><td><a>%s - %s</a></td><td>256</td><td><span>High</span></td><td>50%%</td><td>%s</td><td><span>isp</span></td></tr>`,
			e.Rank, e.Start, e.End, e.Org)
	}
	b.WriteString(`</tbody></table></body></html>`)
	return []byte(b.String())
}

// asnsPage is ipapi.is's most-abusive ASNs page, dated d, stating stated entries and listing ASNs
// from..from+n-1.
func asnsPage(d string, stated, from, n int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><span>Data last updated on <strong>%s</strong></span><p>The table lists the <strong>%d</strong> most abusive ASNs.</p>`, pageDate(d), stated)
	b.WriteString(`<table><thead><tr><th>Rank</th><th>ASN</th><th>Num IPs and Routes</th><th>Score Tag</th><th>Abuse Score</th><th>` + headerOrg + `</th><th>Org Type</th></tr></thead><tbody>`)
	for i := from; i < from+n; i++ {
		e := asEntry(i)
		fmt.Fprintf(&b, `<tr><td>%d</td><td><a>as%d</a></td><td>1</td><td><span>High</span></td><td>50%%</td><td>%s</td><td><span>isp</span></td></tr>`, e.Rank, e.ASN, e.Org)
	}
	b.WriteString(`</tbody></table></body></html>`)
	return []byte(b.String())
}

// lists is a built-in copy of the three Spamhaus lists, parsed from the generated files.
type lists struct{ v4, v6, asn []byte }

// stdSpamhaus is the standard built-in Spamhaus copy: 80, 20 and 20 entries, all dated d0.
func stdSpamhaus() lists {
	return lists{dropFile(v4Row, d0, 0, 80), dropFile(v6Row, d0, 0, 20), dropFile(asnRow, d0, 0, 20)}
}

// stdIpapi is the standard built-in ipapi.is copy: 80 networks and 20 ASNs, both dated d0.
func stdIpapi() abusive.Snapshot { return snapshot(day(d0), 0, 80, day(d0), 0, 20) }

// builtIn parses a built-in copy, failing the test if the parse does.
func builtIn(t *testing.T, sh lists, ip abusive.Snapshot) *threatdata.BuiltIn {
	t.Helper()
	v4, err := spamhaus.ParseDrop(sh.v4, false)
	if err != nil {
		t.Fatalf("the built-in drop_v4: %v", err)
	}
	v6, err := spamhaus.ParseDrop(sh.v6, true)
	if err != nil {
		t.Fatalf("the built-in drop_v6: %v", err)
	}
	asn, err := spamhaus.ParseASNDrop(sh.asn)
	if err != nil {
		t.Fatalf("the built-in asndrop: %v", err)
	}
	return &threatdata.BuiltIn{Spamhaus: spamhaus.Lists{V4: v4, V6: v6, ASNs: asn}, Ipapi: ip}
}

// The files nyx keeps in the threat-data directory.
const (
	spamhausFile = "spamhaus.jsonl"
	ipapiData    = "ipapi.json"
	spamhausSt   = "spamhaus.state.json"
)

func writeFile(t *testing.T, dir, name string, b []byte, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // past the umask
		t.Fatal(err)
	}
}

// state is a source's state file.
type state struct {
	LastResponse *time.Time `json:"last_response"`
	LastChecked  *time.Time `json:"last_checked"`
}

func readState(t *testing.T, dir string) state {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, spamhausSt))
	if err != nil {
		t.Fatalf("reading Spamhaus's state: %v", err)
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatalf("Spamhaus's state %q: %v", b, err)
	}
	return s
}

// writeState writes Spamhaus's state file; a nil time is null.
func writeState(t *testing.T, dir string, lastResponse, lastChecked *time.Time) {
	t.Helper()
	b, err := json.Marshal(state{LastResponse: lastResponse, LastChecked: lastChecked})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, spamhausSt, b, 0o600)
}

// sameTime fails the test unless got is set and is want.
func sameTime(t *testing.T, what string, got *time.Time, want time.Time) {
	t.Helper()
	if got == nil || !got.Equal(want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

// fileSnap is a file's bytes and mode, to show it was left alone.
type fileSnap struct {
	b    []byte
	mode fs.FileMode
}

func snap(t *testing.T, path string) fileSnap {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fileSnap{b, fi.Mode()}
}

func unchanged(t *testing.T, path string, before fileSnap) {
	t.Helper()
	after := snap(t, path)
	if !bytes.Equal(after.b, before.b) {
		t.Errorf("%s changed:\n%s\nwas:\n%s", filepath.Base(path), after.b, before.b)
	}
	if after.mode != before.mode {
		t.Errorf("%s's mode changed to %v from %v", filepath.Base(path), after.mode, before.mode)
	}
}

// reply is a fake host's answer to one path. gate, when set, holds the answer until it is closed;
// stall holds it for that long. Either ends early when the request does.
type reply struct {
	status int
	header map[string]string
	body   []byte
	gate   chan struct{}
	stall  time.Duration
}

func ok(body []byte) reply { return reply{status: 200, body: body} }

// fake is one source's host. It answers each path from its routes and records every request.
type fake struct {
	srv *httptest.Server

	mu     sync.Mutex
	routes map[string]reply
	hits   []string // "GET /path", in order
}

func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{routes: map[string]reply{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits = append(f.hits, r.Method+" "+r.URL.Path)
	rp, found := f.routes[r.URL.Path]
	f.mu.Unlock()
	if !found {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if rp.gate != nil {
		select {
		case <-rp.gate:
		case <-r.Context().Done():
			return
		}
	}
	if rp.stall > 0 {
		select {
		case <-time.After(rp.stall):
		case <-r.Context().Done():
			return
		}
	}
	for k, v := range rp.header {
		w.Header().Set(k, v)
	}
	w.WriteHeader(rp.status)
	_, _ = w.Write(rp.body)
}

func (f *fake) set(path string, r reply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[path] = r
}

func (f *fake) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hits...)
}

// count is the number of requests for path.
func (f *fake) count(path string) int {
	n := 0
	for _, h := range f.requests() {
		if h == "GET "+path {
			n++
		}
	}
	return n
}

// waitFor waits until path has been asked for, failing the test after five seconds. It must be
// called from the test's goroutine.
func (f *fake) waitFor(t *testing.T, path string) {
	t.Helper()
	if !f.asked(path) {
		t.Fatalf("%s was never asked for", path)
	}
}

// asked waits up to five seconds for path to be asked for, and reports whether it was.
func (f *fake) asked(path string) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if f.count(path) > 0 {
			return true
		}
	}
	return false
}

// seen is one request the update made through its client.
type seen struct {
	url, method string
	timeout     time.Duration // ThirdPartyRequest.Timeout
	deadline    time.Duration // the context's time left when the request was made; 0 when none
}

// recorder records every request an update makes, and passes it on.
type recorder struct {
	inner egress.ThirdPartyHTTP
	mu    sync.Mutex
	reqs  []seen
}

func (r *recorder) Do(ctx context.Context, req egress.ThirdPartyRequest) (egress.ThirdPartyResponse, error) {
	s := seen{url: req.URL, method: req.Method, timeout: req.Timeout}
	if d, has := ctx.Deadline(); has {
		s.deadline = time.Until(d)
	}
	r.mu.Lock()
	r.reqs = append(r.reqs, s)
	r.mu.Unlock()
	return r.inner.Do(ctx, req)
}

func (r *recorder) seen() []seen {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]seen(nil), r.reqs...)
}

func (r *recorder) urls() []string {
	var out []string
	for _, s := range r.seen() {
		out = append(out, s.url)
	}
	return out
}

// failing is a client whose every request fails with err, as egress reports a request that got no
// response.
type failing struct{ err error }

func (f failing) Do(context.Context, egress.ThirdPartyRequest) (egress.ThirdPartyResponse, error) {
	return egress.ThirdPartyResponse{}, f.err
}

// world is a threat-data directory, a fake for each host, and the built-in copies an update
// compares against. Its client is egress's third-party client, pointed at the fakes, with the
// harness's 1 s HTTP timeout and no wait between requests.
type world struct {
	t        *testing.T
	dir      string
	spamhaus *fake
	ipapi    *fake
	builtIn  *threatdata.BuiltIn
	eopts    egress.Options
	client   egress.ThirdPartyHTTP // nil: egress's client over eopts
	timeout  time.Duration
	now      time.Time
	rename   func(oldpath, newpath string) error // nil: os.Rename
	rec      *recorder                           // the last update's requests
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, dir: filepath.Join(t.TempDir(), "nyx", "threat-data"), spamhaus: newFake(t), ipapi: newFake(t), now: now}
	w.builtIn = builtIn(t, stdSpamhaus(), stdIpapi())
	w.eopts = egress.Options{
		SourceBaseURLs: map[string]string{threatdata.SpamhausHost: w.spamhaus.srv.URL, threatdata.IpapiHost: w.ipapi.srv.URL},
		ResolverAddrs:  []string{"127.0.0.1:1"},
		HTTPTimeout:    time.Second,
		SourceRates:    map[string]float64{threatdata.SpamhausHost: 1000, threatdata.IpapiHost: 1000},
	}
	w.serveSpamhaus(stdSpamhaus())
	w.serveIpapi(day(d0), 80, 0, 80, day(d0), 20, 0, 20)
	return w
}

// serveSpamhaus makes the Spamhaus fake answer the three files.
func (w *world) serveSpamhaus(l lists) {
	w.spamhaus.set(pathV4, ok(l.v4))
	w.spamhaus.set(pathV6, ok(l.v6))
	w.spamhaus.set(pathASN, ok(l.asn))
}

// serveIpapi makes the ipapi.is fake answer both pages.
func (w *world) serveIpapi(netsDate string, nStated, nFrom, nn int, asnsDate string, aStated, aFrom, an int) {
	w.ipapi.set(pathNetworks, ok(networksPage(netsDate, nStated, nFrom, nn)))
	w.ipapi.set(pathASNs, ok(asnsPage(asnsDate, aStated, aFrom, an)))
}

func (w *world) options() threatdata.Options {
	inner := w.client
	if inner == nil {
		inner = egress.New(w.eopts).Clients(false, []string{threatdata.SpamhausHost, threatdata.IpapiHost}).ThirdParty
	}
	w.rec = &recorder{inner: inner}
	clock := w.now
	return threatdata.Options{Dir: w.dir, HTTP: w.rec, Now: func() time.Time { return clock }, NoFsync: true, Timeout: w.timeout, BuiltIn: w.builtIn,
		Rename: w.rename}
}

// update runs one update with a minute's deadline.
func (w *world) update() threatdata.Result { return w.updateCtx(context.Background()) }

// updateCtx runs one update under ctx, with a minute's deadline.
func (w *world) updateCtx(ctx context.Context) threatdata.Result {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return threatdata.Update(ctx, w.options())
}

func (w *world) load(at time.Time) threatdata.Set { return w.builtIn.Load(w.dir, at) }

func (w *world) path(name string) string { return filepath.Join(w.dir, name) }

// source is the result for a source, failing the test when there is none.
func source(t *testing.T, r threatdata.Result, name string) threatdata.SourceResult {
	t.Helper()
	for _, s := range r.Sources {
		if s.Source == name {
			return s
		}
	}
	t.Fatalf("the result has no source %q: %+v", name, r)
	return threatdata.SourceResult{}
}

// list is the result for a list, failing the test when there is none.
func list(t *testing.T, r threatdata.Result, name string) threatdata.ListResult {
	t.Helper()
	for _, l := range r.Lists {
		if l.List == name {
			return l
		}
	}
	t.Fatalf("the result has no list %q: %+v", name, r)
	return threatdata.ListResult{}
}

// inUse is the description of a list in use, failing the test when there is none.
func inUse(t *testing.T, s threatdata.Set, name string) threatdata.List {
	t.Helper()
	for _, l := range s.Lists {
		if l.Name == name {
			return l
		}
	}
	t.Fatalf("the set has no list %q: %+v", name, s.Lists)
	return threatdata.List{}
}

var listNames = []string{spamhaus.ListV4, spamhaus.ListV6, spamhaus.ListASN, threatdata.ListNetworks, threatdata.ListASNs}

func spamhausLists() []string { return listNames[:3] }
func ipapiLists() []string    { return listNames[3:] }
