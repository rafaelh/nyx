package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net"
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
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// Helpers of the tests of nyx setup --update-threat-data. They give each test its own built-in copy,
// dated 20 days before the clock, never the embedded one, whose dates move with each refresh of the
// built-in data. A download is dated two days after the built-in copy (d2), and a downloaded copy
// already in place one day after it (d1).

// tdDay is t's UTC date as ipapi.is lists are dated.
func tdDay(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// tdStamp is t as a Spamhaus list's date, and every time in the envelope, is written.
func tdStamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// The credit the generated Spamhaus files carry, as Spamhaus's own do.
const (
	tdCopyright = "(c) 2026 The Spamhaus Project SLU"
	tdTerms     = "https://www.spamhaus.org/drop/terms/"
)

// tdCreditLine is the line the update's output ends with, for the credit the fixtures carry.
const tdCreditLine = "Spamhaus DROP data " + tdCopyright + "; terms: " + tdTerms

// The paths of the five lists on their hosts.
const (
	tdPathV4       = "/drop/drop_v4.json"
	tdPathV6       = "/drop/drop_v6.json"
	tdPathASN      = "/drop/asndrop.json"
	tdPathNetworks = "/most-abusive-networks.html"
	tdPathASNs     = "/most-abusive-asn.html"
)

// The files an update keeps in the threat-data directory.
const (
	tdSpamhausData  = "spamhaus.jsonl"
	tdIpapiData     = "ipapi.json"
	tdSpamhausState = "spamhaus.state.json"
	tdIpapiState    = "ipapi.state.json"
)

// tdListNames are the five lists, in the order the update reports them.
var tdListNames = []string{spamhaus.ListV4, spamhaus.ListV6, spamhaus.ListASN, threatdata.ListNetworks, threatdata.ListASNs}

// tdSourceOf is the source of each list.
var tdSourceOf = map[string]string{
	spamhaus.ListV4: threatdata.Spamhaus, spamhaus.ListV6: threatdata.Spamhaus, spamhaus.ListASN: threatdata.Spamhaus,
	threatdata.ListNetworks: threatdata.Ipapi, threatdata.ListASNs: threatdata.Ipapi,
}

func tdV4Row(i int) string {
	return fmt.Sprintf(`{"cidr":"10.%d.%d.0/24","sblid":"SBL%d","rir":"ripencc"}`, i/256, i%256, 100000+i)
}

func tdV6Row(i int) string {
	return fmt.Sprintf(`{"cidr":"2001:db8:%x::/48","sblid":"SBL%d","rir":"apnic"}`, i, 200000+i)
}

func tdASNRow(i int) string {
	return fmt.Sprintf(`{"asn":%d,"rir":"arin","domain":"bad%d.example","cc":"US","asname":"BAD-AS-%d"}`, 64500+i, i, i)
}

// tdDropFile is a Spamhaus file of entries from to from+n-1, dated date, whose metadata states n
// records, each line ending in a newline.
func tdDropFile(row func(int) string, date time.Time, from, n int) []byte {
	var b strings.Builder
	for i := from; i < from+n; i++ {
		b.WriteString(row(i) + "\n")
	}
	fmt.Fprintf(&b, `{"type":"metadata","timestamp":%d,"size":1234,"records":%d,"copyright":%q,"terms":%q}`+"\n",
		date.Unix(), n, tdCopyright, tdTerms)
	return []byte(b.String())
}

// tdSpamhausFiles are the three Spamhaus files.
type tdSpamhausFiles struct{ v4, v6, asn []byte }

// tdSpamhausAt is the three lists dated date: 80, 20 and 20 entries, from the given first entry.
func tdSpamhausAt(date time.Time, from int) tdSpamhausFiles {
	return tdSpamhausFiles{tdDropFile(tdV4Row, date, from, 80), tdDropFile(tdV6Row, date, from, 20), tdDropFile(tdASNRow, date, from, 20)}
}

// tdBundle is a downloaded Spamhaus copy as nyx keeps it: each file after its marker line.
func tdBundle(f tdSpamhausFiles) []byte {
	var b bytes.Buffer
	for _, l := range []struct {
		name string
		raw  []byte
	}{{spamhaus.ListV4, f.v4}, {spamhaus.ListV6, f.v6}, {spamhaus.ListASN, f.asn}} {
		fmt.Fprintf(&b, "{\"list\":%q}\n", l.name)
		b.Write(l.raw)
	}
	return b.Bytes()
}

func tdNetEntry(i int) abusive.NetworkEntry {
	return abusive.NetworkEntry{Rank: i + 1, Start: netip.MustParseAddr(fmt.Sprintf("172.%d.%d.0", 16+i/200, i%200)),
		End: netip.MustParseAddr(fmt.Sprintf("172.%d.%d.255", 16+i/200, i%200)), ScoreTag: "High", AbuseScore: 50, Org: fmt.Sprintf("Org %d", i), OrgType: "isp"}
}

func tdASEntry(i int) abusive.ASNEntry {
	return abusive.ASNEntry{Rank: i + 1, ASN: 65000 + i, ScoreTag: "High", AbuseScore: 50, Org: fmt.Sprintf("AS Org %d", i), OrgType: "isp"}
}

// tdIpapiAt is an ipapi.is copy dated date: 80 networks and 20 ASNs, from the given first entry.
func tdIpapiAt(date time.Time, from int) abusive.Snapshot {
	s := abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: tdDay(date), Stated: 80, Entries: []abusive.NetworkEntry{}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: tdDay(date), Stated: 20, Entries: []abusive.ASNEntry{}},
	}
	for i := from; i < from+80; i++ {
		s.Nets.Entries = append(s.Nets.Entries, tdNetEntry(i))
	}
	for i := from; i < from+20; i++ {
		s.ASNs.Entries = append(s.ASNs.Entries, tdASEntry(i))
	}
	return s
}

// tdIpapiFile is a downloaded ipapi.is copy as nyx keeps it.
func tdIpapiFile(s abusive.Snapshot) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err) // the fixture's own types always marshal
	}
	return b
}

// tdHeaderOrg is the organisation column's header as ipapi.is spells it.
const tdHeaderOrg = "Organization" //nolint:misspell // the page's own spelling

func tdPageDate(d time.Time) string { return d.UTC().Format("January 2, 2006") }

// tdNetworksPage is ipapi.is's most-abusive networks page, dated d, listing networks from..from+n-1
// and stating n.
func tdNetworksPage(d time.Time, from, n int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><span>Data last updated on <strong>%s</strong></span><p>The table lists the <strong>%d</strong> most abusive networks on the Internet.</p>`, tdPageDate(d), n)
	b.WriteString(`<table><thead><tr><th>Rank</th><th>Network</th><th>Num Hosts</th><th>Score Tag</th><th>Abuse Score</th><th>` + tdHeaderOrg + `</th><th>Type</th></tr></thead><tbody>`)
	for i := from; i < from+n; i++ {
		e := tdNetEntry(i)
		fmt.Fprintf(&b, `<tr><td>%d</td><td><a>%s - %s</a></td><td>256</td><td><span>High</span></td><td>50%%</td><td>%s</td><td><span>isp</span></td></tr>`,
			e.Rank, e.Start, e.End, e.Org)
	}
	b.WriteString(`</tbody></table></body></html>`)
	return []byte(b.String())
}

// tdASNsPage is ipapi.is's most-abusive ASNs page, dated d, listing ASNs from..from+n-1 and
// stating n.
func tdASNsPage(d time.Time, from, n int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><span>Data last updated on <strong>%s</strong></span><p>The table lists the <strong>%d</strong> most abusive ASNs.</p>`, tdPageDate(d), n)
	b.WriteString(`<table><thead><tr><th>Rank</th><th>ASN</th><th>Num IPs and Routes</th><th>Score Tag</th><th>Abuse Score</th><th>` + tdHeaderOrg + `</th><th>Org Type</th></tr></thead><tbody>`)
	for i := from; i < from+n; i++ {
		e := tdASEntry(i)
		fmt.Fprintf(&b, `<tr><td>%d</td><td><a>as%d</a></td><td>1</td><td><span>High</span></td><td>50%%</td><td>%s</td><td><span>isp</span></td></tr>`, e.Rank, e.ASN, e.Org)
	}
	b.WriteString(`</tbody></table></body></html>`)
	return []byte(b.String())
}

// tdBuiltIn is the built-in copy of the update's tests, dated d0: the Spamhaus lists of
// tdSpamhausAt and the ipapi.is lists of tdIpapiAt, each from entry 0.
func tdBuiltIn(d0 time.Time) (*threatdata.BuiltIn, error) {
	f := tdSpamhausAt(d0, 0)
	v4, err := spamhaus.ParseDrop(f.v4, false)
	if err != nil {
		return nil, fmt.Errorf("the built-in drop_v4: %w", err)
	}
	v6, err := spamhaus.ParseDrop(f.v6, true)
	if err != nil {
		return nil, fmt.Errorf("the built-in drop_v6: %w", err)
	}
	asn, err := spamhaus.ParseASNDrop(f.asn)
	if err != nil {
		return nil, fmt.Errorf("the built-in asndrop: %w", err)
	}
	return &threatdata.BuiltIn{Spamhaus: spamhaus.Lists{V4: v4, V6: v6, ASNs: asn}, Ipapi: tdIpapiAt(d0, 0)}, nil
}

// tdReply is a fake host's answer to one path. A gate, when set, holds the answer until it is
// closed or the request ends.
type tdReply struct {
	status int
	body   []byte
	gate   chan struct{}
}

func tdOK(body []byte) tdReply { return tdReply{status: http.StatusOK, body: body} }

// tdFake is one source's host. It answers each path from its routes and records every request.
type tdFake struct {
	srv *httptest.Server

	mu     sync.Mutex
	routes map[string]tdReply
	hits   []string // "GET /path", in order
}

func newTDFake(t *testing.T) *tdFake {
	t.Helper()
	f := &tdFake{routes: map[string]tdReply{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *tdFake) serve(w http.ResponseWriter, r *http.Request) {
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
	w.WriteHeader(rp.status)
	_, _ = w.Write(rp.body)
}

func (f *tdFake) set(path string, r tdReply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[path] = r
}

// hold makes path's answer wait for the returned function, which the test's end also calls.
func (f *tdFake) hold(t *testing.T, path string) (release func()) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	gate := make(chan struct{})
	rp := f.routes[path]
	rp.gate = gate
	f.routes[path] = rp
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release) // before the server closes, which waits for its handlers
	return release
}

func (f *tdFake) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.hits...)
}

// count is the number of requests for path.
func (f *tdFake) count(path string) int {
	n := 0
	for _, h := range f.requests() {
		if h == "GET "+path {
			n++
		}
	}
	return n
}

// asked waits up to five seconds for path to be asked for, and reports whether it was.
func (f *tdFake) asked(path string) bool {
	return tdPoll(5*time.Second, func() bool { return f.count(path) > 0 })
}

// tdPoll reports whether cond became true within d.
func tdPoll(d time.Duration, cond func() bool) bool {
	for deadline := time.Now().Add(d); ; time.Sleep(5 * time.Millisecond) {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

// tdClosedURL is the base URL of a loopback port nothing listens on: a request to it gets no
// response.
func tdClosedURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}

// threatWorld is a harness whose update reaches a fake for each source's host, with the built-in
// copies dated d0.
type threatWorld struct {
	t          *testing.T
	h          *harness
	sh, ip     *tdFake
	d0, d1, d2 time.Time // the built-in copy's date, a downloaded copy's, and a download's
}

func newThreatWorld(t *testing.T) *threatWorld {
	t.Helper()
	return newThreatWorldOn(t, newHarness(t))
}

// newThreatWorldOn is newThreatWorld on a harness the caller made. Each source's fake answers a
// download that is newer than the built-in copy: every list dated d2, from entry 5, so that each
// list adds 5 entries and removes 5.
func newThreatWorldOn(t *testing.T, h *harness) *threatWorld {
	t.Helper()
	w := &threatWorld{t: t, h: h, sh: newTDFake(t), ip: newTDFake(t)}
	w.d0 = h.now.AddDate(0, 0, -20)
	w.d1 = w.d0.AddDate(0, 0, 1)
	w.d2 = w.d0.AddDate(0, 0, 2)
	b, err := tdBuiltIn(w.d0)
	if err != nil {
		t.Fatal(err)
	}
	h.threatBuiltIn = b
	tdRoute(h, w.sh.srv.URL, w.ip.srv.URL)
	w.serveSpamhaus(tdSpamhausAt(w.d2, 5))
	w.serveIpapi(w.d2, 5)
	return w
}

// tdRoute points h's requests to the two hosts at the given base URLs, with no wait between
// requests.
func tdRoute(h *harness, spamhausURL, ipapiURL string) {
	h.eopts.SourceBaseURLs = map[string]string{threatdata.SpamhausHost: spamhausURL, threatdata.IpapiHost: ipapiURL}
	h.eopts.SourceRates = map[string]float64{threatdata.SpamhausHost: 1000, threatdata.IpapiHost: 1000}
}

// serveSpamhaus makes the Spamhaus fake answer the three files.
func (w *threatWorld) serveSpamhaus(f tdSpamhausFiles) {
	w.sh.set(tdPathV4, tdOK(f.v4))
	w.sh.set(tdPathV6, tdOK(f.v6))
	w.sh.set(tdPathASN, tdOK(f.asn))
}

// serveIpapi makes the ipapi.is fake answer both pages, dated date, from the given first entry.
func (w *threatWorld) serveIpapi(date time.Time, from int) {
	w.ip.set(tdPathNetworks, tdOK(tdNetworksPage(date, from, 80)))
	w.ip.set(tdPathASNs, tdOK(tdASNsPage(date, from, 20)))
}

// current makes both fakes answer the built-in copy itself, so that every list is already current.
func (w *threatWorld) current() {
	w.serveSpamhaus(tdSpamhausAt(w.d0, 0))
	w.serveIpapi(w.d0, 0)
}

// dir is the threat-data directory of h's environment, under XDG_CONFIG_HOME.
func (w *threatWorld) dir() string {
	return filepath.Join(w.h.env["XDG_CONFIG_HOME"], "nyx", "threat-data")
}

func (w *threatWorld) path(name string) string { return filepath.Join(w.dir(), name) }

// fake is the fake of a source.
func (w *threatWorld) fake(source string) *tdFake {
	if source == threatdata.Spamhaus {
		return w.sh
	}
	return w.ip
}

// tdFirstPath is the path of a source's first list.
func tdFirstPath(source string) string {
	if source == threatdata.Spamhaus {
		return tdPathV4
	}
	return tdPathNetworks
}

// tdStateFile is the name of a source's state file.
func tdStateFile(source string) string {
	if source == threatdata.Spamhaus {
		return tdSpamhausState
	}
	return tdIpapiState
}

// tdState is a source's state file.
type tdState struct {
	LastResponse *time.Time `json:"last_response"`
	LastChecked  *time.Time `json:"last_checked"`
}

// writeState writes a source's state file; a nil time is null.
func (w *threatWorld) writeState(source string, lastResponse, lastChecked *time.Time) {
	w.t.Helper()
	b, err := json.Marshal(tdState{LastResponse: lastResponse, LastChecked: lastChecked})
	if err != nil {
		w.t.Fatal(err)
	}
	tdWrite(w.t, w.dir(), tdStateFile(source), b)
}

// tdReadState reads a source's state file in dir; the zero state when there is none.
func tdReadState(t *testing.T, dir, source string) tdState {
	t.Helper()
	var s tdState
	b, err := os.ReadFile(filepath.Join(dir, tdStateFile(source)))
	if err != nil {
		return s
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Errorf("%s's state %q: %v", source, b, err)
	}
	return s
}

// skipped makes a source's last response ten minutes before the clock, so an update skips it.
func (w *threatWorld) skipped(source string) {
	at := w.h.now.Add(-10 * time.Minute)
	w.writeState(source, &at, &at)
}

// fail makes a source's first list answer status.
func (w *threatWorld) fail(source string, status int) {
	w.fake(source).set(tdFirstPath(source), tdReply{status: status})
}

// unreachable makes a source's requests get no response.
func (w *threatWorld) unreachable(source string) {
	urls := maps.Clone(w.h.eopts.SourceBaseURLs)
	host := threatdata.SpamhausHost
	if source == threatdata.Ipapi {
		host = threatdata.IpapiHost
	}
	urls[host] = tdClosedURL(w.t)
	w.h.eopts.SourceBaseURLs = urls
}

// placeDownloaded writes a downloaded copy of both sources dated d1, from entry 2, and returns
// their bytes, Spamhaus's first.
func (w *threatWorld) placeDownloaded() (sh, ip []byte) {
	w.t.Helper()
	sh, ip = tdBundle(tdSpamhausAt(w.d1, 2)), tdIpapiFile(tdIpapiAt(w.d1, 2))
	tdWrite(w.t, w.dir(), tdSpamhausData, sh)
	tdWrite(w.t, w.dir(), tdIpapiData, ip)
	return sh, ip
}

// tdWrite writes a file of mode 0600 in dir, creating dir.
func tdWrite(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// tdSnap is a file's bytes and mode, to show it was left alone.
type tdSnap struct {
	b    []byte
	mode fs.FileMode
}

func tdSnapshot(t *testing.T, path string) tdSnap {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return tdSnap{b, fi.Mode()}
}

func tdUnchanged(t *testing.T, path string, before tdSnap) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("%s afterwards: %v", filepath.Base(path), err)
		return
	}
	if !bytes.Equal(b, before.b) {
		t.Errorf("%s changed:\n%.300s\nwas:\n%.300s", filepath.Base(path), b, before.b)
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode() != before.mode {
		t.Errorf("%s's mode changed to %v from %v", filepath.Base(path), fi.Mode(), before.mode)
	}
}

// tdExists reports whether path exists.
func tdExists(path string) bool { _, err := os.Stat(path); return err == nil }

// update runs nyx setup --update-threat-data with args, failing the test if it does not end.
func (w *threatWorld) update(args ...string) int {
	w.t.Helper()
	return w.h.execRootTimeout(append([]string{"setup", "--update-threat-data"}, args...)...)
}

// requests is every request both fakes saw, each as "<host> GET <path>".
func (w *threatWorld) requests() []string {
	var out []string
	for _, r := range w.sh.requests() {
		out = append(out, threatdata.SpamhausHost+" "+r)
	}
	for _, r := range w.ip.requests() {
		out = append(out, threatdata.IpapiHost+" "+r)
	}
	return out
}

// threatEnvelope is the update's --json envelope.
type threatEnvelope struct {
	Data struct {
		Sources []threatSourceOut `json:"sources"`
		Lists   []threatListOut   `json:"lists"`
	} `json:"data"`
	Meta struct {
		Errors   []threatErrorOut `json:"errors"`
		Warnings []string         `json:"warnings"`
		Hint     *string          `json:"hint"`
	} `json:"meta"`
}

type threatSourceOut struct {
	Source        string          `json:"source"`
	Outcome       string          `json:"outcome"`
	LastContacted *string         `json:"last_contacted"`
	NextUpdate    *string         `json:"next_update"`
	Copyright     *string         `json:"copyright"`
	Terms         *string         `json:"terms"`
	Error         *threatErrorOut `json:"error"`
}

type threatListOut struct {
	List       string `json:"list"`
	Source     string `json:"source"`
	OldUpdated string `json:"old_updated"`
	NewUpdated string `json:"new_updated"`
	OldEntries int    `json:"old_entries"`
	Entries    int    `json:"entries"`
	Added      int    `json:"added"`
	Removed    int    `json:"removed"`
}

type threatErrorOut struct {
	Error     string  `json:"error"`
	Code      string  `json:"code"`
	Hint      *string `json:"hint"`
	Input     any     `json:"input"`
	Transient bool    `json:"transient"`
}

// threatEnvelope parses stdout as the update's envelope: one JSON object on one line.
func (h *harness) threatEnvelope() threatEnvelope {
	h.t.Helper()
	out := h.stdout.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		h.t.Fatalf("stdout is not one line of JSON:\n%s\nstderr %s", out, h.stderr.String())
	}
	var env threatEnvelope
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		h.t.Fatalf("stdout is not the envelope: %v\n%s", err, out)
	}
	return env
}

// source is the envelope's object for a source, failing the test when there is none.
func (e threatEnvelope) source(t *testing.T, name string) threatSourceOut {
	t.Helper()
	for _, s := range e.Data.Sources {
		if s.Source == name {
			return s
		}
	}
	t.Fatalf("the envelope has no source %q: %+v", name, e.Data.Sources)
	return threatSourceOut{}
}

// list is the envelope's object for a list, failing the test when there is none.
func (e threatEnvelope) list(t *testing.T, name string) threatListOut {
	t.Helper()
	for _, l := range e.Data.Lists {
		if l.List == name {
			return l
		}
	}
	t.Fatalf("the envelope has no list %q: %+v", name, e.Data.Lists)
	return threatListOut{}
}

// outcomes is each source's outcome, as "spamhaus=updated ipapi.is=current".
func (e threatEnvelope) outcomes() string {
	parts := []string{}
	for _, s := range e.Data.Sources {
		parts = append(parts, s.Source+"="+s.Outcome)
	}
	return strings.Join(parts, " ")
}

// tdStr is *s, or "<null>".
func tdStr(s *string) string {
	if s == nil {
		return "<null>"
	}
	return *s
}

// threatLines are the lines of the update's human output on stdout that are not blank.
func (h *harness) threatLines() []string {
	var out []string
	for l := range strings.SplitSeq(h.stdout.String(), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// threatLine is the output line of a list: the one whose first two words are its source and name.
func (h *harness) threatLine(list string) string {
	h.t.Helper()
	for _, l := range h.threatLines() {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == tdSourceOf[list] && f[1] == list {
			return l
		}
	}
	h.t.Errorf("no line for %s %s in the output:\n%s", tdSourceOf[list], list, h.stdout.String())
	return ""
}

// threatFailure is the error of an update that failed (exit 1) or failed in part (exit 7), with
// the per-source lines a human-mode error may carry after it: stderr's first line is the error,
// then its hint and retry lines, then a line for each failed source.
func (h *harness) threatFailure(jsonMode bool) failure {
	h.t.Helper()
	if jsonMode {
		return h.theError(true)
	}
	var lines []string
	for l := range strings.SplitSeq(strings.TrimRight(h.stderr.String(), "\n"), "\n") {
		if !logLayout.MatchString(l) {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		h.t.Fatalf("stderr holds no error")
	}
	m := humanErrorLine.FindStringSubmatch(lines[0])
	if m == nil {
		h.t.Fatalf("stderr's first line %q is not \"error: <message> (<CODE>)\":\n%s", lines[0], h.stderr.String())
	}
	f := failure{msg: m[1], code: m[2]}
	for _, l := range lines[1:] {
		switch {
		case strings.HasPrefix(l, "hint: ") && f.hint == "" && f.targets == nil:
			f.hint = strings.TrimPrefix(l, "hint: ")
		case l == "retry: may succeed after a wait" && f.targets == nil:
			f.transient = true
		case humanErrorLine.MatchString(l):
			f.targets = append(f.targets, strings.TrimPrefix(l, "error: "))
		default:
			h.t.Errorf("stderr holds a line that is not part of the error: %q", l)
		}
	}
	return f
}
