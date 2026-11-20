package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/cve"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
)

// reply is one scripted answer of the fake NVD.
type reply struct {
	status int
	header map[string]string
	body   string
}

// cveTestdata is the cve tool's fixtures, found before any test changes directory.
var cveTestdata, _ = filepath.Abs(filepath.Join("..", "cve", "testdata"))

// nvdFake stands in for the NVD: it serves canned entries, answers by script
// where one is set (repeating the script's last reply), counts the requests it
// has in flight, and records each request's cveId and apiKey header.
type nvdFake struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	entries     map[string]string        // CVE ID -> the NVD's entry JSON
	scripts     map[string][]reply       // CVE ID -> one reply per attempt
	delays      map[string]time.Duration // CVE ID -> how long to wait before answering
	hold        bool                     // never answer; arrived is told of each request
	held        map[string]bool          // the IDs never answered, as hold does for all
	arrived     chan string
	seen, keys  []string
	attempts    map[string]int
	inFlight    int
	maxInFlight int
}

// newNVD starts a fake NVD and points the harness's NVD host at it.
func newNVD(t *testing.T, h *harness) *nvdFake {
	t.Helper()
	f := &nvdFake{t: t, entries: map[string]string{}, scripts: map[string][]reply{}, delays: map[string]time.Duration{},
		attempts: map[string]int{}, arrived: make(chan string, 100)}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	h.eopts.SourceBaseURLs = map[string]string{cve.Host: f.srv.URL}
	return f
}

// fixture serves the cve tool's fixture for its own ID, and returns that ID.
func (f *nvdFake) fixture(name string) string {
	f.t.Helper()
	b, e := loadFixture(f.t, name)
	f.mu.Lock()
	f.entries[e.ID] = string(b)
	f.mu.Unlock()
	return e.ID
}

// entry serves a minimal entry for id.
func (f *nvdFake) entry(id string) {
	f.mu.Lock()
	f.entries[id] = fmt.Sprintf(`{"id":%q,"vulnStatus":"Analyzed","published":"2024-01-01T00:00:00.000","lastModified":"2024-01-02T00:00:00.000",`+
		`"descriptions":[{"lang":"en","value":"About %s."}],"references":[]}`, id, id)
	f.mu.Unlock()
}

func (f *nvdFake) script(id string, replies ...reply) {
	f.mu.Lock()
	f.scripts[id] = replies
	f.mu.Unlock()
}

func (f *nvdFake) serve(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("cveId")
	f.mu.Lock()
	f.seen = append(f.seen, id)
	f.keys = append(f.keys, r.Header.Get("apiKey"))
	attempt := f.attempts[id]
	f.attempts[id]++
	f.inFlight++
	f.maxInFlight = max(f.maxInFlight, f.inFlight)
	delay, hold, script, entry := f.delays[id], f.hold || f.held[id], f.scripts[id], f.entries[id]
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.mu.Unlock()
	}()
	if r.URL.Path != "/rest/json/cves/2.0" || r.Header.Get("Accept") != "application/json" {
		f.t.Errorf("request %s with Accept %q", r.URL, r.Header.Get("Accept"))
	}
	if hold {
		f.arrived <- id
		<-r.Context().Done()
		return
	}
	select {
	case <-time.After(delay):
	case <-r.Context().Done():
		return
	}
	if len(script) > 0 {
		rp := script[min(attempt, len(script)-1)]
		for k, v := range rp.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(rp.status)
		_, _ = io.WriteString(w, rp.body)
		return
	}
	if entry == "" {
		_, _ = io.WriteString(w, `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","vulnerabilities":[]}`)
		return
	}
	_, _ = io.WriteString(w, `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"format":"NVD_CVE","version":"2.0","vulnerabilities":[{"cve":`+entry+`}]}`)
}

// inFlightNow is how many requests the fake is answering.
func (f *nvdFake) inFlightNow() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inFlight
}

func (f *nvdFake) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.seen)
}

func (f *nvdFake) apiKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.keys)
}

// loadFixture is the cve tool's fixture name, as served and as decoded.
func loadFixture(t *testing.T, name string) ([]byte, cve.Entry) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cveTestdata, name))
	if err != nil {
		t.Fatal(err)
	}
	var e cve.Entry
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return b, e
}

// unitJSON is the record of a fixture as the unit tests of the record encode it.
func unitJSON(t *testing.T, fixture string) string {
	t.Helper()
	_, e := loadFixture(t, fixture)
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cve.FromNVD(&e)); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(out.String(), "\n")
}

// unitText is the records of fixtures as the cve tool lays them out, at depth None.
func unitText(t *testing.T, spec string, fixtures ...string) string {
	t.Helper()
	var recs []cve.Record
	for _, name := range fixtures {
		_, e := loadFixture(t, name)
		recs = append(recs, cve.FromNVD(&e))
	}
	f, unknown := cve.Select(spec)
	if unknown != nil {
		t.Fatal(unknown)
	}
	var out bytes.Buffer
	if err := cve.Render(&out, recs, f, layout.Stream{}, nil); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// metaError is one meta.errors entry: the five keys of the error format.
type metaError struct {
	Error     string  `json:"error"`
	Code      string  `json:"code"`
	Hint      *string `json:"hint"`
	Input     any     `json:"input"`
	Transient bool    `json:"transient"`
}

// cveEnvelope is the --json result of nyx cve.
type cveEnvelope struct {
	Data []json.RawMessage `json:"data"`
	Meta struct {
		Count    int         `json:"count"`
		Errors   []metaError `json:"errors"`
		Warnings []string    `json:"warnings"`
	} `json:"meta"`
}

// cveEnvelope parses stdout as the one compact envelope of nyx cve, with
// exactly its keys, in order, and errors and warnings never null.
func (h *harness) cveEnvelope() cveEnvelope {
	h.t.Helper()
	out := h.stdout.String()
	if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
		h.t.Fatalf("stdout is not one line: %q", out)
	}
	line := strings.TrimSuffix(out, "\n")
	var env cveEnvelope
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		h.t.Fatalf("stdout is not the envelope: %v\n%s", err, line)
	}
	if env.Data == nil || env.Meta.Errors == nil || env.Meta.Warnings == nil || env.Meta.Count != len(env.Data) {
		h.t.Errorf("data, meta.errors or meta.warnings is null, or count is wrong: %s", line)
	}
	var again bytes.Buffer
	enc := json.NewEncoder(&again)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(env); err != nil || strings.TrimSuffix(again.String(), "\n") != line {
		h.t.Errorf("the envelope is not compact with its keys in order:\n got %s\nwant %s", line, again.String())
	}
	return env
}

// ids are the "id" of each record in data.
func (e cveEnvelope) ids() []string {
	var out []string
	for _, raw := range e.Data {
		var r struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &r)
		out = append(out, r.ID)
	}
	return out
}

// cveRun runs nyx cve with args, adding --json in JSON mode.
func (h *harness) cveRun(jsonMode bool, args ...string) int {
	h.t.Helper()
	full := append([]string{"cve"}, args...)
	if jsonMode {
		full = append(full, "--json")
	}
	return h.execRoot(full...)
}

var modes = []bool{true, false}

// A found ID's record is the record the unit tests pin, and a rejected CVE is
// a record, not a not-found.
func TestCVE_RecordIsTheUnitRecord(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	log4j, rejected := nvd.fixture("primary-over-secondary.json"), nvd.fixture("rejected.json")
	if code := h.cveRun(true, log4j, rejected); code != 0 || h.stderr.Len() != 0 {
		t.Fatalf("exit %d, stderr %q", code, h.stderr.String())
	}
	env := h.cveEnvelope()
	if len(env.Data) != 2 || string(env.Data[0]) != unitJSON(t, "primary-over-secondary.json") || string(env.Data[1]) != unitJSON(t, "rejected.json") {
		t.Errorf("data %s", env.Data)
	}
	if !strings.Contains(string(env.Data[1]), `"status":"Rejected"`) || len(env.Meta.Errors) != 0 {
		t.Errorf("the rejected CVE: %s, errors %v", env.Data[1], env.Meta.Errors)
	}
	// Without --json the records are the cve tool's layout.
	if code := h.cveRun(false, log4j, rejected); code != 0 || h.stderr.Len() != 0 {
		t.Fatalf("human: exit %d, stderr %q", code, h.stderr.String())
	}
	if want := unitText(t, "all", "primary-over-secondary.json", "rejected.json"); h.stdout.String() != want {
		t.Errorf("human\n got %q\nwant %q", h.stdout.String(), want)
	}
}

// Records come back in argument order whatever order the NVD answers in, and
// no more than four requests are ever in flight.
func TestCVE_ArgumentOrderAndConcurrency(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.setenv("NVD_API_KEY", "k") // 50 per window, so the window never binds
	nvd := newNVD(t, h)
	var args []string
	for i := range 10 {
		id := fmt.Sprintf("CVE-2024-%d", 1000+i)
		nvd.entry(id)
		nvd.delays[id] = 30 * time.Millisecond
		args = append(args, id)
	}
	nvd.delays[args[0]] = 300 * time.Millisecond // the first is answered last
	if code := h.cveRun(true, args...); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got := h.cveEnvelope().ids(); !slices.Equal(got, args) {
		t.Errorf("data in order %v, want %v", got, args)
	}
	if nvd.maxInFlight > 4 || nvd.maxInFlight < 2 {
		t.Errorf("%d requests in flight at most, want 2 to 4", nvd.maxInFlight)
	}
}

// Case and surrounding whitespace are normalised, and an ID given twice is
// looked up and returned once.
func TestCVE_NormalisedAndDeduped(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	id := nvd.fixture("primary-over-secondary.json")
	if code := h.cveRun(true, "cve-2021-44228", " CVE-2021-44228 ", id); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got := h.cveEnvelope().ids(); !slices.Equal(got, []string{id}) || !slices.Equal(nvd.requests(), []string{id}) {
		t.Errorf("data %v, requests %v; want the ID once", got, nvd.requests())
	}
}

// A lone - reads the IDs from stdin, one per line, ignoring blank lines.
func TestCVE_Stdin(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	a, b := nvd.fixture("primary-over-secondary.json"), nvd.fixture("rejected.json")
	h.stdin = strings.NewReader("\n" + a + "\n\n   \ncve-2021-0001\r\n")
	if code := h.cveRun(true, "-"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got := h.cveEnvelope().ids(); !slices.Equal(got, []string{a, b}) {
		t.Errorf("data %v", got)
	}
}

// readSpy fails the test when it is read.
type readSpy struct{ t *testing.T }

func (r readSpy) Read([]byte) (int, error) {
	r.t.Error("stdin was read")
	return 0, io.EOF
}

// - alongside other arguments is a usage error, found before stdin is read.
func TestCVE_DashWithOtherArguments(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"-", "CVE-2021-44228"}, {"CVE-2021-44228", "-"}, {"-", "-"}} {
		for _, jsonMode := range modes {
			h := newHarness(t)
			nvd := newNVD(t, h)
			h.stdin = readSpy{t}
			f := h.failed(h.cveRun(jsonMode, args...), 2, jsonMode)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "-") {
				t.Errorf("%v: %+v", args, f)
			}
			if len(nvd.requests()) != 0 {
				t.Errorf("%v: the NVD was asked %v", args, nvd.requests())
			}
		}
	}
}

// A bare nyx cve, or - with no IDs on stdin, exits 2 with the hint nyx --help
// and does not print the help.
func TestCVE_NoIDs(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		args  []string
		stdin string
	}{{nil, ""}, {[]string{"-"}, ""}, {[]string{"-"}, "\n  \n\n"}} {
		for _, jsonMode := range modes {
			h := newHarness(t)
			nvd := newNVD(t, h)
			h.stdin = strings.NewReader(c.stdin)
			f := h.failed(h.cveRun(jsonMode, c.args...), 2, jsonMode)
			if f.code != "INVALID_INPUT" || f.hint != "nyx --help" {
				t.Errorf("%v with stdin %q: %+v", c.args, c.stdin, f)
			}
			if all := h.stdout.String() + h.stderr.String(); strings.Contains(all, "Examples:") || strings.Contains(all, "Exit codes:") {
				t.Errorf("%v printed the help:\n%s", c.args, all)
			}
			if len(nvd.requests()) != 0 {
				t.Errorf("the NVD was asked %v", nvd.requests())
			}
		}
	}
}

// A malformed ID becomes an INVALID_INPUT entry under its argument as given,
// the valid IDs are still fetched, and the NVD never sees the bad one.
func TestCVE_MalformedAmongValid(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	a, b := nvd.fixture("primary-over-secondary.json"), nvd.fixture("rejected.json")
	f := h.partialOf(h.cveRun(true, a, " cve-2021-123 ", b), true, []string{" cve-2021-123 "}, true)
	env := h.cveEnvelope()
	if got := env.ids(); !slices.Equal(got, []string{a, b}) {
		t.Errorf("data %v", got)
	}
	want := metaError{Error: "not a CVE ID", Code: "INVALID_INPUT", Input: " cve-2021-123 "}
	if len(env.Meta.Errors) != 1 || env.Meta.Errors[0].Hint == nil || *env.Meta.Errors[0].Hint != "expected CVE-YYYY-NNNN, e.g. CVE-2021-44228" {
		t.Fatalf("meta.errors %+v", env.Meta.Errors)
	}
	got := env.Meta.Errors[0]
	got.Hint = nil
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("entry %+v, want %+v", got, want)
	}
	if slices.ContainsFunc(nvd.requests(), func(s string) bool { return strings.Contains(s, "123") && len(s) < 14 }) || len(nvd.requests()) != 2 {
		t.Errorf("the NVD saw %v", nvd.requests())
	}
	if f.msg != "2 of 3 IDs returned, 1 failed" || f.transient {
		t.Errorf("error %+v", f)
	}
}

// A stdin that is never closed ends at the deadline, as a timeout, and the
// call returns.
func TestCVE_StdinNeverClosed(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		newNVD(t, h)
		r, w := io.Pipe()
		t.Cleanup(func() { w.Close() })
		h.stdin = r
		start := time.Now()
		f := h.failed(h.cveRun(jsonMode, "-", "--timeout", "300ms"), 1, jsonMode)
		if f.code != "TIMEOUT" || !strings.Contains(f.msg, "stdin") || f.hint != "close stdin, or pass the IDs as arguments" {
			t.Errorf("%+v", f)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Errorf("the call took %v", el)
		}
	}
}

// Every problem the flags show is reported in one error: an unknown field and
// no IDs at all.
func TestCVE_ProblemsTogether(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	newNVD(t, h)
	f := h.failed(h.cveRun(true, "--fields", "bogus"), 2, true)
	if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, `"bogus"`) || !strings.Contains(f.msg, "no CVE IDs") ||
		!strings.Contains(f.hint, "valid fields: id, status") || !strings.Contains(f.hint, "nyx --help") {
		t.Errorf("%+v", f)
	}
	if got := f.inputOf("fields"); !slices.Equal(got, []string{"bogus"}) {
		t.Errorf("input %v", f.input)
	}
}

// cveGone is an ID the fake NVD does not hold.
const cveGone = "CVE-2099-0001"

// One run per outcome of the batch table, in both modes.
func TestCVE_Outcomes(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		t.Run(fmt.Sprint("json=", jsonMode), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			nvd := newNVD(t, h)
			log4j, rejected := nvd.fixture("primary-over-secondary.json"), nvd.fixture("rejected.json")
			// Every ID succeeded: exit 0.
			if code := h.cveRun(jsonMode, log4j, rejected); code != 0 || h.stderr.Len() != 0 || h.stdout.Len() == 0 {
				t.Errorf("all found: exit %d, stderr %q", code, h.stderr.String())
			}
			outcomeSome(t, h, jsonMode, log4j)
			outcomeNoneFound(t, h, jsonMode)
			outcomeMixed(t, h, nvd, jsonMode)
		})
	}
}

// Some succeeded: exit 7, the records and the failures, with one error: line per failure in human mode.
func outcomeSome(t *testing.T, h *harness, jsonMode bool, log4j string) {
	t.Helper()
	f := h.partialOf(h.cveRun(jsonMode, log4j, cveGone), jsonMode, []string{cveGone}, true)
	if f.msg != "1 of 2 IDs returned, 1 failed" || f.hint != "check the IDs that failed: "+cveGone || f.transient {
		t.Errorf("some: %+v", f)
	}
	if jsonMode {
		env := h.cveEnvelope()
		if !slices.Equal(env.ids(), []string{log4j}) || len(env.Meta.Errors) != 1 || env.Meta.Errors[0].Code != "NOT_FOUND" ||
			env.Meta.Errors[0].Input != cveGone || env.Meta.Errors[0].Error != "not in the NVD" {
			t.Errorf("some: envelope %+v", env)
		}
		return
	}
	if h.stdout.String() != unitText(t, "all", "primary-over-secondary.json") {
		t.Errorf("some: stdout %q", h.stdout.String())
	}
	want := "error: 1 of 2 IDs returned, 1 failed (PARTIAL)\nhint: check the IDs that failed: " + cveGone + "\n" +
		"error: " + cveGone + ": not in the NVD (NOT_FOUND)\n"
	if h.stderr.String() != want {
		t.Errorf("some: stderr\n got %q\nwant %q", h.stderr.String(), want)
	}
	if !slices.Equal(f.targets, []string{cveGone + ": not in the NVD (NOT_FOUND)"}) {
		t.Errorf("some: targets %q", f.targets)
	}
}

// None succeeded, all not found: exit 3, one error listing the IDs.
func outcomeNoneFound(t *testing.T, h *harness, jsonMode bool) {
	t.Helper()
	f := h.failed(h.cveRun(jsonMode, cveGone, "CVE-2099-0002"), 3, jsonMode)
	if f.code != "NOT_FOUND" || f.msg != "2 IDs: not in the NVD" || f.hint != "check the ID; the NVD lists only published CVEs" || f.transient {
		t.Errorf("none found: %+v", f)
	}
	if jsonMode && !slices.Equal(f.inputOf("id"), []string{cveGone, "CVE-2099-0002"}) {
		t.Errorf("none found: input %v", f.input)
	}
	if f = h.failed(h.cveRun(jsonMode, cveGone), 3, jsonMode); f.msg != cveGone+": not in the NVD" {
		t.Errorf("one not found: %+v", f)
	}
}

// None succeeded, with different codes: exit 7 and no records.
func outcomeMixed(t *testing.T, h *harness, nvd *nvdFake, jsonMode bool) {
	t.Helper()
	nvd.script("CVE-2099-0003", reply{status: 500})
	f := h.partialOf(h.cveRun(jsonMode, cveGone, "CVE-2099-0003"), jsonMode, []string{cveGone, "CVE-2099-0003"}, false)
	if f.msg != "none of 2 IDs returned" || !f.transient || f.hint != "run: nyx cve CVE-2099-0003"+map[bool]string{true: " --json"}[jsonMode] {
		t.Errorf("mixed: %+v", f)
	}
	if jsonMode {
		if env := h.cveEnvelope(); len(env.Data) != 0 || len(env.Meta.Errors) != 2 {
			t.Errorf("mixed: envelope %+v", env)
		}
	} else if len(f.targets) != 2 {
		t.Errorf("mixed: targets %q", f.targets)
	}
}

// Every ID refused for the rate limit: exit 1, with the command to run after
// the wait.
func TestCVE_AllRateLimited(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		nvd := newNVD(t, h)
		nvd.script("CVE-2021-44228", reply{status: 429, header: map[string]string{"Retry-After": "120"}})
		f := h.failed(h.cveRun(jsonMode, "cve-2021-44228", "--timeout", "2s"), 1, jsonMode)
		want := "after 120s, run: nyx cve CVE-2021-44228" + map[bool]string{true: " --json"}[jsonMode] + " --timeout 2s"
		if f.code != "RATE_LIMITED" || !f.transient || f.hint != want || f.msg != "cve-2021-44228: "+strings.TrimPrefix(f.msg, "cve-2021-44228: ") {
			t.Errorf("%+v, want the hint %q", f, want)
		}
	}
}

// The envelope is compact, always has errors and warnings, and each entry has
// the five keys of the error format with the argument as given.
func TestCVE_Envelope(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	log4j := nvd.fixture("primary-over-secondary.json")
	if code := h.cveRun(true, log4j); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if out := h.stdout.String(); !strings.HasPrefix(out, `{"data":[{"id":"CVE-2021-44228",`) ||
		!strings.HasSuffix(out, `}],"meta":{"count":1,"errors":[],"warnings":[]}}`+"\n") {
		t.Errorf("stdout %s", out)
	}
	h.cveEnvelope()
	h.partialOf(h.cveRun(true, log4j, " cve-2099-0001\t"), true, []string{" cve-2099-0001\t"}, true)
	env := h.cveEnvelope()
	if len(env.Meta.Errors) != 1 {
		t.Fatalf("errors %+v", env.Meta.Errors)
	}
	e := env.Meta.Errors[0]
	if e.Input != " cve-2099-0001\t" || e.Code != "NOT_FOUND" || e.Hint == nil || e.Transient {
		t.Errorf("entry %+v", e)
	}
	if !strings.Contains(h.stdout.String(), `{"error":"not in the NVD","code":"NOT_FOUND","hint":"check the ID; the NVD lists only published CVEs","input":" cve-2099-0001\t","transient":false}`) {
		t.Errorf("the entry is not the five keys in order: %s", h.stdout.String())
	}
}

// Human mode colours stdout from nyx's palette when it is a terminal.
func TestCVE_HumanColour(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	log4j := nvd.fixture("primary-over-secondary.json")
	h.stdoutTTY = true
	h.setenv("COLORTERM", "truecolor")
	h.setenv("COLUMNS", "70")
	if code := h.cveRun(false, log4j); code != 0 {
		t.Fatalf("exit %d", code)
	}
	d := palette.TrueColor
	at70 := func(depth palette.Depth) layout.Stream {
		return layout.Stream{Terminal: true, Depth: depth, Width: func() int { return 70 }}
	}
	bar := cve.Bar(at70(d), log4j, "CRITICAL", true)
	if !strings.HasPrefix(unmargined(t, h.stdout.String()), bar+"\n\n"+d.BoldText(palette.Semantic, "info", "Status & Dates")+"\n") {
		t.Errorf("stdout %q does not open with the severity's bar %q", h.stdout.String(), bar)
	}
	if w := layout.Measure(bar); w != 70 {
		t.Errorf("the bar is %d cells wide, want the COLUMNS of 70", w)
	}
	// With NO_COLOR the layout stays and no escape byte is written: the bar is the ID and [CRITICAL].
	h.setenv("NO_COLOR", "1")
	code := h.cveRun(false, log4j)
	first, _, _ := strings.Cut(unmargined(t, h.stdout.String()), "\n")
	if code != 0 || strings.Contains(h.stdout.String(), "\x1b") ||
		first != cve.Bar(at70(palette.None), log4j, "CRITICAL", true) || !strings.HasSuffix(first, "[CRITICAL]") {
		t.Errorf("NO_COLOR: exit %d, %q", code, h.stdout.String())
	}
}

// --fields returns the named fields plus id, in both modes; all is the default.
func TestCVE_Fields(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	log4j := nvd.fixture("primary-over-secondary.json")
	for _, spec := range []string{"id,cvss_score", "cvss_score", " cvss_score , "} {
		if code := h.cveRun(true, log4j, "--fields", spec); code != 0 {
			t.Fatalf("--fields %q: exit %d: %s", spec, code, h.stderr.String())
		}
		if got := h.stdout.String(); got != `{"data":[{"id":"CVE-2021-44228","cvss_score":10}],"meta":{"count":1,"errors":[],"warnings":[]}}`+"\n" {
			t.Errorf("--fields %q: %s", spec, got)
		}
		if code := h.cveRun(false, log4j, "--fields", spec); code != 0 || h.stdout.String() != "CVE-2021-44228\n\nCVSS Score\nBase Score: 10.0\n" {
			t.Errorf("--fields %q, human: exit %d, %q", spec, code, h.stdout.String())
		}
	}
	for _, args := range [][]string{{}, {"--fields", "all"}} {
		if code := h.cveRun(true, append([]string{log4j}, args...)...); code != 0 {
			t.Fatalf("exit %d", code)
		}
		if got := keysOf(t, h.cveEnvelope().Data[0]); !slices.Equal(got, cve.FieldNames()) {
			t.Errorf("%v: keys %v", args, got)
		}
	}
	for _, jsonMode := range modes {
		f := h.failed(h.cveRun(jsonMode, log4j, "--fields", "cvss,id"), 2, jsonMode)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, `"cvss"`) || !strings.Contains(f.hint, strings.Join(cve.FieldNames(), ", ")+", or all") {
			t.Errorf("unknown field: %+v", f)
		}
	}
	if len(nvd.requests()) != 8 {
		t.Errorf("%d requests, want 8: a usage error sends none", len(nvd.requests()))
	}
}

// The key is NVD_API_KEY, else keys.nvd from the config file; NVD_API_KEY wins.
func TestCVE_KeySources(t *testing.T) {
	t.Parallel()
	cfgDir := t.TempDir()
	cfg := writeFile(t, cfgDir, "nyx.yaml", "keys:\n  nvd: file-key\n")
	for _, c := range []struct {
		name string
		env  map[string]string
		args []string
		dflt string // the default config file's contents, "" for none
		want string
	}{
		{"NVD_API_KEY", map[string]string{"NVD_API_KEY": " env-key "}, nil, "", "env-key"},
		{"keys.nvd in --config", nil, []string{"--config", cfg}, "", "file-key"},
		{"keys.nvd in the default file", nil, nil, "keys:\n  nvd: default-key\n", "default-key"},
		{"NVD_API_KEY over keys.nvd", map[string]string{"NVD_API_KEY": "env-key"}, []string{"--config", cfg}, "", "env-key"},
		{"keys.nvd over NYX_KEYS_NVD", map[string]string{"NYX_KEYS_NVD": "nyx-key"}, []string{"--config", cfg}, "", "file-key"},
		{"no key", nil, nil, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			nvd := newNVD(t, h)
			for k, v := range c.env {
				h.setenv(k, v)
			}
			if c.dflt != "" {
				if err := os.MkdirAll(filepath.Join(h.env["XDG_CONFIG_HOME"], "nyx"), 0o700); err != nil {
					t.Fatal(err)
				}
				writeFile(t, filepath.Join(h.env["XDG_CONFIG_HOME"], "nyx"), "config.yaml", c.dflt)
			}
			id := nvd.fixture("rejected.json")
			if code := h.cveRun(true, append([]string{id}, c.args...)...); code != 0 {
				t.Fatalf("exit %d: %s", code, h.stderr.String())
			}
			if keys := nvd.apiKeys(); !slices.Equal(keys, []string{c.want}) {
				t.Errorf("apiKey headers %q, want %q", keys, c.want)
			}
		})
	}
}

const nyxKeysWarning = "NYX_KEYS_NVD is not read; set NVD_API_KEY instead"

// NYX_KEYS_NVD is not read: when it is set and no key was found, the call
// warns, in meta.warnings, on stderr, or in the hint of a failure.
func TestCVE_NYXKeysNVDWarns(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"NYX_KEYS_NVD", "NYX_KEYS_nvd", "NYX_KEYS_Nvd"} {
		h := newHarness(t)
		nvd := newNVD(t, h)
		h.setenv(name, "nyx-secret-value")
		id := nvd.fixture("rejected.json")
		if code := h.cveRun(true, id); code != 0 {
			t.Fatalf("%s: exit %d: %s", name, code, h.stderr.String())
		}
		if w := h.cveEnvelope().Meta.Warnings; !slices.Equal(w, []string{nyxKeysWarning}) || h.stderr.Len() != 0 {
			t.Errorf("%s: warnings %q, stderr %q", name, w, h.stderr.String())
		}
		if keys := nvd.apiKeys(); !slices.Equal(keys, []string{""}) {
			t.Errorf("%s: apiKey headers %q, want none", name, keys)
		}
		if code := h.cveRun(false, id); code != 0 || !slices.Equal(h.logMsgs("WARN"), []string{nyxKeysWarning}) {
			t.Errorf("%s, human: exit %d, stderr %q", name, code, h.stderr.String())
		}
		for _, jsonMode := range modes {
			f := h.failed(h.cveRun(jsonMode, id, "--fields", "bogus"), 2, jsonMode)
			if !strings.HasSuffix(f.hint, "; "+nyxKeysWarning) {
				t.Errorf("%s: a failure's hint %q lacks the warning", name, f.hint)
			}
			f = h.failed(h.cveRun(jsonMode, "CVE-2099-0001"), 3, jsonMode)
			if !strings.HasSuffix(f.hint, "; "+nyxKeysWarning) {
				t.Errorf("%s: a not-found's hint %q lacks the warning", name, f.hint)
			}
			// None returned, with mixed codes: human mode leaves stdout empty, so the hint warns;
			// --json writes the envelope, whose meta.warnings holds the warning.
			nvd.script("CVE-2099-0003", reply{status: 500})
			f = h.partialOf(h.cveRun(jsonMode, "CVE-2099-0001", "CVE-2099-0003"), jsonMode, []string{"CVE-2099-0001", "CVE-2099-0003"}, false)
			if strings.HasSuffix(f.hint, "; "+nyxKeysWarning) == jsonMode {
				t.Errorf("%s, json=%v: a PARTIAL with no records has the hint %q", name, jsonMode, f.hint)
			}
		}
		if all := h.stdout.String() + h.stderr.String(); strings.Contains(all, "nyx-secret-value") {
			t.Errorf("%s: the value was printed", name)
		}
	}
	// With a key found, there is nothing to warn about.
	h := newHarness(t)
	nvd := newNVD(t, h)
	h.setenv("NYX_KEYS_NVD", "nyx-key")
	h.setenv("NVD_API_KEY", "env-key")
	if code := h.cveRun(true, nvd.fixture("rejected.json")); code != 0 || len(h.cveEnvelope().Meta.Warnings) != 0 {
		t.Errorf("exit %d, %s", code, h.stdout.String())
	}
}

// The configuration is read as recon reads it: a bad file or NYX_* setting is
// a usage error, and a missing default file is not.
func TestCVE_Configuration(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		env  map[string]string
		args []string
		code int
	}{
		{"an unreadable config file", nil, []string{"--config", "/nonexistent/nyx.yaml"}, 2},
		{"an invalid config file", nil, []string{"--config", "BAD"}, 2},
		{"an invalid NYX_RATE_PER_HOST", map[string]string{"NYX_RATE_PER_HOST": "fast"}, nil, 2},
		{"no default file", nil, nil, 0},
	} {
		h := newHarness(t)
		nvd := newNVD(t, h)
		for k, v := range c.env {
			h.setenv(k, v)
		}
		args := slices.Clone(c.args)
		if len(args) > 1 && args[1] == "BAD" {
			args[1] = writeFile(t, t.TempDir(), "bad.yaml", "nonsense_key: 1\n")
		}
		id := nvd.fixture("rejected.json")
		if c.code == 0 {
			if code := h.cveRun(true, append([]string{id}, args...)...); code != 0 {
				t.Errorf("%s: exit %d: %s", c.name, code, h.stderr.String())
			}
			continue
		}
		if f := h.failed(h.cveRun(true, append([]string{id}, args...)...), 2, true); f.code != "INVALID_INPUT" {
			t.Errorf("%s: %+v", c.name, f)
		}
		if len(nvd.requests()) != 0 {
			t.Errorf("%s: the NVD was asked", c.name)
		}
	}
}

// keys.nvd is a valid key in the config file for every command.
func TestCVE_ReconAcceptsKeysNVD(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	cfg := writeFile(t, t.TempDir(), "nyx.yaml", "keys:\n  nvd: file-key\n")
	if code := h.exec("a.com", "--config", cfg); code != 0 {
		t.Errorf("exit %d: %s", code, h.stderr.String())
	}
}

const secretKey = "sekrit-nvd-key-0123"

// The key never appears in the output: on success, on a refused key, on a
// usage error, and on an NVD message that echoes it, in either mode and with --debug.
func TestCVE_KeyNeverPrinted(t *testing.T) {
	t.Parallel()
	for _, source := range []string{"env", "file"} {
		for _, jsonMode := range modes {
			h := newHarness(t)
			nvd := newNVD(t, h)
			var keyArgs []string
			if source == "env" {
				h.setenv("NVD_API_KEY", secretKey)
			} else {
				keyArgs = []string{"--config", writeFile(t, t.TempDir(), "nyx.yaml", "keys:\n  nvd: "+secretKey+"\n")}
			}
			ok := nvd.fixture("rejected.json")
			nvd.script("CVE-2021-0401", reply{status: 401})
			nvd.script("CVE-2021-0404", reply{status: 404, header: map[string]string{"message": "no such thing as " + secretKey}})
			for _, args := range [][]string{
				{ok, "--debug"},
				{"CVE-2021-0401", "--debug"},
				{"CVE-2021-0404", "--debug"},
				{ok, "--fields", secretKey},
				{secretKey, ok},
			} {
				code := h.cveRun(jsonMode, append(args, keyArgs...)...)
				if all := h.stdout.String() + h.stderr.String(); strings.Contains(all, secretKey) || code == 0 && args[0] != ok {
					t.Errorf("%s, json=%v, %v: exit %d, and the key was printed: %v\n%s", source, jsonMode, args, code, strings.Contains(all, secretKey), all)
				}
			}
			for _, k := range nvd.apiKeys() {
				if k != secretKey {
					t.Errorf("%s: the NVD saw the key %q", source, k)
				}
			}
		}
	}
}

// Unkeyed, five requests go at once and the sixth, whose slot in the window
// is past the deadline, fails at once as a transient rate limit; with a key
// all six go.
func TestCVE_Pacing(t *testing.T) {
	t.Parallel()
	ids := make([]string, 6)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-2024-%d", 2000+i)
	}
	h := newHarness(t)
	nvd := newNVD(t, h)
	for _, id := range ids {
		nvd.entry(id)
	}
	start := time.Now()
	f := h.partialOf(h.cveRun(true, append(slices.Clone(ids), "--timeout", "2s")...), true, []string{ids[5]}, true)
	if el := time.Since(start); el > 1500*time.Millisecond {
		t.Errorf("the call took %v; the sixth ID should fail at once", el)
	}
	env := h.cveEnvelope()
	if len(env.Data) != 5 || len(env.Meta.Errors) != 1 {
		t.Fatalf("envelope %+v", env)
	}
	e := env.Meta.Errors[0]
	if e.Code != "RATE_LIMITED" || !e.Transient || e.Hint == nil || !strings.HasPrefix(*e.Hint, "retry after ") || !strings.Contains(*e.Hint, "NVD_API_KEY") {
		t.Errorf("entry %+v (hint %v)", e, *e.Hint)
	}
	if !f.transient || !strings.HasPrefix(f.hint, "after ") || !strings.HasSuffix(f.hint, ", run: nyx cve "+ids[5]+" --json --timeout 2s") {
		t.Errorf("error %+v", f)
	}
	// Running the hint's command, once the window has room, gets the rest. Each call has its own
	// window, so here it has room at once.
	_, cmd, _ := strings.Cut(f.hint, "run: nyx ")
	if code := h.execRoot(strings.Fields(cmd)...); code != 0 || !slices.Equal(h.cveEnvelope().ids(), []string{ids[5]}) {
		t.Errorf("the hint's command: exit %d, %s", code, h.stdout.String())
	}

	h.setenv("NVD_API_KEY", "k")
	if code := h.cveRun(true, append(slices.Clone(ids), "--timeout", "2s")...); code != 0 || len(h.cveEnvelope().Data) != 6 {
		t.Errorf("keyed: exit %d, %s", code, h.stdout.String())
	}
}

// A request the NVD never answers ends at the deadline as a timeout.
func TestCVE_NeverAnswers(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		nvd := newNVD(t, h)
		nvd.hold = true
		start := time.Now()
		f := h.failed(h.cveRun(jsonMode, "CVE-2021-44228", "--timeout", "500ms"), 1, jsonMode)
		hint := "run: nyx cve CVE-2021-44228" + map[bool]string{true: " --json"}[jsonMode] + " --timeout 500ms, or raise --timeout"
		if f.code != "TIMEOUT" || !f.transient || f.msg != "CVE-2021-44228: no answer from the NVD before the deadline" || f.hint != hint {
			t.Errorf("%+v", f)
		}
		if el := time.Since(start); el > 2*time.Second {
			t.Errorf("the call took %v", el)
		}
	}
}

func TestCVE_BadTimeout(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"soon", "-1s", "0", "10"} {
		h := newHarness(t)
		nvd := newNVD(t, h)
		f := h.failed(h.cveRun(true, "CVE-2021-44228", "--timeout", v), 2, true)
		if f.code != "INVALID_INPUT" || !slices.Equal(f.inputOf("timeout"), []string{v}) {
			t.Errorf("--timeout %s: %+v", v, f)
		}
		if len(nvd.requests()) != 0 {
			t.Errorf("--timeout %s: the NVD was asked", v)
		}
	}
}

// A key the NVD refuses is AUTH_FAILED however the NVD says so, never not
// found, and it stops the batch.
func TestCVE_RefusedKey(t *testing.T) {
	t.Parallel()
	refusals := map[string]reply{
		"a 404 naming the key": {status: 404, header: map[string]string{"message": "Invalid apiKey."}},
		"a 401":                {status: 401},
	}
	for name, rp := range refusals {
		for _, jsonMode := range modes {
			h := newHarness(t)
			h.setenv("NVD_API_KEY", "bad")
			nvd := newNVD(t, h)
			var ids []string
			for i := range 10 {
				id := fmt.Sprintf("CVE-2024-%d", 3000+i)
				nvd.script(id, rp)
				ids = append(ids, id)
			}
			f := h.failed(h.cveRun(jsonMode, ids[0]), 1, jsonMode)
			if f.code != "AUTH_FAILED" || f.msg != ids[0]+": the NVD refused the API key" || f.hint != "check NVD_API_KEY" || f.transient {
				t.Errorf("%s: %+v", name, f)
			}
			before := len(nvd.requests())
			f = h.failed(h.cveRun(jsonMode, ids...), 1, jsonMode)
			if f.code != "AUTH_FAILED" || f.msg != "10 IDs: the NVD refused the API key" {
				t.Errorf("%s, 10 IDs: %+v", name, f)
			}
			if n := len(nvd.requests()) - before; n > 4 {
				t.Errorf("%s: %d requests reached the NVD after the key was refused, want at most 4", name, n)
			}
		}
	}
	// From the config file, the hint names it.
	h := newHarness(t)
	nvd := newNVD(t, h)
	cfg := writeFile(t, t.TempDir(), "nyx.yaml", "keys:\n  nvd: bad\n")
	nvd.script("CVE-2024-3000", reply{status: 401})
	if f := h.failed(h.cveRun(true, "CVE-2024-3000", "--config", cfg), 1, true); f.hint != "check keys.nvd in "+cfg {
		t.Errorf("from the file: %+v", f)
	}
	// A 404 that does not name the key is the NVD's error, not a not-found.
	nvd.script("CVE-2024-3001", reply{status: 404, header: map[string]string{"message": "Invalid cveId parameter."}})
	if f := h.failed(h.cveRun(true, "CVE-2024-3001"), 1, true); f.code != "UPSTREAM_ERROR" || !strings.Contains(f.msg, "Invalid cveId parameter.") {
		t.Errorf("a plain 404: %+v", f)
	}
}

// One ID failing in a batch: a 503 that persists is a transient upstream
// error and the others are returned.
func TestCVE_OneUpstreamFailure(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	log4j := nvd.fixture("primary-over-secondary.json")
	nvd.script("CVE-2024-0503", reply{status: 503, header: map[string]string{"Retry-After": "0"}})
	f := h.partialOf(h.cveRun(true, "CVE-2024-0503", log4j), true, []string{"CVE-2024-0503"}, true)
	if !f.transient || f.hint != "run: nyx cve CVE-2024-0503 --json" {
		t.Errorf("%+v", f)
	}
	env := h.cveEnvelope()
	if !slices.Equal(env.ids(), []string{log4j}) || env.Meta.Errors[0].Code != "UPSTREAM_ERROR" || !env.Meta.Errors[0].Transient {
		t.Errorf("envelope %+v", env)
	}
	if n := slices.Index(nvd.requests(), "CVE-2024-0503"); n < 0 || len(nvd.requests()) != 4 {
		t.Errorf("requests %v, want the 503 tried three times", nvd.requests())
	}
}

// --debug writes one DEBUG line per attempt and never changes stdout.
func TestCVE_Debug(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	log4j := nvd.fixture("primary-over-secondary.json")
	if code := h.cveRun(true, log4j); code != 0 {
		t.Fatal(code)
	}
	plain := h.stdout.String()
	if code := h.cveRun(true, log4j, "--debug"); code != 0 || h.stdout.String() != plain {
		t.Errorf("--debug changed stdout: %q", h.stdout.String())
	}
	if lines := h.debugLines(); len(lines) != 1 || !strings.Contains(lines[0], log4j) || !strings.Contains(lines[0], "200") {
		t.Errorf("debug lines %q", lines)
	}
}

// A signal while a request is in flight ends the call as interrupted, with
// nothing on stdout and the key in neither stream.
func TestCVE_Signal(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		h.setenv("NVD_API_KEY", secretKey)
		h.signals = make(chan os.Signal, 2)
		nvd := newNVD(t, h)
		nvd.hold = true
		go func() {
			<-nvd.arrived
			h.signals <- os.Interrupt
		}()
		start := time.Now()
		f := h.failed(h.cveRun(jsonMode, "CVE-2021-44228", "CVE-2024-3094", "--debug"), 130, jsonMode)
		if f.code != "INTERRUPTED" {
			t.Errorf("%+v", f)
		}
		if strings.Contains(h.stderr.String(), secretKey) {
			t.Error("the key was printed")
		}
		if el := time.Since(start); el > 5*time.Second {
			t.Errorf("the call took %v", el)
		}
	}
}

// A signal after one ID has its record and while another's request is in
// flight still ends the call as interrupted, with nothing on stdout: the
// record is not written as a partial result.
func TestCVE_SignalAfterARecord(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		h.signals = make(chan os.Signal, 2)
		nvd := newNVD(t, h)
		found := nvd.fixture("rejected.json")
		nvd.held = map[string]bool{"CVE-2024-3094": true}
		go func() {
			<-nvd.arrived
			for nvd.inFlightNow() != 1 || len(nvd.requests()) != 2 {
				time.Sleep(5 * time.Millisecond)
			}
			time.Sleep(50 * time.Millisecond) // the found record's answer is read
			h.signals <- os.Interrupt
		}()
		f := h.failed(h.cveRun(jsonMode, found, "CVE-2024-3094"), 130, jsonMode)
		if f.code != "INTERRUPTED" {
			t.Errorf("%+v", f)
		}
	}
}

// cve keeps no state: the same call against the same NVD gives the same bytes.
func TestCVE_RerunIsTheSame(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		nvd := newNVD(t, h)
		args := []string{nvd.fixture("primary-over-secondary.json"), "CVE-2099-0001", nvd.fixture("weaknesses.json")}
		code := h.cveRun(jsonMode, args...)
		out, errOut := h.stdout.String(), h.stderr.String()
		if again := h.cveRun(jsonMode, args...); again != code || h.stdout.String() != out || h.stderr.String() != errOut {
			t.Errorf("json=%v: a second call differs", jsonMode)
		}
	}
}

// nyx cve contacts only the NVD and creates nothing, in the output directory
// or the working directory.
func TestCVE_TouchesNothing(t *testing.T) { //nolint:paralleltest // it changes the working directory, which a parallel test cannot
	h := newHarness(t)
	nvd := newNVD(t, h)
	cwd := emptyDir(t)
	if code := h.cveRun(true, nvd.fixture("rejected.json"), "CVE-2099-0001"); code != 7 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	h.untouched()
	cwd()
}

// The root help lists cve with its flags, an example that passes --json and
// the field names; nyx help cve is nyx cve --help.
func TestCVE_Help(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if code := h.execRoot("--help"); code != 0 {
		t.Fatal(code)
	}
	root := h.stdout.String()
	fieldsLine := "Fields accepted by --fields: " + strings.Join(cve.FieldNames(), ", ") + ", all"
	for _, want := range []string{
		"  nyx cve CVE-2021-44228 CVE-2024-3094 --json\n", "nyx cve <CVE-ID>... [flags]", "Example: nyx cve CVE-2021-44228 CVE-2024-3094 --json",
		"cve flags:", "--fields", "--timeout duration", "--config", fieldsLine,
	} {
		if !strings.Contains(root, want) {
			t.Errorf("the root help lacks %q", want)
		}
	}
	_, cveRef, _ := strings.Cut(root, "nyx cve <CVE-ID>")
	cveRef, _, _ = strings.Cut(cveRef, "\n\n")
	for _, tuning := range []string{"--output-dir", "--rate-per-host", "--engagement"} {
		if strings.Contains(cveRef, tuning) {
			t.Errorf("cve's entry lists %s", tuning)
		}
	}
	if code := h.execRoot("cve", "--help"); code != 0 {
		t.Fatal(code)
	}
	own := h.stdout.String()
	for _, l := range exampleLines(t, own) {
		if !strings.HasPrefix(strings.TrimSpace(l), "nyx cve") || !strings.Contains(l, "--json") {
			t.Errorf("example %q is not a call of nyx cve that passes --json", l)
		}
	}
	if !strings.Contains(own, fieldsLine) || !strings.Contains(own, "(default 60s)") || lastLine(own) != exitCodesLine {
		t.Errorf("nyx cve --help:\n%s", own)
	}
	if code := h.execRoot("help", "cve"); code != 0 || h.stdout.String() != own {
		t.Errorf("nyx help cve differs from nyx cve --help")
	}
	// The shared flags read true for cve.
	for flag, ok := range map[string]func(string) bool{
		"--json":  func(l string) bool { return !strings.Contains(l, "recon") },
		"--debug": func(l string) bool { return strings.Contains(l, "cve") },
	} {
		line := ""
		for l := range strings.SplitSeq(own, "\n") {
			if strings.Contains(l, flag+" ") {
				line = l
			}
		}
		if !ok(line) {
			t.Errorf("%s does not read true for cve: %q", flag, line)
		}
	}
}

// The NVD key never reaches the human output, whole or in part, even inside a long word
// that a terminal's layout breaks or split by a character that cleaning removes.
func TestCVE_HumanOutputRedactsTheKey(t *testing.T) {
	t.Parallel()
	const key = "nvd-Qx7Rt2Zk9Vb4Nm8Lp3Zz"
	for _, terminal := range []bool{false, true} {
		h := newHarness(t)
		h.setenv("NVD_API_KEY", key)
		h.setenv("COLUMNS", "80")
		h.stdoutTTY = terminal
		nvd := newNVD(t, h)
		desc := strings.Repeat("a", 70) + key + strings.Repeat("b", 70) + " and " + key[:8] + `\u001b[31m` + key[8:]
		nvd.mu.Lock()
		nvd.entries["CVE-2024-1000"] = `{"id":"CVE-2024-1000","vulnStatus":"Analyzed","published":"2024-01-01T00:00:00.000","lastModified":"2024-01-02T00:00:00.000",` +
			`"descriptions":[{"lang":"en","value":"` + desc + `"}],"references":[]}`
		nvd.mu.Unlock()
		if code := h.cveRun(false, "CVE-2024-1000"); code != 0 {
			t.Fatalf("terminal %v: exit %d: %s", terminal, code, h.stderr.String())
		}
		out := h.stdout.String()
		for i := 0; i+8 <= len(key); i++ {
			if strings.Contains(out, key[i:i+8]) {
				t.Errorf("terminal %v: %q of the key reached stdout:\n%s", terminal, key[i:i+8], out)
				break
			}
		}
		if strings.Count(out, "****") < 2 {
			t.Errorf("terminal %v: both keys should be masked:\n%s", terminal, out)
		}
	}
}
