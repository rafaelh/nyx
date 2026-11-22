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

// defaultFieldNames are the keys of a record when --fields is not given: every field but the two lists.
func defaultFieldNames() []string {
	return slices.DeleteFunc(cve.FieldNames(), func(n string) bool { return n == "affected_products" || n == "references" })
}

// withCounts is the JSON of a record whose lists are empty with a count in front
// of each, as every field of it is written.
func withCounts(record string) string {
	return strings.NewReplacer(`"affected_products":[]`, `"affected_products_count":{"total":0},"affected_products":[]`,
		`"references":[]`, `"references_count":{"total":0},"references":[]`).Replace(record)
}

// withoutLists is the JSON of a record whose lists are empty as it is written
// when the lists are left out: a count in place of each.
func withoutLists(record string) string {
	return strings.NewReplacer(`"affected_products":[]`, `"affected_products_count":{"total":0}`,
		`"references":[]`, `"references_count":{"total":0}`).Replace(record)
}

// unitText is the records of fixtures as the cve tool lays them out, at depth None, for a
// --fields value; "" here is the default, which --fields "" is not.
func unitText(t *testing.T, spec string, fixtures ...string) string {
	t.Helper()
	var recs []cve.Record
	for _, name := range fixtures {
		_, e := loadFixture(t, name)
		recs = append(recs, cve.FromNVD(&e))
	}
	f := cve.DefaultFields()
	if spec != "" {
		var unknown []string
		if f, unknown = cve.Select(spec); unknown != nil {
			t.Fatal(unknown)
		}
	}
	projected := make([]cve.Projected, len(recs))
	for i, r := range recs {
		projected[i] = cve.View{Fields: f}.Project(r)
	}
	var out bytes.Buffer
	if err := cve.Render(&out, projected, layout.Stream{}, nil, time.UTC); err != nil {
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
		Hint     *string     `json:"hint"`
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
	if !strings.Contains(line, `,"hint":`) {
		h.t.Errorf("meta has no hint key: %s", line)
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
	if len(env.Data) != 2 || string(env.Data[0]) != withoutLists(unitJSON(t, "primary-over-secondary.json")) || string(env.Data[1]) != withoutLists(unitJSON(t, "rejected.json")) {
		t.Errorf("data %s", env.Data)
	}
	// Every field is the unit record, with a count in front of each list.
	if code := h.cveRun(true, log4j, rejected, "--fields", "all"); code != 0 {
		t.Fatalf("--fields all: exit %d", code)
	}
	if env := h.cveEnvelope(); len(env.Data) != 2 || string(env.Data[0]) != withCounts(unitJSON(t, "primary-over-secondary.json")) || string(env.Data[1]) != withCounts(unitJSON(t, "rejected.json")) {
		t.Errorf("--fields all: data %s", env.Data)
	}
	if !strings.Contains(string(env.Data[1]), `"status":"Rejected"`) || len(env.Meta.Errors) != 0 {
		t.Errorf("the rejected CVE: %s, errors %v", env.Data[1], env.Meta.Errors)
	}
	// Without --json the records are the cve tool's layout.
	if code := h.cveRun(false, log4j, rejected); code != 0 || h.stderr.Len() != 0 {
		t.Fatalf("human: exit %d, stderr %q", code, h.stderr.String())
	}
	if want := unitText(t, "", "primary-over-secondary.json", "rejected.json"); h.stdout.String() != want {
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
		t.Run(fmt.Sprint("json=", jsonMode), func(t *testing.T) {
			t.Parallel()
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
		})
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

// A bad --limit and a bad --match are reported with every other problem, in the one
// error, before stdin is read or the NVD is asked.
func TestCVE_LimitAndMatchProblemsTogether(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		nvd := newNVD(t, h)
		h.stdin = readSpy{t}
		f := h.failed(h.cveRun(jsonMode, "-", "--fields", "bogus", "--limit", "0", "--match", "  ", "--timeout", "soon"), 2, jsonMode)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, `"bogus"`) || !strings.Contains(f.msg, "--limit") || !strings.Contains(f.msg, "--match") || !strings.Contains(f.msg, "timeout") {
			t.Errorf("json=%v: %+v", jsonMode, f)
		}
		if jsonMode {
			for name, want := range map[string][]string{"fields": {"bogus"}, "limit": {"0"}, "match": {"  "}, "timeout": {"soon"}} {
				if got := f.inputOf(name); !slices.Equal(got, want) {
					t.Errorf("input %q = %v, want %v", name, got, want)
				}
			}
		}
		if len(nvd.requests()) != 0 {
			t.Errorf("the NVD was asked %v", nvd.requests())
		}
	}
	// The same, with a --limit that repeats and a --match with nothing in it to show.
	h := newHarness(t)
	nvd := newNVD(t, h)
	h.stdin = readSpy{t}
	f := h.failed(h.cveRun(true, "-", "--limit", "1", "--limit", "2", "--match", "a", "--match", "b", "--fields", "cvss_score"), 2, true)
	if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "--limit was given more than once") || !strings.Contains(f.msg, "--match was given more than once") ||
		len(f.inputOf("limit")) != 1 || len(f.inputOf("match")) != 1 || len(nvd.requests()) != 0 {
		t.Errorf("repeated flags: %+v, requests %v", f, nvd.requests())
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
	if h.stdout.String() != unitText(t, "", "primary-over-secondary.json") {
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
		!strings.HasSuffix(out, `}],"meta":{"count":1,"errors":[],"warnings":[],"hint":null}}`+"\n") {
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

// --fields returns the named fields plus id, in both modes; the default is every field but the two lists.
func TestCVE_Fields(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	log4j := nvd.fixture("primary-over-secondary.json")
	for _, spec := range []string{"id,cvss_score", "cvss_score", " cvss_score , "} {
		if code := h.cveRun(true, log4j, "--fields", spec); code != 0 {
			t.Fatalf("--fields %q: exit %d: %s", spec, code, h.stderr.String())
		}
		if got := h.stdout.String(); got != `{"data":[{"id":"CVE-2021-44228","cvss_score":10}],"meta":{"count":1,"errors":[],"warnings":[],"hint":null}}`+"\n" {
			t.Errorf("--fields %q: %s", spec, got)
		}
		if code := h.cveRun(false, log4j, "--fields", spec); code != 0 || h.stdout.String() != "CVE-2021-44228\n\nCVSS Score\nBase Score: 10.0\n" {
			t.Errorf("--fields %q, human: exit %d, %q", spec, code, h.stdout.String())
		}
	}
	// The default leaves out the two lists, and all has every field.
	defaultNames := defaultFieldNames()
	for args, want := range map[string][]string{"": defaultNames, "all": cve.FieldNames()} {
		argv := []string{log4j}
		if args != "" {
			argv = append(argv, "--fields", args)
		}
		if code := h.cveRun(true, argv...); code != 0 {
			t.Fatalf("exit %d", code)
		}
		if got := keysOf(t, h.cveEnvelope().Data[0]); !slices.Equal(got, want) {
			t.Errorf("%q: keys %v, want %v", args, got, want)
		}
	}
	if code := h.cveRun(true, log4j, "--fields", ""); code != 0 || !strings.HasPrefix(h.stdout.String(), `{"data":[{"id":"CVE-2021-44228"}],`) {
		t.Errorf(`--fields "": exit %d, %s`, code, h.stdout.String())
	}
	for _, jsonMode := range modes {
		f := h.failed(h.cveRun(jsonMode, log4j, "--fields", "cvss,id"), 2, jsonMode)
		if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, `"cvss"`) || !strings.Contains(f.hint, strings.Join(cve.FieldNames(), ", ")+", or all") {
			t.Errorf("unknown field: %+v", f)
		}
	}
	if len(nvd.requests()) != 9 {
		t.Errorf("%d requests, want 9: a usage error sends none", len(nvd.requests()))
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
// all six go. The deadline is far inside the 30 second window, and the time limit far
// short of the deadline, so only waiting for the deadline can fail it on a busy machine.
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
	code := h.cveRun(true, append(slices.Clone(ids), "--timeout", "20s")...)
	if el := time.Since(start); el > 10*time.Second {
		t.Errorf("the call took %v; the sixth request should fail at once", el)
	}
	env := h.cveEnvelope()
	if len(env.Data) != 5 || len(env.Meta.Errors) != 1 {
		t.Fatalf("envelope %+v", env)
	}
	// The workers run together, so which ID gets the sixth slot is up to the scheduler: it is the
	// one that is missing.
	var late string
	for _, id := range ids {
		if !slices.Contains(env.ids(), id) {
			late = id
		}
	}
	if late == "" {
		t.Fatalf("every ID was returned: %+v", env)
	}
	f := h.partialOf(code, true, []string{late}, true)
	e := env.Meta.Errors[0]
	if e.Code != "RATE_LIMITED" || !e.Transient || e.Hint == nil || !strings.HasPrefix(*e.Hint, "retry after ") || !strings.Contains(*e.Hint, "NVD_API_KEY") {
		t.Errorf("entry %+v (hint %v)", e, *e.Hint)
	}
	if !f.transient || !strings.HasPrefix(f.hint, "after ") || !strings.HasSuffix(f.hint, ", run: nyx cve "+late+" --json --timeout 20s") {
		t.Errorf("error %+v", f)
	}
	// Running the hint's command, once the window has room, gets the rest. Each call has its own
	// window, so here it has room at once.
	_, cmd, _ := strings.Cut(f.hint, "run: nyx ")
	if code := h.execRoot(strings.Fields(cmd)...); code != 0 || !slices.Equal(h.cveEnvelope().ids(), []string{late}) {
		t.Errorf("the hint's command: exit %d, %s", code, h.stdout.String())
	}

	h.setenv("NVD_API_KEY", "k")
	if code := h.cveRun(true, append(slices.Clone(ids), "--timeout", "20s")...); code != 0 || len(h.cveEnvelope().Data) != 6 {
		t.Errorf("keyed: exit %d, %s", code, h.stdout.String())
	}
}

// A request the NVD never answers ends at the deadline as a timeout.
func TestCVE_NeverAnswers(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		t.Run(fmt.Sprint("json=", jsonMode), func(t *testing.T) {
			t.Parallel()
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
		})
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
		ids := []string{nvd.fixture("primary-over-secondary.json"), "CVE-2099-0001", nvd.fixture("weaknesses.json"), nvd.fixture("long-lists.json")}
		for _, flags := range [][]string{nil, {"--fields", "affected_products,references", "--match", "log4j", "--limit", "1"}} {
			args := slices.Concat(ids, flags)
			code := h.cveRun(jsonMode, args...)
			out, errOut := h.stdout.String(), h.stderr.String()
			if again := h.cveRun(jsonMode, args...); again != code || h.stdout.String() != out || h.stderr.String() != errOut {
				t.Errorf("json=%v, %v: a second call differs", jsonMode, flags)
			}
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
	// The footer lists the counts, --fields describes the new default and no flag says all is it.
	if !strings.Contains(fieldsLine, "affected_products_count, affected_products, references_count, references") {
		t.Errorf("the field names lack the counts: %s", fieldsLine)
	}
	checkFlagLines(t, own)
	if !strings.Contains(own, "nyx cve CVE-2021-44228 --fields affected_products --match log4j --limit 10 --json") {
		t.Errorf("nyx cve --help lacks the example of --match and --limit:\n%s", own)
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

// checkFlagLines checks the help's lines for --fields, --limit and --match: --fields describes the new
// default and none of the three reads as if it had one.
func checkFlagLines(t *testing.T, help string) {
	t.Helper()
	for l := range strings.SplitSeq(help, "\n") {
		switch flag, _, _ := strings.Cut(strings.TrimSpace(l), " "); flag {
		case "--fields":
			if strings.Contains(l, `(default "all")`) || !strings.Contains(l, "affected_products") || !strings.Contains(l, "references") {
				t.Errorf("--fields reads %q", l)
			}
		case "--limit", "--match":
			if strings.Contains(l, "(default") {
				t.Errorf("%q reads as if it had a default", l)
			}
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

const (
	hintBoth     = "use --fields affected_products,references (or --fields all) to list them"
	hintProducts = "use --fields affected_products (or --fields all) to list them"
	hintRefs     = "use --fields references (or --fields all) to list them"

	// The heading of each list in human mode when its count is shown and it has entries.
	tippedProducts = "Affected Products (--fields affected_products to show)"
	tippedRefs     = "References (--fields references to show)"
)

// recordOf is a record of data as its keys and their JSON.
func recordOf(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// listOf is the entries of a list key of a record.
func listOf(t *testing.T, rec map[string]json.RawMessage, key string) []json.RawMessage {
	t.Helper()
	var l []json.RawMessage
	if err := json.Unmarshal(rec[key], &l); err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return l
}

// The default has every field but the two lists, with the number of entries of each, and
// is no longer for a record with long lists than for one with an entry in each.
func TestCVE_DefaultDoesNotGrowWithTheLists(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	long, one := nvd.fixture("long-lists.json"), nvd.fixture("one-each.json")
	defaultNames := defaultFieldNames()
	for id, want := range map[string][2]string{long: {`{"total":6}`, `{"total":5}`}, one: {`{"total":1}`, `{"total":1}`}} {
		if code := h.cveRun(true, id); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		raw := h.cveEnvelope().Data[0]
		rec := recordOf(t, raw)
		if got := keysOf(t, raw); !slices.Equal(got, defaultNames) {
			t.Errorf("%s: keys %v", id, got)
		}
		if string(rec["affected_products_count"]) != want[0] || string(rec["references_count"]) != want[1] {
			t.Errorf("%s: counts %s and %s, want %v", id, rec["affected_products_count"], rec["references_count"], want)
		}
		if strings.Contains(string(raw), "log4j") || strings.Contains(string(raw), "https://") {
			t.Errorf("%s: an entry of a list is in the default record: %s", id, raw)
		}
	}
	lines := map[string]int{}
	for _, id := range []string{long, one} {
		if code := h.cveRun(false, id); code != 0 {
			t.Fatalf("human: exit %d: %s", code, h.stderr.String())
		}
		out := h.stdout.String()
		lines[id] = strings.Count(out, "\n")
		for _, bad := range []string{"- ", "https://", "log4j"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: %q is in the default human output:\n%s", id, bad, out)
			}
		}
		for _, want := range []string{tippedProducts + "\n", tippedRefs + "\n"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: no %q section:\n%s", id, want, out)
			}
		}
	}
	if lines[long] != lines[one] {
		t.Errorf("the default is %d lines for long lists and %d for one entry each", lines[long], lines[one])
	}
	if code := h.cveRun(false, long); code != 0 || !strings.Contains(h.stdout.String(), tippedProducts+"\n6 listed\n") || !strings.Contains(h.stdout.String(), tippedRefs+"\n5 listed\n") {
		t.Errorf("human: exit %d\n%s", code, h.stdout.String())
	}
}

// The counts can be named like any field, a list brings its count, all has every
// field and an empty --fields has the id alone.
func TestCVE_FieldsWithCounts(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	long := nvd.fixture("long-lists.json")
	for _, c := range []struct {
		spec string
		keys []string
		refs string
	}{
		{"references_count", []string{"id", "references_count"}, ""},
		{"affected_products_count,references_count", []string{"id", "affected_products_count", "references_count"}, ""},
		{"references", []string{"id", "references_count", "references"}, `{"total":5}`},
		{"affected_products,references", []string{"id", "affected_products_count", "affected_products", "references_count", "references"}, `{"total":5}`},
		{"all", cve.FieldNames(), `{"total":5}`},
		{"", []string{"id"}, ""},
	} {
		if code := h.cveRun(true, long, "--fields", c.spec); code != 0 {
			t.Fatalf("--fields %q: exit %d: %s", c.spec, code, h.stderr.String())
		}
		raw := h.cveEnvelope().Data[0]
		keys := keysOf(t, raw)
		if !slices.Equal(keys, c.keys) {
			t.Errorf("--fields %q: keys %v, want %v", c.spec, keys, c.keys)
		}
		if got := string(recordOf(t, raw)["references_count"]); c.refs != "" && got != c.refs {
			t.Errorf("--fields %q: references_count %s", c.spec, got)
		}
	}
	// In human mode a count alone and a list with its number read as the layout says.
	if code := h.cveRun(false, long, "--fields", "references_count"); code != 0 || h.stdout.String() != "CVE-2023-0100\n\n"+tippedRefs+"\n5 listed\n" {
		t.Errorf("a count alone: exit %d, %q", code, h.stdout.String())
	}
	if code := h.cveRun(false, long, "--fields", "references", "--limit", "2"); code != 0 || !strings.Contains(h.stdout.String(), "References (5)\n") {
		t.Errorf("a list: exit %d, %q", code, h.stdout.String())
	}
}

// A hint on how to see the lists is in meta.hint under --json and, in human mode, the flag
// after the heading of each list it names whose count is shown, with nothing on stderr; it
// says nothing when there is nothing to list.
func TestCVE_ListHint(t *testing.T) {
	t.Parallel()
	both, products, refs := []string{"affected_products", "references"}, []string{"affected_products"}, []string{"references"}
	for _, c := range []struct {
		name     string
		ids      []string // fixtures
		flags    []string
		want     string   // "" for no hint
		tips     []string // the lists whose heading names their flag in human mode
		wantCode int
	}{
		{"the default names both", []string{"long-lists.json"}, nil, hintBoth, both, 0},
		{"the id alone names both, with no heading to name them in", []string{"long-lists.json"}, []string{"--fields", "id"}, hintBoth, nil, 0},
		{"all says nothing", []string{"long-lists.json"}, []string{"--fields", "all"}, "", nil, 0},
		{"both lists says nothing", []string{"long-lists.json"}, []string{"--fields", "affected_products,references"}, "", nil, 0},
		{"one list names the other", []string{"long-lists.json"}, []string{"--fields", "affected_products"}, hintRefs, nil, 0},
		{"one list and the other's count names the other", []string{"long-lists.json"}, []string{"--fields", "affected_products,references_count"}, hintRefs, refs, 0},
		{"lists with no entries in any record", []string{"rejected.json", "primary-over-secondary.json"}, nil, "", nil, 0},
		{"a list with entries in one record", []string{"rejected.json", "references.json"}, nil, hintRefs, refs, 0},
		{"a match that matches only references", []string{"long-lists.json"}, []string{"--match", "psirt"}, hintRefs, refs, 0},
		{"a match that matches only products", []string{"long-lists.json"}, []string{"--match", "tomcat"}, hintProducts, products, 0},
		{"a match that matches nothing", []string{"long-lists.json"}, []string{"--match", "zzz"}, "", nil, 0},
	} {
		for _, jsonMode := range modes {
			h := newHarness(t)
			nvd := newNVD(t, h)
			args := slices.Clone(c.flags)
			for _, f := range c.ids {
				args = append([]string{nvd.fixture(f)}, args...)
			}
			if code := h.cveRun(jsonMode, args...); code != c.wantCode {
				t.Fatalf("%s, json=%v: exit %d: %s", c.name, jsonMode, code, h.stderr.String())
			}
			if jsonMode {
				checkJSONHint(t, h, c.name, c.want)
			} else {
				checkHumanHint(t, h, c.name, c.tips)
			}
		}
	}
}

// checkJSONHint checks meta.hint is want (null for ""), and that nothing else carried it.
func checkJSONHint(t *testing.T, h *harness, name, want string) {
	t.Helper()
	hint := h.cveEnvelope().Meta.Hint
	if want == "" && hint != nil || want != "" && (hint == nil || *hint != want) {
		t.Errorf("%s: meta.hint %v, want %q", name, hint, want)
	}
	if h.stderr.Len() != 0 {
		t.Errorf("%s: --json wrote %q to stderr", name, h.stderr.String())
	}
}

// checkHumanHint checks that each of the lists tips, and no other, has its flag after its
// heading on stdout, and that nothing is said on stderr.
func checkHumanHint(t *testing.T, h *harness, name string, tips []string) {
	t.Helper()
	out := h.stdout.String()
	for _, l := range []struct{ name, heading string }{
		{"affected_products", tippedProducts},
		{"references", tippedRefs},
	} {
		if named, tipped := slices.Contains(tips, l.name), strings.Contains(out, l.heading+"\n"); named != tipped {
			t.Errorf("%s: %s tipped %v, want %v:\n%s", name, l.name, tipped, named, out)
		}
	}
	if h.stderr.Len() != 0 {
		t.Errorf("%s: wrote %q to stderr", name, h.stderr.String())
	}
	if strings.Contains(out, "use --fields") {
		t.Errorf("%s: the JSON hint is on stdout:\n%s", name, out)
	}
}

// A batch with a failure still says how to see the lists of the records that came
// back; with no record back there is nothing to say.
func TestCVE_ListHintInABatch(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		nvd := newNVD(t, h)
		long := nvd.fixture("long-lists.json")
		nvd.script("CVE-2099-0003", reply{status: 500})
		h.partialOf(h.cveRun(jsonMode, long, cveGone), jsonMode, []string{cveGone}, true)
		if jsonMode {
			if hint := h.cveEnvelope().Meta.Hint; hint == nil || *hint != hintBoth {
				t.Errorf("PARTIAL: meta.hint %v", hint)
			}
		} else {
			if strings.Contains(h.stderr.String(), "use --fields") || !strings.Contains(h.stdout.String(), tippedProducts+"\n") {
				t.Errorf("PARTIAL: the flag should be after the heading, not on stderr:\n%s\n%s", h.stdout.String(), h.stderr.String())
			}
		}
		// No record came back: mixed codes is a PARTIAL with nothing to list, and there is no line.
		h.partialOf(h.cveRun(jsonMode, cveGone, "CVE-2099-0003"), jsonMode, []string{cveGone, "CVE-2099-0003"}, false)
		if jsonMode {
			if hint := h.cveEnvelope().Meta.Hint; hint != nil {
				t.Errorf("no record: meta.hint %q", *hint)
			}
		} else if strings.Contains(h.stderr.String(), "use --fields") || strings.Contains(h.stdout.String(), "(--fields") {
			t.Errorf("no record: %s", h.stderr.String())
		}
	}
}

// --limit keeps the first entries of each shown list in the NVD's order, and says how many it left out.
func TestCVE_Limit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	long := nvd.fixture("long-lists.json")
	if code := h.cveRun(true, long, "--fields", "affected_products,references", "--limit", "2"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	rec := recordOf(t, h.cveEnvelope().Data[0])
	products, refs := listOf(t, rec, "affected_products"), listOf(t, rec, "references")
	if len(products) != 2 || len(refs) != 2 || !strings.Contains(string(products[1]), `"version_start_including":"2.4.0"`) || !strings.Contains(string(refs[1]), "github.com") {
		t.Errorf("--limit 2 kept %s and %s", products, refs)
	}
	if string(rec["affected_products_count"]) != `{"total":6,"omitted":4}` || string(rec["references_count"]) != `{"total":5,"omitted":3}` {
		t.Errorf("counts %s and %s", rec["affected_products_count"], rec["references_count"])
	}
	// A limit above a list's length leaves none out, and says so as 0 in JSON and not at all in human mode.
	if code := h.cveRun(true, long, "--fields", "affected_products,references", "--limit", "5"); code != 0 {
		t.Fatal(code)
	}
	rec = recordOf(t, h.cveEnvelope().Data[0])
	if string(rec["affected_products_count"]) != `{"total":6,"omitted":1}` || string(rec["references_count"]) != `{"total":5,"omitted":0}` || len(listOf(t, rec, "references")) != 5 {
		t.Errorf("--limit 5: counts %s and %s", rec["affected_products_count"], rec["references_count"])
	}
	if code := h.cveRun(false, long, "--fields", "affected_products,references", "--limit", "5"); code != 0 ||
		strings.Count(h.stdout.String(), "more not shown") != 1 || !strings.Contains(h.stdout.String(), "1 more not shown\n") {
		t.Errorf("--limit 5, human: exit %d\n%s", code, h.stdout.String())
	}
	// Without --limit every entry is shown, and the counts have no omitted key.
	if code := h.cveRun(true, long, "--fields", "affected_products,references"); code != 0 {
		t.Fatal(code)
	}
	rec = recordOf(t, h.cveEnvelope().Data[0])
	if len(listOf(t, rec, "affected_products")) != 6 || string(rec["affected_products_count"]) != `{"total":6}` {
		t.Errorf("no limit: %s", rec["affected_products_count"])
	}
	if code := h.cveRun(false, long, "--fields", "affected_products,references"); code != 0 || strings.Contains(h.stdout.String(), "not shown") {
		t.Errorf("no limit, human: exit %d\n%s", code, h.stdout.String())
	}
	// Only the shown list has an omitted count.
	if code := h.cveRun(true, long, "--fields", "references,affected_products_count", "--limit", "2"); code != 0 {
		t.Fatal(code)
	}
	if rec = recordOf(t, h.cveEnvelope().Data[0]); string(rec["affected_products_count"]) != `{"total":6}` || string(rec["references_count"]) != `{"total":5,"omitted":3}` {
		t.Errorf("one list shown: %s and %s", rec["affected_products_count"], rec["references_count"])
	}
}

// A --limit that is not a positive integer, or is given twice, or has no list to cut, is a usage error.
func TestCVE_BadLimit(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		args []string
		hint string // what the hint holds, "" for any
	}{
		{"zero", []string{"--limit", "0", "--fields", "references"}, ""},
		{"negative", []string{"--limit", "-1", "--fields", "references"}, ""},
		{"a word", []string{"--limit", "abc", "--fields", "references"}, ""},
		{"a fraction", []string{"--limit", "1.5", "--fields", "references"}, ""},
		{"empty", []string{"--limit", "", "--fields", "references"}, ""},
		{"too long for an int", []string{"--limit", "99999999999999999999", "--fields", "references"}, ""},
		{"twice", []string{"--limit", "1", "--limit", "2", "--fields", "references"}, ""},
		{"with the default fields", []string{"--limit", "2"}, "add affected_products or references to --fields"},
		{"with other fields", []string{"--limit", "2", "--fields", "cvss_score"}, "add affected_products or references to --fields"},
		{"with only a count", []string{"--limit", "2", "--fields", "references_count"}, "add affected_products or references to --fields"},
		{"with an empty --fields", []string{"--limit", "2", "--fields", ""}, "add affected_products or references to --fields"},
	} {
		for _, jsonMode := range modes {
			h := newHarness(t)
			nvd := newNVD(t, h)
			args := slices.Concat([]string{nvd.fixture("long-lists.json")}, c.args)
			f := h.failed(h.cveRun(jsonMode, args...), 2, jsonMode)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "--limit") || c.hint != "" && !strings.Contains(f.hint, c.hint) {
				t.Errorf("%s, json=%v: %+v", c.name, jsonMode, f)
			}
			if len(nvd.requests()) != 0 {
				t.Errorf("%s: the NVD was asked", c.name)
			}
		}
	}
}

// --match keeps the entries of a list that contain the text, ignoring case and
// surrounding space, and counts them against the total.
func TestCVE_Match(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	long := nvd.fixture("long-lists.json")
	for _, match := range []string{"log4j", "LOG4J", " log4j ", "apache log4j"} {
		if code := h.cveRun(true, long, "--fields", "affected_products,references", "--match", match); code != 0 {
			t.Fatalf("--match %q: exit %d: %s", match, code, h.stderr.String())
		}
		rec := recordOf(t, h.cveEnvelope().Data[0])
		if match == "apache log4j" {
			if len(listOf(t, rec, "references")) != 0 || string(rec["references_count"]) != `{"total":5,"matched":0}` {
				t.Errorf("--match %q: references %s, %s", match, rec["references"], rec["references_count"])
			}
		}
		if len(listOf(t, rec, "affected_products")) != 3 || string(rec["affected_products_count"]) != `{"total":6,"matched":3}` {
			t.Errorf("--match %q: %s, %s", match, rec["affected_products"], rec["affected_products_count"])
		}
	}
	// The default fields hold the counts, so a match counts against them with no list shown.
	if code := h.cveRun(true, long, "--match", "log4j"); code != 0 {
		t.Fatal(code)
	}
	rec := recordOf(t, h.cveEnvelope().Data[0])
	if string(rec["affected_products_count"]) != `{"total":6,"matched":3}` || string(rec["references_count"]) != `{"total":5,"matched":2}` || rec["references"] != nil {
		t.Errorf("--match with the default: %s, %s", rec["affected_products_count"], rec["references_count"])
	}
	if code := h.cveRun(false, long, "--match", "log4j"); code != 0 || !strings.Contains(h.stdout.String(), tippedProducts+"\n3 of 6 match\n") || !strings.Contains(h.stdout.String(), tippedRefs+"\n2 of 5 match\n") {
		t.Errorf("--match, human: exit %d\n%s", code, h.stdout.String())
	}
	// A count alone is enough to match against.
	if code := h.cveRun(true, long, "--fields", "references_count", "--match", "x"); code != 0 {
		t.Errorf("--fields references_count --match x: exit %d: %s", code, h.stderr.String())
	}
	// A reference matches by its tag.
	if code := h.cveRun(true, long, "--fields", "references", "--match", "vendor advisory"); code != 0 || len(listOf(t, recordOf(t, h.cveEnvelope().Data[0]), "references")) != 2 {
		t.Errorf("a tag: exit %d: %s", code, h.stdout.String())
	}
}

// --match with nothing to show it, or with no text, or twice, is a usage error.
func TestCVE_BadMatch(t *testing.T) {
	t.Parallel()
	const hint = "add affected_products, references or their counts to --fields"
	for _, c := range []struct {
		name string
		args []string
		hint string
	}{
		{"empty", []string{"--match", ""}, ""},
		{"blank", []string{"--match", "   "}, ""},
		{"twice", []string{"--match", "a", "--match", "b"}, ""},
		{"with no list or count", []string{"--match", "log4j", "--fields", "id,cvss_score"}, hint},
		{"with an empty --fields", []string{"--match", "log4j", "--fields", ""}, hint},
	} {
		for _, jsonMode := range modes {
			h := newHarness(t)
			nvd := newNVD(t, h)
			f := h.failed(h.cveRun(jsonMode, append([]string{nvd.fixture("long-lists.json")}, c.args...)...), 2, jsonMode)
			if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "--match") || c.hint != "" && !strings.Contains(f.hint, c.hint) {
				t.Errorf("%s, json=%v: %+v", c.name, jsonMode, f)
			}
			if len(nvd.requests()) != 0 {
				t.Errorf("%s: the NVD was asked", c.name)
			}
		}
	}
	// An unknown field is the one problem: no second, misleading one about the match.
	h := newHarness(t)
	newNVD(t, h)
	f := h.failed(h.cveRun(true, "CVE-2021-44228", "--fields", "bogus", "--match", "x", "--limit", "2"), 2, true)
	if strings.Contains(f.msg, "--match") || strings.Contains(f.msg, "--limit") {
		t.Errorf("a bad --fields also gave: %+v", f)
	}
}

// A --match that matches nothing never removes a record: every ID the NVD holds is returned, the exit code and
// meta.count are as without it, and the list says that nothing matched, which is not that the NVD listed none.
func TestCVE_MatchNeverRemovesARecord(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		nvd := newNVD(t, h)
		long, rejected, one := nvd.fixture("long-lists.json"), nvd.fixture("rejected.json"), nvd.fixture("one-each.json")
		ids := []string{long, rejected, one}
		if code := h.cveRun(jsonMode, append(slices.Clone(ids), "--fields", "affected_products,references")...); code != 0 {
			t.Fatalf("exit %d", code)
		}
		without := h.stdout.String()
		if code := h.cveRun(jsonMode, append(slices.Clone(ids), "--fields", "affected_products,references", "--match", "zzzz-nothing")...); code != 0 || h.stderr.Len() != 0 {
			t.Fatalf("json=%v: exit %d, stderr %q", jsonMode, code, h.stderr.String())
		}
		if jsonMode {
			env := h.cveEnvelope()
			if env.Meta.Count != 3 || !slices.Equal(env.ids(), ids) {
				t.Errorf("meta.count %d, ids %v", env.Meta.Count, env.ids())
			}
			for i, want := range []string{`{"total":6,"matched":0}`, `{"total":0,"matched":0}`, `{"total":1,"matched":0}`} {
				rec := recordOf(t, env.Data[i])
				if string(rec["affected_products_count"]) != want || len(listOf(t, rec, "affected_products")) != 0 || string(rec["affected_products"]) != "[]" {
					t.Errorf("record %d: %s, %s", i, rec["affected_products_count"], rec["affected_products"])
				}
			}
			continue
		}
		out := h.stdout.String()
		if strings.Count(out, "CVE-") != strings.Count(without, "CVE-") {
			t.Errorf("a record was removed:\n%s", out)
		}
		for _, want := range []string{"Affected Products (0 of 6 match)\nNo affected products match.\n", "References (0 of 5 match)\nNo references match.\n",
			"Affected Products (0 of 0 match)\nNo affected products listed.\n", "References (0 of 0 match)\nNo references listed.\n",
			"Affected Products (0 of 1 match)\nNo affected products match.\n"} {
			if !strings.Contains(out, want) {
				t.Errorf("human output lacks %q:\n%s", want, out)
			}
		}
	}
}

// --match does not change what a batch with a failure returns.
func TestCVE_MatchDoesNotChangeAPartialResult(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		nvd := newNVD(t, h)
		long := nvd.fixture("long-lists.json")
		nvd.script("CVE-2024-0503", reply{status: 503, header: map[string]string{"Retry-After": "0"}})
		args := []string{long, cveGone, "CVE-2024-0503", "--fields", "affected_products"}
		without := h.partialOf(h.cveRun(jsonMode, args...), jsonMode, []string{cveGone, "CVE-2024-0503"}, true)
		var envWithout cveEnvelope
		if jsonMode {
			envWithout = h.cveEnvelope()
		}
		with := h.partialOf(h.cveRun(jsonMode, append(args, "--match", "zzz")...), jsonMode, []string{cveGone, "CVE-2024-0503"}, true)
		if with.msg != without.msg || with.code != without.code || !slices.Equal(with.targets, without.targets) {
			t.Errorf("json=%v: the error differs:\n%+v\n%+v", jsonMode, without, with)
		}
		if jsonMode {
			env := h.cveEnvelope()
			a, _ := json.Marshal(envWithout.Meta.Errors)
			b, _ := json.Marshal(env.Meta.Errors)
			if env.Meta.Count != envWithout.Meta.Count || string(a) != string(b) {
				t.Errorf("meta differs: %s and %s", a, b)
			}
		}
	}
}

// The match is made before the limit: the limit and what is left out count the matching entries.
func TestCVE_MatchThenLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	if code := h.cveRun(true, nvd.fixture("long-lists.json"), "--fields", "affected_products", "--match", "log4j", "--limit", "1"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	rec := recordOf(t, h.cveEnvelope().Data[0])
	products := listOf(t, rec, "affected_products")
	if len(products) != 1 || !strings.Contains(string(products[0]), `"version_end_excluding":"2.3.1"`) || string(rec["affected_products_count"]) != `{"total":6,"matched":3,"omitted":2}` {
		t.Errorf("%s, %s", products, rec["affected_products_count"])
	}
	// A match only the third entry has is the first the limit keeps.
	if code := h.cveRun(true, nvd.fixture("long-lists.json"), "--fields", "affected_products", "--match", "tomcat", "--limit", "1"); code != 0 {
		t.Fatal(code)
	}
	if products = listOf(t, recordOf(t, h.cveEnvelope().Data[0]), "affected_products"); len(products) != 1 || !strings.Contains(string(products[0]), "tomcat") {
		t.Errorf("%s", products)
	}
	if code := h.cveRun(false, nvd.fixture("long-lists.json"), "--fields", "affected_products,references", "--match", "log4j", "--limit", "1"); code != 0 ||
		!strings.Contains(h.stdout.String(), "Affected Products (3 of 6 match)\n- apache log4j (>= 2.0.1, < 2.3.1)\n2 more not shown\n") {
		t.Errorf("human: exit %d\n%s", code, h.stdout.String())
	}
}

// The command that retries what failed repeats --limit and --match as they were given, quoted.
func TestCVE_RetryRepeatsLimitAndMatch(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		h := newHarness(t)
		nvd := newNVD(t, h)
		long := nvd.fixture("long-lists.json")
		nvd.script("CVE-2024-0503", reply{status: 503, header: map[string]string{"Retry-After": "0"}})
		f := h.partialOf(h.cveRun(jsonMode, "CVE-2024-0503", long, "--fields", "references", "--limit", "2", "--match", " Log4J "), jsonMode, []string{"CVE-2024-0503"}, true)
		want := "run: nyx cve CVE-2024-0503" + map[bool]string{true: " --json"}[jsonMode] + " --fields references --limit 2 --match ' Log4J '"
		if f.hint != want {
			t.Errorf("json=%v: hint %q, want %q", jsonMode, f.hint, want)
		}
	}
	// Without them given, the command does not name them.
	h := newHarness(t)
	nvd := newNVD(t, h)
	nvd.script("CVE-2024-0503", reply{status: 503, header: map[string]string{"Retry-After": "0"}})
	if f := h.partialOf(h.cveRun(true, "CVE-2024-0503", nvd.fixture("long-lists.json")), true, []string{"CVE-2024-0503"}, true); f.hint != "run: nyx cve CVE-2024-0503 --json" {
		t.Errorf("hint %q", f.hint)
	}
}

// A key in the --match, or in a matched reference, is masked: in the retry command, and in the matched list.
func TestCVE_MatchedKeyIsMasked(t *testing.T) {
	t.Parallel()
	const key = "nvd-Qx7Rt2Zk9Vb4Nm8Lp3Zz"
	for _, jsonMode := range modes {
		h := newHarness(t)
		h.setenv("NVD_API_KEY", key)
		nvd := newNVD(t, h)
		nvd.mu.Lock()
		nvd.entries["CVE-2024-1000"] = `{"id":"CVE-2024-1000","vulnStatus":"Analyzed","published":"2024-01-01T00:00:00.000","lastModified":"2024-01-02T00:00:00.000",` +
			`"descriptions":[{"lang":"en","value":"About it."}],"references":[{"url":"https://example.com/?token=` + key + `","tags":["Patch"]},{"url":"https://example.com/other"}]}`
		nvd.mu.Unlock()
		nvd.script("CVE-2024-0503", reply{status: 503, header: map[string]string{"Retry-After": "0"}})
		f := h.partialOf(h.cveRun(jsonMode, "CVE-2024-0503", "CVE-2024-1000", "--fields", "references", "--match", key), jsonMode, []string{"CVE-2024-0503"}, true)
		// The NVD's text is data under --json, as it is without --match; human mode masks it.
		all := h.stderr.String()
		if !jsonMode {
			all += h.stdout.String()
		}
		for i := 0; i+8 <= len(key); i++ {
			if strings.Contains(all, key[i:i+8]) {
				t.Errorf("json=%v: %q of the key reached the output:\n%s", jsonMode, key[i:i+8], all)
				break
			}
		}
		if !strings.Contains(f.hint, "--match") || !strings.Contains(f.hint, "****") {
			t.Errorf("json=%v: the retry command %q should hold the masked match", jsonMode, f.hint)
		}
		out := h.stdout.String()
		if jsonMode && !strings.Contains(out, `"matched":1`) || !jsonMode && (!strings.Contains(out, "****") || !strings.Contains(out, "References (1 of 2 match)")) {
			t.Errorf("json=%v: the matched reference should be shown, masked in human mode:\n%s", jsonMode, out)
		}
	}
}
