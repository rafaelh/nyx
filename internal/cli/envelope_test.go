package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/engagement"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/report"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

var (
	envelopeKeys = []string{"data", "meta"}
	dataKeys     = []string{"engagement", "directory", "counts", "failed_jobs", "deferred", "not_configured", "findings",
		"candidates", "candidates_total", "unconfirmed_risky_ports", "hosts_in_scope_by_address", "notes", "changes"}
	metaKeys = []string{"count", "deadline_exceeded", "jobs_completed", "jobs_cancelled", "warnings"}
)

// keysOf are the keys of the JSON object at raw, in the order they are written.
func keysOf(t *testing.T, raw json.RawMessage) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %s", raw)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

// envelope parses one compact stdout line and verifies ordered interface keys.
func (h *harness) envelope() report.Envelope {
	h.t.Helper()
	line := h.stdout.String()
	if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
		h.t.Fatalf("stdout is not one line:\n%s", line)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &top); err != nil {
		h.t.Fatalf("stdout is not JSON: %v\n%s", err, line)
	}
	if got := keysOf(h.t, json.RawMessage(line)); !slices.Equal(got, envelopeKeys) {
		h.t.Fatalf("envelope keys = %v, want %v", got, envelopeKeys)
	}
	if got := keysOf(h.t, top["data"]); !slices.Equal(got, dataKeys) {
		h.t.Fatalf("data keys = %v, want %v", got, dataKeys)
	}
	if got := keysOf(h.t, top["meta"]); !slices.Equal(got, metaKeys) {
		h.t.Fatalf("meta keys = %v, want %v", got, metaKeys)
	}
	var env report.Envelope
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		h.t.Fatal(err)
	}
	return env
}

// Empty runs still emit all keys, empty lists and null first-run changes.
func TestEnvelope_EveryKeyOnEveryRun(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	line := strings.TrimSuffix(h.stdout.String(), "\n")
	h.envelope() // checks the keys and their order
	for _, want := range []string{
		`"failed_jobs":[]`, `"deferred":[]`, `"not_configured":[]`, `"findings":[]`, `"candidates":[]`,
		`"candidates_total":0`, `"unconfirmed_risky_ports":0`, `"notes":[]`, `"changes":null`,
		`"meta":{"count":1,"deadline_exceeded":false,"jobs_completed":0,"jobs_cancelled":0,"warnings":[]}}`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("envelope lacks %s:\n%s", want, line)
		}
	}
	if !strings.HasPrefix(line, `{"data":{"engagement":"a.com","directory":`+fmt.Sprintf("%q", h.eng("a.com"))+`,"counts":[`) {
		t.Errorf("envelope starts %.120s", line)
	}
	if h.stderr.Len() != 0 {
		t.Errorf("stderr on exit 0: %q", h.stderr.String())
	}
}

// The exact bytes of the envelope of a fixed run: compact, one line, the keys in order.
func TestEnvelope_ExactBytes(t *testing.T) {
	t.Parallel()
	h := newHarness(t, finder("fake", obs("hostname", "www.a.com")), erring("flaky", 1, errors.New("boom")))
	if code := h.exec("a.com", "--json"); code != 7 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	want := `{"data":{"engagement":"a.com","directory":` + fmt.Sprintf("%q", h.eng("a.com")) +
		`,"counts":[{"category":"code mentions","n":0},{"category":"findings","n":0},{"category":"hosts","n":1},{"category":"ips","n":0},` +
		`{"category":"open ports (confirmed)","n":0},{"category":"open ports (third-party reported)","n":0},{"category":"third parties","n":0},` +
		`{"category":"unresolved names","n":0},{"category":"urls","n":0},{"category":"web services","n":0}],"failed_jobs":[{"procedure":"flaky","n":1}],"deferred":[],"not_configured":[],` +
		`"findings":[],"candidates":[],"candidates_total":0,"unconfirmed_risky_ports":0,"hosts_in_scope_by_address":0,"notes":[],"changes":null},` +
		`"meta":{"count":1,"deadline_exceeded":false,"jobs_completed":2,"jobs_cancelled":0,"warnings":[]}}` + "\n"
	if got := h.stdout.String(); got != want {
		t.Errorf("envelope:\n got %s\nwant %s", got, want)
	}
}

// JSON output stays event-free; --debug adds only stderr debug lines.
func TestEnvelope_NoEventLinesAndDebugOnlyAddsDebugLines(t *testing.T) {
	t.Parallel()
	run1 := func(extra ...string) (stdout, stderr string) {
		h := newHarness(t, finder("fake", obs("hostname", "www.a.com")))
		args := append([]string{"a.com", "--json"}, extra...)
		if code := h.exec(args...); code != 0 {
			t.Fatalf("exit %d\n%s", code, h.stderr.String())
		}
		h.envelope()
		return strings.ReplaceAll(h.stdout.String(), h.out, "OUT"), h.stderr.String()
	}
	out, errOut := run1()
	if errOut != "" {
		t.Errorf("stderr on exit 0: %q", errOut)
	}
	if strings.Contains(out, `"type":`) {
		t.Errorf("event lines on stdout: %s", out)
	}
	dbgOut, dbgErr := run1("--debug")
	if dbgOut != out {
		t.Errorf("--debug changed stdout:\n%s\n%s", out, dbgOut)
	}
	for l := range strings.SplitSeq(strings.TrimSpace(dbgErr), "\n") {
		if l != "" && !strings.Contains(l, "| DEBUG |") {
			t.Errorf("a line that is not DEBUG on stderr under --json --debug: %q", l)
		}
	}
}

// A warning is in meta.warnings and not on stderr, stripped of terminal escapes and with key values
// masked.
func TestEnvelope_WarningsAreInMetaMaskedAndStripped(t *testing.T) {
	t.Parallel()
	warner := &testkit.Procedure{ProcedureName: "warner", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("w", 1) },
		RunFn: func(ctx context.Context, c run.Job, _ egress.Clients) ([]run.Observation, error) {
			run.Warnf(ctx, "result truncated \x1b[31mred\x1b[0m for key sekret-key-123")
			return nil, nil
		}}
	h := newHarness(t, warner)
	h.setKey("shodan", "sekret-key-123")
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	env := h.envelope()
	if len(env.Meta.Warnings) != 1 {
		t.Fatalf("warnings = %q", env.Meta.Warnings)
	}
	w := env.Meta.Warnings[0]
	if strings.Contains(w, "\x1b") || strings.Contains(w, "sekret-key-123") || !strings.Contains(w, "****") || !strings.Contains(w, "truncated") {
		t.Errorf("warning = %q, want it stripped and masked", w)
	}
	if h.stderr.Len() != 0 {
		t.Errorf("a warning went to stderr under --json: %q", h.stderr.String())
	}
}

// not_configured names each procedure that did not run, and why, in registry order; it is empty
// when all ran.
func TestEnvelope_NotConfigured(t *testing.T) {
	t.Parallel()
	procedure := func(name string, kind run.Contact) *testkit.Procedure {
		return &testkit.Procedure{ProcedureName: name, Kind: kind}
	}
	nokey := procedure("keyed", run.ThirdParty)
	nokey.ConfiguredFn = func(run.Env) (bool, string) { return false, "no key" }
	h := newHarness(t, procedure("skipme", run.ThirdParty), procedure("probe", run.Target), nokey, procedure("ok", run.ThirdParty))
	if code := h.exec("a.com", "--json", "--skip", "skipme"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	want := []report.ProcedureReason{{Procedure: "skipme", Reason: "skipped"}, {Procedure: "probe", Reason: "no authorisation"}, {Procedure: "keyed", Reason: "no key"}}
	if got := h.envelope().Data.NotConfigured; !slices.Equal(got, want) {
		t.Errorf("not_configured = %v, want %v", got, want)
	}

	h = newHarness(t, procedure("skipme", run.ThirdParty), procedure("probe", run.Target), nokey)
	if code := h.exec("a.com", "--json", "--passive", "--skip", "skipme"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	want = []report.ProcedureReason{{Procedure: "skipme", Reason: "skipped"}, {Procedure: "probe", Reason: "passive-only"}, {Procedure: "keyed", Reason: "no key"}}
	if got := h.envelope().Data.NotConfigured; !slices.Equal(got, want) {
		t.Errorf("not_configured = %v, want %v", got, want)
	}

	h = newHarness(t, procedure("ok", run.ThirdParty))
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if got := h.envelope().Data.NotConfigured; len(got) != 0 {
		t.Errorf("not_configured = %v, want none", got)
	}
}

// directory is absolute even when --output-dir is relative.
func TestEnvelope_DirectoryIsAbsolute(t *testing.T) {
	// Not parallel: it changes the working directory.
	dir := t.TempDir()
	t.Chdir(dir)
	h := newHarness(t, noop())
	if code := h.execRoot("recon", "--output-dir", "out", "a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	got := h.envelope().Data.Directory
	if !filepath.IsAbs(got) || !strings.HasSuffix(got, "/out/a.com") {
		t.Errorf("directory = %q, want an absolute path ending /out/a.com", got)
	}
}

// The summary lists the first 20 high-confidence candidates and their total, and a candidate's
// sources are a list.
func TestEnvelope_CandidatesAreCappedAndSourcesAreAList(t *testing.T) {
	t.Parallel()
	// Each root is found through three families, so it is a high-confidence candidate.
	m := map[string][]run.Observation{}
	for i := range 23 {
		for _, fam := range []string{"crtsh", "wayback", "otx"} {
			m[fmt.Sprintf("%s:r%02d", fam, i)] = list(root(fmt.Sprintf("r%02d.org", i)))
		}
	}
	h := newHarness(t, pivot{newSrc("pivot", m)})
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	d := h.envelope().Data
	if d.CandidatesTotal != 23 || len(d.Candidates) != 20 {
		t.Fatalf("candidates = %d of %d, want 20 of 23", len(d.Candidates), d.CandidatesTotal)
	}
	for _, c := range d.Candidates {
		if !slices.Equal(c.Sources, []string{"crtsh", "otx", "wayback"}) {
			t.Errorf("sources of %s = %v, want a list of the three families", c.Value, c.Sources)
		}
	}
	// The human summary says how many more there are.
	h = newHarness(t, pivot{newSrc("pivot", m)})
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "and 3 more in candidates.csv") {
		t.Errorf("summary: %s", h.stdout.String())
	}
}

// Subsequent runs report changes; first runs have no comparison baseline.
func TestEnvelope_ChangesSinceTheLastRun(t *testing.T) {
	t.Parallel()
	hosts := []string{"www.a.com"}
	st := &testkit.Procedure{ProcedureName: "fake", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("c", len(hosts)) },
		RunFn: func(_ context.Context, c run.Job, _ egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("hostname", hosts[int(c.Key[len(c.Key)-1]-'0')])}, nil
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	if ch := h.envelope().Data.Changes; ch != nil {
		t.Errorf("a first run has changes: %+v", ch)
	}
	hosts = append(hosts, "api.a.com")
	if code := h.exec("-e", "a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	ch := h.envelope().Data.Changes
	if ch == nil || !slices.Contains(ch.Counts, report.ChangeCount{Kind: kinds.LabelHostname, Change: "new", N: 1}) {
		t.Errorf("changes = %+v, want one new hostname", ch)
	}
	if ch != nil && ch.Findings == nil {
		t.Error("changes.findings is null, want a list")
	}
}

// stdout is empty under --json on every exit other than 0 and 7.
func TestEnvelope_StdoutIsEmptyOnOtherExits(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	h.failed(h.exec("--bogus", "--json"), 2, true)
	h = newHarness(t, noop())
	h.failed(h.exec("-e", "nope", "--json"), 3, true)

	h = newHarness(t, noop())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.failed(h.execCtx(ctx, "a.com", "--json"), 130, true)

	h = newHarness(t, noop())
	h.failed(h.exec("--json", "--cidr", "10.0.0.0/16", "--netblock-limit", "1000"), 2, true)

	hold := &testkit.Procedure{ProcedureName: "hold", Kind: run.ThirdParty}
	h = newHarness(t, hold)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	eng, err := engagement.Open(h.eng("a.com"), engagement.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	h.failed(h.exec("-e", "a.com", "--json"), 1, true)
}

// Sanitise and redact target/source text in findings and envelope warnings.
func TestEnvelope_FindingTextIsStrippedAndMasked(t *testing.T) {
	t.Parallel()
	const key = "sekret-key-4242"
	st := finder("finder", obs("finding", "e", "category", "exposed", "severity", "high",
		"target", "https://a.com/\x1b[2Jx", "detail", "echoed \x1b]0;pwn\x07"+key))
	h := newHarness(t, st)
	h.setKey("fake", key)
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	fs := h.envelope().Data.Findings
	if len(fs) != 1 || fs[0].Detail == nil {
		t.Fatalf("findings = %+v", fs)
	}
	for _, text := range []string{fs[0].Target, *fs[0].Detail} {
		if strings.ContainsAny(text, "\x1b\x07") || strings.Contains(text, key) {
			t.Errorf("%q still has an escape or the key", text)
		}
	}
	if !strings.Contains(*fs[0].Detail, "****") {
		t.Errorf("detail = %q, want the key masked", *fs[0].Detail)
	}
}

// noteProcedure is a procedure that adds a line to the summary.
type noteProcedure struct {
	*testkit.Procedure
	text string
}

func (s noteProcedure) Notes(run.View) []string { return []string{s.text} }

// Procedure notes bypass store/log cleaning, so the envelope must clean and redact them itself.
func TestEnvelope_NotesAreStrippedAndMasked(t *testing.T) {
	t.Parallel()
	const key = "sekret-key-4242"
	h := newHarness(t, noteProcedure{&testkit.Procedure{ProcedureName: "noter", Kind: run.ThirdParty}, "seen \x1b[31mred\x1b[0m " + key})
	h.setKey("fake", key)
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatalf("exit %d\n%s", code, h.stderr.String())
	}
	notes := h.envelope().Data.Notes
	if len(notes) != 1 || strings.Contains(notes[0], "\x1b") || strings.Contains(notes[0], key) || !strings.Contains(notes[0], "****") {
		t.Errorf("notes = %q, want the escape stripped and the key masked", notes)
	}
	if strings.Contains(h.stdout.String(), key) {
		t.Error("the key is in stdout")
	}
}

// The rows and counts named after the unit of work use the words procedure and job, and the old
// keys are not written at all.
func TestEnvelope_ProcedureAndJobKeys(t *testing.T) {
	t.Parallel()
	nokey := &testkit.Procedure{ProcedureName: "keyed", Kind: run.ThirdParty,
		ConfiguredFn: func(run.Env) (bool, string) { return false, "no key" }}
	h := newHarness(t, erring("flaky", 1, errors.New("boom")), budgeted(1, func(run.View) []run.Job { return costed(1, 1, 1) }), nokey)
	h.partial(h.exec("a.com", "--json"), true)
	line := h.stdout.String()
	env, ok := tryEnvelope(line)
	if !ok || len(env.Data.FailedJobs) != 1 || len(env.Data.Deferred) != 1 || len(env.Data.NotConfigured) != 1 {
		t.Fatalf("precondition: failed %v, deferred %v, not configured %v", env.Data.FailedJobs, env.Data.Deferred, env.Data.NotConfigured)
	}
	for _, want := range []string{
		`"failed_jobs":[{"procedure":"flaky","n":1}]`,
		`"deferred":[{"procedure":"budgeted","n":`,
		`"not_configured":[{"procedure":"keyed","reason":"no key"}]`,
		`"jobs_completed":`, `"jobs_cancelled":0`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("envelope lacks %s:\n%s", want, line)
		}
	}
	for _, old := range []string{"failed_checks", "checks_completed", "checks_cancelled", `"stage"`} {
		if strings.Contains(line, old) {
			t.Errorf("envelope has the old key %s:\n%s", old, line)
		}
	}
	h.envelope() // the data and meta keys, in order
}
