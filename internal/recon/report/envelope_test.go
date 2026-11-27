package report_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/rafaelh/nyx/internal/recon/report"
)

// fixedEnvelope is a run with something in every key.
func fixedEnvelope() report.Envelope {
	finding := report.FindingRow{Severity: "high", Category: "exposed-admin", Target: "https://a.example.com/admin", Detail: new("login <page> & more")}
	return report.Envelope{
		Data: report.Summary{
			Engagement:    "acme",
			Directory:     "/tmp/acme",
			Counts:        []report.CountRow{{Category: "hosts", N: 3}, {Category: "urls", N: 2}},
			FailedJobs:    []report.ProcedureCount{{Procedure: "dns", N: 1}},
			Deferred:      []report.ProcedureCount{{Procedure: "shodan", N: 4}},
			NotConfigured: []report.ProcedureReason{{Procedure: "ports", Reason: "passive-only"}},
			Findings: []report.FindingRow{
				finding,
				{Severity: "medium", Category: "banner", Target: "10.0.0.1:21"},
			},
			Candidates: []report.CandidateRow{{
				Kind: "root", Value: "x.org", Sources: []string{"crtsh", "whoisxml"},
				EvidenceCount: 2, Confidence: "high", Promote: "-d x.org",
			}},
			CandidatesTotal:       23,
			UnconfirmedRiskyPorts: 3,
			HostsInScopeByAddress: 2,
			Notes:                 []string{"n1"},
			Changes: &report.Changes{
				Counts:   []report.ChangeCount{{Kind: "hostname", Change: "new", N: 2}},
				Findings: []report.FindingRow{finding},
			},
		},
		Meta: report.Meta{Count: 1, DeadlineExceeded: true, JobsCompleted: 5, JobsCancelled: 2, Warnings: []string{"w"}},
	}
}

// The envelope of a fixed run is one compact line with every key, in order.
func TestEnvelope_ExactBytes(t *testing.T) {
	t.Parallel()
	out := encode(t, fixedEnvelope())
	want := `{"data":{"engagement":"acme","directory":"/tmp/acme",` +
		`"counts":[{"category":"hosts","n":3},{"category":"urls","n":2}],` +
		`"failed_jobs":[{"procedure":"dns","n":1}],` +
		`"deferred":[{"procedure":"shodan","n":4}],` +
		`"not_configured":[{"procedure":"ports","reason":"passive-only"}],` +
		`"findings":[{"severity":"high","category":"exposed-admin","target":"https://a.example.com/admin","detail":"login <page> & more"},` +
		`{"severity":"medium","category":"banner","target":"10.0.0.1:21","detail":null}],` +
		`"candidates":[{"kind":"root","value":"x.org","sources":["crtsh","whoisxml"],"evidence_count":2,"confidence":"high","promote":"-d x.org"}],` +
		`"candidates_total":23,"unconfirmed_risky_ports":3,"hosts_in_scope_by_address":2,"notes":["n1"],` +
		`"changes":{"counts":[{"kind":"hostname","change":"new","n":2}],` +
		`"findings":[{"severity":"high","category":"exposed-admin","target":"https://a.example.com/admin","detail":"login <page> & more"}]}},` +
		`"meta":{"count":1,"deadline_exceeded":true,"jobs_completed":5,"jobs_cancelled":2,"warnings":["w"]}}` + "\n"
	if got := out; got != want {
		t.Errorf("envelope\n got %s\nwant %s", got, want)
	}
}

// Empty and zero-value envelopes retain complete keys, empty lists and null first-run changes.
func TestEnvelope_ZeroValueShape(t *testing.T) {
	t.Parallel()
	out := encode(t, report.Envelope{})
	want := `{"data":{"engagement":"","directory":"","counts":[],"failed_jobs":[],"deferred":[],"not_configured":[],` +
		`"findings":[],"candidates":[],"candidates_total":0,"unconfirmed_risky_ports":0,"hosts_in_scope_by_address":0,"notes":[],"changes":null},` +
		`"meta":{"count":0,"deadline_exceeded":false,"jobs_completed":0,"jobs_cancelled":0,"warnings":[]}}` + "\n"
	if got := out; got != want {
		t.Errorf("zero envelope\n got %s\nwant %s", got, want)
	}
}

// Lists nested in a row or in the changes are [] too, and a nil detail stays null.
func TestEnvelope_NestedNilListsAreEmpty(t *testing.T) {
	t.Parallel()
	env := report.Envelope{Data: report.Summary{
		Candidates: []report.CandidateRow{{Kind: "root", Value: "x.org"}},
		Findings:   []report.FindingRow{{Severity: "high", Category: "c", Target: "t"}},
		Changes:    &report.Changes{},
	}}
	out := encode(t, env)
	containsAll(t, out, `"sources":[]`, `"detail":null`, `"changes":{"counts":[],"findings":[]}`)
	if strings.Contains(out, `"sources":null`) || strings.Contains(out, `"counts":null`) {
		t.Errorf("a nil list was written as null: %s", out)
	}
}

// Writing the envelope turns nil lists into [] in the output only.
func TestEnvelope_WriteLeavesTheValueAlone(t *testing.T) {
	t.Parallel()
	env := report.Envelope{Data: report.Summary{
		Candidates: []report.CandidateRow{{Kind: "root"}},
		Changes:    &report.Changes{},
	}}
	if err := report.WriteEnvelope(&bytes.Buffer{}, env); err != nil {
		t.Fatal(err)
	}
	if env.Data.Counts != nil || env.Meta.Warnings != nil || env.Data.Candidates[0].Sources != nil ||
		env.Data.Changes.Counts != nil || env.Data.Changes.Findings != nil {
		t.Errorf("WriteEnvelope changed its argument: %+v", env)
	}
}

// Unescaped HTML-sensitive characters must still round-trip as valid JSON.
func TestEnvelope_DoesNotEscapeHTML(t *testing.T) {
	t.Parallel()
	env := report.Envelope{Meta: report.Meta{Warnings: []string{"a <b> & c > d"}}}
	out := encode(t, env)
	if !strings.Contains(out, `"a <b> & c > d"`) || strings.Contains(out, `\u00`) {
		t.Errorf("HTML characters were escaped: %s", out)
	}
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "}\n") {
		t.Errorf("not one newline-terminated line: %q", out)
	}
	var back report.Envelope
	if err := json.Unmarshal([]byte(out), &back); err != nil || back.Meta.Warnings[0] != "a <b> & c > d" {
		t.Errorf("round trip: %v %+v", err, back)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("closed") }

func TestEnvelope_WriteReturnsTheWriteError(t *testing.T) {
	t.Parallel()
	if err := report.WriteEnvelope(failWriter{}, report.Envelope{}); err == nil {
		t.Error("a failed write returned no error")
	}
}

// secretEnvelope has the secret in every string position.
func secretEnvelope() report.Envelope {
	s := "SEKRET"
	row := report.FindingRow{Severity: s, Category: s, Target: s, Detail: new(s)}
	return report.Envelope{
		Data: report.Summary{
			Engagement:    s,
			Directory:     s,
			Counts:        []report.CountRow{{Category: s, N: 1}},
			FailedJobs:    []report.ProcedureCount{{Procedure: s, N: 1}},
			Deferred:      []report.ProcedureCount{{Procedure: s, N: 1}},
			NotConfigured: []report.ProcedureReason{{Procedure: s, Reason: s}},
			Findings:      []report.FindingRow{row, {Severity: s}},
			Candidates: []report.CandidateRow{{
				Kind: s, Value: s, Sources: []string{s, s}, EvidenceCount: 1, Confidence: s, Promote: s,
			}},
			CandidatesTotal: 1,
			Notes:           []string{s, s},
			Changes: &report.Changes{
				Counts:   []report.ChangeCount{{Kind: s, Change: s, N: 1}},
				Findings: []report.FindingRow{row},
			},
		},
		Meta: report.Meta{Count: 1, Warnings: []string{s, s}},
	}
}

func mask(s string) string { return strings.ReplaceAll(s, "SEKRET", "****") }

// Map masks a string in every place, and the original is untouched.
func TestEnvelope_MapMasksEveryString(t *testing.T) {
	t.Parallel()
	orig := secretEnvelope()
	got := orig.Map(mask)

	out := encode(t, got)
	if strings.Contains(out, "SEKRET") {
		t.Errorf("a string was not mapped: %s", out)
	}
	if n := strings.Count(out, "****"); n != strings.Count(mustJSON(t, orig), "SEKRET") {
		t.Errorf("%d masked strings, want one for each of the original's", n)
	}
	if !reflect.DeepEqual(orig, secretEnvelope()) {
		t.Errorf("Map changed the receiver:\n%s", mustJSON(t, orig))
	}
	// Numbers and flags come through.
	if got.Meta.Count != 1 || got.Data.CandidatesTotal != 1 || got.Data.Counts[0].N != 1 {
		t.Errorf("numbers lost: %+v", got)
	}
}

// encode applies WriteEnvelope's output format.
func encode(t *testing.T, env report.Envelope) string {
	t.Helper()
	var buf bytes.Buffer
	if err := report.WriteEnvelope(&buf, env); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func mustJSON(t *testing.T, env report.Envelope) string {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The copy shares no slice or pointer with the receiver, so changing it
// changes nothing there, even with the identity function.
func TestEnvelope_MapDoesNotAlias(t *testing.T) {
	t.Parallel()
	orig := secretEnvelope()
	cp := orig.Map(func(s string) string { return s })
	cp.Data.Counts[0].Category = "x"
	cp.Data.FailedJobs[0].Procedure = "x"
	cp.Data.Deferred[0].Procedure = "x"
	cp.Data.NotConfigured[0].Reason = "x"
	cp.Data.Findings[0].Target = "x"
	*cp.Data.Findings[0].Detail = "x"
	cp.Data.Candidates[0].Sources[0] = "x"
	cp.Data.Notes[0] = "x"
	cp.Data.Changes.Counts[0].Kind = "x"
	cp.Data.Changes.Findings[0].Category = "x"
	*cp.Data.Changes.Findings[0].Detail = "x"
	cp.Meta.Warnings[0] = "x"
	if !reflect.DeepEqual(orig, secretEnvelope()) {
		t.Errorf("the copy shares memory with the receiver:\n%s", mustJSON(t, orig))
	}
}

// Nil stays nil and an empty list stays empty, and a nil detail and changes
// stay nil, so mapping never invents a value.
func TestEnvelope_MapKeepsAbsence(t *testing.T) {
	t.Parallel()
	got := report.Envelope{}.Map(func(s string) string { return s })
	if !reflect.DeepEqual(got, report.Envelope{}) {
		t.Errorf("zero envelope: %#v", got)
	}
	env := report.Envelope{Data: report.Summary{Findings: []report.FindingRow{{Severity: "high"}}}}
	if f := env.Map(mask).Data.Findings[0]; f.Detail != nil {
		t.Errorf("a nil detail became %q", *f.Detail)
	}
}

// Warnings keeps the message of each warning event in order and ignores the
// other types.
func TestWarnings_KeepsWarningsInOrder(t *testing.T) {
	t.Parallel()
	var w report.Warnings
	if got := w.List(); got == nil || len(got) != 0 {
		t.Errorf("empty list = %#v, want non-nil and empty", got)
	}
	for _, e := range []report.Event{
		{Type: "run_start", Fields: map[string]any{"message": "no"}},
		{Type: "warning", Fields: map[string]any{"message": "first"}},
		{Type: "debug", Fields: map[string]any{"message": "no"}},
		{Type: "found", Fields: map[string]any{"message": "no"}},
		{Type: "warning", Fields: map[string]any{"message": "second"}},
		{Type: "warning", Fields: map[string]any{"message": "second"}},
		{Type: "procedure", Fields: map[string]any{"message": "no"}},
	} {
		w.Emit(e)
	}
	if got, want := strings.Join(w.List(), ","), "first,second,second"; got != want {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	var _ report.Emitter = &w
}

// List is a copy: changing it, or emitting more, leaves the other alone.
func TestWarnings_ListIsACopy(t *testing.T) {
	t.Parallel()
	var w report.Warnings
	w.Emit(report.Event{Type: "warning", Fields: map[string]any{"message": "a"}})
	l := w.List()
	l[0] = "changed"
	w.Emit(report.Event{Type: "warning", Fields: map[string]any{"message": "b"}})
	if got := strings.Join(w.List(), ","); got != "a,b" {
		t.Errorf("warnings = %q", got)
	}
	if len(l) != 1 {
		t.Errorf("an earlier list grew: %q", l)
	}
}

// Many goroutines may emit at once; run with -race.
func TestWarnings_Concurrent(t *testing.T) {
	t.Parallel()
	var w report.Warnings
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			w.Emit(report.Event{Type: "warning", Fields: map[string]any{"message": fmt.Sprint("m", i)}})
			_ = w.List()
		})
	}
	wg.Wait()
	got := w.List()
	seen := map[string]bool{}
	for _, m := range got {
		seen[m] = true
	}
	if len(got) != 50 || len(seen) != 50 {
		t.Errorf("%d warnings, %d distinct, want 50", len(got), len(seen))
	}
}
