package cve

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
)

func ok(id string) Result { return Result{Input: id, ID: id, Record: &Record{ID: id}} }

func failed(input string, code clierr.Code, msg, hint string, transient bool, wait time.Duration) Result {
	id, valid := NormaliseID(input)
	if !valid {
		id = ""
	}
	return Result{Input: input, ID: id, Fail: &Failure{Err: &clierr.Error{Code: code, Message: msg, Hint: hint, Transient: transient}, Wait: wait}}
}

func notFound(id string) Result {
	return failed(id, clierr.NotFound, "not in the NVD", "check the ID; the NVD lists only published CVEs", false, 0)
}

func limited(id string, wait time.Duration) Result {
	return failed(id, clierr.RateLimited, "the NVD refused the request for exceeding its rate limit", fmt.Sprintf("retry after %ds", int(wait.Seconds())), true, wait)
}

func command(ids []string) string { return "nyx cve " + strings.Join(ids, " ") + " --json" }

// ids are n distinct CVE IDs from CVE-2026-1000.
func ids(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("CVE-2026-%d", 1000+i)
	}
	return out
}

func TestOutcome_Rows(t *testing.T) {
	t.Parallel()
	a, b, c := "CVE-2021-44228", "CVE-2024-3094", "CVE-2099-0001"
	cases := []struct {
		name     string
		results  []Result
		records  []string // the IDs of the records, in order
		metaErrs []string // the inputs of the meta.errors entries, in order
		want     *clierr.Error
	}{
		{"every ID succeeded", []Result{ok(a), ok(b)}, []string{a, b}, nil, nil},
		{"some succeeded", []Result{ok(a), notFound(c), ok(b)}, []string{a, b}, []string{c}, &clierr.Error{
			Code: clierr.Partial, Message: "2 of 3 IDs returned, 1 failed", Hint: "check the IDs that failed: " + c,
			Input: map[string][]string{"id": {c}}, Targets: []clierr.Target{{Input: c, Message: "not in the NVD", Code: clierr.NotFound}}}},
		{"one not found", []Result{notFound(c)}, nil, []string{c}, &clierr.Error{
			Code: clierr.NotFound, Message: c + ": not in the NVD", Hint: "check the ID; the NVD lists only published CVEs",
			Input: map[string][]string{"id": {c}}}},
		{"all not found", []Result{notFound(a), notFound(c)}, nil, []string{a, c}, &clierr.Error{
			Code: clierr.NotFound, Message: "2 IDs: not in the NVD", Hint: "check the ID; the NVD lists only published CVEs",
			Input: map[string][]string{"id": {a, c}}}},
		{"all refused keys", []Result{failed(a, clierr.AuthFailed, "the NVD refused the API key", "check keys.nvd in nyx.yaml", false, 0),
			failed(b, clierr.AuthFailed, "the NVD refused the API key", "check keys.nvd in nyx.yaml", false, 0)}, nil, []string{a, b}, &clierr.Error{
			Code: clierr.AuthFailed, Message: "2 IDs: the NVD refused the API key", Hint: "check keys.nvd in nyx.yaml",
			Input: map[string][]string{"id": {a, b}}}},
		{"all rate-limited: the command hint, after the longest wait", []Result{limited(a, 10*time.Second), limited(b, 24200*time.Millisecond)},
			nil, []string{a, b}, &clierr.Error{
				Code: clierr.RateLimited, Message: "2 IDs: the NVD refused the request for exceeding its rate limit",
				Hint: "after 25s, run: nyx cve " + a + " " + b + " --json", Transient: true, Input: map[string][]string{"id": {a, b}}}},
		{"all timed out: the command hint, and to raise --timeout", []Result{
			failed(a, clierr.Timeout, "no answer from the NVD before the deadline", "raise --timeout", true, 0)}, nil, []string{a}, &clierr.Error{
			Code: clierr.Timeout, Message: a + ": no answer from the NVD before the deadline",
			Hint: "run: nyx cve " + a + " --json, or raise --timeout", Transient: true, Input: map[string][]string{"id": {a}}}},
		{"one code, different messages", []Result{failed(a, clierr.UpstreamError, "the NVD answered HTTP 400", "", false, 0),
			failed(b, clierr.UpstreamError, "the NVD answered HTTP 404: Invalid cveId parameter.", "", false, 0)}, nil, []string{a, b}, &clierr.Error{
			Code: clierr.UpstreamError, Message: "2 IDs failed (UPSTREAM_ERROR)", Input: map[string][]string{"id": {a, b}}}},
		{"none succeeded, mixed codes", []Result{notFound(a), limited(b, 3*time.Second)}, nil, []string{a, b}, &clierr.Error{
			Code: clierr.Partial, Message: "none of 2 IDs returned", Hint: "after 3s, run: nyx cve " + b + " --json", Transient: true,
			Input: map[string][]string{"id": {a, b}}, Targets: []clierr.Target{
				{Input: a, Message: "not in the NVD", Code: clierr.NotFound},
				{Input: b, Message: "the NVD refused the request for exceeding its rate limit", Code: clierr.RateLimited}}}},
		{"a transient failure with no known wait", []Result{ok(a), failed(" cve-2024-3094 ", clierr.UpstreamError, "the NVD answered HTTP 503", "retry later", true, 0)},
			[]string{a}, []string{" cve-2024-3094 "}, &clierr.Error{
				Code: clierr.Partial, Message: "1 of 2 IDs returned, 1 failed", Hint: "run: nyx cve " + b + " --json", Transient: true,
				Input:   map[string][]string{"id": {" cve-2024-3094 "}},
				Targets: []clierr.Target{{Input: " cve-2024-3094 ", Message: "the NVD answered HTTP 503", Code: clierr.UpstreamError}}}},
		{"a malformed ID among valid ones", []Result{ok(a), failed("cve-bad", clierr.InvalidInput, "not a CVE ID", "expected CVE-YYYY-NNNN, e.g. CVE-2021-44228", false, 0), ok(b)},
			[]string{a, b}, []string{"cve-bad"}, &clierr.Error{
				Code: clierr.Partial, Message: "2 of 3 IDs returned, 1 failed", Hint: "check the IDs that failed: cve-bad",
				Input: map[string][]string{"id": {"cve-bad"}}, Targets: []clierr.Target{{Input: "cve-bad", Message: "not a CVE ID", Code: clierr.InvalidInput}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			recs, metaErrs, err := Outcome(c.results, command)
			var gotRecs, gotInputs []string
			for _, r := range recs {
				gotRecs = append(gotRecs, r.ID)
			}
			for _, e := range metaErrs {
				in, _ := e.Input.(string)
				gotInputs = append(gotInputs, in)
			}
			if !reflect.DeepEqual(gotRecs, c.records) || !reflect.DeepEqual(gotInputs, c.metaErrs) {
				t.Errorf("records %v, meta.errors %v; want %v and %v", gotRecs, gotInputs, c.records, c.metaErrs)
			}
			if !reflect.DeepEqual(err, c.want) {
				t.Errorf("error\n got %+v\nwant %+v", err, c.want)
			}
		})
	}
}

// Each meta.errors entry is the failure's error with the argument, as given, as its input.
func TestOutcome_MetaErrorEntries(t *testing.T) {
	t.Parallel()
	_, metaErrs, _ := Outcome([]Result{ok("CVE-2021-44228"), limited(" cve-2024-3094", 5*time.Second)}, command)
	want := &clierr.Error{Code: clierr.RateLimited, Message: "the NVD refused the request for exceeding its rate limit", Hint: "retry after 5s",
		Input: " cve-2024-3094", Transient: true}
	if len(metaErrs) != 1 || !reflect.DeepEqual(metaErrs[0], want) {
		t.Errorf("meta.errors %+v, want [%+v]", metaErrs, want)
	}
}

// Past 20 IDs the hint names the failures instead of listing them.
func TestOutcome_LongListsAreCapped(t *testing.T) {
	t.Parallel()
	var transient, permanent, short []Result
	for _, id := range ids(21) {
		transient = append(transient, limited(id, 25*time.Second))
		permanent = append(permanent, notFound(id))
	}
	for _, id := range ids(20) {
		short = append(short, failed(id, clierr.NetworkError, "cannot reach the NVD", "retry later", true, 0))
	}
	for _, c := range []struct {
		name    string
		results []Result
		hint    string
	}{
		{"21 transient, with a wait", append([]Result{ok("CVE-2021-44228")}, transient...),
			"after 25s, retry the 21 failed IDs marked transient in meta.errors (or the error: lines)"},
		{"2 transient, with no wait", append([]Result{ok("CVE-2021-44228")}, short[0], failed("CVE-2026-2000", clierr.NetworkError, "x", "", true, 0)),
			"run: nyx cve CVE-2026-1000 CVE-2026-2000 --json"},
		{"21 none worth retrying", append([]Result{ok("CVE-2021-44228")}, permanent...),
			"check the 21 IDs that failed in meta.errors (or the error: lines)"},
		{"20 transient are listed", append([]Result{ok("CVE-2021-44228")}, short...),
			"run: " + command(ids(20))},
	} {
		_, _, err := Outcome(c.results, command)
		if err == nil || err.Hint != c.hint {
			t.Errorf("%s: %+v, want the hint %q", c.name, err, c.hint)
		}
	}
	// A single-code error writes neither meta.errors nor error: lines, so its command lists every ID.
	if _, _, err := Outcome(transient, command); err == nil || err.Code != clierr.RateLimited || err.Hint != "after 25s, run: "+command(ids(21)) {
		t.Errorf("21 transient, none succeeded: %+v", err)
	}
	noWait := make([]Result, 0, 22)
	noWait = append(noWait, ok("CVE-2021-44228"))
	for _, id := range ids(21) {
		noWait = append(noWait, failed(id, clierr.NetworkError, "cannot reach the NVD", "retry later", true, 0))
	}
	if _, _, err := Outcome(noWait, command); err == nil || err.Hint != "retry the 21 failed IDs marked transient in meta.errors (or the error: lines)" {
		t.Errorf("21 transient with no wait: %+v", err)
	}
}

// PARTIAL is transient when any failure is, and its hint retries only those.
func TestOutcome_PartialRetriesOnlyTransientFailures(t *testing.T) {
	t.Parallel()
	_, _, err := Outcome([]Result{ok("CVE-2021-44228"), notFound("CVE-2099-0001"), limited("CVE-2024-3094", 2*time.Second)}, command)
	if err == nil || !err.Transient || err.Hint != "after 2s, run: nyx cve CVE-2024-3094 --json" ||
		!reflect.DeepEqual(err.Input, map[string][]string{"id": {"CVE-2099-0001", "CVE-2024-3094"}}) {
		t.Errorf("%+v", err)
	}
}
