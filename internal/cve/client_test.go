package cve

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/egress"
)

// answer is one scripted reply of the fake NVD: a response, an error, or
// (hold) no answer until the request's context ends.
type answer struct {
	status int
	header map[string][]string
	body   string
	err    error
	hold   bool
	trunc  bool
}

// fakeNVD is an egress.ThirdPartyHTTP that answers from a script, repeating its
// last answer, and records each request.
type fakeNVD struct {
	mu      sync.Mutex
	script  []answer
	reqs    []egress.ThirdPartyRequest
	reqTime []time.Time
}

func (f *fakeNVD) Do(ctx context.Context, r egress.ThirdPartyRequest) (egress.ThirdPartyResponse, error) {
	f.mu.Lock()
	a := f.script[min(len(f.reqs), len(f.script)-1)]
	f.reqs = append(f.reqs, r)
	f.reqTime = append(f.reqTime, time.Now())
	f.mu.Unlock()
	switch {
	case a.hold:
		<-ctx.Done()
		return egress.ThirdPartyResponse{}, errors.New("Get: " + ctx.Err().Error()) // scrubbed, as egress does
	case a.err != nil:
		return egress.ThirdPartyResponse{}, a.err
	}
	return egress.ThirdPartyResponse{Status: a.status, Header: a.header, Body: []byte(a.body), Truncated: a.trunc}, nil
}

func (f *fakeNVD) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func found(t *testing.T, fixture string) answer {
	t.Helper()
	b, err := os.ReadFile("testdata/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	return answer{status: 200, body: `{"resultsPerPage":1,"startIndex":0,"totalResults":1,"vulnerabilities":[{"cve":` + string(b) + `}]}`}
}

var (
	none         = answer{status: 200, body: `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`}
	unavailable  = answer{status: 503}
	tooMany      = answer{status: 429, header: map[string][]string{"Retry-After": {"0"}}}
	plain403     = answer{status: 403, body: "Forbidden"}
	badKey404    = answer{status: 404, header: map[string][]string{"Message": {"Invalid apiKey."}}}
	badParam404  = answer{status: 404, header: map[string][]string{"Message": {"Invalid cveId parameter."}}}
	networkError = answer{err: errors.New("dial tcp: connection refused")}
)

// newTestClient is a Client over the script, with a 1ms backoff.
func newTestClient(keyed bool, script ...answer) (*Client, *fakeNVD) {
	f := &fakeNVD{script: script}
	c := NewClient(Config{HTTP: f, Keyed: keyed, AuthHint: "check NVD_API_KEY"})
	c.backoff = time.Millisecond
	return c, f
}

// failure is Get's error as a *Failure, failing the test otherwise.
func failure(t *testing.T, err error) *Failure {
	t.Helper()
	var f *Failure
	if !errors.As(err, &f) || f.Err == nil {
		t.Fatalf("Get's error = %v, want a *Failure", err)
	}
	return f
}

func withTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestClient_Found(t *testing.T) {
	t.Parallel()
	for _, keyed := range []bool{false, true} {
		c, f := newTestClient(keyed, found(t, "primary-over-secondary.json"))
		ctx := withTimeout(t, time.Minute)
		rec, err := c.Get(ctx, "CVE-2021-44228")
		if err != nil {
			t.Fatalf("keyed=%v: %v", keyed, err)
		}
		if got := encode(t, rec); got != fixtureRecords["primary-over-secondary.json"] {
			t.Errorf("record %s", got)
		}
		r := f.reqs[0]
		if r.Method != "GET" || r.URL != "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228" || r.Accept != "application/json" {
			t.Errorf("request %+v", r)
		}
		if keyed != (r.KeySource == "nvd" && r.KeyHeader == "apiKey") || !keyed && (r.KeySource != "" || r.KeyHeader != "") {
			t.Errorf("keyed=%v: key source %q, header %q", keyed, r.KeySource, r.KeyHeader)
		}
		// The invocation's deadline governs the request, not egress's default.
		if r.Timeout <= 50*time.Second || r.Timeout > time.Minute {
			t.Errorf("request timeout %v, want the time left to the deadline", r.Timeout)
		}
	}
}

// expectFailure checks a Get that failed: its code, transient, the number of
// requests made, and that its message and hint contain the given text.
func expectFailure(t *testing.T, err error, f *fakeNVD, code clierr.Code, transient bool, calls int, msg, hint string) *Failure {
	t.Helper()
	fl := failure(t, err)
	e := fl.Err
	if e.Code != code || e.Transient != transient || f.calls() != calls {
		t.Errorf("got %s transient=%v after %d requests, want %s transient=%v after %d: %+v", e.Code, e.Transient, f.calls(), code, transient, calls, e)
	}
	if !strings.Contains(e.Message, msg) || !strings.Contains(e.Hint, hint) {
		t.Errorf("message %q, hint %q; want them to contain %q and %q", e.Message, e.Hint, msg, hint)
	}
	if e.Input != nil {
		t.Errorf("input %v, want none: the command sets it", e.Input)
	}
	return fl
}

func TestClient_Classification(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		keyed     bool
		script    []answer
		code      clierr.Code
		transient bool
		calls     int
		msg, hint string
	}{
		{"no vulnerabilities is not found", false, []answer{none}, clierr.NotFound, false, 1, "not in the NVD", "check the ID; the NVD lists only published CVEs"},
		{"401", true, []answer{{status: 401}}, clierr.AuthFailed, false, 1, "the NVD refused the API key", "check NVD_API_KEY"},
		{"404 naming the key in its message header", true, []answer{badKey404}, clierr.AuthFailed, false, 1, "the NVD refused the API key", "check NVD_API_KEY"},
		{"403 naming the key in its body", true, []answer{{status: 403, body: `{"message":"Invalid APIKEY"}`}}, clierr.AuthFailed, false, 1, "the NVD refused the API key", "check NVD_API_KEY"},
		{"any other 404", false, []answer{badParam404}, clierr.UpstreamError, false, 1, "Invalid cveId parameter.", ""},
		{"500 is not retried", false, []answer{{status: 500}}, clierr.UpstreamError, true, 1, "500", "retry later"},
		{"503 three times", false, []answer{unavailable}, clierr.UpstreamError, true, 3, "503", "retry later"},
		{"other 4xx", false, []answer{{status: 400}}, clierr.UpstreamError, false, 1, "400", ""},
		{"undecodable body", false, []answer{{status: 200, body: "<html>"}}, clierr.UpstreamError, false, 1, "", ""},
		{"truncated body", false, []answer{{status: 200, body: `{"vulnerabilities":[`, trunc: true}}, clierr.UpstreamError, false, 1, "", ""},
		{"unkeyed 403 with a plain body", false, []answer{plain403}, clierr.RateLimited, true, 3, "", "retry after"},
		{"keyed 403 with a plain body", true, []answer{plain403}, clierr.RateLimited, true, 3, "", "retry after"},
		{"429 three times", false, []answer{tooMany}, clierr.RateLimited, true, 3, "", "or set NVD_API_KEY for 50 requests per 30s"},
		{"network error three times", false, []answer{networkError}, clierr.NetworkError, true, 3, "connection refused", "retry later"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			cl, f := newTestClient(c.keyed, c.script...)
			_, err := cl.Get(withTimeout(t, time.Minute), "CVE-2021-44228")
			_ = expectFailure(t, err, f, c.code, c.transient, c.calls, c.msg, c.hint)
		})
	}
}

// A keyed rate-limit hint does not suggest setting a key.
func TestClient_RateLimitHintWhenKeyed(t *testing.T) {
	t.Parallel()
	cl, f := newTestClient(true, tooMany)
	_, err := cl.Get(withTimeout(t, time.Minute), "CVE-2021-44228")
	if fl := expectFailure(t, err, f, clierr.RateLimited, true, 3, "", "retry after"); strings.Contains(fl.Err.Hint, "NVD_API_KEY") {
		t.Errorf("hint %q suggests a key the call already has", fl.Err.Hint)
	}
}

func TestClient_RetriesThenSucceeds(t *testing.T) {
	t.Parallel()
	ok := found(t, "rejected.json")
	for name, script := range map[string][]answer{
		"429 with Retry-After 0, then 200": {tooMany, ok},
		"503 twice, then 200":              {unavailable, unavailable, ok},
		"a network error, then 200":        {networkError, ok},
		"a plain 403, then 200":            {plain403, ok},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cl, f := newTestClient(false, script...)
			rec, err := cl.Get(withTimeout(t, time.Minute), "CVE-2021-0001")
			if err != nil || rec.Status != "Rejected" || f.calls() != len(script) {
				t.Errorf("rec %+v, err %v after %d requests", rec, err, f.calls())
			}
		})
	}
}

// A Retry-After that would pass the deadline fails the ID at once, as a
// transient rate limit with the wait in its hint.
func TestClient_RetryAfterPastTheDeadline(t *testing.T) {
	t.Parallel()
	cl, f := newTestClient(false, answer{status: 429, header: map[string][]string{"Retry-After": {"120"}}})
	start := time.Now()
	_, err := cl.Get(withTimeout(t, time.Second), "CVE-2021-44228")
	fl := expectFailure(t, err, f, clierr.RateLimited, true, 1, "", "retry after 120s; or set NVD_API_KEY for 50 requests per 30s")
	if fl.Wait != 120*time.Second || time.Since(start) > 500*time.Millisecond {
		t.Errorf("wait %v after %v, want 120s at once", fl.Wait, time.Since(start))
	}
}

// A backoff that would pass the deadline after anything but a rate limit is a
// timeout, transient, with the wait in its hint.
func TestClient_BackoffPastTheDeadline(t *testing.T) {
	t.Parallel()
	cl, f := newTestClient(false, unavailable)
	cl.backoff = 4 * time.Second // the first retry waits 2s to 6s
	start := time.Now()
	_, err := cl.Get(withTimeout(t, 300*time.Millisecond), "CVE-2021-44228")
	fl := expectFailure(t, err, f, clierr.Timeout, true, 1, "", ", or raise --timeout")
	if !strings.HasPrefix(fl.Err.Hint, "retry after ") || fl.Wait < 2*time.Second || time.Since(start) > 200*time.Millisecond {
		t.Errorf("hint %q, wait %v after %v; want the wait in the hint, at once", fl.Err.Hint, fl.Wait, time.Since(start))
	}
}

// A request the deadline cuts off is a timeout and is not retried.
func TestClient_DeadlineDuringARequest(t *testing.T) {
	t.Parallel()
	cl, f := newTestClient(false, answer{hold: true})
	_, err := cl.Get(withTimeout(t, 100*time.Millisecond), "CVE-2021-44228")
	_ = expectFailure(t, err, f, clierr.Timeout, true, 1, "no answer from the NVD before the deadline", "raise --timeout")
}

// A cancel that is not the deadline (a signal) is returned as the context's error.
func TestClient_Cancelled(t *testing.T) {
	t.Parallel()
	cl, _ := newTestClient(false, answer{hold: true})
	ctx, cancel := context.WithCancel(withTimeout(t, time.Minute))
	time.AfterFunc(50*time.Millisecond, cancel)
	_, err := cl.Get(ctx, "CVE-2021-44228")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// Every attempt takes its own slot in the window: unkeyed, five requests go at
// once and the sixth, whose slot is after the deadline, fails at once as a
// rate limit with the wait in its hint.
func TestClient_WindowSlotPastTheDeadline(t *testing.T) {
	t.Parallel()
	cl, f := newTestClient(false, none)
	ctx := withTimeout(t, 2*time.Second)
	for range 5 {
		if _, err := cl.Get(ctx, "CVE-2021-44228"); failure(t, err).Err.Code != clierr.NotFound {
			t.Fatal(err)
		}
	}
	start := time.Now()
	_, err := cl.Get(ctx, "CVE-2021-44228")
	fl := expectFailure(t, err, f, clierr.RateLimited, true, 5, "", "; or set NVD_API_KEY for 50 requests per 30s")
	if !strings.HasPrefix(fl.Err.Hint, "retry after 30s") && !strings.HasPrefix(fl.Err.Hint, "retry after 29s") || time.Since(start) > 200*time.Millisecond {
		t.Errorf("hint %q after %v, want the wait for the slot, at once", fl.Err.Hint, time.Since(start))
	}
	keyed, kf := newTestClient(true, none)
	for range 6 {
		_, _ = keyed.Get(ctx, "CVE-2021-44228")
	}
	if kf.calls() != 6 {
		t.Errorf("keyed: %d requests, want 6 within the window of 50", kf.calls())
	}
}

// The first refused key stops the batch: an ID not yet sent fails with the
// same error and no request.
func TestClient_RefusedKeyStopsTheBatch(t *testing.T) {
	t.Parallel()
	cl, f := newTestClient(true, badKey404)
	ctx := withTimeout(t, time.Minute)
	first, second := failure(t, second(cl.Get(ctx, "CVE-2021-44228"))), failure(t, second(cl.Get(ctx, "CVE-2021-45046")))
	if f.calls() != 1 || first.Err.Code != clierr.AuthFailed || second.Err.Code != clierr.AuthFailed ||
		first.Err.Message != second.Err.Message || second.Err.Hint != "check NVD_API_KEY" {
		t.Errorf("after %d requests: %+v then %+v", f.calls(), first.Err, second.Err)
	}
	// A 404 that does not name the key does not stop it.
	cl, f = newTestClient(true, badParam404, found(t, "rejected.json"))
	_, _ = cl.Get(ctx, "CVE-2021-44228")
	if _, err := cl.Get(ctx, "CVE-2021-0001"); err != nil || f.calls() != 2 {
		t.Errorf("after a plain 404: %v after %d requests", err, f.calls())
	}
}

func second(_ Record, err error) error { return err }

// --debug gets one line per attempt, naming the ID, the status, the attempt and the wait.
func TestClient_DebugLines(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var lines []string
	f := &fakeNVD{script: []answer{unavailable, found(t, "rejected.json")}}
	cl := NewClient(Config{HTTP: f, Debug: func(s string) { mu.Lock(); lines = append(lines, s); mu.Unlock() }})
	cl.backoff = time.Millisecond
	if _, err := cl.Get(withTimeout(t, time.Minute), "CVE-2021-0001"); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || !strings.Contains(lines[0], "CVE-2021-0001") || !strings.Contains(lines[0], "503") ||
		!strings.Contains(lines[0], "attempt 1") || !strings.Contains(lines[0], "retry in") ||
		!strings.Contains(lines[1], "200") || !strings.Contains(lines[1], "attempt 2") {
		t.Errorf("debug lines %q", lines)
	}
}

// A wait for a slot in the window is in the attempt's debug line.
func TestClient_DebugLinesNameTheSlotWait(t *testing.T) {
	t.Parallel()
	var lines []string
	f := &fakeNVD{script: []answer{found(t, "rejected.json")}}
	cl := NewClient(Config{HTTP: f, Debug: func(s string) { lines = append(lines, s) }})
	cl.win = newWindow(1, 30*time.Millisecond, time.Now)
	if wait, ok := cl.win.reserve(withTimeout(t, time.Minute)); !ok || wait != 0 {
		t.Fatalf("the first slot: %v, %v", wait, ok)
	}
	if _, err := cl.Get(withTimeout(t, time.Minute), "CVE-2021-0001"); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "attempt 1 (after a wait of ") || !strings.Contains(lines[0], "for the rate limit): HTTP 200") {
		t.Errorf("debug lines %q", lines)
	}
}

// Once the deadline has passed, an ID not yet sent is a timeout, not a rate
// limit, and is never sent.
func TestClient_DeadlinePassedBeforeSending(t *testing.T) {
	t.Parallel()
	f := &fakeNVD{script: []answer{found(t, "rejected.json")}}
	cl := NewClient(Config{HTTP: f})
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := cl.Get(ctx, "CVE-2021-0001")
	var fl *Failure
	if !errors.As(err, &fl) || fl.Err.Code != clierr.Timeout || !fl.Err.Transient || f.calls() != 0 {
		t.Errorf("%v after %d requests, want a transient TIMEOUT and none", err, f.calls())
	}
}
