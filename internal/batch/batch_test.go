package batch_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/batch"
	"github.com/rafaelh/nyx/internal/clierr"
)

var cfg = batch.Config{
	Noun:    "inputs",
	Key:     "input",
	Command: func(retry []string) string { return "nyx ip " + strings.Join(retry, " ") + " --json" },
}

func fail(name string, code clierr.Code, msg, hint string, transient bool) batch.Failure {
	retry := ""
	if transient {
		retry = name
	}
	return batch.Failure{Name: name, Retry: retry, Err: &clierr.Error{Code: code, Message: msg, Hint: hint, Transient: transient}}
}

func network(name string) batch.Failure {
	return fail(name, clierr.NetworkError, "no answer", "check the connection", true)
}

func inputs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.0.0.%d", i)
	}
	return out
}

func TestOutcome_NothingFailed(t *testing.T) {
	t.Parallel()
	metaErrs, err := batch.Outcome(cfg, 3, 3, nil)
	if metaErrs != nil || err != nil {
		t.Errorf("Outcome = %v, %v; want nil, nil", metaErrs, err)
	}
}

func TestOutcome_OneCode(t *testing.T) {
	t.Parallel()
	notFound := func(n string) batch.Failure {
		return fail(n, clierr.NotFound, "no such name", "check the spelling", false)
	}
	cases := []struct {
		name     string
		failures []batch.Failure
		code     clierr.Code
		message  string
		hint     string
	}{
		{"one failure", []batch.Failure{notFound("a.example")}, clierr.NotFound, "a.example: no such name", "check the spelling"},
		{"messages agree", []batch.Failure{notFound("a.example"), notFound("b.example")}, clierr.NotFound, "2 inputs: no such name", "check the spelling"},
		{"messages differ", []batch.Failure{notFound("a.example"), fail("b.example", clierr.NotFound, "no addresses", "x", false)},
			clierr.NotFound, "2 inputs failed (NOT_FOUND)", "check the spelling"},
		{"transient failures get the retry command", []batch.Failure{network("1.1.1.1"), network("2.2.2.2")},
			clierr.NetworkError, "2 inputs: no answer", "run: nyx ip 1.1.1.1 2.2.2.2 --json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			metaErrs, err := batch.Outcome(cfg, len(c.failures), 0, c.failures)
			if err == nil || err.Code != c.code || err.Message != c.message || err.Hint != c.hint || len(err.Targets) != 0 {
				t.Fatalf("error = %+v; want %s %q hint %q and no targets", err, c.code, c.message, c.hint)
			}
			if len(metaErrs) != len(c.failures) {
				t.Errorf("%d meta errors, want %d", len(metaErrs), len(c.failures))
			}
		})
	}
}

func TestOutcome_OneCodeListsEveryFailureHoweverMany(t *testing.T) {
	t.Parallel()
	var failures []batch.Failure
	for _, n := range inputs(25) {
		failures = append(failures, network(n))
	}
	_, err := batch.Outcome(cfg, 25, 0, failures)
	if err == nil || err.Code != clierr.NetworkError || !strings.HasPrefix(err.Hint, "run: nyx ip 10.0.0.0 ") || !strings.Contains(err.Hint, "10.0.0.24 --json") {
		t.Errorf("hint = %q; a single code's error is all that is written, so it lists all 25", err.Hint)
	}
}

func TestOutcome_TimeoutsSayToRaiseTheDeadline(t *testing.T) {
	t.Parallel()
	f := fail("1.1.1.1", clierr.Timeout, "no answer before the deadline", "x", true)
	_, err := batch.Outcome(cfg, 1, 0, []batch.Failure{f})
	if err == nil || err.Code != clierr.Timeout || err.Hint != "run: nyx ip 1.1.1.1 --json, or raise --timeout" || !err.Transient {
		t.Errorf("error = %+v", err)
	}
	// Mixed with a success, the error is PARTIAL and does not mention the timeout.
	_, err = batch.Outcome(cfg, 2, 1, []batch.Failure{f})
	if err == nil || err.Code != clierr.Partial || strings.Contains(err.Hint, "--timeout") {
		t.Errorf("partial error = %+v", err)
	}
}

func TestOutcome_MixedCodesArePartial(t *testing.T) {
	t.Parallel()
	failures := []batch.Failure{
		fail("a.example", clierr.NotFound, "no such name", "check", false),
		network("1.1.1.1"),
	}
	metaErrs, err := batch.Outcome(cfg, 2, 0, failures)
	if err == nil || err.Code != clierr.Partial || err.Message != "none of 2 inputs returned" || !err.Transient {
		t.Fatalf("error = %+v", err)
	}
	if err.Hint != "run: nyx ip 1.1.1.1 --json" {
		t.Errorf("the hint retries only the transient failure: %q", err.Hint)
	}
	wantTargets := []clierr.Target{
		{Input: "a.example", Message: "no such name", Code: clierr.NotFound},
		{Input: "1.1.1.1", Message: "no answer", Code: clierr.NetworkError},
	}
	if fmt.Sprint(err.Targets) != fmt.Sprint(wantTargets) {
		t.Errorf("targets = %v, want %v", err.Targets, wantTargets)
	}
	if got := fmt.Sprint(err.Input); got != "map[input:[a.example 1.1.1.1]]" {
		t.Errorf("input = %v", got)
	}
	if len(metaErrs) != 2 || metaErrs[0].Input != "a.example" || metaErrs[1].Input != "1.1.1.1" {
		t.Errorf("meta errors = %+v", metaErrs)
	}
}

func TestOutcome_PartialCountsAndHint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		failures []batch.Failure
		returned int
		message  string
		hint     string
		trans    bool
	}{
		{"some returned", []batch.Failure{network("1.1.1.1")}, 2, "2 of 3 inputs returned, 1 failed", "run: nyx ip 1.1.1.1 --json", true},
		{"nothing worth retrying lists the inputs to check",
			[]batch.Failure{fail("a.example", clierr.NotFound, "no such name", "x", false), fail("b.example", clierr.InvalidInput, "bad", "x", false)},
			1, "1 of 3 inputs returned, 2 failed", "check the inputs that failed: a.example, b.example", false},
		{"only transient failures are retried",
			[]batch.Failure{fail("a.example", clierr.NotFound, "no such name", "x", false), network("1.1.1.1"), network("2.2.2.2")},
			1, "1 of 3 inputs returned, 3 failed", "run: nyx ip 1.1.1.1 2.2.2.2 --json", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := batch.Outcome(cfg, 3, c.returned, c.failures)
			if err == nil || err.Code != clierr.Partial || err.Message != c.message || err.Hint != c.hint || err.Transient != c.trans {
				t.Errorf("error = %+v", err)
			}
		})
	}
}

func TestOutcome_RetryTextIsNotTheName(t *testing.T) {
	t.Parallel()
	// A CIDR failed on two of its addresses: it is shown by its name and retried by those addresses.
	cidr := fail("10.0.0.0/30", clierr.NetworkError, "no answer", "x", true)
	cidr.Retry = "10.0.0.1 10.0.0.2"
	skip := network("9.9.9.9")
	skip.Retry = "" // a failure that is not worth retrying, whatever its error says
	_, err := batch.Outcome(cfg, 3, 1, []batch.Failure{cidr, skip})
	if err == nil || err.Hint != "run: nyx ip 10.0.0.1 10.0.0.2 --json" || !err.Transient {
		t.Errorf("error = %+v", err)
	}
	if err.Targets[0].Input != "10.0.0.0/30" {
		t.Errorf("targets = %v", err.Targets)
	}
}

func TestOutcome_NoRetryTextMeansNothingToRetry(t *testing.T) {
	t.Parallel()
	f := network("1.1.1.1")
	f.Retry = ""
	_, err := batch.Outcome(cfg, 2, 1, []batch.Failure{f})
	if err == nil || err.Hint != "check the inputs that failed: 1.1.1.1" {
		t.Errorf("error = %+v", err)
	}
}

func TestOutcome_EntryOverridesTheName(t *testing.T) {
	t.Parallel()
	f := network("example.com")
	f.Entry = map[string][]string{"input": {"example.com"}, "address": {"192.0.2.1"}}
	metaErrs, err := batch.Outcome(cfg, 2, 1, []batch.Failure{f})
	if err == nil || len(metaErrs) != 1 || fmt.Sprint(metaErrs[0].Input) != "map[address:[192.0.2.1] input:[example.com]]" {
		t.Errorf("meta errors = %+v", metaErrs)
	}
	if fmt.Sprint(err.Input) != "map[input:[example.com]]" {
		t.Errorf("the error lists the name: %v", err.Input)
	}
	if f.Err.Input != nil {
		t.Error("the failure's own error must not be changed")
	}
}

func TestOutcome_WaitIsTheLongest(t *testing.T) {
	t.Parallel()
	a, b := network("1.1.1.1"), network("2.2.2.2")
	a.Wait, b.Wait = 1500*time.Millisecond, 4200*time.Millisecond
	_, err := batch.Outcome(cfg, 3, 1, []batch.Failure{a, b})
	if err == nil || err.Hint != "after 5s, run: nyx ip 1.1.1.1 2.2.2.2 --json" {
		t.Errorf("error = %+v", err)
	}
}

func TestOutcome_MoreThanTwentyPointAtTheFailures(t *testing.T) {
	t.Parallel()
	var transient, permanent []batch.Failure
	for _, n := range inputs(21) {
		transient = append(transient, network(n))
		permanent = append(permanent, fail(n, clierr.NotFound, "no such name", "x", false))
	}
	_, err := batch.Outcome(cfg, 22, 1, transient)
	if err == nil || err.Hint != "retry the 21 failed inputs marked transient in meta.errors (or the error: lines)" {
		t.Errorf("transient: %+v", err)
	}
	_, err = batch.Outcome(cfg, 22, 1, permanent)
	if err == nil || err.Hint != "check the 21 inputs that failed in meta.errors (or the error: lines)" {
		t.Errorf("permanent: %+v", err)
	}
	// Exactly twenty are still listed.
	_, err = batch.Outcome(cfg, 21, 1, transient[:20])
	if err == nil || !strings.HasPrefix(err.Hint, "run: nyx ip 10.0.0.0 ") {
		t.Errorf("twenty: %+v", err)
	}
	// The wait still leads the pointer.
	transient[0].Wait = 2 * time.Second
	_, err = batch.Outcome(cfg, 22, 1, transient)
	if err == nil || !strings.HasPrefix(err.Hint, "after 2s, retry the 21 failed") {
		t.Errorf("wait: %+v", err)
	}
}

func TestOutcome_NounAndKeyComeFromTheConfig(t *testing.T) {
	t.Parallel()
	c := batch.Config{Noun: "IDs", Key: "id", Command: cfg.Command}
	_, err := batch.Outcome(c, 3, 1, []batch.Failure{fail("x", clierr.NotFound, "m", "h", false)})
	if err == nil || err.Message != "1 of 3 IDs returned, 1 failed" || fmt.Sprint(err.Input) != "map[id:[x]]" || err.Hint != "check the IDs that failed: x" {
		t.Errorf("error = %+v", err)
	}
}

func TestSeconds(t *testing.T) {
	t.Parallel()
	for d, want := range map[time.Duration]string{0: "1s", time.Millisecond: "1s", time.Second: "1s", 1001 * time.Millisecond: "2s", 90 * time.Second: "90s"} {
		if got := batch.Seconds(d); got != want {
			t.Errorf("Seconds(%v) = %q, want %q", d, got, want)
		}
	}
}
