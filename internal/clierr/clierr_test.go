package clierr_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/rafaelh/nyx/internal/clierr"
)

// Every error code has its exit code; the table is part of the stable interface.
func TestExitCodes(t *testing.T) {
	for code, want := range map[clierr.Code]int{
		clierr.NetworkError: 1, clierr.Timeout: 1, clierr.RateLimited: 1, clierr.UpstreamError: 1,
		clierr.AuthFailed: 1, clierr.Unexpected: 1,
		clierr.InvalidInput: 2,
		clierr.NotFound:     3,
		clierr.Partial:      7,
		clierr.Interrupted:  130,
		"SOMETHING_NEW":     1,
	} {
		if got := clierr.ExitCode(code); got != want {
			t.Errorf("ExitCode(%s) = %d, want %d", code, got, want)
		}
	}
	// The names themselves are the interface.
	for code, name := range map[clierr.Code]string{
		clierr.NetworkError: "NETWORK_ERROR", clierr.Timeout: "TIMEOUT", clierr.RateLimited: "RATE_LIMITED",
		clierr.UpstreamError: "UPSTREAM_ERROR", clierr.AuthFailed: "AUTH_FAILED", clierr.Unexpected: "UNEXPECTED_ERROR",
		clierr.InvalidInput: "INVALID_INPUT", clierr.NotFound: "NOT_FOUND", clierr.Partial: "PARTIAL",
		clierr.Interrupted: "INTERRUPTED",
	} {
		if string(code) != name {
			t.Errorf("%q is spelt %q", name, code)
		}
	}
}

// Problems become one usage error: every message, the distinct hints, and each
// failing value under its argument's name, always as a list.
func TestProblemsUsage(t *testing.T) {
	var p clierr.Problems
	if p.Err() != nil {
		t.Fatal("no problems is no error")
	}
	p.Add("concurrency", "abc", `concurrency: invalid value "abc": not an integer`, "")
	p.Add("redo", "nope", `unknown stage "nope" for --redo`, "valid stages: a, b")
	p.Add("skip", "resolve", `stage "resolve" cannot be skipped`, "valid stages: a, b")
	p.Add("domain", "x y", `invalid domain "x y"`, "")
	p.Add("domain", "z_z", `invalid domain "z_z"`, "")
	p.Add("engagement", "", "missing -e", "")
	p.Add("", "", "no inputs", "")
	var err error = p
	var back clierr.Problems
	if !errors.As(err, &back) || len(back) != 7 {
		t.Fatalf("Problems is not an error that keeps its problems: %v", err)
	}
	e := p.Usage("nyx recon --help")
	if e.Code != clierr.InvalidInput || clierr.ExitCode(e.Code) != 2 {
		t.Errorf("code %s", e.Code)
	}
	if want := `concurrency: invalid value "abc": not an integer; unknown stage "nope" for --redo; stage "resolve" cannot be skipped; invalid domain "x y"; invalid domain "z_z"; missing -e; no inputs`; e.Message != want {
		t.Errorf("message = %q", e.Message)
	}
	if e.Hint != "valid stages: a, b" {
		t.Errorf("hint = %q", e.Hint)
	}
	b, _ := json.Marshal(e.Input)
	if want := `{"concurrency":["abc"],"domain":["x y","z_z"],"engagement":[],"redo":["nope"],"skip":["resolve"]}`; string(b) != want {
		t.Errorf("input = %s, want %s", b, want)
	}

	// No hint of its own: the default. No named argument: no input.
	var q clierr.Problems
	q.Merge(errors.New("plain"))
	if e := q.Usage("nyx recon --help"); e.Hint != "nyx recon --help" || e.Input != nil || e.Message != "plain" {
		t.Errorf("%+v", e)
	}
	q.Merge(p)
	if len(q) != 8 {
		t.Errorf("Merge of Problems kept %d", len(q))
	}
}

func TestPanicError(t *testing.T) {
	if got := (&clierr.PanicError{Value: "boom"}).Error(); got != "unexpected failure: boom" {
		t.Errorf("%q", got)
	}
}
