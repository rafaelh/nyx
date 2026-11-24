package cli_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/httpsrc"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// partial verifies exit 7 after output and returns its PARTIAL error.
func (h *harness) partial(code int, jsonMode bool) failure {
	h.t.Helper()
	return h.partialOf(code, jsonMode, nil, true)
}

// partialOf checks failed-input metadata and handles empty-record human/JSON output
// conventions.
func (h *harness) partialOf(code int, jsonMode bool, ids []string, records bool) failure {
	h.t.Helper()
	if code != 7 {
		h.t.Fatalf("exit %d, want 7\nstdout %q\nstderr %q", code, h.stdout.String(), h.stderr.String())
	}
	if empty := h.stdout.Len() == 0; empty != (!records && !jsonMode) {
		h.t.Errorf("stdout is empty %v on exit 7 (records %v, json %v): %q", empty, records, jsonMode, h.stdout.String())
	}
	f := h.theError(jsonMode)
	if f.code != "PARTIAL" {
		h.t.Errorf("code = %s, want PARTIAL: %+v", f.code, f)
	}
	switch {
	case ids == nil && f.input != nil:
		h.t.Errorf("input = %v, want null", f.input)
	case ids != nil && jsonMode && !slices.Equal(f.inputOf("id"), ids):
		h.t.Errorf("input = %v, want the IDs %v", f.input, ids)
	}
	return f
}

// partialFailed verifies a retryable partial error naming a procedure and failed-job count.
func (h *harness) partialFailed(code int, procedure string, n int) failure {
	h.t.Helper()
	f := h.partial(code, true)
	if want := fmt.Sprintf("%d jobs failed: %s %d", n, procedure, n); f.msg != want || !f.transient {
		h.t.Errorf("error = %+v, want %q, transient", f, want)
	}
	return f
}

// erring is a procedure whose jobs fail with err (n jobs, keys f000...).
func erring(name string, n int, err error) *testkit.Procedure {
	return &testkit.Procedure{ProcedureName: name, Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("f", n) },
		RunFn:  func(context.Context, run.Job, egress.Clients) ([]run.Observation, error) { return nil, err }}
}

// Failed jobs preserve successful output and retry cleanly after the fault is removed.
func TestPartial_FailedJob(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range []bool{true, false} {
		t.Run(fmt.Sprint("json=", jsonMode), func(t *testing.T) {
			t.Parallel()
			bad := erring("flaky", 2, errors.New("source unavailable"))
			ok := finder("fine", obs("hostname", "www.a.com"))
			h := newHarness(t, bad, ok)
			args := []string{"a.com"}
			if jsonMode {
				args = append(args, "--json")
			}
			f := h.partial(h.exec(args...), jsonMode)
			if f.msg != "2 jobs failed: flaky 2" || !f.transient {
				t.Errorf("%+v", f)
			}
			if want := "nyx recon --output-dir " + h.out + " a.com" + map[bool]string{true: " --json"}[jsonMode]; f.hint != want {
				t.Errorf("hint = %q, want %q", f.hint, want)
			}
			if jsonMode {
				env := h.envelope()
				if env.Meta.JobsCompleted != 3 || env.Meta.DeadlineExceeded || len(env.Data.FailedJobs) != 1 || env.Data.FailedJobs[0].N != 2 {
					t.Errorf("envelope = %+v", env)
				}
			} else if !strings.Contains(h.stdout.String(), "Failed jobs") {
				t.Errorf("summary: %s", h.stdout.String())
			}
			if !slices.Contains(h.completed("a.com", "fine"), "c000") {
				t.Error("the other procedure did not complete its job")
			}
			bad.RunFn = nil
			if code := h.exec(append([]string{"-e", "a.com"}, args[1:]...)...); code != 0 {
				t.Errorf("re-run with the fault gone: exit %d\n%s", code, h.stderr.String())
			}
		})
	}
}

// Key-only failures are non-transient unless another failure makes retry worthwhile.
func TestPartial_TransientByCause(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name       string
		procedures func() []run.Procedure
		transient  bool
	}{
		{"a rejected key", func() []run.Procedure {
			return []run.Procedure{erring("keyed", 3, fmt.Errorf("HTTP 401: %w", run.ErrKeyRejected))}
		}, false},
		{"a rejected key and another failure", func() []run.Procedure {
			return []run.Procedure{erring("keyed", 3, fmt.Errorf("HTTP 401: %w", run.ErrKeyRejected)), erring("flaky", 1, errors.New("boom"))}
		}, true},
		{"a plain abort", func() []run.Procedure {
			return []run.Procedure{erring("limited", 2, fmt.Errorf("HTTP 429: %w", run.ErrAbortProcedure))}
		}, true},
		{"a spent quota", func() []run.Procedure {
			return []run.Procedure{erring("spent", 2, fmt.Errorf("HTTP 429: %w", run.ErrQuota))}
		}, true},
		{"a server error", func() []run.Procedure { return []run.Procedure{erring("flaky", 2, errors.New("HTTP 500"))} }, true},
		{"a panic", func() []run.Procedure { return []run.Procedure{panicking("boom")} }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, c.procedures()...)
			f := h.partial(h.exec("a.com", "--concurrency", "1"), false)
			if f.transient != c.transient {
				t.Errorf("transient = %v, want %v: %+v", f.transient, c.transient, f)
			}
			if got := strings.Contains(h.stderr.String(), "retry: may succeed after a wait"); got != c.transient {
				t.Errorf("retry line = %v\n%s", got, h.stderr.String())
			}
		})
	}
}

func panicking(name string) *testkit.Procedure {
	return &testkit.Procedure{ProcedureName: name, Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("p", 1) },
		RunFn:  func(context.Context, run.Job, egress.Clients) ([]run.Observation, error) { panic("boom") }}
}

// keyedGet is a procedure whose one job asks a keyed source through the shared HTTP helper.
func keyedGet(name string) *testkit.Procedure {
	return &testkit.Procedure{ProcedureName: name, Kind: run.ThirdParty, Src: []string{"api.example-source.test"},
		JobsFn: func(run.View) []run.Job { return testkit.Keys("k", 3) },
		RunFn: func(ctx context.Context, _ run.Job, e egress.Clients) ([]run.Observation, error) {
			_, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example-source.test/x",
				KeySource: "shodan", KeyHeader: "X-Key"})
			return nil, err
		}}
}

// Key refusals differ from transient quota/outage responses.
func TestPartial_KeyedSourceStatuses(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		code      int
		transient bool
	}{{401, false}, {403, false}, {429, true}, {500, true}} {
		t.Run(fmt.Sprint(c.code), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, keyedGet("keyed"))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", c.code) }))
			t.Cleanup(srv.Close)
			h.eopts.SourceBaseURLs = map[string]string{"api.example-source.test": srv.URL}
			h.setKey("shodan", "sekret-key-123")
			f := h.partial(h.exec("a.com", "--json", "--concurrency", "1", "--rate-per-source", "1000"), true)
			if f.transient != c.transient || !strings.Contains(f.msg, "keyed ") {
				t.Errorf("%d: %+v", c.code, f)
			}
			if strings.Contains(h.stdout.String()+h.stderr.String(), "sekret-key-123") {
				t.Error("the key reached the output")
			}
		})
	}
	// A rejected key and a failure for another reason: transient.
	h := newHarness(t, keyedGet("keyed"), erring("flaky", 1, errors.New("boom")))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusUnauthorized) }))
	t.Cleanup(srv.Close)
	h.eopts.SourceBaseURLs = map[string]string{"api.example-source.test": srv.URL}
	h.setKey("shodan", "sekret-key-123")
	if f := h.partial(h.exec("a.com", "--json", "--concurrency", "1", "--rate-per-source", "1000"), true); !f.transient {
		t.Errorf("a rejected key and another failure: %+v", f)
	}
}

// Unconfigured, deferred, capped or skipped previous failures do not make current work partial.
func TestPartial_ExitsZeroFor(t *testing.T) {
	t.Parallel()
	t.Run("not configured", func(t *testing.T) {
		t.Parallel()
		nokey := &testkit.Procedure{ProcedureName: "keyed", Kind: run.ThirdParty, ConfiguredFn: func(run.Env) (bool, string) { return false, "no key" }}
		h := newHarness(t, nokey)
		if code := h.exec("a.com", "--json"); code != 0 {
			t.Errorf("exit %d\n%s", code, h.stderr.String())
		}
	})
	t.Run("deferred by a budget", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, budgeted(1, func(run.View) []run.Job { return costed(1, 1, 1) }))
		if code := h.exec("a.com", "--json"); code != 0 {
			t.Fatalf("exit %d\n%s", code, h.stderr.String())
		}
		if env := h.envelope(); len(env.Data.Deferred) != 1 {
			t.Errorf("deferred = %v", env.Data.Deferred)
		}
	})
	t.Run("truncated by a page cap", func(t *testing.T) {
		t.Parallel()
		st := &testkit.Procedure{ProcedureName: "paged", Kind: run.ThirdParty,
			JobsFn: func(run.View) []run.Job { return testkit.Keys("p", 1) },
			RunFn: func(ctx context.Context, _ run.Job, _ egress.Clients) ([]run.Observation, error) {
				run.Warnf(ctx, "result truncated at the page cap")
				return nil, nil
			}}
		h := newHarness(t, st)
		if code := h.exec("a.com", "--json"); code != 0 {
			t.Fatalf("exit %d\n%s", code, h.stderr.String())
		}
		if w := h.envelope().Meta.Warnings; len(w) != 1 {
			t.Errorf("warnings = %q", w)
		}
	})
	t.Run("a failure recorded earlier for a skipped procedure", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t, erring("flaky", 1, errors.New("boom")), noop())
		h.partial(h.exec("a.com"), false)
		if code := h.exec("-e", "a.com", "--skip", "flaky"); code != 0 {
			t.Errorf("exit %d\n%s", code, h.stderr.String())
		}
	})
}

// A job a procedure abandoned without running it is failed but not completed.
func TestPartial_AbortedJobsAreNotCompleted(t *testing.T) {
	t.Parallel()
	h := newHarness(t, erring("keyed", 4, fmt.Errorf("HTTP 401: %w", run.ErrKeyRejected)))
	f := h.partial(h.exec("a.com", "--json", "--concurrency", "1", "--rate-per-source", "1000"), true)
	env := h.envelope()
	if f.msg != "4 jobs failed: keyed 4" || env.Meta.JobsCompleted != 1 {
		t.Errorf("%+v completed %d, want 4 failed and 1 completed", f, env.Meta.JobsCompleted)
	}
}

// A run the deadline ended says so, in the error and in both modes' results.
func TestPartial_DeadlineMessageAndHint(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range []bool{true, false} {
		t.Run(fmt.Sprint("json=", jsonMode), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, erring("flaky", 1, errors.New("boom")), blocking("permutations", 2, 3))
			args := []string{"a.com", "--timeout", "400ms", "--concurrency", "5"}
			if jsonMode {
				args = append(args, "--json")
			}
			f := h.partial(h.exec(args...), jsonMode)
			want := "the deadline (--timeout 400ms) stopped the run: 3 jobs completed, 3 cancelled (permutations 3); failed jobs: flaky 1"
			if f.msg != want || !f.transient {
				t.Errorf("message = %q, want %q (transient %v)", f.msg, want, f.transient)
			}
			if jsonMode {
				env := h.envelope()
				if !env.Meta.DeadlineExceeded || env.Meta.JobsCompleted != 3 || env.Meta.JobsCancelled != 3 {
					t.Errorf("meta = %+v", env.Meta)
				}
			} else if !strings.Contains(h.stdout.String(), "Stopped by the deadline: 3 jobs completed, 3 cancelled") {
				t.Errorf("summary: %s", h.stdout.String())
			}
		})
	}
}

// The hint is the caller's call with --redo removed and everything else kept, shell-quoted; running it
// carries on.
func TestPartial_DeadlineHint(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name   string
		before []string
		redo   []string
		quote  bool
	}{
		{"redo with its value", nil, []string{"--redo", "slow"}, false},
		{"redo=value", nil, []string{"--redo=slow"}, false},
		{"a shared flag before the command", []string{"--json"}, []string{"--redo", "slow"}, false},
		{"an argument that needs quoting", nil, nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			st := blocking("slow", 1, 2)
			h := newHarness(t, st)
			args := slices.Clone(c.before)
			args = append(args, "recon", "--output-dir", h.out, "--timeout", "400ms")
			var kept []string
			if c.quote {
				kept = []string{"--org", "Acme Pty", "a.com"}
			} else {
				kept = []string{"a.com"}
			}
			full := append(append(slices.Clone(args), kept...), c.redo...)
			// Seed the engagement, then use --redo against it where the case has one.
			if c.redo != nil {
				if code := h.execRoot(append(slices.Clone(args), kept...)...); code != 7 {
					t.Fatalf("seed run: exit %d", code)
				}
				st.RunFn = func(ctx context.Context, k run.Job, _ egress.Clients) ([]run.Observation, error) {
					if strings.HasPrefix(k.Key, "b") {
						<-ctx.Done()
						return nil, ctx.Err()
					}
					return nil, nil
				}
			}
			jsonMode := slices.Contains(c.before, "--json")
			f := h.partial(h.execRoot(full...), jsonMode)
			want := "nyx " + strings.Join(append(append(slices.Clone(c.before), "recon", "--output-dir", h.out, "--timeout", "400ms"), quoteAll(kept)...), " ")
			if f.hint != want || !f.transient {
				t.Errorf("hint = %q, want %q (transient %v)", f.hint, want, f.transient)
			}
			// Running the hint's arguments completes the run.
			st.RunFn = nil
			if code := h.execRoot(shellSplit(t, f.hint)...); code != 0 {
				t.Errorf("running the hint: exit %d\n%s", code, h.stderr.String())
			}
		})
	}
}

// shellSplit splits a hint the way a POSIX shell would: words, and single quotes around a word.
func shellSplit(t *testing.T, hint string) []string {
	t.Helper()
	rest, ok := strings.CutPrefix(hint, "nyx ")
	if !ok {
		t.Fatalf("hint %q is not a nyx call", hint)
	}
	var out []string
	var cur strings.Builder
	quoted, inWord := false, false
	for _, r := range rest {
		switch {
		case r == '\'':
			quoted, inWord = !quoted, true
		case r == ' ' && !quoted:
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

func quoteAll(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = a
		if strings.ContainsAny(a, " ") {
			out[i] = "'" + a + "'"
		}
	}
	return out
}

// With no job succeeding the hint says to raise --timeout, and the error is not transient, whatever
// the failures were.
func TestPartial_RaiseTimeoutWhenNothingSucceeded(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name       string
		procedures []run.Procedure
		timeout    string
	}{
		{"a timeout too small to start a job", []run.Procedure{blocking("slow", 3, 0)}, "1ms"},
		{"every started job cancelled", []run.Procedure{blocking("slow", 0, 3)}, "400ms"},
		{"one job that always fails and the rest cancelled", []run.Procedure{erring("flaky", 1, errors.New("boom")), blocking("slow", 0, 3)}, "400ms"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, c.procedures...)
			f := h.partial(h.exec("a.com", "--timeout", c.timeout), false)
			if want := "raise --timeout: no job succeeded within " + c.timeout; f.hint != want || f.transient {
				t.Errorf("hint %q transient %v, want %q and not transient", f.hint, f.transient, want)
			}
		})
	}
}

// Cancellation during deadline cleanup still yields INTERRUPTED with empty stdout.
func TestPartial_SignalDuringWrapUpLeavesStdoutEmpty(t *testing.T) {
	t.Parallel()
	var cut atomic.Bool
	st := &testkit.Procedure{ProcedureName: "slow", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("b", 1) },
		RunFn: func(ctx context.Context, _ run.Job, _ egress.Clients) ([]run.Observation, error) {
			<-ctx.Done()
			cut.Store(true)
			return nil, ctx.Err()
		}}
	h := newHarness(t, st)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.files = append(output.Default(), output.File{Name: "wrapup.txt", Format: output.TXT, Rows: func(output.Snapshot) []output.Row {
		if cut.Load() {
			cancel()
		}
		return nil
	}})
	code := h.execCtx(ctx, "a.com", "--json", "--timeout", "400ms")
	f := h.failed(code, 130, true)
	if f.code != "INTERRUPTED" {
		t.Errorf("%+v", f)
	}
}

// The netblock limit met while the deadline's wrap-up rebuilds the scope is the error (exit 2), not
// the deadline's.
func TestPartial_NetblockLimitComesBeforeTheDeadline(t *testing.T) {
	t.Parallel()
	// Discover an oversized block before a second blocking job so cleanup, rather than
	// normal procedure completion, encounters the limit.
	asn := expander{&testkit.Procedure{ProcedureName: "asn", Kind: run.ThirdParty,
		JobsFn: func(v run.View) []run.Job {
			var cs []run.Job
			for _, a := range v.Inputs().ASNs {
				cs = append(cs, run.Job{Key: a})
			}
			return append(cs, run.Job{Key: "block"})
		},
		RunFn: func(ctx context.Context, c run.Job, _ egress.Clients) ([]run.Observation, error) {
			if c.Key == "block" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return []run.Observation{kinds.Netblock.Obs("10.0.0.0/22", kinds.NetblockAttrs{ASN: c.Key})}, nil
		}}}
	h := newHarness(t, asn)
	code := h.exec("--asn", "64500", "--netblock-limit", "1000", "--timeout", "400ms", "--concurrency", "2")
	f := h.failed(code, 2, false)
	if f.code != "INVALID_INPUT" || !strings.Contains(f.msg, "1024") {
		t.Errorf("%+v", f)
	}
}

// A fatal error (a file that cannot be written) comes before the netblock limit.
func TestPartial_FatalErrorComesBeforeTheNetblockLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if err := os.Mkdir(filepath.Join(h.eng("a.com"), "blocked"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.files = append(output.Default(), output.File{Name: "blocked", Format: output.TXT, Rows: func(output.Snapshot) []output.Row {
		return []output.Row{{Cells: []string{"x"}, Current: true}}
	}})
	f := h.failed(h.exec("-e", "a.com", "--cidr", "10.0.0.0/16", "--netblock-limit", "1000"), 1, false)
	if f.code != "UNEXPECTED_ERROR" {
		t.Errorf("%+v", f)
	}
}

// A signal after output cannot replace the already-reported partial outcome.
func TestPartial_SignalAfterTheResultKeepsExit7(t *testing.T) {
	t.Parallel()
	h := newHarness(t, erring("flaky", 1, errors.New("boom")))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := h.deps()
	d.Stdout = cancelOnWrite{w: &h.stdout, cancel: cancel}
	code := cli.Execute(ctx, []string{"recon", "--output-dir", h.out, "a.com", "--json"}, d)
	if code != 7 {
		t.Fatalf("exit %d, want 7\nstderr %s", code, h.stderr.String())
	}
	if f := h.theError(true); f.code != "PARTIAL" {
		t.Errorf("%+v", f)
	}
	if h.stdout.Len() == 0 {
		t.Error("the result was not written")
	}
}

// cancelOnWrite cancels the command once a write has gone through.
type cancelOnWrite struct {
	w      interface{ Write([]byte) (int, error) }
	cancel context.CancelFunc
}

func (c cancelOnWrite) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.cancel()
	return n, err
}
