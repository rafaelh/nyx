package cli_test

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/engagement"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

func noop() *testkit.Stage { return &testkit.Stage{StageName: "noop", Kind: run.ThirdParty} }

func obs(kind, key string, kv ...any) run.Observation {
	a := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		a[kv[i].(string)] = kv[i+1]
	}
	return run.Observation{Kind: kind, Key: key, Attrs: a}
}

func csvRows(t *testing.T, body string) [][]string {
	t.Helper()
	r, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("csv: %v\n%s", err, body)
	}
	return r
}

func hasRow(rows [][]string, cells ...string) bool {
outer:
	for _, r := range rows {
		if len(r) < len(cells) {
			continue
		}
		for i, c := range cells {
			if r[i] != c {
				continue outer
			}
		}
		return true
	}
	return false
}

// Every input form is stored; files ignore comments and blanks.
func TestInputsStored(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	df := writeFile(t, t.TempDir(), "d.txt", "# comment\n\nfile.example.org\n")
	xf := writeFile(t, t.TempDir(), "x.txt", "# c\n*.dev.example.com\n\n")
	code := h.exec("Example.com", "-d", df, "--org", "Acme Corp", "--asn", "13335", "--cidr", "10.1.2.3/24",
		"-x", "admin.example.com", "--exclude-file", xf)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	cmp := func(kind string, want ...string) {
		t.Helper()
		if got := h.inputs("example.com", kind); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v, want %v", kind, got, want)
		}
	}
	cmp("root", "example.com", "file.example.org")
	cmp("org", "Acme Corp")
	cmp("asn", "AS13335")
	cmp("cidr", "10.1.2.0/24")
	cmp("exclude", "*.dev.example.com", "admin.example.com")
	rows := csvRows(t, h.readOut("example.com", "scope.csv"))
	for _, want := range [][]string{{"root", "example.com"}, {"org", "Acme Corp"}, {"asn", "AS13335"}, {"cidr", "10.1.2.0/24"}} {
		if !hasRow(rows, want...) {
			t.Errorf("scope.csv missing %v:\n%v", want, rows)
		}
	}
}

// Engagement naming.
func TestEngagementDirNaming(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	for _, c := range []struct {
		args []string
		dir  string
	}{
		{[]string{"Example.COM", "other.org"}, "example.com"},
		{[]string{"--org", "Acme Corp, Inc."}, "acme-corp-inc"},
		{[]string{"--asn", "64500"}, "as64500"},
		{[]string{"--cidr", "10.0.0.0/24"}, "10.0.0.0_24"},
		{[]string{"-e", "custom-name", "example.net"}, "custom-name"},
		{[]string{"-e", "Custom Name", "example.net"}, "custom-name"},
		{[]string{"-e", "../escape", "example.net"}, "escape"},
	} {
		if code := h.exec(c.args...); code != 0 {
			t.Fatalf("%v: exit %d %s", c.args, code, h.stderr.String())
		}
		if st, err := os.Stat(h.eng(c.dir)); err != nil || !st.IsDir() {
			t.Errorf("%v: expected dir %s", c.args, c.dir)
		}
	}
	for _, bad := range []string{"---", "..", "/"} {
		if code := h.exec("-e", bad, "example.com"); code != 2 || !strings.Contains(h.stderr.String(), bad) {
			t.Errorf("-e %s: exit %d, stderr %q", bad, code, h.stderr.String())
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(h.out), "escape")); err == nil {
		t.Error("-e escaped the output directory")
	}
}

func TestNoInputsAndNoEngagement(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.exec(); code != 2 {
		t.Errorf("no inputs: exit %d", code)
	}
}

// Help.
func TestHelp(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "alpha", Kind: run.ThirdParty}
	h := newHarness(t, st, &testkit.Stage{StageName: "beta", Kind: run.ThirdParty})
	if code := h.exec("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	help := h.stdout.String()
	for _, w := range []string{
		"--ports", "37,53,79-81,443", "--risky-ports", "21,23,445,1433", "--concurrency", "10", "--rate-per-host", "--rate-per-source", "--rate-dns", "50",
		"--crawl-depth", "--crawl-pages", "100", "--output-dir", "--netblock-limit", "4096", "--wordlist", "--sensitive-paths", config.BuiltinSensitivePathsLabel(), "--storage-max-names", "--cert-expiry-days",
		"config.yaml", ".config/nyx", "keys.<source>", "--redo", "--passive", "--authorised", "--json",
	} {
		if !strings.Contains(help, w) {
			t.Errorf("help missing %q", w)
		}
	}
	if strings.Contains(help, "NYX_") {
		t.Error("help must not name a NYX_* variable: no setting is read from the environment")
	}
	if strings.Contains(help, "49152-49157") {
		t.Error("help must not list the default ports")
	}
	if strings.Contains(help, "--key") || strings.Contains(help, "--api-key") {
		t.Error("help must not offer key flags")
	}
	topic := h.stagesHelp()
	for _, s := range []string{"alpha", "beta"} {
		if stageRow(topic, s) == "" {
			t.Errorf("help stages does not list %s:\n%s", s, topic)
		}
	}
}

// Re-runs add inputs; the engagement name alone resumes; promoted candidates move into scope.
func TestRerunAddsAndResumes(t *testing.T) {
	t.Parallel()
	var gotRoots, gotExcl []string
	st := &testkit.Stage{StageName: "spy", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check {
		in := v.Inputs()
		gotRoots, gotExcl = in.Roots, in.Exclusions
		return nil
	}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "-x", "x.a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if code := h.exec("-e", "a.com", "b.com", "-x", "y.a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if strings.Join(gotRoots, ",") != "a.com,b.com" || strings.Join(gotExcl, ",") != "x.a.com,y.a.com" {
		t.Errorf("after add: %v %v", gotRoots, gotExcl)
	}
	if code := h.exec("-e", "a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if strings.Join(gotRoots, ",") != "a.com,b.com" || strings.Join(gotExcl, ",") != "x.a.com,y.a.com" {
		t.Errorf("resume must keep stored scope: %v %v", gotRoots, gotExcl)
	}
}

func TestPromotedCandidate(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "disc", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 1) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("root", "partner.net"), obs("hostname", "www.partner.net")}, nil
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	cand := csvRows(t, h.readOut("a.com", "candidates.csv"))
	if !hasRow(cand, "root", "partner.net") || !hasRow(cand, "hostname", "www.partner.net") {
		t.Fatalf("candidates.csv: %v", cand)
	}
	if code := h.exec("-e", "a.com", "partner.net"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	cand = csvRows(t, h.readOut("a.com", "candidates.csv"))
	if hasRow(cand, "root", "partner.net") || hasRow(cand, "hostname", "www.partner.net") {
		t.Errorf("promoted root and its hosts must leave candidates.csv: %v", cand)
	}
	if !hasRow(csvRows(t, h.readOut("a.com", "scope.csv")), "root", "partner.net") {
		t.Error("promoted root missing from scope.csv")
	}
}

// An empty directory, or one whose creation was interrupted, is adopted as the
// engagement. (A directory that is not an engagement is refused: see
// TestEngagementErrors_ForeignDirectory.)
func TestEngagementDirAdopted(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if err := os.MkdirAll(h.eng("empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if code := h.exec("-e", "empty", "a.com"); code != 0 {
		t.Errorf("empty dir should be adopted: %d %s", code, h.stderr.String())
	}
	if err := os.MkdirAll(filepath.Join(h.eng("half"), ".nyx"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.eng("half"), ".nyx", "lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := h.exec("-e", "half", "a.com"); code != 0 {
		t.Errorf("interrupted creation should be adopted: %d %s", code, h.stderr.String())
	}
}

// Re-runs perform only checks without a recorded result.
func TestResumeOnlyNewChecks(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "ports", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check {
		var cs []run.Check
		for _, p := range v.Settings().Ports {
			cs = append(cs, run.Check{Key: fmt.Sprintf("h:%d", p)})
		}
		return cs
	}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--ports", "80,443"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if len(st.Executed()) != 2 {
		t.Fatalf("first run: %v", st.Executed())
	}
	st.Reset()
	h.exec("-e", "a.com", "--ports", "80,443")
	if len(st.Executed()) != 0 {
		t.Errorf("second run repeated checks: %v", st.Executed())
	}
	st.Reset()
	h.exec("-e", "a.com", "--ports", "80,443,8080")
	if got := st.Executed(); len(got) != 1 || got[0] != "h:8080" {
		t.Errorf("added port: %v", got)
	}
}

func TestKeyEncodedSettingCreatesNewChecks(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "crawl", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check {
		return []run.Check{{Key: fmt.Sprintf("https://a.com|depth=%d|pages=%d", v.Settings().Crawl.MaxDepth, v.Settings().Crawl.MaxPages)}}
	}}
	h := newHarness(t, st)
	h.exec("a.com")
	st.Reset()
	h.exec("-e", "a.com")
	if len(st.Executed()) != 0 {
		t.Fatal("unchanged settings repeated work")
	}
	h.exec("-e", "a.com", "--crawl-depth", "3")
	if got := st.Executed(); len(got) != 1 || !strings.Contains(got[0], "depth=3") {
		t.Errorf("%v", got)
	}
}

// inScopeHostnames are the in-scope hostname records a fake stage reads, in key order.
func inScopeHostnames(v run.View) []string {
	var out []string
	for _, rec := range v.Records(kinds.Hostname) {
		if v.Scope().HostInScope(rec.Key) {
			out = append(out, rec.Key)
		}
	}
	return out
}

// Transient failures.
func TestTransientFailure(t *testing.T) {
	t.Parallel()
	flaky := &testkit.Stage{StageName: "flaky", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			cs := []run.Check{{Key: "X"}, {Key: "Y"}}
			for _, hn := range inScopeHostnames(v) {
				cs = append(cs, run.Check{Key: "host:" + hn})
			}
			return cs
		},
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			if c.Key == "X" {
				return nil, fmt.Errorf("timeout talking to source")
			}
			return nil, nil
		}}
	// A later stage creates new in-scope hostnames so a second pass happens.
	later := &testkit.Stage{StageName: "later", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("l", 1) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("hostname", "new.a.com")}, nil
		}}
	h := newHarness(t, flaky, later)
	if code := h.exec("a.com", "--json"); code != 7 {
		t.Fatalf("exit %d (a failed check makes the run partial): %s", code, h.stderr.String())
	}
	count := 0
	for _, k := range flaky.Executed() {
		if k == "X" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("X attempted %d times in one run (passes: %v)", count, flaky.Executed())
	}
	if !slices.Contains(flaky.Executed(), "host:new.a.com") {
		t.Errorf("second pass did not happen: %v", flaky.Executed())
	}
	if slices.Contains(h.completed("a.com", "flaky"), "X") || !slices.Contains(h.completed("a.com", "flaky"), "Y") {
		t.Errorf("completed = %v", h.completed("a.com", "flaky"))
	}
	if f := h.failedChecks("flaky"); len(f) != 1 || f[0].key != "X" || f[0].err != "timeout talking to source" {
		t.Errorf("failures = %v", f)
	}
	evs := h.events()
	if st := lastState(evs, "flaky"); st.str("state") != "done" || st.num("failed") != 1 {
		t.Errorf("stage state: %v", st)
	}
	sum := ofType(evs, "summary")[0]
	if f, _ := sum["failed"].(map[string]any); f["flaky"] != float64(1) {
		t.Errorf("summary failed = %v", sum["failed"])
	}
	// Retried on every subsequent run.
	flaky.Reset()
	h.exec("-e", "a.com")
	if !slices.Contains(flaky.Executed(), "X") {
		t.Error("X must be retried on the next run")
	}
}

func TestErrAbortStage(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "abort", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 4) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return nil, fmt.Errorf("source says no: %w", run.ErrAbortStage)
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--json", "--concurrency", "1"); code != 7 {
		t.Fatal(h.stderr.String())
	}
	if len(st.Executed()) != 1 {
		t.Errorf("abort must stop sending: %v", st.Executed())
	}
	s := lastState(h.events(), "abort")
	if s.str("state") != "failed" || s.num("failed") != 4 {
		t.Errorf("state = %v", s)
	}
	if len(h.completed("a.com", "abort")) != 0 {
		t.Error("aborted checks must not be recorded")
	}
}

// A stage whose check enumeration fails is counted as failed once per
// run, and the run still terminates.
func TestEnumerationErrorTerminates(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "enum", Kind: run.ThirdParty,
		ChecksFn:  func(v run.View) []run.Check { return testkit.Keys("c", 1) },
		ChecksErr: errors.New("cannot list checks"),
	}
	h := newHarness(t, st)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if code := h.execCtx(ctx, "a.com", "--json"); code != 7 {
		t.Fatalf("exit %d (the run must end on its own, partial for the failed enumeration): %s", code, h.stderr.String())
	}
	s := lastState(h.events(), "enum")
	if s.str("state") != "done" || s.num("failed") != 1 {
		t.Errorf("state = %v", s)
	}
}

// Redo.
func redoStages(behaviour *int) (*testkit.Stage, *testkit.Stage) {
	s := &testkit.Stage{StageName: "src", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			if *behaviour == 2 {
				return testkit.Keys("k", 2)[1:] // k1 only: k0 becomes an orphan
			}
			return testkit.Keys("k", 2)
		},
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			switch {
			case c.Key == "k000" && *behaviour == 0:
				return []run.Observation{obs("web_service", "u0", "host", "a.com")}, nil
			case c.Key == "k001":
				return []run.Observation{obs("web_service", "u1", "host", "a.com")}, nil
			}
			return nil, nil
		}}
	o := &testkit.Stage{StageName: "other", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("t", 1) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("web_service", "u1", "host", "a.com")}, nil
		}}
	return s, o
}

func currentOf(t *testing.T, h *harness, kind string) map[string]string {
	t.Helper()
	rows, err := h.openDB("a.com").Query("SELECT key, current FROM records WHERE kind=?", kind)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k string
		var c int
		if err := rows.Scan(&k, &c); err != nil {
			t.Fatal(err)
		}
		m[k] = fmt.Sprint(c)
	}
	return m
}

func TestRedo(t *testing.T) {
	t.Parallel()
	b := 0
	src, other := redoStages(&b)
	h := newHarness(t, src, other)
	h.exec("a.com", "--json")
	if got := h.total("web services"); got != 2 {
		t.Fatalf("first summary web services = %v", got)
	}
	src.Reset()
	other.Reset()
	b = 1 // k0 no longer observes u0
	if code := h.exec("-e", "a.com", "--redo", "src", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if len(src.Executed()) != 2 || len(other.Executed()) != 0 {
		t.Errorf("redo executed src=%v other=%v", src.Executed(), other.Executed())
	}
	cur := currentOf(t, h, "web_service")
	if cur["u0"] != "0" || cur["u1"] != "1" {
		t.Errorf("currency = %v (u1 is still observed by another stage)", cur)
	}
	if got := h.total("web services"); got != 1 {
		t.Errorf("summary must count current records only: %v", got)
	}
	if _, ok := h.meta("a.com", "redo:src"); ok {
		t.Error("redo marker should be cleared")
	}
}

func TestRedoSweepsOrphanedChecks(t *testing.T) {
	t.Parallel()
	b := 0
	src, other := redoStages(&b)
	h := newHarness(t, src, other)
	h.exec("a.com")
	b = 2
	if code := h.exec("-e", "a.com", "--redo", "src"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if cur := currentOf(t, h, "web_service"); cur["u0"] != "0" {
		t.Errorf("orphaned check's observation must be swept: %v", cur)
	}
}

// A redo whose enumeration fails part-way must not sweep the checks it never
// listed, and stays pending.
func TestRedoKeepsUnlistedChecksOnEnumerationError(t *testing.T) {
	t.Parallel()
	b := 0
	src, other := redoStages(&b)
	h := newHarness(t, src, other)
	h.exec("a.com")
	b = 2                                                          // k0 is not listed...
	src.ChecksErr = errors.New("listing failed")                   // ...because enumeration fails
	if code := h.exec("-e", "a.com", "--redo", "src"); code != 7 { // the failed enumeration is a failed check
		t.Fatal(h.stderr.String())
	}
	if cur := currentOf(t, h, "web_service"); cur["u0"] != "1" {
		t.Errorf("unlisted check's observation must survive: %v", cur)
	}
	if _, ok := h.meta("a.com", "redo:src"); !ok {
		t.Error("redo must stay pending after an enumeration error")
	}
}

// A check key containing a configured key value is stored redacted, yet still
// recognised as completed: within the run and on the next one.
func TestRedactedCheckKeyCompletes(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "asnish", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return []run.Check{{Key: "AS4123"}} }}
	h := newHarness(t, st)
	h.setKey("fake", "123")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if code := h.execCtx(ctx, "a.com"); code != 0 {
		t.Fatalf("exit %d (the run must end on its own): %s", code, h.stderr.String())
	}
	if code := h.execCtx(ctx, "-e", "a.com"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if got := st.Executed(); len(got) != 1 {
		t.Errorf("executed %v; want the check once across both runs", got)
	}
}

func TestRedoUnknownStage(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.exec("a.com", "--redo", "nope"); code != 2 || !strings.Contains(h.stderr.String(), "nope") {
		t.Errorf("exit %d stderr %q", code, h.stderr.String())
	}
	if _, err := os.Stat(h.eng("a.com")); err == nil {
		t.Error("nothing should be created before validation passes")
	}
}

// Discovery loop across stages and passes.
func TestDiscoveryLoop(t *testing.T) {
	t.Parallel()
	perHost := func(prefix string) func(v run.View) []run.Check {
		return func(v run.View) []run.Check {
			var cs []run.Check
			for _, hn := range inScopeHostnames(v) {
				cs = append(cs, run.Check{Key: prefix + hn, Input: hn})
			}
			return cs
		}
	}
	a := &testkit.Stage{StageName: "A", Kind: run.ThirdParty, ChecksFn: perHost("A:")}
	b := &testkit.Stage{StageName: "B", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check {
			return append([]run.Check{{Key: "B:seed"}}, perHost("B:")(v)...)
		},
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			switch c.Key {
			case "B:seed":
				return []run.Observation{obs("hostname", "new1.a.com"), obs("hostname", "other.net")}, nil
			case "B:new1.a.com":
				return []run.Observation{obs("hostname", "later.a.com")}, nil
			}
			return nil, nil
		}}
	c := &testkit.Stage{StageName: "C", Kind: run.ThirdParty, ChecksFn: perHost("C:")}
	h := newHarness(t, a, b, c)
	done := make(chan int, 1)
	go func() { done <- h.exec("a.com") }()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal(h.stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("run did not terminate")
	}
	for _, want := range []string{"C:new1.a.com", "C:later.a.com"} {
		if !slices.Contains(c.Executed(), want) {
			t.Errorf("C executed %v, missing %s", c.Executed(), want)
		}
	}
	for _, want := range []string{"A:new1.a.com", "A:later.a.com"} {
		if !slices.Contains(a.Executed(), want) {
			t.Errorf("A needs a second pass for %s: %v", want, a.Executed())
		}
	}
	for _, st := range []*testkit.Stage{a, b, c} {
		for _, k := range st.Executed() {
			if strings.Contains(k, "other.net") {
				t.Errorf("out-of-scope name given to stage %s: %s", st.StageName, k)
			}
		}
	}
	if !hasRow(csvRows(t, h.readOut("a.com", "candidates.csv")), "hostname", "other.net") {
		t.Error("other.net must be recorded as a candidate")
	}
}

// Passive mode.
func TestPassive(t *testing.T) {
	t.Parallel()
	target := &testkit.Stage{StageName: "probe", Kind: run.Target, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("p", 3) }}
	third := &testkit.Stage{StageName: "third", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("t", 2) }}
	h := newHarness(t, third, target)
	if code := h.exec("a.com", "--passive", "--authorised", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if len(target.Executed()) != 0 || len(third.Executed()) != 2 {
		t.Errorf("target=%v third=%v", target.Executed(), third.Executed())
	}
	s := lastState(h.events(), "probe")
	if s.str("state") != "not-configured" || s.str("reason") != "passive-only" {
		t.Errorf("state = %v", s)
	}
	if h.network() != 0 {
		t.Error("traffic during passive run")
	}
}

// Acknowledgement.
// ackStage has two fixed checks plus one per root, so adding a root creates new work.
func ackStage() *testkit.Stage {
	return &testkit.Stage{StageName: "probe", Kind: run.Target, ChecksFn: func(v run.View) []run.Check {
		cs := testkit.Keys("p", 2)
		for _, r := range v.Inputs().Roots {
			cs = append(cs, run.Check{Key: "r:" + r})
		}
		return cs
	}}
}

func TestAckFlag(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"--authorised", "--authorized"} {
		st := ackStage()
		h := newHarness(t, st)
		if code := h.exec("a.com", flag); code != 0 {
			t.Fatal(h.stderr.String())
		}
		if len(st.Executed()) != 3 {
			t.Errorf("%s: executed %v", flag, st.Executed())
		}
	}
	st := ackStage()
	h := newHarness(t, st)
	h.exec("a.com", "--authorised", "--passive")
	if _, ok := h.meta("a.com", "ack_at"); !ok {
		t.Error("--authorised --passive must store the ack")
	}
	h.exec("-e", "a.com")
	if len(st.Executed()) != 3 {
		t.Errorf("stored ack should let the next non-passive run proceed: %v", st.Executed())
	}
}

// Netblock guard.

// asnServer answers RIPEstat announced-prefixes with the current *prefix.
func asnServer(t *testing.T, h *harness, prefix *string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"status":"ok","data":{"prefixes":[{"prefix":%q}]}}`, *prefix)
	}))
	t.Cleanup(srv.Close)
	h.eopts.SourceBaseURLs = map[string]string{"stat.ripe.net": srv.URL}
}

func TestNetblockGuard(t *testing.T) {
	t.Parallel()
	var prefix = "10.0.0.0/22" // 1024 addresses
	after := &testkit.Stage{StageName: "after", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("a", 2) }}
	h := newHarness(t, newASN(), after)
	asnServer(t, h, &prefix)

	code := h.exec("--asn", "64500", "--netblock-limit", "1000")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %s %s", code, h.stdout.String(), h.stderr.String())
	}
	if !strings.Contains(h.stdout.String()+h.stderr.String(), "1024") {
		t.Errorf("total not shown: %q %q", h.stdout.String(), h.stderr.String())
	}
	if len(after.Executed()) != 0 || h.network() != 0 {
		t.Errorf("later stages ran on unapproved netblocks: %v net=%d", after.Executed(), h.network())
	}

	if code = h.exec("-e", "as64500", "--netblock-limit", "1000", "--allow-large-netblocks"); code != 0 {
		t.Fatalf("override: exit %d: %s", code, h.stderr.String())
	}
	if len(after.Executed()) != 2 {
		t.Errorf("override should proceed: %v", after.Executed())
	}
	if v, ok := h.meta("as64500", "netblock_approved"); !ok || v != "1024" {
		t.Errorf("approval = %q %v", v, ok)
	}
	after.Reset()
	if code = h.exec("-e", "as64500", "--netblock-limit", "1000"); code != 0 {
		t.Fatalf("remembered approval: exit %d", code)
	}
	prefix = "10.0.0.0/21" // 2048: growth beyond the approved count
	if code = h.exec("-e", "as64500", "--netblock-limit", "1000", "--redo", "asn"); code != 2 {
		t.Errorf("growth beyond approval must stop again: exit %d", code)
	}
}

// A netblock is in scope for an input ASN when a stage that expands the input
// ASNs observes it under that ASN's check, whatever the stage is called; another
// stage's netblock is not, even one named asn.
func TestASNNetblocksComeFromTheExpandingStage(t *testing.T) {
	t.Parallel()
	announce := func(name, prefix string) *testkit.Stage {
		return &testkit.Stage{StageName: name, Kind: run.ThirdParty,
			ChecksFn: func(v run.View) []run.Check {
				var cs []run.Check
				for _, a := range v.Inputs().ASNs {
					cs = append(cs, run.Check{Key: a})
				}
				return cs
			},
			RunFn: func(_ context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
				return []run.Observation{kinds.Netblock.Obs(prefix, kinds.NetblockAttrs{ASN: c.Key})}, nil
			}}
	}
	h := newHarness(t, expander{announce("announcer", "198.51.100.0/24")}, announce("asn", "203.0.113.0/24"))
	if code := h.exec("--asn", "64500"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	var got []string
	for _, r := range h.table("as64500", "scope.csv") {
		if r["type"] == "netblock" {
			got = append(got, r["value"]+" "+r["source"])
		}
	}
	if want := []string{"198.51.100.0/24 AS64500"}; !slices.Equal(got, want) {
		t.Errorf("scope.csv netblocks = %v, want %v", got, want)
	}
}

func TestNetblockInputGuard(t *testing.T) {
	t.Parallel()
	first := &testkit.Stage{StageName: "first", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("a", 2) }}
	h := newHarness(t, first)
	if code := h.exec("--cidr", "10.0.0.0/16", "--netblock-limit", "100"); code != 2 || len(first.Executed()) != 0 {
		t.Errorf("exit %d executed %v", code, first.Executed())
	}
}

// excluded.csv, end to end through the CLI.
func TestExcludedCSV(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "disc", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 1) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return []run.Observation{
				obs("hostname", "admin.a.com"), obs("hostname", "db.a.com"), obs("hostname", "www.a.com"),
				obs("resolution", "db.a.com|A|198.51.100.7", "name", "db.a.com", "type", "A", "value", "198.51.100.7"),
				obs("resolution", "www.a.com|A|203.0.113.5", "name", "www.a.com", "type", "A", "value", "203.0.113.5"),
			}, nil
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "-x", "admin.a.com", "-x", "198.51.100.0/24"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	rows := csvRows(t, h.readOut("a.com", "excluded.csv"))
	if !hasRow(rows, "admin.a.com") || !hasRow(rows, "db.a.com") || hasRow(rows, "www.a.com") {
		t.Fatalf("excluded.csv = %v", rows)
	}
	for _, r := range rows[1:] {
		if r[1] == "" {
			t.Errorf("no reason for %v", r)
		}
	}
	if strings.Contains(h.readOut("a.com", "candidates.csv"), "admin.a.com") {
		t.Error("excluded name must not be a candidate")
	}
}

// States, found lines, counts, summary.
func TestStageStatesAndFound(t *testing.T) {
	t.Parallel()
	prev := &testkit.Stage{StageName: "prev", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("p", 2) }}
	failing := &testkit.Stage{StageName: "failing", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("f", 2) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return nil, fmt.Errorf("source unavailable")
		}}
	partial := &testkit.Stage{StageName: "partial", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("q", 2) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			if c.Key == "q000" {
				return nil, fmt.Errorf("rate limited")
			}
			return []run.Observation{
				obs("web_service", "https://a.com"), obs("url", "https://a.com/x"), obs("url", "https://a.com/y"),
				obs("open_port", "1.2.3.4:80"), obs("hostname", "www.a.com"),
				obs("finding", "f1", "category", "exposed", "severity", "high", "target", "https://a.com/.git", "detail", "git"),
				obs("finding", "f2", "category", "banner", "severity", "medium", "target", "1.2.3.4:21", "detail", "ftp"),
				obs("finding", "f3", "category", "misc", "severity", "low", "target", "x", "detail", "minor"),
			}, nil
		}}
	nokey := &testkit.Stage{StageName: "nokey", Kind: run.ThirdParty, ConfiguredFn: func(run.Env) (bool, string) { return false, "no key" }}
	empty := &testkit.Stage{StageName: "empty", Kind: run.ThirdParty}
	target := &testkit.Stage{StageName: "probe", Kind: run.Target, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("x", 1) }}
	h := newHarness(t, prev, failing, partial, nokey, empty, target)
	if code := h.exec("a.com", "--json"); code != 7 {
		t.Fatal(h.stderr.String())
	}
	evs := h.events()
	checkStageStates(t, evs)
	checkFoundLines(t, evs)
	checkStatesSummary(t, evs)
	// Re-run: nothing new is printed, previously-done stages say so.
	h.exec("-e", "a.com", "--json")
	evs = h.events()
	if len(ofType(evs, "found")) != 0 {
		t.Errorf("records already known must not be printed again: %v", ofType(evs, "found"))
	}
	if s := lastState(evs, "prev"); s.str("state") != "done-previously" {
		t.Errorf("prev = %v", s)
	}
}

// checkStageStates checks each stage's last state, reason and counts, and that
// there is one line per state change: no consecutive duplicates for any stage.
func checkStageStates(t *testing.T, evs []event) {
	t.Helper()
	want := map[string][2]string{ // state, reason
		"failing": {"failed", ""}, "partial": {"done", ""}, "nokey": {"not-configured", "no key"},
		"empty": {"done", ""}, "probe": {"not-configured", "no authorisation"}, "prev": {"done", ""},
	}
	for name, w := range want {
		s := lastState(evs, name)
		if s == nil || s.str("state") != w[0] || s.str("reason") != w[1] {
			t.Errorf("%s: %v, want %v", name, s, w)
		}
	}
	if s := lastState(evs, "partial"); s.num("checks") != 2 || s.num("failed") != 1 {
		t.Errorf("partial counts: %v", s)
	}
	if s := lastState(evs, "empty"); s.num("checks") != 0 {
		t.Errorf("empty: %v", s)
	}
	for _, name := range []string{"prev", "failing", "partial", "nokey", "empty", "probe"} {
		se := stageEvents(evs, name)
		for i := 1; i < len(se); i++ {
			if se[i].str("state") == se[i-1].str("state") && se[i].num("checks") == se[i-1].num("checks") {
				t.Errorf("%s: repeated stage line %v", name, se)
			}
		}
	}
}

// checkFoundLines checks that found lines come only for printed kinds, and
// that URLs are counted, not printed.
func checkFoundLines(t *testing.T, evs []event) {
	t.Helper()
	found := map[string]bool{}
	for _, e := range ofType(evs, "found") {
		found[e.str("category")+"|"+e.str("value")] = true
	}
	for _, w := range []string{"web service|https://a.com", "host|www.a.com"} {
		if !found[w] {
			t.Errorf("missing found %q in %v", w, found)
		}
	}
	// 1.2.3.4 is not port-eligible, so its open port is neither printed nor
	// counted.
	if found["open port|1.2.3.4:80"] {
		t.Error("an open port on an address that is not port-eligible must not be printed")
	}
	for k := range found {
		if strings.Contains(k, "/x") || strings.Contains(k, "/y") {
			t.Errorf("URLs must not be printed: %s", k)
		}
	}
	urlCount := 0
	for _, e := range ofType(evs, "count") {
		if e.str("category") == "urls" {
			urlCount = e.num("n")
		}
	}
	if urlCount != 2 {
		t.Errorf("urls count = %d", urlCount)
	}
}

// checkStatesSummary checks the summary: totals, failed counts, and the high
// and medium findings listed individually.
func checkStatesSummary(t *testing.T, evs []event) {
	t.Helper()
	sum := ofType(evs, "summary")
	if len(sum) != 1 {
		t.Fatalf("summaries: %d", len(sum))
	}
	totals := sum[0]["totals"].(map[string]any)
	// 1.2.3.4 is neither in a netblock nor the address of an in-scope name, so
	// its open port is not the target's and is not counted.
	if totals["urls"] != float64(2) || totals["hosts"] != float64(1) || totals["open ports (confirmed)"] != float64(0) {
		t.Errorf("totals = %v", totals)
	}
	failed := sum[0]["failed"].(map[string]any)
	if failed["failing"] != float64(2) || failed["partial"] != float64(1) {
		t.Errorf("failed = %v", failed)
	}
	fs := sum[0]["findings"].([]any)
	if len(fs) != 2 {
		t.Errorf("findings = %v (want high and medium only)", fs)
	}
}

// With --json stdout is one unstyled JSON object when the run ends, and an error is the JSON error on
// stderr.
func TestJSONMode(t *testing.T) {
	t.Parallel()
	h := newHarness(t, noop())
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	h.envelope() // fails unless stdout is exactly one envelope line
	if strings.Contains(h.stdout.String(), "\x1b") {
		t.Error("ANSI in JSON mode")
	}
	for _, typ := range []string{"run_start", "summary"} {
		if len(ofType(h.events(), typ)) != 1 {
			t.Errorf("want exactly one %s event", typ)
		}
	}
	if len(ofType(h.events(), "run_end")) != 0 {
		t.Error("a run_end event: the envelope is the only result")
	}
	h.stdoutTTY = true
	h.exec("b.com", "--json")
	if strings.Contains(h.stdout.String(), "\x1b") {
		t.Error("ANSI in JSON mode on a TTY")
	}
	// An error is the JSON error on stderr, not an event.
	if f := h.failed(h.exec("co.uk", "--json"), 2, true); !strings.Contains(f.msg, "co.uk") {
		t.Errorf("error = %+v", f)
	}
	if code := h.exec("--json", "--help"); code != 0 {
		t.Errorf("exit %d", code)
	}
}

func TestNonTTYNoANSI(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 1) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return []run.Observation{obs("web_service", "https://a.com")}, nil
		}}
	h := newHarness(t, st)
	h.exec("a.com")
	if strings.Contains(h.stdout.String(), "\x1b") || h.stdout.Len() == 0 {
		t.Errorf("non-TTY stdout: %q", h.stdout.String())
	}
	if strings.Contains(h.stderr.String(), "\x1b") || h.stderr.Len() == 0 {
		t.Errorf("non-TTY stderr: %q", h.stderr.String())
	}
	// On a terminal stdout carries only the summary, whose headings are bold.
	h.stdoutTTY = true
	h.exec("b.com")
	if !strings.Contains(h.stdout.String(), "\x1b[") {
		t.Errorf("TTY stdout should be styled: %q", h.stdout.String())
	}
	if strings.Contains(h.stderr.String(), "\x1b") {
		t.Errorf("stderr is not a terminal, so it must stay plain: %q", h.stderr.String())
	}
}

// Concurrency bound.
func TestConcurrencyBound(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 24) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			time.Sleep(15 * time.Millisecond)
			return nil, nil
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com", "--concurrency", "3"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if m := st.MaxActive(); m > 3 || m < 2 {
		t.Errorf("max concurrent = %d, want 2..3", m)
	}
}

// Invalid input is rejected before any activity.
func TestInvalidInputsTouchNothing(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "s", Kind: run.Target, ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 3) }}
	badCfg := writeFile(t, t.TempDir(), "bad.yaml", "concurency: 3\n")
	badList := writeFile(t, t.TempDir(), "d.txt", "ok.example.com\nco.uk\n")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"malformed domain", []string{"bad domain.com"}, "bad domain.com"},
		{"public suffix", []string{"co.uk"}, "co.uk"},
		{"bad cidr", []string{"a.com", "--cidr", "10.0.0.0/33"}, "10.0.0.0/33"},
		{"bad asn", []string{"a.com", "--asn", "ASxyz"}, "ASxyz"},
		{"bad exclusion", []string{"a.com", "-x", "a b"}, "a b"},
		{"bad config value", []string{"a.com", "--concurrency", "0"}, "concurrency"},
		{"bad port", []string{"a.com", "--ports", "70000"}, "70000"},
		{"unknown config key", []string{"a.com", "--config", badCfg}, "concurency"},
		{"unknown redo", []string{"a.com", "--redo", "bogus"}, "bogus"},
		{"bad value in file", []string{"-d", badList}, "co.uk"},
		{"missing config", []string{"a.com", "--config", "/no/such/config.yaml"}, "/no/such/config.yaml"},
	}
	for _, c := range cases {
		// Not parallel: the cases share st.
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, st)
			st.Reset()
			code := h.exec(append(c.args, "--authorised")...)
			if code != 2 {
				t.Errorf("exit %d, stderr %q", code, h.stderr.String())
			}
			if !strings.Contains(h.stderr.String(), c.want) {
				t.Errorf("stderr %q should name %q", h.stderr.String(), c.want)
			}
			if len(st.Executed()) != 0 {
				t.Errorf("checks ran before validation: %v", st.Executed())
			}
			h.untouched()
		})
	}
}

// Exit codes and lock.
func TestExitCodes(t *testing.T) {
	t.Parallel()
	st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 2) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			return nil, fmt.Errorf("transient")
		}}
	h := newHarness(t, st)
	if code := h.exec("a.com"); code != 7 {
		t.Errorf("a failed check makes the run partial: exit %d", code)
	}

	e, err := engagement.Open(h.eng("a.com"), engagement.Options{})
	if err != nil {
		t.Fatal(err)
	}
	code := h.exec("-e", "a.com")
	e.Close()
	if code != 1 || !strings.Contains(strings.ToLower(h.stderr.String()), "lock") && !strings.Contains(strings.ToLower(h.stderr.String()), "running") {
		t.Errorf("held lock: exit %d, stderr %q", code, h.stderr.String())
	}
	if code = h.exec("-e", "a.com"); code != 7 {
		t.Errorf("lock released: exit %d, want 7 (the failed checks are retried and fail again)", code)
	}

	// A corrupt store is a fatal runtime error.
	if err := os.MkdirAll(filepath.Join(h.eng("bad"), ".nyx"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.eng("bad"), ".nyx", "state.db"), []byte("this is not a sqlite database, just some text padding padding padding padding"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code = h.exec("-e", "bad", "a.com"); code != 1 {
		t.Errorf("corrupt store: exit %d", code)
	}
}

func TestInterruptedByContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	st := &testkit.Stage{StageName: "s", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 50) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			if c.Key == "c005" {
				cancel()
			}
			time.Sleep(5 * time.Millisecond)
			return nil, nil
		}}
	h := newHarness(t, st)
	if code := h.execCtx(ctx, "a.com", "--concurrency", "1"); code != 130 {
		t.Errorf("exit %d, want 130", code)
	}
	if len(h.completed("a.com", "s")) >= 50 {
		t.Error("run should have stopped early")
	}
	if _, err := os.Stat(h.eng("a.com") + "/scope.csv"); err != nil {
		t.Error("outputs should still be rendered on interrupt")
	}
}

// Keys never leak.
func TestSecretsNeverLeak(t *testing.T) {
	t.Parallel()
	const fakeKey, otherKey = "FAKESENTINEL-7f3a91", "OTHERSENTINEL-c20b44"
	var gotFake, gotOther string
	mk := func(name, source string, got *string) *testkit.Stage {
		return &testkit.Stage{StageName: name, Kind: run.ThirdParty, Src: []string{"api.example.net"},
			ConfiguredFn: func(e run.Env) (bool, string) {
				k, ok := e.Key(source)
				*got = k.Reveal()
				return ok, "no key"
			},
			ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", 3) },
			RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
				key := *got
				switch c.Key {
				case "c000":
					return []run.Observation{obs("web_service", "https://a.com/?k="+key, "token", key)}, nil
				case "c001":
					_, err := e.ThirdParty.Do(ctx, egress.ThirdPartyRequest{Method: "GET", URL: "https://api.example.net/x?key=" + key})
					return nil, fmt.Errorf("request failed: %w (key %s)", err, key)
				}
				return nil, fmt.Errorf("auth %s rejected", key)
			}}
	}
	cfgDir := t.TempDir()
	cfg := writeFile(t, cfgDir, "config.yaml", "keys:\n  fake: "+fakeKey+"\n  other: "+otherKey+"\n")
	for _, jsonMode := range []bool{true, false} {
		a, b := mk("viafake", "fake", &gotFake), mk("viaother", "other", &gotOther)
		h := newHarness(t, a, b)
		h.eopts.SourceBaseURLs = map[string]string{"api.example.net": "http://127.0.0.1:1"} // refuses connections; error text includes the URL
		args := []string{"a.com", "--debug", "--config", cfg, "--rate-per-source", "1000"}
		if jsonMode {
			args = append(args, "--json")
		}
		if code := h.exec(args...); code != 7 { // each stage's rejected check is a failed check
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
		if gotFake != fakeKey || gotOther != otherKey {
			t.Fatalf("keys not delivered to stages: %q %q", gotFake, gotOther)
		}
		scan := func(where string, data []byte) {
			for _, k := range []string{fakeKey, otherKey} {
				if strings.Contains(string(data), k) {
					t.Errorf("json=%v: %s contains %s", jsonMode, where, k)
				}
			}
		}
		scan("stdout", h.stdout.Bytes())
		scan("stderr", h.stderr.Bytes())
		_ = filepath.WalkDir(h.eng("a.com"), func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if b, rerr := os.ReadFile(p); rerr == nil {
					scan(p, b)
				}
			}
			return nil
		})
	}
}
