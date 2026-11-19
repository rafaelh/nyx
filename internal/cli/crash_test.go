package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// TestMain lets the test binary re-execute itself as `nyx` with a fake stage.
func TestMain(m *testing.M) {
	if os.Getenv("NYX_TEST_CHILD") == "1" {
		os.Exit(childMain())
	}
	os.Exit(m.Run())
}

func childMain() int {
	n, _ := strconv.Atoi(os.Getenv("NYX_TEST_N"))
	delay, _ := time.ParseDuration(os.Getenv("NYX_TEST_DELAY"))
	logPath := os.Getenv("NYX_TEST_LOG")
	stubborn := os.Getenv("NYX_TEST_STUBBORN") == "1" // checks that do not stop when cancelled
	hosts := os.Getenv("NYX_TEST_HOSTS") == "1"       // each check finds the hostname <key>.a.com, not a web service
	st := &testkit.Stage{StageName: "fake", Kind: run.ThirdParty,
		ChecksFn: func(v run.View) []run.Check { return testkit.Keys("c", n) },
		RunFn: func(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
			if logPath != "" {
				f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
				if err == nil {
					fmt.Fprintln(f, c.Key)
					f.Close()
				}
			}
			if stubborn {
				time.Sleep(delay)
				return nil, nil
			}
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if hosts {
				return []run.Observation{obs("hostname", c.Key+".a.com")}, nil
			}
			return []run.Observation{obs("web_service", "ws-"+c.Key)}, nil
		}}
	d := cli.DefaultDeps()
	d.Stages = []run.Stage{st}
	d.Signals = cli.NotifySignals()
	// The crash tests kill the process, not the machine: the page cache keeps every write, so
	// output files need no fsync (which on macOS flushes the whole drive cache).
	d.NoFsync = true
	return cli.Execute(context.Background(), strings.Split(os.Getenv("NYX_TEST_ARGS"), "\x1f"), d)
}

type child struct {
	t              *testing.T
	cmd            *exec.Cmd
	log            string
	out            string
	stdout, stderr *bytes.Buffer
}

type childOpts struct {
	n         int
	delay     time.Duration
	fault     string
	faultFile string
	args      []string
	human     bool // leave out --json
	stubborn  bool // checks ignore cancellation
	openStdin bool // stdin is a pipe that is never closed
	hosts     bool // each check finds a hostname in scope of a.com
}

// startChild starts the test binary as nyx in a child process. Only the
// subtests of TestChildProcesses call it.
func startChild(t *testing.T, out string, o childOpts) *child {
	t.Helper()
	c := &child{t: t, log: filepath.Join(t.TempDir(), "log"), out: out, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	args := []string{"recon", "--output-dir", out}
	if !o.human {
		args = append(args, "--json")
	}
	args = append(args, o.args...)
	c.cmd = exec.Command(os.Args[0], "-test.run=NoSuchTestEver")
	// The developer's NYX_* settings must not reach the child.
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "NYX_") })
	c.cmd.Env = append(env,
		"NYX_TEST_CHILD=1", "NYX_TEST_N="+strconv.Itoa(o.n), "NYX_TEST_DELAY="+o.delay.String(),
		"NYX_TEST_LOG="+c.log, "NYX_TEST_ARGS="+strings.Join(args, "\x1f"),
		"XDG_CONFIG_HOME="+t.TempDir(), "HOME="+t.TempDir())
	if o.fault != "" {
		c.cmd.Env = append(c.cmd.Env, "NYX_FAULT="+o.fault, "NYX_FAULT_FILE="+o.faultFile)
	}
	if o.stubborn {
		c.cmd.Env = append(c.cmd.Env, "NYX_TEST_STUBBORN=1")
	}
	if o.hosts {
		c.cmd.Env = append(c.cmd.Env, "NYX_TEST_HOSTS=1")
	}
	c.cmd.Stdout, c.cmd.Stderr = c.stdout, c.stderr
	if o.openStdin {
		w, err := c.cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { w.Close() })
	}
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.cmd.Process.Kill(); _ = c.cmd.Wait() })
	return c
}

// wait returns the exit code (-1 if killed by a signal).
func (c *child) wait() int {
	c.t.Helper()
	done := make(chan struct{})
	go func() { _ = c.cmd.Wait(); close(done) }() // ProcessState carries the outcome
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		_ = c.cmd.Process.Kill()
		c.t.Fatal("child did not exit")
	}
	return c.cmd.ProcessState.ExitCode()
}

func (c *child) executed() []string {
	f, err := os.Open(c.log)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (c *child) waitFault(file string) string {
	c.t.Helper()
	waitFor(c.t, "fault point", func() bool { _, err := os.Stat(file); return err == nil })
	time.Sleep(50 * time.Millisecond)
	b, _ := os.ReadFile(file)
	return strings.TrimSpace(string(b))
}

func (c *child) kill(sig syscall.Signal) { _ = c.cmd.Process.Signal(sig) }

const nChecks = 40

func engDirOf(out string) string { return filepath.Join(out, "a.com") }

func committed(t *testing.T, out string) map[string]bool {
	t.Helper()
	db := openDB(t, filepath.Join(engDirOf(out), ".nyx", "state.db"))
	m := map[string]bool{}
	for _, k := range queryStrings(t, db, "SELECT key FROM checks WHERE stage='fake'") {
		m[k] = true
	}
	return m
}

func allKeys(n int) []string {
	var ks []string
	for _, c := range testkit.Keys("c", n) {
		ks = append(ks, c.Key)
	}
	return ks
}

func setDiff(all []string, exclude map[string]bool) []string {
	var out []string
	for _, k := range all {
		if !exclude[k] {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// sorted is a sorted copy of s.
func sorted(s []string) []string { return slices.Sorted(slices.Values(s)) }

func assertOutputsIntact(t *testing.T, out string) {
	t.Helper()
	entries, _ := os.ReadDir(engDirOf(out))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(engDirOf(out), e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > 0 && b[len(b)-1] != '\n' {
			t.Errorf("%s ends mid-line: %q", e.Name(), b[max(0, len(b)-30):])
		}
		if strings.HasSuffix(e.Name(), ".csv") {
			r := csv.NewReader(strings.NewReader(string(b)))
			if _, err := r.ReadAll(); err != nil {
				t.Errorf("%s does not parse: %v", e.Name(), err)
			}
		}
	}
}

func finishAndCheck(t *testing.T, out string, wantRun2 []string, o childOpts) {
	t.Helper()
	c2 := startChild(t, out, childOpts{n: nChecks, args: o.args})
	if code := c2.wait(); code != 0 {
		t.Fatalf("recovery run exit %d", code)
	}
	if got := sorted(c2.executed()); strings.Join(got, ",") != strings.Join(wantRun2, ",") {
		t.Errorf("recovery run executed %d checks, want %d\n got %v\nwant %v", len(got), len(wantRun2), got, wantRun2)
	}
	if got := committed(t, out); len(got) != nChecks {
		t.Errorf("after recovery %d checks recorded, want %d", len(got), nChecks)
	}
	if entries, _ := os.ReadDir(filepath.Join(engDirOf(out), ".nyx", "tmp")); len(entries) != 0 {
		t.Errorf("tmp not swept: %v", entries)
	}
	assertOutputsIntact(t, out)
}

// TestChildProcesses runs the tests that start nyx in a child process, in
// parallel with each other but with nothing else.
//
// It is not parallel itself. Between fork and exec a child holds a copy of
// every open descriptor, including the engagement lock of any in-process run,
// so an in-process run that closes its engagement and reopens it could find the
// flock still held and fail with LOCKED. Go starts the parallel top-level tests
// only once every other top-level test has finished, so no child is forked
// while they run.
func TestChildProcesses(t *testing.T) {
	for _, tc := range []struct {
		name string
		test func(*testing.T)
	}{
		{"CrashRenderMidFile", testCrashRenderMidFile},
		{"CrashPoints", testCrashPoints},
		{"CrashDuringRedo", testCrashDuringRedo},
		{"Signals", testSignals},
		{"Signals_SecondExitsAtOnce", testSignalsSecondExitsAtOnce},
		{"StdinIsNotRead", testStdinIsNotRead},
		{"Signals_InterruptedRunWritesChanges", testSignalsInterruptedRunWritesChanges},
		{"TimeoutInAChildProcess", testTimeoutInAChildProcess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.test(t)
		})
	}
}

// A kill -9 while an output file is mid-write.
func testCrashRenderMidFile(t *testing.T) {
	out := t.TempDir()
	c1 := startChild(t, out, childOpts{n: nChecks, args: []string{"a.com"}})
	if code := c1.wait(); code != 0 {
		t.Fatalf("first run exit %d", code)
	}
	before, _ := os.ReadFile(filepath.Join(engDirOf(out), "scope.csv"))

	ff := filepath.Join(t.TempDir(), "fault")
	c2 := startChild(t, out, childOpts{n: nChecks, fault: "render-mid-file", faultFile: ff, args: []string{"-e", "a.com", "--redo", "fake"}})
	c2.waitFault(ff)
	c2.kill(syscall.SIGKILL)
	c2.wait()
	if entries, _ := os.ReadDir(filepath.Join(engDirOf(out), ".nyx", "tmp")); len(entries) == 0 {
		t.Error("fault did not leave a partial temp file; the hook may not be reached")
	}
	assertOutputsIntact(t, out)
	if after, _ := os.ReadFile(filepath.Join(engDirOf(out), "scope.csv")); string(after) != string(before) {
		t.Error("scope.csv changed by an interrupted render")
	}
	// The interrupted redo is finished by the next run, which is not blocked by the dead lock.
	c3 := startChild(t, out, childOpts{n: nChecks, args: []string{"-e", "a.com"}})
	if code := c3.wait(); code != 0 {
		t.Fatalf("next run exit %d", code)
	}
	if entries, _ := os.ReadDir(filepath.Join(engDirOf(out), ".nyx", "tmp")); len(entries) != 0 {
		t.Errorf("tmp not swept: %v", entries)
	}
	assertOutputsIntact(t, out)
}

// A kill -9 at in-check-tx, in-flight and after-commit.
func testCrashPoints(t *testing.T) {
	for _, point := range []string{"in-check-tx", "in-flight", "after-commit"} {
		t.Run(point, func(t *testing.T) {
			t.Parallel()
			out := t.TempDir()
			ff := filepath.Join(t.TempDir(), "fault")
			c1 := startChild(t, out, childOpts{n: nChecks, fault: point, faultFile: ff, args: []string{"a.com"}})
			detail := c1.waitFault(ff)
			if point == "in-flight" {
				time.Sleep(400 * time.Millisecond) // let the other workers' completions commit
			}
			c1.kill(syscall.SIGKILL)
			c1.wait()

			done := committed(t, out)
			if point == "after-commit" && len(done) == 0 {
				t.Error("after-commit pause but nothing committed")
			}
			if point == "in-flight" {
				key := strings.Fields(detail)[len(strings.Fields(detail))-1]
				if done[key] {
					t.Errorf("in-flight check %s must not be recorded", key)
				}
			}
			if point == "in-check-tx" && len(done) == nChecks {
				t.Error("in-check-tx: the pending transaction must not have committed")
			}
			finishAndCheck(t, out, setDiff(allKeys(nChecks), done), childOpts{args: []string{"-e", "a.com"}})
		})
	}
}

// A redo interrupted after a commit is finished by the next plain run.
func testCrashDuringRedo(t *testing.T) {
	out := t.TempDir()
	c1 := startChild(t, out, childOpts{n: nChecks, args: []string{"a.com"}})
	if code := c1.wait(); code != 0 {
		t.Fatalf("first run exit %d", code)
	}
	ff := filepath.Join(t.TempDir(), "fault")
	// Slow checks spread completions over several commit batches, so the first commit is partial.
	c2 := startChild(t, out, childOpts{n: nChecks, delay: 30 * time.Millisecond, fault: "after-commit", faultFile: ff,
		args: []string{"-e", "a.com", "--redo", "fake", "--concurrency", "4"}})
	c2.waitFault(ff)
	c2.kill(syscall.SIGKILL)
	c2.wait()
	db := openDB(t, filepath.Join(engDirOf(out), ".nyx", "state.db"))
	if v := queryStrings(t, db, "SELECT key FROM meta WHERE key='redo:fake'"); len(v) != 1 {
		t.Fatalf("redo marker must survive the crash: %v", v)
	}
	done := committed(t, out)
	if len(done) == 0 || len(done) == nChecks {
		t.Fatalf("want a partial redo at the crash point, got %d of %d checks recorded", len(done), nChecks)
	}
	finishAndCheck(t, out, setDiff(allKeys(nChecks), done), childOpts{args: []string{"-e", "a.com"}}) // no --redo
	db2 := openDB(t, filepath.Join(engDirOf(out), ".nyx", "state.db"))
	if v := queryStrings(t, db2, "SELECT key FROM meta WHERE key='redo:fake'"); len(v) != 0 {
		t.Errorf("redo marker should be cleared: %v", v)
	}
}

// Each signal ends the run with its own exit code and one INTERRUPTED error,
// with the completed checks saved and the outputs rendered; a re-run finishes
// the rest. In human mode stdout is empty.
func testSignals(t *testing.T) {
	for name, c := range map[string]struct {
		sig  syscall.Signal
		code int
	}{"SIGINT": {syscall.SIGINT, 130}, "SIGTERM": {syscall.SIGTERM, 143}, "SIGHUP": {syscall.SIGHUP, 129}} {
		for _, human := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s human=%v", name, human), func(t *testing.T) {
				t.Parallel()
				out := t.TempDir()
				c1 := startChild(t, out, childOpts{n: nChecks, delay: 60 * time.Millisecond, args: []string{"a.com", "--concurrency", "2"}, human: human})
				waitFor(t, "some checks", func() bool { return len(c1.executed()) >= 6 })
				c1.kill(c.sig)
				if code := c1.wait(); code != c.code {
					t.Fatalf("exit %d, want %d\n%s", code, c.code, c1.stderr.String())
				}
				c1.checkInterrupted(!human)
				if human && c1.stdout.Len() != 0 {
					t.Errorf("stdout %q", c1.stdout.String())
				}
				assertOutputsIntact(t, out)
				done := committed(t, out)
				if len(done) == 0 || len(done) == nChecks {
					t.Fatalf("expected a partial run, got %d recorded", len(done))
				}
				if _, err := os.Stat(filepath.Join(engDirOf(out), "scope.csv")); err != nil {
					t.Error("outputs must be rendered on interrupt")
				}
				finishAndCheck(t, out, setDiff(allKeys(nChecks), done), childOpts{args: []string{"-e", "a.com"}})
			})
		}
	}
}

// checkInterrupted asserts that stderr ends with exactly one INTERRUPTED error.
func (c *child) checkInterrupted(jsonMode bool) {
	c.t.Helper()
	stderr := c.stderr.String()
	if jsonMode {
		lines := strings.Split(strings.TrimSpace(stderr), "\n")
		if len(lines) != 1 || !strings.Contains(lines[0], `"code":"INTERRUPTED"`) || strings.Count(stderr, `"code":`) != 1 {
			c.t.Errorf("stderr is not one INTERRUPTED error:\n%s", stderr)
		}
		return
	}
	if strings.Count(stderr, "error: ") != 1 || !strings.Contains(stderr, "(INTERRUPTED)") {
		c.t.Errorf("stderr does not hold one INTERRUPTED error:\n%s", stderr)
	}
}

// A second signal exits at once with the first one's code, and the error is
// still written once.
func testSignalsSecondExitsAtOnce(t *testing.T) {
	for name, c := range map[string]struct {
		first, second syscall.Signal
		code          int
	}{"TERM then INT": {syscall.SIGTERM, syscall.SIGINT, 143}, "INT then HUP": {syscall.SIGINT, syscall.SIGHUP, 130}} {
		for _, human := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s human=%v", name, human), func(t *testing.T) {
				t.Parallel()
				out := t.TempDir()
				// The checks ignore the cancel and take a minute, so only the
				// second signal can end the run soon.
				c1 := startChild(t, out, childOpts{n: nChecks, delay: time.Minute, stubborn: true, human: human, args: []string{"a.com", "--concurrency", "2"}})
				waitFor(t, "the checks to start", func() bool { return len(c1.executed()) >= 2 })
				c1.kill(c.first)
				time.Sleep(200 * time.Millisecond)
				start := time.Now()
				c1.kill(c.second)
				if code := c1.wait(); code != c.code {
					t.Fatalf("exit %d, want %d\n%s", code, c.code, c1.stderr.String())
				}
				if d := time.Since(start); d > 10*time.Second {
					t.Errorf("the second signal took %s to end the run", d)
				}
				c1.checkInterrupted(!human)
			})
		}
	}
}

// A run whose stdin is a pipe that never closes still finishes: nothing reads it.
func testStdinIsNotRead(t *testing.T) {
	out := t.TempDir()
	c := startChild(t, out, childOpts{n: 3, args: []string{"a.com"}, openStdin: true, human: true})
	if code := c.wait(); code != 0 {
		t.Fatalf("exit %d\n%s", code, c.stderr.String())
	}
}

// changedHosts are the hostnames of the "new" rows of an engagement's changes.csv.
func changedHosts(t *testing.T, out string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(engDirOf(out), "changes.csv"))
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, row := range csvRows(t, string(b))[1:] {
		if row[0] == "new" && row[1] == "hostname" {
			hosts = append(hosts, strings.TrimSuffix(row[2], ".a.com"))
		}
	}
	slices.Sort(hosts)
	return hosts
}

// An interrupted run writes changes.csv for the work it completed before it
// exited 130, and the run that resumes it compares against where that run
// stopped, so the two files together list each new hostname once.
func testSignalsInterruptedRunWritesChanges(t *testing.T) {
	out := t.TempDir()
	args := []string{"a.com", "--concurrency", "2"}
	c0 := startChild(t, out, childOpts{n: 3, hosts: true, args: args})
	if code := c0.wait(); code != 0 {
		t.Fatalf("first run exit %d\n%s", code, c0.stderr.String())
	}
	if _, err := os.Stat(filepath.Join(engDirOf(out), "changes.csv")); err == nil {
		t.Error("a first run wrote changes.csv")
	}

	c1 := startChild(t, out, childOpts{n: nChecks, hosts: true, delay: 60 * time.Millisecond, args: []string{"-e", "a.com", "--concurrency", "2"}})
	waitFor(t, "some checks", func() bool { return len(c1.executed()) >= 6 })
	c1.kill(syscall.SIGINT)
	if code := c1.wait(); code != 130 {
		t.Fatalf("exit %d, want 130\n%s", code, c1.stderr.String())
	}
	assertOutputsIntact(t, out)
	interrupted := changedHosts(t, out)
	if len(interrupted) == 0 || len(interrupted) >= nChecks-3 {
		t.Fatalf("the interrupted run listed %d new hostnames of %d", len(interrupted), nChecks-3)
	}
	for _, h := range interrupted {
		if slices.Contains(allKeys(3), h) {
			t.Errorf("%s was found by the first run, not the interrupted one", h)
		}
	}

	c2 := startChild(t, out, childOpts{n: nChecks, hosts: true, args: []string{"-e", "a.com", "--concurrency", "2"}})
	if code := c2.wait(); code != 0 {
		t.Fatalf("resumed run exit %d\n%s", code, c2.stderr.String())
	}
	resumed := changedHosts(t, out)
	for _, h := range resumed {
		if slices.Contains(interrupted, h) {
			t.Errorf("%s was new in the interrupted run and is new again in the resumed one", h)
		}
	}
	all := sorted(append(slices.Clone(interrupted), resumed...))
	if want := allKeys(nChecks)[3:]; !slices.Equal(all, want) {
		t.Errorf("new hostnames across both runs\n got %v\nwant %v", all, want)
	}
}

// A real process given --timeout exits 7 by the deadline plus a wide margin (the suite runs under
// -race), leaves its files intact and writes the envelope, and the run after it finishes the rest.
func testTimeoutInAChildProcess(t *testing.T) {
	out := t.TempDir()
	start := time.Now()
	// The checks wait for an hour unless cancelled: the deadline is what ends them.
	c1 := startChild(t, out, childOpts{n: nChecks, delay: time.Hour, args: []string{"a.com", "--timeout", "3s"}})
	code := c1.wait()
	if code != 7 {
		t.Fatalf("first run exit %d, want 7\nstdout %s\nstderr %s", code, c1.stdout.String(), c1.stderr.String())
	}
	if took := time.Since(start); took > 30*time.Second {
		t.Errorf("the run took %v for a 3s deadline", took)
	}
	env, ok := tryEnvelope(c1.stdout.String())
	if !ok || !env.Meta.DeadlineExceeded || env.Meta.ChecksCancelled == 0 {
		t.Errorf("stdout is not the envelope of a run the deadline ended: %s", c1.stdout.String())
	}
	if !strings.Contains(c1.stderr.String(), `"code":"PARTIAL"`) {
		t.Errorf("stderr: %s", c1.stderr.String())
	}
	assertOutputsIntact(t, out)
	if got := committed(t, out); len(got) != 0 {
		t.Errorf("%d cancelled checks were recorded as done", len(got))
	}
	finishAndCheck(t, out, allKeys(nChecks), childOpts{args: []string{"-e", "a.com"}})
}
