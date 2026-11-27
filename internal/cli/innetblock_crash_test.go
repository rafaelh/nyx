package cli_test

import (
	"bytes"
	"context"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/egress/egresstest"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// The in-netblock procedure killed at a crash point in its rows job, in a child process
// (TestChildProcesses runs testLkInNetblockCrash).

// lkChildEnv names the child process this file starts: it runs nyx with a procedure that finds
// two candidate hostnames and the real in-netblock procedure, against the parent's fake DNS.
const (
	lkChildEnv    = "NYX_TEST_LK_CHILD"
	lkChildDNSEnv = "NYX_TEST_LK_DNS"
)

// lkCrashNames are the candidate hostnames the child's finder records, at addresses outside the
// first run's netblock and inside the second's.
var lkCrashNames = map[string]string{"a.hosted.org": "192.0.2.10", "b.hosted.org": "192.0.2.11"}

func init() {
	if os.Getenv(lkChildEnv) == "1" { //nolint:forbidigo // set only by testLkInNetblockCrash, for its child process
		os.Exit(lkChildMain())
	}
}

func lkChildMain() int {
	finder := &testkit.Procedure{ProcedureName: "lkfinder", Kind: run.ThirdParty,
		JobsFn: func(run.View) []run.Job { return testkit.Keys("c", 1) },
		RunFn: func(context.Context, run.Job, egress.Clients) ([]run.Observation, error) {
			var out []run.Observation
			for _, n := range slices.Sorted(maps.Keys(lkCrashNames)) {
				out = append(out, obs("hostname", n))
			}
			return out, nil
		}}
	d := cli.DefaultDeps()
	procedures := []run.Procedure{finder}
	for _, p := range d.Procedures {
		if p.Name() == "in-netblock" {
			procedures = append(procedures, p)
		}
	}
	d.Procedures = procedures
	d.Signals = cli.NotifySignals()
	d.NoFsync = true
	d.Egress.ResolverAddrs = []string{os.Getenv(lkChildDNSEnv)} //nolint:forbidigo // the parent's fake DNS, for this child process
	d.Egress.PublicRanges = egresstest.DocumentationRanges
	d.Egress.DNSTimeout = 2 * time.Second
	return cli.Execute(context.Background(), strings.Split(os.Getenv("NYX_TEST_ARGS"), "\x1f"), d) //nolint:forbidigo // as above
}

// lkStartChild starts the test binary as lkChildMain's nyx, with the fault point when fault is
// not "".
func lkStartChild(t *testing.T, out, dnsAddr, fault, faultFile string, args ...string) *child {
	t.Helper()
	c := &child{t: t, log: filepath.Join(t.TempDir(), "log"), out: out, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	full := append([]string{"recon", "--output-dir", out, "--json", "--rate-dns", "100000"}, args...)
	c.cmd = exec.Command(os.Args[0], "-test.run=NoSuchTestEver")
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool { return strings.HasPrefix(kv, "NYX_") }) //nolint:forbidigo // the child inherits the process environment, without the developer's NYX_* settings
	env = append(env, lkChildEnv+"=1", lkChildDNSEnv+"="+dnsAddr, "NYX_TEST_ARGS="+strings.Join(full, "\x1f"),
		"XDG_CONFIG_HOME="+t.TempDir(), "HOME="+t.TempDir())
	if fault != "" {
		env = append(env, "NYX_FAULT="+fault, "NYX_FAULT_FILE="+faultFile)
	}
	c.cmd.Env = env
	c.cmd.Stdout, c.cmd.Stderr = c.stdout, c.stderr
	if err := c.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.cmd.Process.Kill(); _ = c.cmd.Wait() })
	return c
}

// lkRows are the records the in-netblock procedure lists for names in scope by address (every
// observation it made but the lookups themselves), as "kind key", sorted.
func lkRows(t *testing.T, out string) []string {
	t.Helper()
	db := openDB(t, filepath.Join(engDirOf(out), ".nyx", "state.db"))
	return queryStrings(t, db, "SELECT kind || ' ' || key FROM observations WHERE producer='in-netblock' AND kind != 'candidate_lookup'")
}

// A kill -9 at in-job-tx while the rows of names in scope by address are being written leaves
// either all of their rows or none, and the next run lists them all.
func testLkInNetblockCrash(t *testing.T) {
	d := egresstest.NewDNS(t)
	for n, a := range lkCrashNames {
		d.A(n, a)
	}
	out := t.TempDir()
	// The first run looks the names up, outside its netblock: they stay candidates, with no rows.
	c1 := lkStartChild(t, out, d.Addr, "", "", "--cidr", "198.51.100.0/30", "a.com")
	if code := c1.wait(); code != 0 {
		t.Fatalf("first run exit %d\n%s", code, c1.stderr.String())
	}
	for n := range lkCrashNames {
		if got := d.Count(n, "A"); got != 1 {
			t.Fatalf("the first run asked %s A %d times, want once", n, got)
		}
	}
	if rows := lkRows(t, out); len(rows) != 0 {
		t.Fatalf("names outside every netblock have rows: %v", rows)
	}

	// The second run adds their netblock, so its only work is listing their rows; it is killed
	// in the transaction that writes them.
	args := []string{"--cidr", "198.51.100.0/30", "--cidr", "192.0.2.0/28", "-e", "a.com"}
	ff := filepath.Join(t.TempDir(), "fault")
	c2 := lkStartChild(t, out, d.Addr, "in-job-tx", ff, args...)
	c2.waitFault(ff)
	c2.kill(syscall.SIGKILL)
	c2.wait()
	crashed := lkRows(t, out)

	c3 := lkStartChild(t, out, d.Addr, "", "", args...)
	if code := c3.wait(); code != 0 {
		t.Fatalf("recovery run exit %d\n%s", code, c3.stderr.String())
	}
	all := lkRows(t, out)
	for _, want := range []string{"hostname a.hosted.org", "hostname b.hosted.org", "root hosted.org", "ip 192.0.2.10", "ip 192.0.2.11"} {
		if !slices.Contains(all, want) {
			t.Errorf("after the recovery run the rows lack %q: %v", want, all)
		}
	}
	if !slices.ContainsFunc(all, func(r string) bool { return strings.HasPrefix(r, "resolution ") }) {
		t.Errorf("after the recovery run the rows hold no resolution: %v", all)
	}
	if len(crashed) != 0 && !slices.Equal(crashed, all) {
		t.Errorf("the crash left part of the rows\n got %v\nwant all of %v or none", crashed, all)
	}
	for n := range lkCrashNames {
		if got := d.Count(n, "A"); got != 1 {
			t.Errorf("listing the rows of %s asked it again: A %d times in all", n, got)
		}
	}
}
