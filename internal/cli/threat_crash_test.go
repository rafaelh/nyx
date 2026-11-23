package cli_test

import (
	"bytes"
	"context"
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
	"github.com/rafaelh/nyx/internal/threatdata"
)

// The update in a child process: killed at its fault points, and ended by each signal. Each test
// gives the child a downloaded copy of both sources, dated d1, and checks that it is still the copy
// in use afterwards, byte for byte.

// threatChildMain runs nyx in a child process as the real binary would, with the signals main
// subscribes to, its two hosts at the fakes the parent gives, and a built-in copy dated by the
// parent, so that both read the same one.
func threatChildMain() int {
	base, err := strconv.ParseInt(os.Getenv("NYX_TEST_THREAT_BASE"), 10, 64) //nolint:forbidigo // the parent's settings for this child process
	if err != nil {
		return 98
	}
	builtIn, err := tdBuiltIn(time.Unix(base, 0).UTC())
	if err != nil {
		return 99
	}
	d := cli.DefaultDeps()
	d.Signals = cli.NotifySignals()
	d.NoFsync = true
	d.ThreatBuiltIn = builtIn
	d.Egress.SourceBaseURLs = map[string]string{
		threatdata.SpamhausHost: os.Getenv("NYX_TEST_SPAMHAUS_URL"), //nolint:forbidigo // as above
		threatdata.IpapiHost:    os.Getenv("NYX_TEST_IPAPI_URL"),    //nolint:forbidigo // as above
	}
	d.Egress.SourceRates = map[string]float64{threatdata.SpamhausHost: 1000, threatdata.IpapiHost: 1000}
	return cli.Execute(context.Background(), strings.Split(os.Getenv("NYX_TEST_ARGS"), "\x1f"), d) //nolint:forbidigo // as above
}

// threatChild is a world for an update in a child process: a config directory, fakes for the two
// hosts, and the dates of the copies.
type threatChild struct {
	t          *testing.T
	cfg        string // the child's XDG_CONFIG_HOME
	sh, ip     *tdFake
	d0, d1, d2 time.Time
	before     map[string][]byte // the downloaded copy in place, by file name
}

// newThreatChild makes the world: a downloaded copy of both sources dated d1 in place, and fakes
// that answer a download dated d2.
func newThreatChild(t *testing.T) *threatChild {
	t.Helper()
	c := &threatChild{t: t, cfg: t.TempDir(), sh: newTDFake(t), ip: newTDFake(t)}
	c.d0 = time.Now().UTC().Truncate(time.Second).AddDate(0, 0, -20)
	c.d1, c.d2 = c.d0.AddDate(0, 0, 1), c.d0.AddDate(0, 0, 2)
	w := &threatWorld{t: t, sh: c.sh, ip: c.ip, d0: c.d0, d1: c.d1, d2: c.d2}
	w.serveSpamhaus(tdSpamhausAt(c.d2, 5))
	w.serveIpapi(c.d2, 5)
	c.before = map[string][]byte{tdSpamhausData: tdBundle(tdSpamhausAt(c.d1, 2)), tdIpapiData: tdIpapiFile(tdIpapiAt(c.d1, 2))}
	for name, b := range c.before {
		tdWrite(t, c.dir(), name, b)
	}
	return c
}

func (c *threatChild) dir() string { return filepath.Join(c.cfg, "nyx", "threat-data") }

// threatProc is the child process of an update, with a channel closed when it has exited.
type threatProc struct {
	*child
	exited chan struct{}
}

// start starts nyx setup --update-threat-data in a child process, with fault, when set, as its
// fault point. Only the subtests of TestChildProcesses call it.
func (c *threatChild) start(fault, faultFile string) *threatProc {
	c.t.Helper()
	ch := &threatProc{child: &child{t: c.t, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}}
	ch.cmd = exec.Command(os.Args[0], "-test.run=NoSuchTestEver")
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool { //nolint:forbidigo // the child process's own environment
		return strings.HasPrefix(kv, "NYX_") || strings.HasPrefix(kv, "XDG_CONFIG_HOME=") || strings.HasPrefix(kv, "HOME=")
	})
	env = append(env, "NYX_TEST_THREAT_CHILD=1",
		"NYX_TEST_ARGS="+strings.Join([]string{"setup", "--update-threat-data"}, "\x1f"),
		"NYX_TEST_THREAT_BASE="+strconv.FormatInt(c.d0.Unix(), 10),
		"NYX_TEST_SPAMHAUS_URL="+c.sh.srv.URL, "NYX_TEST_IPAPI_URL="+c.ip.srv.URL,
		"XDG_CONFIG_HOME="+c.cfg, "HOME="+c.cfg)
	ch.cmd.Env = env
	if fault != "" {
		ch.cmd.Env = append(ch.cmd.Env, "NYX_FAULT="+fault, "NYX_FAULT_FILE="+faultFile)
	}
	ch.cmd.Stdout, ch.cmd.Stderr = ch.stdout, ch.stderr
	if err := ch.cmd.Start(); err != nil {
		c.t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = ch.cmd.Wait(); close(exited) }()
	ch.exited = exited
	c.t.Cleanup(func() { _ = ch.cmd.Process.Kill(); <-exited })
	return ch
}

// done reports whether the child has exited.
func (p *threatProc) done() bool {
	select {
	case <-p.exited:
		return true
	default:
		return false
	}
}

// untouched checks that both sources' downloaded copies are as they were, and that they are the
// copies in use: no temporary file the update left is read.
func (c *threatChild) untouched() {
	c.t.Helper()
	for name, b := range c.before {
		got, err := os.ReadFile(filepath.Join(c.dir(), name))
		if err != nil || !bytes.Equal(got, b) {
			c.t.Errorf("%s is no longer the previous copy (%v):\n%.200s", name, err, got)
		}
	}
	builtIn, err := tdBuiltIn(c.d0)
	if err != nil {
		c.t.Fatal(err)
	}
	set := builtIn.Load(c.dir(), time.Now())
	if len(set.Warnings) != 0 {
		c.t.Errorf("reading the threat data warns: %+v", set.Warnings)
	}
	if len(set.Lists) != len(tdListNames) {
		c.t.Fatalf("the threat data in use is %+v, want five lists", set.Lists)
	}
	for _, l := range set.Lists {
		want := tdStamp(c.d1)
		if l.Source == threatdata.Ipapi {
			want = tdDay(c.d1)
		}
		if !l.Downloaded || l.Updated != want {
			c.t.Errorf("%s in use: %+v, want the previous downloaded copy, dated %s", l.Name, l, want)
		}
	}
}

// temporary lists the temporary files a source's update left in dir.
func tdTemporary(dir, source string) []string {
	stem := "spamhaus"
	if source == threatdata.Ipapi {
		stem = "ipapi"
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "."+stem+"-*.tmp"))
	return matches
}

// waitFaultOrExit waits for the child to reach its fault point, failing the test when it exits
// first or does not get there in time.
func waitFaultOrExit(t *testing.T, ch *threatProc, file string) {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		if _, err := os.Stat(file); err == nil {
			time.Sleep(50 * time.Millisecond)
			return
		}
		select {
		case <-ch.exited:
			t.Fatalf("the update exited %d before its fault point\nstdout %s\nstderr %s", ch.cmd.ProcessState.ExitCode(), ch.stdout, ch.stderr)
		case <-deadline:
			t.Fatal("the update never reached its fault point")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// waitExit returns the child's exit code, failing the test if it does not exit.
func waitExit(t *testing.T, ch *threatProc) int {
	t.Helper()
	select {
	case <-ch.exited:
	case <-time.After(60 * time.Second):
		_ = ch.cmd.Process.Kill()
		t.Fatal("the update did not exit")
	}
	return ch.cmd.ProcessState.ExitCode()
}

// A kill -9 at either fault point of either source leaves each source with its previous copy, which
// stays the copy in use. Only the source under test is answered: the other's first request is held,
// so it never reaches a fault point. At the first point the source's response is already recorded;
// at the second its new copy is in a temporary file, which nothing reads.
func testThreatCrashPoints(t *testing.T) {
	for _, point := range []string{"threat-after-response", "threat-before-rename"} {
		for _, source := range []string{threatdata.Spamhaus, threatdata.Ipapi} {
			t.Run(point+" "+source, func(t *testing.T) {
				t.Parallel()
				c := newThreatChild(t)
				other := c.ip
				if source == threatdata.Ipapi {
					other = c.sh
				}
				otherSource := threatdata.Ipapi
				if source == threatdata.Ipapi {
					otherSource = threatdata.Spamhaus
				}
				other.hold(t, tdFirstPath(otherSource))
				ff := filepath.Join(t.TempDir(), "fault")
				ch := c.start(point, ff)
				waitFaultOrExit(t, ch, ff)
				_ = ch.cmd.Process.Signal(syscall.SIGKILL)
				waitExit(t, ch)

				c.untouched()
				switch point {
				case "threat-after-response":
					if tdReadState(t, c.dir(), source).LastResponse == nil {
						t.Errorf("%s's response was not recorded before the fault point", source)
					}
				case "threat-before-rename":
					if len(tdTemporary(c.dir(), source)) == 0 {
						t.Errorf("no temporary file of %s was left: the fault point is not between its write and its rename", source)
					}
				}
			})
		}
	}
}

// Each signal ends an update in flight with its own exit code and one INTERRUPTED error, an empty
// stdout and both previous copies in use.
func testThreatSignals(t *testing.T) {
	for name, s := range map[string]struct {
		sig  syscall.Signal
		code int
	}{"SIGINT": {syscall.SIGINT, 130}, "SIGTERM": {syscall.SIGTERM, 143}, "SIGHUP": {syscall.SIGHUP, 129}} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := newThreatChild(t)
			c.sh.hold(t, tdPathV6) // drop_v4 has answered; drop_v6 is in flight
			c.ip.hold(t, tdPathNetworks)
			ch := c.start("", "")
			asked := func() bool { return c.sh.count(tdPathV6) > 0 && c.ip.count(tdPathNetworks) > 0 || ch.done() }
			if !tdPoll(30*time.Second, asked) || ch.done() {
				t.Fatalf("the update never had both sources in flight: Spamhaus saw %v, ipapi.is %v\nstderr %s",
					c.sh.requests(), c.ip.requests(), ch.stderr)
			}
			_ = ch.cmd.Process.Signal(s.sig)
			if code := waitExit(t, ch); code != s.code {
				t.Fatalf("exit %d, want %d\nstderr %s", code, s.code, ch.stderr)
			}
			if ch.stdout.Len() != 0 {
				t.Errorf("stdout %q after a signal", ch.stdout)
			}
			ch.checkInterrupted(false)
			c.untouched()
			if n := c.sh.count(tdPathASN); n != 0 {
				t.Errorf("asndrop was asked for %d times after the signal", n)
			}
		})
	}
}
