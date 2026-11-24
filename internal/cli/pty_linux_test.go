//go:build linux

package cli_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The sequences a full-screen program uses to take the terminal and to give it back.
const (
	enterAltScreen = "\x1b[?1049h"
	leaveAltScreen = "\x1b[?1049l"
	showCursor     = "\x1b[?25h"
)

// pty is a pseudo-terminal pair, with what is written to its master collected.
type pty struct {
	t      *testing.T
	master *os.File
	slave  *os.File

	mu  sync.Mutex
	out bytes.Buffer
}

// openPTY opens a pseudo-terminal of 100 by 30 cells.
func openPTY(t *testing.T) *pty {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	fd := int(master.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 30, Col: 100}); err != nil {
		t.Fatal(err)
	}
	p := &pty{t: t, master: master, slave: slave}
	t.Cleanup(func() { master.Close(); slave.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			p.mu.Lock()
			p.out.Write(buf[:n])
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return p
}

func (p *pty) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

// termios reads settings from the pseudo-terminal's slave side.
func (p *pty) termios() unix.Termios {
	p.t.Helper()
	tio, err := unix.IoctlGetTermios(int(p.slave.Fd()), unix.TCGETS)
	if err != nil {
		p.t.Fatal(err)
	}
	return *tio
}

func (p *pty) send(keys ...string) {
	p.t.Helper()
	for _, k := range keys {
		if _, err := p.master.WriteString(k); err != nil {
			p.t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// setupOnPTY is a nyx setup child process on a pty.
type setupOnPTY struct {
	t      *testing.T
	pty    *pty
	cmd    *exec.Cmd
	before unix.Termios
	done   chan struct{}
}

// startSetup waits for a real child editor to acquire and draw on its pseudo-terminal.
func startSetup(t *testing.T, config string, extraEnv ...string) *setupOnPTY {
	t.Helper()
	p := openPTY(t)
	s := &setupOnPTY{t: t, pty: p, before: p.termios(), done: make(chan struct{})}
	s.cmd = exec.Command(os.Args[0], "-test.run=NoSuchTestEver")
	base := []string{"NYX_TEST_SETUP_CHILD=1", "NYX_TEST_ARGS=" + strings.Join([]string{"setup", "--config", config}, "\x1f"),
		"TERM=xterm-256color", "HOME=" + t.TempDir(), "XDG_CONFIG_HOME=" + t.TempDir()}
	s.cmd.Env = slices.Concat(base, extraEnv)
	s.cmd.Stdin, s.cmd.Stdout, s.cmd.Stderr = p.slave, p.slave, p.slave
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.cmd.Wait(); close(s.done) }()
	t.Cleanup(func() { _ = s.cmd.Process.Kill(); <-s.done })
	waitFor(t, "setup to draw", func() bool {
		o := p.output()
		return strings.Contains(o, enterAltScreen) && strings.Contains(o, "Keys")
	})
	time.Sleep(200 * time.Millisecond) // the input is being read
	return s
}

// exit waits for the child and returns its exit code.
func (s *setupOnPTY) exit() int {
	s.t.Helper()
	select {
	case <-s.done:
	case <-time.After(30 * time.Second):
		s.t.Fatalf("setup did not exit; output:\n%q", s.pty.output())
	}
	time.Sleep(50 * time.Millisecond) // the last output reaches the master
	return s.cmd.ProcessState.ExitCode()
}

// restored verifies original terminal settings, alternate-screen exit and visible cursor after
// the final draw.
func (s *setupOnPTY) restored() {
	s.t.Helper()
	if after := s.pty.termios(); after != s.before {
		s.t.Errorf("the terminal settings changed:\nbefore %+v\nafter  %+v", s.before, after)
	}
	out := s.pty.output()
	enter, leave := strings.LastIndex(out, enterAltScreen), strings.LastIndex(out, leaveAltScreen)
	if leave < enter || leave < 0 {
		s.t.Errorf("the alternate screen was not left after it was entered")
	}
	if show := strings.LastIndex(out, showCursor); show < enter {
		s.t.Errorf("the cursor was not shown again")
	}
}

// after returns what the terminal was sent after it was given back.
func (s *setupOnPTY) after() string {
	out := s.pty.output()
	return out[strings.LastIndex(out, leaveAltScreen):]
}

// ptyEdit is the key presses that enter a key on the second row of the Keys tab.
var ptyEdit = []string{keyDown, keyEnter, "pty-key-0123456789", keyEnter}

// Real-terminal tests cover save/discard/quit, signals and panics, ensuring terminal
// restoration precedes error output.
func testSetupOnAPty(t *testing.T) {
	t.Run("save", testPTYSave)
	t.Run("discard", testPTYDiscard)
	t.Run("quit", testPTYQuit)
	for _, c := range []struct {
		sig  syscall.Signal
		want int
		name string
	}{{syscall.SIGTERM, 143, "SIGTERM"}, {syscall.SIGHUP, 129, "SIGHUP"}, {syscall.SIGINT, 130, "SIGINT"}} {
		t.Run(c.name, func(t *testing.T) { testPTYSignal(t, c.sig, c.want, c.name) })
	}
	t.Run("second signal", testPTYSecondSignal)
	t.Run("panic", testPTYPanic)
}

func testPTYSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.yaml")
	s := startSetup(t, path)
	s.pty.send(append(slices.Clone(ptyEdit), keyCtrlS, "q")...)
	if code := s.exit(); code != 0 {
		t.Fatalf("exit %d\n%q", code, s.pty.output())
	}
	s.restored()
	if got := readFileOrEmpty(t, path); !strings.Contains(got, "shodan: pty-key-0123456789") {
		t.Errorf("file %q", got)
	}
	if strings.Contains(s.pty.output(), "pty-key-012345") {
		t.Error("the key is on the terminal beyond its last 4 characters")
	}
}

func testPTYDiscard(t *testing.T) {
	path := writeFile(t, t.TempDir(), "nyx.yaml", "concurrency: 7\n")
	s := startSetup(t, path)
	s.pty.send(append(slices.Clone(ptyEdit), "q", "d")...)
	if code := s.exit(); code != 0 {
		t.Fatalf("exit %d\n%q", code, s.pty.output())
	}
	s.restored()
	if got := readFileOrEmpty(t, path); got != "concurrency: 7\n" {
		t.Errorf("file %q", got)
	}
}

func testPTYQuit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.yaml")
	s := startSetup(t, path)
	s.pty.send("q")
	if code := s.exit(); code != 0 {
		t.Fatalf("exit %d\n%q", code, s.pty.output())
	}
	s.restored()
	if got := readFileOrEmpty(t, path); got != "<absent>" {
		t.Errorf("a quit with no change wrote %q", got)
	}
}

// testPTYSignal ends setup with sig in the middle of an unsaved edit.
func testPTYSignal(t *testing.T, sig syscall.Signal, want int, name string) {
	t.Helper()
	path := writeFile(t, t.TempDir(), "nyx.yaml", "concurrency: 7\n")
	s := startSetup(t, path)
	s.pty.send(ptyEdit...) // an edit that is never saved
	_ = s.cmd.Process.Signal(sig)
	if code := s.exit(); code != want {
		t.Fatalf("exit %d, want %d\n%q", code, want, s.pty.output())
	}
	s.restored()
	if got := readFileOrEmpty(t, path); got != "concurrency: 7\n" {
		t.Errorf("file %q", got)
	}
	if !strings.Contains(s.after(), "interrupted by "+name) {
		t.Errorf("the error does not come after the terminal is restored: %q", s.after())
	}
}

// A second signal must restore the terminal and exit even while a save is stuck.
func testPTYSecondSignal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.yaml")
	faultFile := filepath.Join(t.TempDir(), "fault")
	s := startSetup(t, path, "NYX_FAULT=in-config-save", "NYX_FAULT_FILE="+faultFile)
	s.pty.send(append(slices.Clone(ptyEdit), keyCtrlS)...)
	waitFor(t, "the save to start", func() bool { _, err := os.Stat(faultFile); return err == nil })
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	time.Sleep(100 * time.Millisecond)
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	if code := s.exit(); code != 143 {
		t.Fatalf("exit %d\n%q", code, s.pty.output())
	}
	s.restored()
	if got := readFileOrEmpty(t, path); got != "<absent>" {
		t.Errorf("a save that never finished left %q", got)
	}
	if !strings.Contains(s.after(), "interrupted by SIGTERM") {
		t.Errorf("the error does not come after the terminal is restored: %q", s.after())
	}
}

// A panic inside the editor ends it as an unexpected failure, with the terminal given back first.
func testPTYPanic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.yaml")
	marker := filepath.Join(t.TempDir(), "panic")
	s := startSetup(t, path, "NYX_TEST_PANIC_FILE="+marker)
	writeFile(t, filepath.Dir(marker), "panic", "")
	// Tab to Settings, edit output_dir to a relative path, which asks for the working directory.
	s.pty.send(keyTab, keyEnter, "relative/dir", keyEnter)
	if code := s.exit(); code != 1 {
		t.Fatalf("exit %d\n%q", code, s.pty.output())
	}
	s.restored()
	if after := s.after(); !strings.Contains(after, "UNEXPECTED_ERROR") || !strings.Contains(after, "forced panic") {
		t.Errorf("the error does not come after the terminal is restored: %q", after)
	}
}
