package setup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/term/palette"
)

// syncBuffer permits concurrent Program writes and test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// session runs the Program with pipe-fed input in the background.
type session struct {
	t      *testing.T
	in     *io.PipeWriter
	out    *syncBuffer
	done   chan error
	cancel context.CancelFunc
	kill   func()
}

func startSession(t *testing.T, b Backend, mod func(*Options)) *session {
	t.Helper()
	pr, pw := io.Pipe()
	s := &session{t: t, in: pw, out: &syncBuffer{}, done: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	t.Cleanup(func() { cancel(); pw.Close(); pr.Close() })
	o := Options{
		In: pr, Out: s.out, Env: []string{"TERM=xterm-256color"}, Depth: palette.None,
		Width: 80, Height: 24,
		OnProgram: func(kill func()) { s.kill = kill },
	}
	if mod != nil {
		mod(&o)
	}
	go func() { s.done <- Run(ctx, b, o) }()
	return s
}

func (s *session) send(text string) {
	s.t.Helper()
	if _, err := io.WriteString(s.in, text); err != nil {
		s.t.Fatalf("write input: %v", err)
	}
}

func (s *session) waitOut(sub string) {
	s.t.Helper()
	until(s.t, "output "+sub, func() bool { return strings.Contains(s.out.String(), sub) })
}

func (s *session) result() error {
	s.t.Helper()
	select {
	case err := <-s.done:
		return err
	case <-time.After(10 * time.Second):
		s.t.Fatalf("Run did not return; output:\n%q", s.out.String())
		return nil
	}
}

func until(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRun_EditsSavesAndQuitsThroughARealProgram(t *testing.T) {
	t.Parallel()
	b := newFake()
	s := startSession(t, b, nil)
	s.waitOut("nyx setup")
	s.send("\r")
	s.send("abcdefghijklmnop")
	s.send("\r")
	s.send("\x13")
	until(t, "the save", func() bool { n, _, _ := b.counts(); return n == 1 })
	s.send("q")
	if err := s.result(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if e := b.save(t, 0); e.Set["keys.securitytrails"] != "abcdefghijklmnop" || len(e.Set) != 1 {
		t.Errorf("saved %+v", e)
	}
	out := s.out.String()
	if !strings.Contains(out, "\x1b[?1049h") || !strings.HasSuffix(strings.TrimRight(out, "\r\n"), "\x1b[?1049l") && !strings.Contains(out[strings.LastIndex(out, "\x1b[?1049l"):], "\x1b[?25h") {
		t.Errorf("the alternate screen is not entered and left, or the cursor is not shown:\n%q", out)
	}
	noKeyIn(t, "the output", out, "abcdefghijklmnop")
}

func TestRun_QuitWithNoChangeWritesNothing(t *testing.T) {
	t.Parallel()
	b := newFake()
	s := startSession(t, b, nil)
	s.waitOut("nyx setup")
	s.send("\x03")
	if err := s.result(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n, o, _ := b.counts(); n != 0 || o != 0 {
		t.Errorf("wrote: %d %d", n, o)
	}
}

func TestRun_AContextCancelEndsTheProgramWithTheContextError(t *testing.T) {
	t.Parallel()
	s := startSession(t, newFake(), nil)
	s.waitOut("nyx setup")
	s.cancel()
	err := s.result()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want an error wrapping context.Canceled", err)
	}
	if !strings.Contains(s.out.String(), "\x1b[?1049l") {
		t.Error("the alternate screen was not left")
	}
}

func TestRun_ASaveUnderWayCompletesWhenTheFirstSignalArrives(t *testing.T) {
	t.Parallel()
	b := newFake()
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	b.saveFn = func(snap Snapshot, e Edits) (Snapshot, error) {
		close(started)
		<-release
		close(finished)
		return b.applied(snap, e), nil
	}
	s := startSession(t, b, nil)
	s.waitOut("nyx setup")
	s.send("\r")
	s.send("abcdefghijklmnop")
	s.send("\r")
	s.send("\x13")
	<-started
	s.cancel() // simulate first-signal cancellation
	select {
	case err := <-s.done:
		t.Fatalf("Run returned %v before the save finished", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the save did not finish")
	}
	if err := s.result(); !errors.Is(err, context.Canceled) {
		t.Errorf("Run returned %v", err)
	}
}

func TestRun_OnProgramGivesAKillThatRestoresTheTerminal(t *testing.T) {
	t.Parallel()
	s := startSession(t, newFake(), nil)
	s.waitOut("nyx setup")
	if s.kill == nil {
		t.Fatal("OnProgram was not called before the program ran")
	}
	go s.kill()
	err := s.result()
	if !errors.Is(err, tea.ErrProgramKilled) {
		t.Errorf("Run returned %v, want ErrProgramKilled", err)
	}
	if !strings.Contains(s.out.String(), "\x1b[?1049l") {
		t.Error("the alternate screen was not left")
	}
}

func TestRun_ErrorFromOpenIsReturnedBeforeAnyUI(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.openErr = &FileError{Path: testPath, Problems: []string{"bad"}}
	var out syncBuffer
	err := Run(context.Background(), b, Options{In: strings.NewReader(""), Out: &out})
	if _, ok := errors.AsType[*FileError](err); !ok {
		t.Fatalf("Run returned %v", err)
	}
	if out.String() != "" {
		t.Errorf("wrote %q before the UI", out.String())
	}
}

func TestRun_APanicInUpdateIsReturnedWithoutTheKeyAndTheTerminalRestored(t *testing.T) {
	t.Parallel()
	const key = "Lm5RxV8cZq2NwT7hYb3D"
	b := newFake()
	b.checkFn = func(string, string) (string, error) { panic("boom while checking " + key) }
	s := startSession(t, b, nil)
	s.waitOut("nyx setup")
	s.send("\r")
	s.send(key)
	s.send("\r")
	s.send("\t")
	s.send("\x1b[B")
	s.send("\r")
	s.send("12")
	s.send("\r") // inject a backend validation panic
	err := s.result()
	var pe *clierr.PanicError
	if !errors.As(err, &pe) {
		t.Fatalf("Run returned %v, want a *clierr.PanicError", err)
	}
	noKeyIn(t, "the error", err.Error()+string(pe.Stack)+sprintf("%v", pe.Value), key)
	if !strings.Contains(err.Error(), "boom while checking") {
		t.Errorf("the panic's own text is lost: %v", err)
	}
	out := s.out.String()
	noKeyIn(t, "the output", out, key)
	if !strings.Contains(out[strings.LastIndex(out, "\x1b[?1049"):], "\x1b[?1049l") {
		t.Error("the alternate screen was not left after the panic")
	}
}

func TestRun_APanicInACommandIsReturnedWithoutTheKey(t *testing.T) {
	t.Parallel()
	const key = "Jd6PfK1sUe9XaC4oMz8G"
	b := newFake()
	b.snap.Keys["securitytrails"] = KeyState{Value: config.Secret(key)}
	b.testFn = func(context.Context, string, config.Secret) TestResult { panic("boom while testing " + key) }
	s := startSession(t, b, nil)
	s.waitOut("nyx setup")
	s.send("t")
	err := s.result()
	var pe *clierr.PanicError
	if !errors.As(err, &pe) {
		t.Fatalf("Run returned %v, want a *clierr.PanicError", err)
	}
	noKeyIn(t, "the error", err.Error()+string(pe.Stack)+sprintf("%v", pe.Value), key)
	if !strings.Contains(err.Error(), "boom while testing") {
		t.Errorf("the panic's own text is lost: %v", err)
	}
	out := s.out.String()
	noKeyIn(t, "the output", out, key)
	if !strings.Contains(out, "\x1b[?1049l") {
		t.Error("the alternate screen was not left after the panic")
	}
}

func TestRoot_APanicInViewIsRecovered(t *testing.T) {
	t.Parallel()
	killed := false
	g := &guard{kill: func() { killed = true }}
	r := &root{g: g} // exercise panic recovery before a model exists
	_ = r.View()
	if g.panicErr == nil || !killed {
		t.Fatalf("panic %v killed %v", g.panicErr, killed)
	}
}

func TestSafe_ACommandsPanicBecomesAMessageThatRepanicsInUpdate(t *testing.T) {
	t.Parallel()
	msg := safe(func() tea.Msg { panic("inside the command") })()
	if _, ok := msg.(panicMsg); !ok {
		t.Fatalf("got %T", msg)
	}
	g := &guard{}
	r := &root{m: &model{}, g: g}
	r.Update(msg)
	if g.panicErr == nil || !strings.Contains(g.panicErr.Error(), "inside the command") {
		t.Fatalf("panic = %v", g.panicErr)
	}
	if safe(nil) != nil {
		t.Error("safe(nil) is not nil")
	}
}
