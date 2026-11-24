package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// failureWriter prints at most one error even when normal exit and a second signal race to
// report it.
type failureWriter struct {
	w     io.Writer
	json  bool
	depth palette.Depth // of stderr; only the "error:" prefix is coloured

	once sync.Once
	mu   sync.Mutex
	red  *config.Redactor
}

func newFailureWriter(w io.Writer, jsonMode bool, depth palette.Depth, red *config.Redactor) *failureWriter {
	return &failureWriter{w: w, json: jsonMode, depth: depth, red: red}
}

// setRedactor replaces the redactor, once the configuration has loaded and
// every key is known.
func (f *failureWriter) setRedactor(r *config.Redactor) {
	f.mu.Lock()
	f.red = r
	f.mu.Unlock()
}

// errorLine defines the five ordered JSON error keys, also used for lookup meta.errors entries.
type errorLine struct {
	Error     string  `json:"error"`
	Code      string  `json:"code"`
	Hint      *string `json:"hint"`
	Input     any     `json:"input"`
	Transient bool    `json:"transient"`
}

// newErrorLine redacts JSON error fields and encodes empty hints as null.
func newErrorLine(e *clierr.Error, red *config.Redactor) errorLine {
	l := errorLine{Error: red.Redact(e.Message), Code: string(e.Code), Input: red.Any(e.Input), Transient: e.Transient}
	if e.Hint != "" {
		h := red.Redact(e.Hint)
		l.Hint = &h
	}
	return l
}

// write emits one redacted error in the chosen mode and ignores later attempts.
func (f *failureWriter) write(e *clierr.Error) {
	f.once.Do(func() {
		f.mu.Lock()
		red := f.red
		f.mu.Unlock()
		var b bytes.Buffer
		if f.json {
			l := newErrorLine(e, red)
			if err := lineEncoder(&b).Encode(l); err != nil {
				fmt.Fprintf(&b, "{\"error\":%q,\"code\":%q,\"hint\":null,\"input\":null,\"transient\":false}\n", err.Error(), clierr.Unexpected)
			}
		} else {
			clean := func(s string) string { return sanitize.Text(red.Redact(s)) }
			prefix := f.depth.Text(palette.Semantic, "error", "error:")
			fmt.Fprintf(&b, "%s %s (%s)\n", prefix, clean(e.Message), e.Code)
			if e.Hint != "" {
				fmt.Fprintf(&b, "hint: %s\n", clean(e.Hint))
			}
			if e.Transient {
				b.WriteString("retry: may succeed after a wait\n")
			}
			for _, t := range e.Targets {
				fmt.Fprintf(&b, "%s %s: %s (%s)\n", prefix, clean(t.Input), clean(t.Message), t.Code)
			}
		}
		_, _ = f.w.Write(b.Bytes())
	})
}

// signalInfo maps termination signals to names and shell-style status codes, 128 plus signal
// number.
type signalInfo struct {
	code int
	name string
}

var signalInfos = map[os.Signal]signalInfo{
	os.Interrupt: {130, "SIGINT"}, unix.SIGTERM: {143, "SIGTERM"}, unix.SIGHUP: {129, "SIGHUP"},
}

// signalOf supplies signal name/status, defaulting unknown signals to SIGINT.
func signalOf(s os.Signal) signalInfo {
	if i, ok := signalInfos[s]; ok {
		return i
	}
	return signalInfos[os.Interrupt]
}

// signals watches Deps.Signals for one command.
type signals struct {
	mu    sync.Mutex
	first os.Signal
	done  chan struct{}
}

// watchSignals cancels on the first signal and calls the non-returning second handler on the
// next. Already queued signals are handled before work starts.
func watchSignals(ch <-chan os.Signal, cancel func(), second func(os.Signal)) *signals {
	s := &signals{done: make(chan struct{})}
	if ch == nil {
		return s
	}
	select {
	case sig := <-ch:
		s.record(sig)
		cancel()
	default:
	}
	go func() {
		for {
			select {
			case sig := <-ch:
				if first := s.received(); first != nil {
					second(first)
					return
				}
				s.record(sig)
				cancel()
			case <-s.done:
				return
			}
		}
	}()
	return s
}

func (s *signals) record(sig os.Signal) {
	s.mu.Lock()
	s.first = sig
	s.mu.Unlock()
}

// received is the first signal, or nil.
func (s *signals) received() os.Signal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.first
}

func (s *signals) stop() { close(s.done) }
