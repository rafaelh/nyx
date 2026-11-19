package cli

import (
	"bytes"
	"encoding/json"
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

// failureWriter writes the one error of a failed call to stderr, at most
// once: the second signal and the normal exit may both ask for it.
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

// errorLine is the JSON error: exactly these five keys, in this order. It is
// also each meta.errors entry of nyx cve.
type errorLine struct {
	Error     string  `json:"error"`
	Code      string  `json:"code"`
	Hint      *string `json:"hint"`
	Input     any     `json:"input"`
	Transient bool    `json:"transient"`
}

// newErrorLine is e as the JSON error, with every API key masked; an empty
// hint is null.
func newErrorLine(e *clierr.Error, red *config.Redactor) errorLine {
	l := errorLine{Error: red.Redact(e.Message), Code: string(e.Code), Input: red.Any(e.Input), Transient: e.Transient}
	if e.Hint != "" {
		h := red.Redact(e.Hint)
		l.Hint = &h
	}
	return l
}

// write writes e, unless an error has been written already. Every API key is
// masked in either mode.
func (f *failureWriter) write(e *clierr.Error) {
	f.once.Do(func() {
		f.mu.Lock()
		red := f.red
		f.mu.Unlock()
		var b bytes.Buffer
		if f.json {
			l := newErrorLine(e, red)
			enc := json.NewEncoder(&b)
			enc.SetEscapeHTML(false) // a URL's & stays readable
			if err := enc.Encode(l); err != nil {
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

// signalInfo is the exit code (128 plus the signal's number, as a shell
// reports it) and the name of each signal that ends a command.
type signalInfo struct {
	code int
	name string
}

var signalInfos = map[os.Signal]signalInfo{
	os.Interrupt: {130, "SIGINT"}, unix.SIGTERM: {143, "SIGTERM"}, unix.SIGHUP: {129, "SIGHUP"},
}

// signalOf is how a command signal s ended exits and is named; any other
// signal counts as SIGINT.
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

// watchSignals records the first signal and cancels the command; a second
// calls second, which does not return. A signal already waiting when the
// command starts is taken at once, before any work.
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
