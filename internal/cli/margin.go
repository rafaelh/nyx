package cli

import (
	"io"
	"sync"
)

// margin sets nyx's output on a terminal apart from the shell prompts around it: a blank line
// before the first thing written and one after the last. Only a stream that is a terminal is
// wrapped, and neither is under --json, so output that a program reads stays byte for byte the
// same. A stream nothing is written to stays empty. The two streams usually share one terminal, so
// they share one margin: the opening line goes to whichever is written first and the closing line
// to whichever was written last.
type margin struct {
	mu     sync.Mutex
	opened bool
	last   io.Writer // the stream written last, or nil when nothing is to close
	endsNL bool      // whether the last write ended its line
}

// wrap is w with the margin, or w itself when it is not a terminal.
func (m *margin) wrap(w io.Writer, terminal bool) io.Writer {
	if !terminal {
		return w
	}
	return &marginWriter{m: m, w: w}
}

// close writes the closing blank line, if anything was written; it ends an unfinished line first.
// A second call writes nothing.
func (m *margin) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		return
	}
	end := "\n"
	if !m.endsNL {
		end = "\n\n"
	}
	_, _ = io.WriteString(m.last, end)
	m.last = nil
}

type marginWriter struct {
	m *margin
	w io.Writer
}

func (mw *marginWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return mw.w.Write(p)
	}
	m := mw.m
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.opened {
		if _, err := io.WriteString(mw.w, "\n"); err != nil {
			return 0, err
		}
		m.opened = true
	}
	m.last, m.endsNL = mw.w, p[len(p)-1] == '\n'
	return mw.w.Write(p)
}
