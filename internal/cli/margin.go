package cli

import (
	"io"
	"sync"
)

// margin separates terminal output from shell prompts with leading and trailing blank lines.
// Empty streams stay empty and --json bypasses margins. Since stdout and stderr usually share a
// terminal, the opening line uses the first written stream and the closing line uses the last.
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

// close adds the trailing margin once, completing an unfinished output line first.
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
