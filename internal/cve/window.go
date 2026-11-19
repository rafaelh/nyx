package cve

import (
	"context"
	"sync"
	"time"
)

// window paces request starts to the NVD's rolling limit: at most n in any
// window of the given size. It records when each of the last n requests
// started, or is due to, and a new one may start once the oldest has left the
// window. Unlike a token bucket, that never admits more than n in a rolling
// window, and a batch of up to n starts at once. One window is shared by
// every request of a batch.
type window struct {
	mu     sync.Mutex
	n      int
	size   time.Duration
	starts []time.Time // the last n start times, oldest first; some may be in the future
	now    func() time.Time
}

func newWindow(n int, size time.Duration, now func() time.Time) *window {
	return &window{n: n, size: size, starts: make([]time.Time, 0, n), now: now}
}

// reserve claims the next slot and returns how long until it. A slot after
// ctx's deadline is not claimed: reserve returns at once, with ok false and
// how long until that slot.
func (w *window) reserve(ctx context.Context) (wait time.Duration, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := w.now()
	start := now
	if len(w.starts) == w.n {
		if free := w.starts[0].Add(w.size); free.After(now) {
			start = free
		}
	}
	wait = start.Sub(now)
	if deadline, has := ctx.Deadline(); has && start.After(deadline) {
		return wait, false
	}
	if len(w.starts) == w.n {
		w.starts = append(w.starts[:0], w.starts[1:]...) // in place: the slice keeps its capacity
	}
	w.starts = append(w.starts, start)
	return wait, true
}

// sleep waits for d, or until ctx ends, and returns ctx's error if it ended first.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
