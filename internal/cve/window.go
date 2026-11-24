package cve

import (
	"context"
	"sync"
	"time"
)

// window limits request starts to n in any rolling interval. It tracks actual or reserved
// starts and waits for the oldest to expire. Up to n requests can start together; unlike a
// token bucket, refill cannot exceed the rolling limit. A batch shares one window.
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

// reserve claims the next request slot and returns its delay. Slots beyond ctx's deadline are
// not claimed; the result includes their delay with ok=false.
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

// sleep stops early on context termination and returns its error.
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
