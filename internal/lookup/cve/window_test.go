package cve

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeClock starts from real time so manually advanced timestamps still produce meaningful
// context deadlines.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func reserveN(t *testing.T, w *window, ctx context.Context, n int) []time.Duration {
	t.Helper()
	var out []time.Duration
	for range n {
		d, ok := w.reserve(ctx)
		if !ok {
			t.Fatalf("reserve refused a slot after %v", d)
		}
		out = append(out, d)
	}
	return out
}

func TestWindow_Limits(t *testing.T) {
	t.Parallel()
	for _, n := range []int{rateWithoutKey, rateWithKey} {
		clk := newFakeClock()
		w := newWindow(n, rateWindow, clk.now)
		for i, d := range reserveN(t, w, context.Background(), n) {
			if d != 0 {
				t.Errorf("n=%d: request %d waits %v, want none", n, i+1, d)
			}
		}
		if d := reserveN(t, w, context.Background(), 1)[0]; d != rateWindow {
			t.Errorf("n=%d: request %d waits %v, want %v", n, n+1, d, rateWindow)
		}
	}
	if rateWithoutKey != 5 || rateWithKey != 50 || rateWindow != 30*time.Second {
		t.Errorf("the limits are %d and %d per %v, want 5 and 50 per 30s", rateWithoutKey, rateWithKey, rateWindow)
	}
}

// The window rolls: a slot frees 30 seconds after the request that held it
// started, not at the edge of a fixed window.
func TestWindow_Rolls(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	w := newWindow(5, 30*time.Second, clk.now)
	reserveN(t, w, context.Background(), 1) // t0
	clk.advance(20 * time.Second)
	reserveN(t, w, context.Background(), 4) // t0+20s
	got := reserveN(t, w, context.Background(), 2)
	// The sixth waits for t0's slot (t0+30s); the seventh for the first of t0+20s's (t0+50s).
	if got[0] != 10*time.Second || got[1] != 30*time.Second {
		t.Errorf("waits %v, want [10s 30s]", got)
	}
	clk.advance(40 * time.Second) // t0+60s: t0+20s's slots and the sixth's have freed, the seventh's not
	got = reserveN(t, w, context.Background(), 4)
	if got[0] != 0 || got[1] != 0 || got[2] != 0 || got[3] != 0 {
		t.Errorf("after the slots freed, waits %v, want none", got)
	}
	if d := reserveN(t, w, context.Background(), 1)[0]; d != 20*time.Second {
		t.Errorf("then a wait of %v, want 20s (the seventh's slot at t0+50s frees at t0+80s)", d)
	}
}

// A slot after the deadline fails at once with its wait, and is not claimed.
func TestWindow_SlotAfterTheDeadline(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	w := newWindow(5, 30*time.Second, clk.now)
	reserveN(t, w, context.Background(), 5)
	ctx, cancel := context.WithDeadline(context.Background(), clk.now().Add(25*time.Second))
	defer cancel()
	for range 2 {
		if d, ok := w.reserve(ctx); ok || d != 30*time.Second {
			t.Fatalf("reserve = %v, %v; want the slot past the deadline refused, with its 30s wait", d, ok)
		}
	}
	// Neither refusal claimed the slot: the next request still gets t0+30s.
	if d := reserveN(t, w, context.Background(), 1)[0]; d != 30*time.Second {
		t.Errorf("wait %v, want 30s", d)
	}
}

// Many workers reserving at once never get more than n slots in a window.
func TestWindow_Concurrent(t *testing.T) {
	t.Parallel()
	clk := newFakeClock()
	w := newWindow(5, 30*time.Second, clk.now)
	var mu sync.Mutex
	var waits []time.Duration
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			d, ok := w.reserve(context.Background())
			if !ok {
				t.Error("reserve refused a slot with no deadline")
			}
			mu.Lock()
			waits = append(waits, d)
			mu.Unlock()
		})
	}
	wg.Wait()
	count := map[time.Duration]int{}
	for _, d := range waits {
		count[d]++
	}
	if count[0] != 5 || count[30*time.Second] != 5 || count[60*time.Second] != 2 {
		t.Errorf("waits %v, want 5 at once, 5 after 30s and 2 after 60s", count)
	}
}
