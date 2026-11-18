package cli

import (
	"testing"
	"time"
)

// The reserve is a tenth of the timeout, at least 2s, at most 60s, and never more than half.
func TestReserve(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ timeout, want time.Duration }{
		{400 * time.Millisecond, 200 * time.Millisecond}, // half beats the 2s floor
		{3 * time.Second, 1500 * time.Millisecond},
		{10 * time.Second, 2 * time.Second}, // the floor beats a tenth
		{30 * time.Second, 3 * time.Second},
		{10 * time.Minute, 60 * time.Second}, // a tenth is exactly the cap
		{2 * time.Hour, 60 * time.Second},    // the cap beats a tenth
	} {
		if got := reserve(c.timeout); got != c.want {
			t.Errorf("reserve(%v) = %v, want %v", c.timeout, got, c.want)
		}
	}
}
