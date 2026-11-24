package cli

import (
	"testing"
	"time"
)

// Reserve 10% for cleanup, bounded by two seconds, one minute and half the total timeout.
func TestReserve(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ timeout, want time.Duration }{
		{400 * time.Millisecond, 200 * time.Millisecond}, // short timeouts use the half-timeout bound
		{3 * time.Second, 1500 * time.Millisecond},
		{10 * time.Second, 2 * time.Second}, // small reserves use the two-second floor
		{30 * time.Second, 3 * time.Second},
		{10 * time.Minute, 60 * time.Second}, // boundary case at one minute
		{2 * time.Hour, 60 * time.Second},    // long timeouts use the one-minute cap
	} {
		if got := reserve(c.timeout); got != c.want {
			t.Errorf("reserve(%v) = %v, want %v", c.timeout, got, c.want)
		}
	}
}
