package iplookup

import (
	"testing"
	"time"
)

func TestDeadline(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		active    bool
		addresses int
		want      time.Duration
	}{
		{"one address", false, 1, 12 * time.Second},
		{"two addresses", false, 2, 13250 * time.Millisecond},
		{"the cap", false, 256, 12*time.Second + 255*1250*time.Millisecond},
		{"one address, active", true, 1, 30 * time.Second},
		{"two addresses, active", true, 2, 32 * time.Second},
		{"the cap, active", true, 256, 30*time.Second + 255*2*time.Second},
		{"none counts as one", false, 0, 12 * time.Second},
		{"negative counts as one, active", true, -4, 30 * time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := Deadline(c.active, c.addresses); got != c.want {
				t.Errorf("Deadline(%v, %d) = %v, want %v", c.active, c.addresses, got, c.want)
			}
		})
	}
}

func TestDeadline_NeverOverflows(t *testing.T) {
	t.Parallel()
	for _, active := range []bool{false, true} {
		got := Deadline(active, 1<<62)
		if got <= 0 {
			t.Errorf("active=%v: a huge count gave %v", active, got)
		}
		if got < Deadline(active, MaxAddresses) {
			t.Errorf("active=%v: a huge count gave less (%v) than the cap's", active, got)
		}
	}
}
