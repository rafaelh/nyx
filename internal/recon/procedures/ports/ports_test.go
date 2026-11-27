package ports

import (
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
)

// A banner needs no cap of its own on the names taken from it: the shortest name below a root
// takes about seven bytes with its separator, so one banner read cannot hold 1,000 of them.
func TestBannerCannotHoldTheNameCap(t *testing.T) {
	t.Parallel()
	if egress.MaxBanner <= 0 || egress.MaxBanner/7 >= 1000 {
		t.Errorf("egress.MaxBanner = %d: a banner could hold %d names, want under 1,000", egress.MaxBanner, egress.MaxBanner/7)
	}
}
