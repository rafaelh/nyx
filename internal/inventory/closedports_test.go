package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/provider"
)

// Inventory normalises mapped addresses when recording closed ports.
func TestPortClosed(t *testing.T) {
	t.Parallel()
	inv := inventory.New(inventory.Data{ClosedPorts: []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.5:3306"), netip.MustParseAddrPort("[2001:db8::1]:22"),
	}}, provider.Default())
	for _, c := range []struct {
		ap   string
		want bool
	}{
		{"203.0.113.5:3306", true}, {"[::ffff:203.0.113.5]:3306", true}, {"[2001:db8::1]:22", true},
		{"203.0.113.5:3307", false}, {"203.0.113.6:3306", false},
	} {
		if got := inv.PortClosed(netip.MustParseAddrPort(c.ap)); got != c.want {
			t.Errorf("PortClosed(%s) = %v, want %v", c.ap, got, c.want)
		}
	}
}
