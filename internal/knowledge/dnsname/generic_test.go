package dnsname_test

import (
	"net/netip"
	"testing"

	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
)

// A name is generic for an IPv4 address when it holds the address's four decimal octets, forwards
// or backwards, joined by "." or "-", with or without zero padding, and touching no other digit.
func TestGeneric(t *testing.T) {
	t.Parallel()
	const addr = "203.0.113.5"
	for _, c := range []struct {
		name string
		addr string
		want bool
	}{
		// The three forms a generic name takes.
		{"203-0-113-5.static.example.net", addr, true},
		{"5.113.0.203.example.net", addr, true},
		{"203-000-113-005.example.net", addr, true},
		// Forwards with ".", backwards with "-", and mixed separators.
		{"host.203.0.113.5.example.net", addr, true},
		{"5-113-0-203.example.net", addr, true},
		{"ip-5-113-0-203.dsl.example.net", addr, true},
		{"203.0-113.5.example.net", addr, true},
		{"5-113.0-203.example.net", addr, true},
		{"005.113.000.203.example.net", addr, true},
		// A run that touches another digit is not the octet.
		{"1203-0-113-5.example.net", addr, false},
		{"203-0-113-50.example.net", addr, false},
		{"5-113-0-2031.example.net", addr, false},
		// Four digits are not an octet, even with a leading zero.
		{"0203-0-113-5.example.net", addr, false},
		{"203-0-113-0005.example.net", addr, false},
		// The octets in another order, or only three of them.
		{"113-0-203-5.example.net", addr, false},
		{"203-113-0-5.example.net", addr, false},
		{"0-203-5-113.example.net", addr, false},
		{"203-0-113.example.net", addr, false},
		// Octets joined by something other than one "." or "-".
		{"203-0-ab-113-5.example.net", addr, false},
		{"203-0x113-5.example.net", addr, false},
		{"203_0_113_5.example.net", addr, false},
		// No digits at all.
		{"www.example.net", addr, false},
		// Another address's octets.
		{"203-0-113-6.example.net", addr, false},
		{"10-0-0-1.example.net", "10.0.0.1", true},
		{"1.0.0.10.example.net", "10.0.0.1", true},
		// An IPv6 address is never generic, even when its low 32 bits spell an IPv4 address the
		// name holds.
		{"203-0-113-5.example.net", "2001:db8::cb00:7105", false},
		{"2001-db8--5.example.net", "2001:db8::5", false},
		{"2001-db8-0-0-0-0-0-5.example.net", "2001:db8::5", false},
	} {
		if got := dnsname.Generic(c.name, netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("Generic(%q, %s) = %v, want %v", c.name, c.addr, got, c.want)
		}
	}
}

// An IPv4-mapped IPv6 address is judged as the IPv4 address it holds.
func TestGeneric_IPv4MappedAddress(t *testing.T) {
	t.Parallel()
	a := netip.MustParseAddr("::ffff:203.0.113.5")
	if !dnsname.Generic("203-0-113-5.example.net", a) {
		t.Errorf("Generic of %s = false, want true", a)
	}
	if dnsname.Generic("203-0-113-6.example.net", a) {
		t.Errorf("Generic of another address's name with %s = true, want false", a)
	}
}
