package addrkind

import (
	"net/netip"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// Cover unreachable IANA entries at their boundaries, accounting for more-specific exceptions.
func TestOf_RegistryRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		addr string
		want Kind
	}{
		// IPv4: this network and this host.
		{"0.0.0.0", "unspecified"},
		{"0.0.0.1", "this-network"},
		{"0.255.255.255", "this-network"},
		{"1.0.0.0", Public},
		// Private use.
		{"10.0.0.0", "private"},
		{"10.255.255.255", "private"},
		{"11.0.0.0", Public},
		{"9.255.255.255", Public},
		{"172.16.0.0", "private"},
		{"172.31.255.255", "private"},
		{"172.15.255.255", Public},
		{"172.32.0.0", Public},
		{"192.168.0.0", "private"},
		{"192.168.255.255", "private"},
		{"192.167.255.255", Public},
		{"192.169.0.0", Public},
		// Shared address space.
		{"100.64.0.0", "cgnat"},
		{"100.127.255.255", "cgnat"},
		{"100.63.255.255", Public},
		{"100.128.0.0", Public},
		// Loopback and link-local.
		{"127.0.0.1", "loopback"},
		{"127.0.0.0", "loopback"},
		{"127.255.255.255", "loopback"},
		{"169.254.0.0", "link-local"},
		{"169.254.255.255", "link-local"},
		{"169.253.255.255", Public},
		{"169.255.0.0", Public},
		// IETF protocol assignments and the more specific rows inside them.
		{"192.0.0.0", "ietf-protocol"},
		{"192.0.0.1", "ietf-protocol"},
		{"192.0.0.7", "ietf-protocol"},
		{"192.0.0.8", "dummy"},
		{"192.0.0.9", Public},
		{"192.0.0.10", Public},
		{"192.0.0.11", "ietf-protocol"},
		{"192.0.0.169", "ietf-protocol"},
		{"192.0.0.170", "nat64-discovery"},
		{"192.0.0.171", "nat64-discovery"},
		{"192.0.0.172", "ietf-protocol"},
		{"192.0.0.255", "ietf-protocol"},
		{"192.0.1.0", Public},
		// Documentation.
		{"192.0.2.0", "documentation"},
		{"192.0.2.255", "documentation"},
		{"198.51.100.0", "documentation"},
		{"198.51.100.255", "documentation"},
		{"203.0.113.0", "documentation"},
		{"203.0.113.255", "documentation"},
		{"203.0.112.255", Public},
		{"203.0.114.0", Public},
		// Benchmarking.
		{"198.18.0.0", "benchmarking"},
		{"198.19.255.255", "benchmarking"},
		{"198.17.255.255", Public},
		{"198.20.0.0", Public},
		// Reachable rows of the registry.
		{"192.31.196.1", Public},
		{"192.52.193.1", Public},
		{"192.175.48.1", Public},
		// The terminated 6to4 relay row is not in the table, but the live 6a44 relay row inside it is.
		{"192.88.99.1", Public},
		{"192.88.99.2", "6a44-relay"},
		{"192.88.99.3", Public},
		// Reserved and broadcast.
		{"240.0.0.0", "reserved"},
		{"255.255.255.254", "reserved"},
		{"255.255.255.255", "broadcast"},
		{"239.255.255.255", "multicast"},
		// Multicast.
		{"224.0.0.0", "multicast"},
		{"224.0.0.1", "multicast"},
		{"232.1.2.3", "multicast"},
		{"223.255.255.255", Public},

		// IPv6: unspecified and loopback.
		{"::", "unspecified"},
		{"::1", "loopback"},
		{"::2", "reserved"},
		// Translation.
		{"64:ff9b::", Public},
		{"64:ff9b::1.2.3.4", Public},
		{"64:ff9b::ffff:ffff", Public},
		{"64:ff9b::1:0:0", "reserved"},
		{"64:ff9b:1::", "nat64-local"},
		{"64:ff9b:1:ffff:ffff:ffff:ffff:ffff", "nat64-local"},
		{"64:ff9b:2::", "reserved"},
		// Discard-only and the dummy prefix.
		{"100::", "discard"},
		{"100::ffff:ffff:ffff:ffff", "discard"},
		{"100:0:0:1::", "dummy"},
		{"100:0:0:1:ffff:ffff:ffff:ffff", "dummy"},
		{"100:0:0:2::", "reserved"},
		// IETF protocol assignments and the rows inside them.
		{"2001::1", "teredo"},
		{"2001::", "teredo"},
		{"2001:0:ffff:ffff:ffff:ffff:ffff:ffff", "teredo"},
		{"2001:1::", "ietf-protocol"},
		{"2001:1::1", Public},
		{"2001:1::2", Public},
		{"2001:1::3", Public},
		{"2001:1::4", "ietf-protocol"},
		{"2001:2::", "benchmarking"},
		{"2001:2:0:ffff:ffff:ffff:ffff:ffff", "benchmarking"},
		{"2001:2:1::", "ietf-protocol"},
		{"2001:3::1", Public},
		{"2001:4:112::1", Public},
		{"2001:4:113::1", "ietf-protocol"},
		{"2001:10::1", "ietf-protocol"},
		{"2001:20::1", Public},
		{"2001:2f:ffff::1", Public},
		{"2001:30::1", Public},
		{"2001:40::1", "ietf-protocol"},
		{"2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "ietf-protocol"},
		{"2001:200::1", Public},
		// Documentation.
		{"2001:db8::", "documentation"},
		{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "documentation"},
		{"2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", Public},
		{"2001:db9::", Public},
		{"3fff::", "documentation"},
		{"3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", "documentation"},
		{"3fff:1000::", Public},
		// 6to4.
		{"2002::", "6to4"},
		{"2002:c000:204::1", "6to4"},
		{"2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "6to4"},
		{"2003::", Public},
		// Direct delegation AS112.
		{"2620:4f:8000::1", Public},
		// Ordinary global unicast.
		{"2000::", Public},
		{"2606:4700::1111", Public},
		{"2a00:1450:4001::", Public},
		{"3ffe::1", Public},
		{"3fff:2000::", Public},
		{"3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Public},
		// SRv6 SIDs.
		{"5f00::", "srv6"},
		{"5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "srv6"},
		{"5eff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "reserved"},
		{"5f01::", "reserved"},
		// Unique local and link-local.
		{"fc00::", "ula"},
		{"fd00::1", "ula"},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ula"},
		{"fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "reserved"},
		{"fe00::", "reserved"},
		{"fe80::", "link-local"},
		{"fe80::1", "link-local"},
		{"febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "link-local"},
		{"fec0::1", "reserved"},
		// Multicast.
		{"ff00::", "multicast"},
		{"ff02::1", "multicast"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "multicast"},
		// Outside 2000::/3 and in no row: reserved.
		{"1::", "reserved"},
		{"4000::", "reserved"},
		{"8000::1", "reserved"},
		{"a000::", "reserved"},
		{"e000::", "reserved"},
		{"::1.2.3.4", "reserved"},
		{"1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "reserved"},
	} {
		if got := Of(addr(tc.addr)); got != tc.want {
			t.Errorf("Of(%s) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// The longest prefix wins, whichever way the registry's rows differ.
func TestOf_LongestPrefixWins(t *testing.T) {
	t.Parallel()
	// 192.0.0.0/24 is not reachable but 192.0.0.9 and 192.0.0.10 are; 192.0.0.8 is not.
	if got := Of(addr("192.0.0.9")); got != Public {
		t.Errorf("192.0.0.9 = %q, want public", got)
	}
	if got := Of(addr("192.0.0.10")); got != Public {
		t.Errorf("192.0.0.10 = %q, want public", got)
	}
	if got := Of(addr("192.0.0.8")); got == Public {
		t.Errorf("192.0.0.8 is public")
	}
	// Teredo sits inside 2001::/23, which is not reachable, and 2001:20::/28 is reachable.
	if Of(addr("2001::1")) != "teredo" || Of(addr("2001:20::1")) != Public {
		t.Errorf("2001::1 = %q, 2001:20::1 = %q", Of(addr("2001::1")), Of(addr("2001:20::1")))
	}
	// The row order in the table does not matter.
	for _, r := range registry {
		if got := lookup(r.prefix.Addr()); got.bits < r.prefix.Bits() {
			t.Errorf("%s: matched a shorter prefix, /%d", r.prefix, got.bits)
		}
	}
}

// Mapped addresses use IPv4 classification; zone identifiers do not affect kind.
func TestOf_UnmapsFirst(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		addr string
		want Kind
	}{
		{"::ffff:10.0.0.1", "private"},
		{"::ffff:8.8.8.8", Public},
		{"::ffff:127.0.0.1", "loopback"},
		{"::ffff:0.0.0.0", "unspecified"},
		{"::ffff:255.255.255.255", "broadcast"},
		{"::ffff:224.0.0.1", "multicast"},
		{"::ffff:192.0.0.9", Public},
		{"fe80::1%eth0", "link-local"},
		{"2606:4700::1111%eth0", Public},
	} {
		if got := Of(addr(tc.addr)); got != tc.want {
			t.Errorf("Of(%s) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestOf_InvalidAddressIsNotPublic(t *testing.T) {
	t.Parallel()
	if got := Of(netip.Addr{}); got != "reserved" {
		t.Errorf("Of(zero) = %q, want reserved", got)
	}
}

// "Broadcast" is 255.255.255.255 only: the rest of 240.0.0.0/4 is reserved.
func TestOf_BroadcastIsOneAddress(t *testing.T) {
	t.Parallel()
	n := 0
	for _, s := range []string{"255.255.255.253", "255.255.255.254", "255.255.255.255", "240.0.0.0", "247.1.1.1"} {
		if Of(addr(s)) == "broadcast" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d of the sample addresses are broadcast, want 1", n)
	}
}

func TestRegistry_Wellformed(t *testing.T) {
	t.Parallel()
	seen := map[netip.Prefix]bool{}
	for _, r := range registry {
		if r.prefix != r.prefix.Masked() || !r.prefix.IsValid() {
			t.Errorf("%s is not a masked prefix", r.prefix)
		}
		if seen[r.prefix] {
			t.Errorf("%s is listed twice", r.prefix)
		}
		seen[r.prefix] = true
	}
}

// Every kind the registry names is one some address has. The one exception is the IPv4-mapped
// range, whose addresses are unmapped before the lookup.
func TestRegistry_EachKindIsProduced(t *testing.T) {
	t.Parallel()
	got := map[Kind]bool{}
	for _, r := range registry {
		got[Of(r.prefix.Addr())] = true
	}
	for _, s := range []string{"224.0.0.1", "ff02::1", "255.255.255.255", "0.0.0.0", "0.1.2.3", "240.0.0.1", "1::"} {
		got[Of(addr(s))] = true
	}
	for _, r := range registry {
		if r.kind != "ipv4-mapped" && !got[r.kind] {
			t.Errorf("no address has kind %q", r.kind)
		}
	}
}
