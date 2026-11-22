// Package addrkind says what kind of address an IP address is: public, or which special-purpose
// kind of non-public address (private, loopback, link-local and so on). It is pure.
//
// The table is written by hand from IANA's two special-purpose address registries,
// iana-ipv4-special-registry-1.csv and iana-ipv6-special-registry-1.csv, and was checked row by
// row against the files as published on 2026-11-21. The registries gain rows now and then, so
// compare the table with the current files when changing it.
//
// An address is non-public when its row's "Globally Reachable" column is False or N/A, and public
// when it is True or no row lists it. A more specific row beats a less specific one, so 192.0.0.0/24
// (False) holds the reachable 192.0.0.9/32 and 192.0.0.10/32 (True). Terminated rows (the 6to4
// relay anycast 192.88.99.0/24 and the deprecated ORCHID 2001:10::/28) are left out, so their
// addresses take the row that covers them, if any; the live 6a44 relay row 192.88.99.2/32 inside
// the terminated block is kept. A row whose reachable value is True has the kind Public.
//
// Two things are not in those registries. Multicast (224.0.0.0/4 and ff00::/8) has registries of
// its own. And an IPv6 address outside 2000::/3 that no row lists is "reserved": that comes from
// IANA's IPv6 Address Space registry, since only 2000::/3 is allocated for global unicast.
//
// An IPv4-mapped IPv6 address is looked up as the IPv4 address it carries.
package addrkind

import "net/netip"

// Kind is the kind of an address: Public, or the name of a non-public kind.
type Kind string

// Public is an address that is globally reachable.
const Public Kind = "public"

// row is one registry entry. Its kind is Public when the registry marks it globally reachable.
type row struct {
	prefix netip.Prefix
	kind   Kind
}

func p(s string, k Kind) row { return row{netip.MustParsePrefix(s), k} }

// registry is the table. Order does not matter: the longest matching prefix wins.
var registry = []row{
	// IPv4 special-purpose address registry.
	p("0.0.0.0/8", "this-network"),
	p("0.0.0.0/32", "unspecified"),
	p("10.0.0.0/8", "private"),
	p("100.64.0.0/10", "cgnat"),
	p("127.0.0.0/8", "loopback"),
	p("169.254.0.0/16", "link-local"),
	p("172.16.0.0/12", "private"),
	p("192.0.0.0/24", "ietf-protocol"),
	p("192.0.0.0/29", "ietf-protocol"), // IPv4 service continuity prefix
	p("192.0.0.8/32", "dummy"),
	p("192.0.0.9/32", Public),  // Port Control Protocol anycast
	p("192.0.0.10/32", Public), // TURN anycast
	p("192.0.0.170/32", "nat64-discovery"),
	p("192.0.0.171/32", "nat64-discovery"),
	p("192.0.2.0/24", "documentation"),
	p("192.31.196.0/24", Public),      // AS112-v4
	p("192.52.193.0/24", Public),      // AMT
	p("192.88.99.2/32", "6a44-relay"), // a live row inside the terminated 6to4 relay block
	p("192.168.0.0/16", "private"),
	p("192.175.48.0/24", Public), // direct delegation AS112 service
	p("198.18.0.0/15", "benchmarking"),
	p("198.51.100.0/24", "documentation"),
	p("203.0.113.0/24", "documentation"),
	p("240.0.0.0/4", "reserved"),
	p("255.255.255.255/32", "broadcast"),
	// The IPv4 multicast registries.
	p("224.0.0.0/4", "multicast"),

	// IPv6 special-purpose address registry.
	p("::1/128", "loopback"),
	p("::/128", "unspecified"),
	p("::ffff:0:0/96", "ipv4-mapped"),
	p("64:ff9b::/96", Public), // IPv4-IPv6 translation
	p("64:ff9b:1::/48", "nat64-local"),
	p("100::/64", "discard"),
	p("100:0:0:1::/64", "dummy"),
	p("2001::/23", "ietf-protocol"),
	p("2001::/32", "teredo"),
	p("2001:1::1/128", Public), // Port Control Protocol anycast
	p("2001:1::2/128", Public), // TURN anycast
	p("2001:1::3/128", Public), // DNS-SD service registration protocol anycast
	p("2001:2::/48", "benchmarking"),
	p("2001:3::/32", Public),     // AMT
	p("2001:4:112::/48", Public), // AS112-v6
	p("2001:20::/28", Public),    // ORCHIDv2
	p("2001:30::/28", Public),    // drone remote ID entity tags
	p("2001:db8::/32", "documentation"),
	p("2002::/16", "6to4"),
	p("2620:4f:8000::/48", Public), // direct delegation AS112 service
	p("3fff::/20", "documentation"),
	p("5f00::/16", "srv6"),
	p("fc00::/7", "ula"),
	p("fe80::/10", "link-local"),
	// The IPv6 multicast registries.
	p("ff00::/8", "multicast"),
}

// globalUnicast is the part of the IPv6 space that is allocated for global unicast; an address
// outside it that no row lists is reserved.
var globalUnicast = netip.MustParsePrefix("2000::/3")

// found is the row an address matched, or none.
type found struct {
	kind Kind
	bits int
	ok   bool
}

// lookup finds the longest prefix of the registry that holds a.
func lookup(a netip.Addr) found {
	var best found
	for _, r := range registry {
		if bits := r.prefix.Bits(); r.prefix.Contains(a) && (!best.ok || bits > best.bits) {
			best = found{r.kind, bits, true}
		}
	}
	return best
}

// Of is the kind of a. An invalid address is "reserved", never Public.
func Of(a netip.Addr) Kind {
	if !a.IsValid() {
		return "reserved"
	}
	a = a.Unmap().WithZone("")
	if f := lookup(a); f.ok {
		return f.kind
	}
	if a.Is6() && !globalUnicast.Contains(a) {
		return "reserved"
	}
	return Public
}

// names are the non-public kinds, in the order docs/ip.md lists them.
var names = []string{
	"private", "ula", "loopback", "link-local", "cgnat", "multicast", "unspecified", "this-network",
	"broadcast", "documentation", "benchmarking", "reserved", "ietf-protocol", "6to4", "teredo",
	"nat64-local", "discard", "dummy", "srv6", "nat64-discovery", "6a44-relay", "ipv4-mapped",
}

// Names are the non-public kind names, in a stable order. (Public is not among them.) No address
// has "ipv4-mapped": an IPv4-mapped address is looked up as the IPv4 address, but the registry's
// row is kept so its name is not lost.
func Names() []string { return append([]string(nil), names...) }
