// Package addrkind classifies public and special-purpose IP addresses without I/O. Its table
// follows IANA's IPv4/IPv6 special-purpose registries as checked on 2026-11-21.
//
// Globally Reachable=True or no matching row means public; False/N/A means non-public. More
// specific prefixes win. Terminated rows are omitted, while active exceptions remain. Multicast
// comes from separate registries, and unmatched IPv6 outside global-unicast 2000::/3 is
// reserved. IPv4-mapped IPv6 addresses use their embedded IPv4 classification.
package addrkind

import "net/netip"

// Kind distinguishes public addresses from named special-purpose ranges.
type Kind string

// Public is an address that is globally reachable.
const Public Kind = "public"

// row maps a registry prefix to its reachability class.
type row struct {
	prefix netip.Prefix
	kind   Kind
}

func p(s string, k Kind) row { return row{netip.MustParsePrefix(s), k} }

// registry uses longest-prefix matching regardless of row order.
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

// globalUnicast bounds ordinary IPv6 global-unicast allocation. Unlisted addresses outside it
// are reserved.
var globalUnicast = netip.MustParsePrefix("2000::/3")

// found holds the matching registry row, when present.
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

// Of classifies an address, treating invalid addresses as reserved.
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

// PublicPrefix reports whether every address of a prefix may be public: no special-purpose row
// that is not globally reachable overlaps it, and an IPv6 prefix lies inside 2000::/3.
func PublicPrefix(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	p = p.Masked()
	for _, r := range registry {
		if r.kind != Public && r.prefix.Overlaps(p) {
			return false
		}
	}
	return p.Addr().Is4() || p.Bits() >= globalUnicast.Bits() && globalUnicast.Contains(p.Addr())
}
