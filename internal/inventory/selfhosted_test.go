package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/provider"
)

// A name server or mail host is self-hosted when it is in scope, or when one of
// the addresses looked up for it is inside an in-scope netblock or is
// port-eligible. A known provider's domain, a shared address and an address of
// unknown owner are never a sign, whatever else is true of the host.
func TestSelfHosted(t *testing.T) {
	t.Parallel()
	var d inventory.Data
	// www.example.com is an in-scope host on dedicated, shared and unknown-owner addresses.
	resolve(&d, "www.example.com", "203.0.113.50", "104.16.0.5", "192.0.2.77")
	d.Owners = map[netip.Addr]provider.Owner{
		ip("203.0.113.50"): {ASN: 64500, Holder: "ACME-NET", Known: true},
		ip("203.0.113.51"): {ASN: 64500, Holder: "ACME-NET", Known: true},
		ip("104.16.0.5"):   {ASN: 13335, Holder: "CLOUDFLARENET", Known: true},
	}
	server := func(host string, addrs ...string) {
		for _, a := range addrs {
			d.ServerAddresses = append(d.ServerAddresses, inventory.ServerAddress{Host: host, Addr: ip(a)})
		}
	}
	server("ns-netblock.other.test", "198.51.100.9")             // inside an in-scope netblock
	server("ns-eligible.other.test", "203.0.113.50")             // the address an in-scope host has, dedicated
	server("ns-dedicated.other.test", "203.0.113.51")            // dedicated, but no in-scope host is there
	server("ns1.cloudflare.com", "198.51.100.10")                // a known provider's domain, in a netblock
	server("ns-shared.other.test", "104.16.0.5")                 // shared provider infrastructure
	server("ns-unknown.other.test", "192.0.2.77")                // owner unknown, though an in-scope host is there
	server("ns-excluded.other.test", "198.51.100.66")            // inside an excluded CIDR
	server("ns-mixed.other.test", "104.16.0.5", "198.51.100.11") // one shared address, one in a netblock
	server("ns.excluded.example.com", "198.51.100.12")

	inv := inventory.New(d, provider.Default())
	sc := newScope(inv, "198.51.100.64/28", "ns.excluded.example.com")

	for _, c := range []struct {
		host string
		want bool
		why  string
	}{
		{"ns1.example.com", true, "in scope, with no address on record"},
		{"NS1.Example.COM.", true, "the name is normalised"},
		{"ns-netblock.other.test", true, "address inside an in-scope netblock"},
		{"ns-eligible.other.test", true, "port-eligible address"},
		{"ns-dedicated.other.test", false, "a dedicated address nothing in scope uses is just somebody's server"},
		{"ns1.cloudflare.com", false, "known provider, even inside a netblock"},
		{"ns-shared.other.test", false, "shared address"},
		{"ns-unknown.other.test", false, "unknown owner"},
		{"ns-excluded.other.test", false, "excluded address"},
		{"ns-mixed.other.test", true, "any one self-hosted address is enough"},
		{"ns.excluded.example.com", false, "an excluded host is never a sign"},
		{"ns-nothing.other.test", false, "no address looked up"},
	} {
		if got := inv.SelfHosted(c.host, sc); got != c.want {
			t.Errorf("SelfHosted(%s) = %v, want %v (%s)", c.host, got, c.want, c.why)
		}
	}
}

// A looked-up server address is not an address the inventory resolves: the
// server never becomes resolved, probed or port-eligible because of it.
func TestServerAddressesChangeNothing(t *testing.T) {
	t.Parallel()
	var base inventory.Data
	resolve(&base, "www.example.com", "203.0.113.50")
	base.Owners = map[netip.Addr]provider.Owner{ip("203.0.113.50"): {ASN: 64500, Holder: "ACME-NET", Known: true},
		ip("203.0.113.60"): {ASN: 64500, Holder: "ACME-NET", Known: true}}
	extra := base
	extra.ServerAddresses = []inventory.ServerAddress{{Host: "ns.other.test", Addr: ip("203.0.113.60")}, {Host: "ns.example.com", Addr: ip("203.0.113.61")}}

	db := provider.Default()
	a, b := inventory.New(base, db), inventory.New(extra, db)
	sa, sb := newScope(a), newScope(b)
	if len(a.Addrs()) != len(b.Addrs()) {
		t.Errorf("resolved names changed: %v -> %v", a.Addrs(), b.Addrs())
	}
	if b.PortEligible(ip("203.0.113.60"), sb) || a.PortEligible(ip("203.0.113.60"), sa) {
		t.Error("a name server's address became port-eligible")
	}
	if len(a.KnownAddrs(sa)) != len(b.KnownAddrs(sb)) {
		t.Errorf("known addresses changed: %v -> %v", a.KnownAddrs(sa), b.KnownAddrs(sb))
	}
}
