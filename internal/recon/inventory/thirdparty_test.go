package inventory_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/scope"
)

// thirdPartyData is a root with names handed to a vendor no entry lists, to a listed cloud
// platform, to a listed platform by way of another of the root's names, and to nobody.
func thirdPartyData() inventory.Data {
	d := inventory.Data{Roots: []string{"Example.com"}}
	d.Resolutions = []inventory.Resolution{
		// An unlisted vendor: the first target outside the root names the third party.
		{Name: "learn.example.com", Type: "CNAME", Value: "cl2.vendor-lms.test"},
		{Name: "cl2.vendor-lms.test", Type: "CNAME", Value: "lb.vendor-internal.test"},
		{Name: "learn.example.com", Type: "A", Value: "203.0.113.30"},
		// An alias of an alias: the chain leaves the root at its second hop.
		{Name: "sso.example.com", Type: "CNAME", Value: "id.example.com"},
		{Name: "id.example.com", Type: "CNAME", Value: "tenant.idp-vendor.test"},
		{Name: "sso.example.com", Type: "A", Value: "203.0.113.31"},
		{Name: "id.example.com", Type: "A", Value: "203.0.113.31"},
		// A listed cloud platform runs the organisation's own workload; its internals, which
		// no entry lists, are not a third party.
		{Name: "app.example.com", Type: "CNAME", Value: "acme.azurewebsites.net"},
		{Name: "acme.azurewebsites.net", Type: "CNAME", Value: "waws-prod-1.vip.azure-internal.test"},
		{Name: "app.example.com", Type: "A", Value: "203.0.113.32"},
		// An alias that stays under the root, and a name with no alias.
		{Name: "login.example.com", Type: "CNAME", Value: "www.example.com"},
		{Name: "login.example.com", Type: "A", Value: "203.0.113.33"},
		{Name: "www.example.com", Type: "A", Value: "203.0.113.33"},
		// A name under no root that is an alias of an unlisted name.
		{Name: "shop.other.test", Type: "CNAME", Value: "stores.vendor-shop.test"},
		{Name: "shop.other.test", Type: "A", Value: "203.0.113.34"},
		// Aliases that lead to no address: one out of the root, one inside it.
		{Name: "old.example.com", Type: "CNAME", Value: "d111.vendor-cdn.test"},
		{Name: "gone.example.com", Type: "CNAME", Value: "missing.example.com"},
		{Name: "moved.example.com", Type: "CNAME", Value: "old.example.com"},
	}
	for _, n := range []string{"learn", "sso", "id", "app", "login", "www", "old", "gone", "moved"} {
		d.Hosts = append(d.Hosts, inventory.Host{Name: n + ".example.com", Producers: []string{"crtsh"}})
	}
	d.Owners = map[netip.Addr]provider.Owner{}
	for _, a := range []string{"203.0.113.30", "203.0.113.31", "203.0.113.32", "203.0.113.33", "203.0.113.34"} {
		d.Owners[netip.MustParseAddr(a)] = provider.Owner{ASN: 64500, Holder: "EXAMPLE-NET", Known: true}
	}
	return d
}

func thirdPartyScope(inv *inventory.Inventory) *scope.Scope {
	return scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly()})
}

// A name under an input root whose alias leaves the roots for a target no entry lists is served
// by a third party: SaaS for the checks that skip one. Its address stays port-eligible, as nothing
// says the address is shared.
func TestThirdPartyByAlias(t *testing.T) {
	t.Parallel()
	inv := inventory.New(thirdPartyData(), provider.Default())
	sc := thirdPartyScope(inv)
	for host, want := range map[string]bool{
		"learn.example.com": true,
		"sso.example.com":   true, // by way of id.example.com
		"id.example.com":    true,
		"app.example.com":   false, // a listed cloud platform, whatever its internals are called
		"login.example.com": false, // the alias stays under the root
		"www.example.com":   false,
		"shop.other.test":   false, // not under an input root
	} {
		if got := inv.SaaSServed(host); got != want {
			t.Errorf("SaaSServed(%s) = %v, want %v", host, got, want)
		}
	}
	for addr, want := range map[string]bool{
		"203.0.113.30": true, // an unlisted third party's address: not known to be shared
		"203.0.113.31": true,
		"203.0.113.32": false, // the listed cloud platform's entry makes it shared
		"203.0.113.33": true,  // the organisation's own
	} {
		if got := inv.PortEligible(netip.MustParseAddr(addr), sc); got != want {
			t.Errorf("PortEligible(%s) = %v, want %v", addr, got, want)
		}
	}
}

// The third party is listed once per name, by the registrable domain of the target the name was
// handed to; a listed entry later in the chain keeps its own row.
func TestThirdPartyByAlias_ProviderHosts(t *testing.T) {
	t.Parallel()
	inv := inventory.New(thirdPartyData(), provider.Default())
	var got []string
	for _, ph := range inv.ProviderHosts(thirdPartyScope(inv)) {
		if ph.Evidence == "cname" {
			got = append(got, ph.Hostname+" "+ph.Provider+" "+ph.Entry.Class+" "+ph.CNAME)
		}
	}
	want := []string{
		"app.example.com azure  acme.azurewebsites.net",
		"id.example.com idp-vendor.test saas tenant.idp-vendor.test",
		"learn.example.com vendor-lms.test saas cl2.vendor-lms.test",
		"moved.example.com vendor-cdn.test saas d111.vendor-cdn.test",
		"old.example.com vendor-cdn.test saas d111.vendor-cdn.test",
		"sso.example.com idp-vendor.test saas tenant.idp-vendor.test",
	}
	if !slices.Equal(got, want) {
		t.Errorf("provider hosts by alias:\n got %q\nwant %q", got, want)
	}
}

// Without input roots nothing is known to be the organisation's by name, so no alias is a third
// party's.
func TestThirdPartyByAlias_NeedsRoots(t *testing.T) {
	t.Parallel()
	d := thirdPartyData()
	d.Roots = nil
	inv := inventory.New(d, provider.Default())
	if inv.SaaSServed("learn.example.com") {
		t.Error("SaaSServed(learn.example.com) with no roots: an alias is a third party's only when the name is under a root")
	}
}

// An alias with no address whose chain leaves the roots dangles; one that stays under the roots,
// one that resolves and one that is not in scope do not.
func TestDanglingAliases(t *testing.T) {
	t.Parallel()
	inv := inventory.New(thirdPartyData(), provider.Default())
	got := inv.DanglingAliases(thirdPartyScope(inv))
	want := []inventory.Alias{
		{Hostname: "moved.example.com", Target: "d111.vendor-cdn.test"},
		{Hostname: "old.example.com", Target: "d111.vendor-cdn.test"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("DanglingAliases = %+v, want %+v", got, want)
	}
}
