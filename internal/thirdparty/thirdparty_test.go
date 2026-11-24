package thirdparty_test

import (
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
	"github.com/rafaelh/nyx/internal/thirdparty"
)

func build(roots, hosts []string, cnames map[string]string, wildcards []inventory.Wildcard) []store.Obs {
	var d inventory.Data
	for _, h := range hosts {
		d.Hosts = append(d.Hosts, inventory.Host{Name: h})
	}
	for name, target := range cnames {
		d.Resolutions = append(d.Resolutions, inventory.Resolution{Name: name, Type: "CNAME", Value: target})
	}
	d.Wildcards = wildcards
	inv := inventory.New(d, provider.Default())
	sc := scope.New(scope.Config{Roots: roots, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly()})
	return thirdparty.CNAME(sc, inv)
}

func keys(obs []store.Obs) []string {
	var out []string
	for _, o := range obs {
		out = append(out, o.Key)
	}
	slices.Sort(out)
	return out
}

// SaaS dependency rows deduplicate per root/provider suffix across hostname chains.
func TestCNAMEDerivation(t *testing.T) {
	t.Parallel()
	obs := build([]string{"example.com", "example.org"},
		[]string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.org", "f.other.test", "g.example.com"},
		map[string]string{
			"a.example.com": "x.myshopify.com", "b.example.com": "y.myshopify.com", // deduplicate shared dependency
			"c.example.com": "d1.cloudfront.net",                                   // ignore CDN-only hosting
			"d.example.com": "hop.example.net", "hop.example.net": "end.readme.io", // follow the full chain
			"e.example.org": "x.myshopify.com", // preserve separate root attribution
			"f.other.test":  "x.zendesk.com",   // ignore external hostname
		}, nil)
	want := []string{"example.com|cname|myshopify.com", "example.com|cname|readme.io", "example.org|cname|myshopify.com"}
	if got := keys(obs); !slices.Equal(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	for _, o := range obs {
		a := kinds.ThirdParty.Attrs(store.Record{Kind: o.Kind, Key: o.Key, Attrs: o.Attrs, Current: true})
		if o.Kind != "third_party" || a.Mechanism != "cname" || a.Root == "" || a.Domain == "" || a.Provider == "" || a.Depth != 0 {
			t.Errorf("obs %s = %+v", o.Key, a)
		}
	}
}

// Wildcard-only names cannot establish SaaS dependencies.
func TestCNAMEDerivationSkipsWildcardOnly(t *testing.T) {
	t.Parallel()
	obs := build([]string{"example.com"}, []string{"x.wild.example.com", "real.example.com"},
		map[string]string{"x.wild.example.com": "w.myshopify.com", "real.example.com": "r.github.io"},
		[]inventory.Wildcard{{Zone: "wild.example.com", CNAME: "w.myshopify.com"}})
	if got := keys(obs); !slices.Equal(got, []string{"example.com|cname|github.io"}) {
		t.Errorf("keys = %v", got)
	}
}
