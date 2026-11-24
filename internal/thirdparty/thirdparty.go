// Package thirdparty derives dependency records from scope and inventory without I/O.
package thirdparty

import (
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

// CNAME derives SaaS dependencies for in-scope, non-wildcard-only names. Each matched provider
// suffix contributes one record under the most specific input root. Excluded/candidate names
// and CDN/cloud-only chains do not contribute SaaS dependencies.
func CNAME(sc *scope.Scope, inv *inventory.Inventory) []store.Obs {
	seen := map[string]bool{}
	var obs []store.Obs
	for _, h := range inv.ProviderHosts(sc) {
		if h.Evidence != "cname" || h.Entry.Class != provider.ClassSaaS {
			continue
		}
		root := sc.RootOf(h.Hostname)
		if root == "" {
			continue
		}
		o := kinds.ThirdPartyObs(root, kinds.MechanismCNAME, h.Entry.Suffix, 0)
		if seen[o.Key] {
			continue
		}
		seen[o.Key] = true
		obs = append(obs, o)
	}
	return obs
}
