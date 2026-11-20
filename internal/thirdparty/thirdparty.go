// Package thirdparty derives third-party records from other records. It is pure
// knowledge: it reads a scope and an inventory and does no I/O.
package thirdparty

import (
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

// CNAME derives the third parties that in-scope hostnames are served by: for
// each in-scope hostname that does not answer only because of a wildcard, and
// each provider entry of class SaaS at any hop of its CNAME chain, one record
// per root and entry suffix (github.io, myshopify.com). The root is the most
// specific input root that covers the name (Scope.RootOf). Names that are
// excluded or only candidates are never listed, nor is a chain on which no
// SaaS entry appears (one that reaches only a CDN or a cloud service).
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
