package kinds

import (
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/scope"
)

// ASN records an autonomous system found by an organisation search, keyed "AS<n>". It stays a
// candidate until supplied with --asn, which also brings its announced netblocks into scope.
var ASN = define[ASNAttrs](Kind{Name: "asn", Singular: "asn", place: placeASN})

// placeASN recognises input ASNs; other ASNs remain candidates.
func placeASN(sc *scope.Scope, _ *inventory.Inventory, key string) (scope.Class, bool) {
	if sc.HasASN(key) {
		return scope.InScope, true
	}
	return scope.Candidate, true
}

// ASNAttrs identifies the searched organisation, the registry's registrant name and the
// registry.
type ASNAttrs struct {
	Org        string `json:"org,omitempty"`
	Registrant string `json:"registrant,omitempty"`
	Registry   string `json:"registry,omitempty"`
}
