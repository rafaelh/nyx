package kinds

import (
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/scope"
)

// ASN is an autonomous system an organisation search found, keyed "AS<n>". It
// is a candidate for as long as the ASN is not an input, and the --asn input
// that promotes it brings its announced netblocks into scope.
var ASN = define[ASNAttrs](Kind{Name: "asn", Singular: "asn", place: placeASN})

// placeASN places an ASN in scope when it is an input, and as a candidate
// otherwise.
func placeASN(sc *scope.Scope, _ *inventory.Inventory, key string) (scope.Class, bool) {
	if sc.HasASN(key) {
		return scope.InScope, true
	}
	return scope.Candidate, true
}

// ASNAttrs: the organisation input the search was for, the registrant name the
// registry holds for the system, and the registry.
type ASNAttrs struct {
	Org        string `json:"org,omitempty"`
	Registrant string `json:"registrant,omitempty"`
	Registry   string `json:"registry,omitempty"`
}
