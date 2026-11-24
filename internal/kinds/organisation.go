package kinds

import (
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/scope"
)

// Organisation records a registry's registrant name. It is listed as a candidate only when
// Inventory.RegistrantCandidate qualifies it. Adding --org promotes it and enables registry
// searches for its netblocks; other names remain stored but unlisted.
var Organisation = defineBare(Kind{Name: "organisation", Singular: "organisation", place: placeOrganisation})

// placeOrganisation checks --org inputs first, then Inventory.RegistrantCandidate.
func placeOrganisation(sc *scope.Scope, inv *inventory.Inventory, key string) (scope.Class, bool) {
	switch {
	case sc.MatchesOrg(key):
		return scope.InScope, true
	case inv.RegistrantCandidate(sc, key):
		return scope.Candidate, true
	}
	return 0, false
}
