package kinds

import (
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/scope"
)

// Organisation is a registrant name a registry gave for an address, keyed by
// the name as the registry gives it. It is a candidate only while the rule of
// Inventory.RegistrantCandidate holds, and the --org input that promotes it
// searches the registries for the organisation's own netblocks. Otherwise it
// stays on record and is not listed.
var Organisation = defineBare(Kind{Name: "organisation", Singular: "organisation", place: placeOrganisation})

// placeOrganisation places an organisation in scope when it matches an --org
// input, and as a candidate while Inventory.RegistrantCandidate holds.
func placeOrganisation(sc *scope.Scope, inv *inventory.Inventory, key string) (scope.Class, bool) {
	switch {
	case sc.MatchesOrg(key):
		return scope.InScope, true
	case inv.RegistrantCandidate(sc, key):
		return scope.Candidate, true
	}
	return 0, false
}
