package kinds

// Organisation is a registrant name a registry gave for an address, keyed by
// the name as the registry gives it. It is a candidate only while the rule of
// Inventory.RegistrantCandidate holds, and the --org input that promotes it
// searches the registries for the organisation's own netblocks. Otherwise it
// stays on record and is not listed.
var Organisation = defineBare(Kind{Name: "organisation", Singular: "organisation", Category: Candidates, Entity: true})
