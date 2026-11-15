package kinds

// ASN is an autonomous system an organisation search found, keyed "AS<n>". It
// is a candidate for as long as the ASN is not an input, and the --asn input
// that promotes it brings its announced netblocks into scope.
var ASN = define[ASNAttrs](Kind{Name: "asn", Singular: "asn", Category: Candidates, Entity: true})

// ASNAttrs: the organisation input the search was for, the registrant name the
// registry holds for the system, and the registry.
type ASNAttrs struct {
	Org        string `json:"org,omitempty"`
	Registrant string `json:"registrant,omitempty"`
	Registry   string `json:"registry,omitempty"`
}
