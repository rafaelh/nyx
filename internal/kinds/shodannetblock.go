package kinds

// ShodanNetblock is the outcome of one netblock search, keyed by the CIDR.
var ShodanNetblock = define[ShodanNetblockAttrs](Kind{Name: "shodan_netblock"})

// ShodanNetblockAttrs: whether the search stopped at its page cap with matches
// left unread, so addresses inside the block may be missing from it.
type ShodanNetblockAttrs struct {
	Truncated bool `json:"truncated"`
}
