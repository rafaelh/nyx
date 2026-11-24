package kinds

// ShodanNetblock is the outcome of one netblock search, keyed by the CIDR.
var ShodanNetblock = define[ShodanNetblockAttrs](Kind{Name: "shodan_netblock"})

// ShodanNetblockAttrs records whether the page cap left results unread, potentially missing
// addresses in the block.
type ShodanNetblockAttrs struct {
	Truncated bool `json:"truncated"`
}
