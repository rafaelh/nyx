package kinds

// DNSClaim is a DNS record a third party says exists, as opposed to a Resolution,
// which nyx's own lookup found. It is a separate kind so that no reader of
// resolutions (the inventory, the scope, the egress policy) can mistake one for
// the other: a claim is shown in resolutions.csv and decides nothing.
var DNSClaim = defineJoined(Kind{Name: "dns_claim", Change: "resolution"},
	func(a *DNSClaimAttrs) []*string { return []*string{&a.Name, &a.Type, &a.Value} })

// DNSClaimAttrs: one A, AAAA, CNAME, MX or NS record and who reported it. The
// record's key is "name|TYPE|value", the same as a Resolution of the record.
type DNSClaimAttrs struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}
