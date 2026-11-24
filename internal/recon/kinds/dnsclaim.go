package kinds

// DNSClaim records a third party's reported DNS answer. It appears in resolutions.csv but
// cannot establish resolution, scope or permission to contact a target; those use nyx's own
// Resolution records.
var DNSClaim = defineJoined(Kind{Name: "dns_claim", Change: "resolution"},
	func(a *DNSClaimAttrs) []*string { return []*string{&a.Name, &a.Type, &a.Value} })

// DNSClaimAttrs describes a reported A, AAAA, CNAME, MX or NS answer and its source. Keys use
// "name|TYPE|value", matching Resolution keys.
type DNSClaimAttrs struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	Source string `json:"source"`
}
