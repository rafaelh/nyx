package kinds

// Origin evidence supports findings without affecting counts or permission to contact targets.

// HistoricalAddress records a past DNS address for an in-scope host. It never counts as a
// current resolution for scope, inventory or wildcard checks.
var HistoricalAddress = defineJoined(Kind{Name: "historical_address", HostAttr: "host", Change: "historical address"},
	func(a *HistoricalAddressAttrs) []*string { return []*string{&a.Host, &a.Type, &a.Addr} })

// HistoricalAddressAttrs identifies a host, address and A/AAAA type, plus optional first/last
// observation dates. resolutions.csv adds "-historical" to the type. Keys use
// "<host>|<type>|<address>".
type HistoricalAddressAttrs struct {
	Host      string `json:"host"`
	Addr      string `json:"addr"`
	Type      string `json:"type"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// OriginCheck records a GET / response from a candidate origin, using the CDN/WAF hostname for
// SNI and Host. Keys use "<host>|<address>".
var OriginCheck = defineJoined(Kind{Name: "origin_check", HostAttr: "host"},
	func(a *OriginCheckAttrs) []*string { return []*string{&a.Host, &a.Addr} })

// OriginCheckAttrs holds the responding scheme, status, title, body length and certificate-name
// match. HTTP has no certificate match. Zero values are stored so later jobs replace earlier
// results completely.
type OriginCheckAttrs struct {
	Host          string `json:"host"`
	Addr          string `json:"addr"`
	Scheme        string `json:"scheme"`
	Status        int    `json:"status"`
	Title         string `json:"title"`
	BodyLen       int    `json:"body_len"`
	CertNamesHost bool   `json:"cert_names_host"`
}
