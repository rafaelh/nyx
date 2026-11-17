package kinds

// Origin exposure evidence. Neither kind is counted, and neither is read by anything that decides
// what may be contacted: the findings package derives origin-exposure findings from them.

// HistoricalAddress is an address a hostname resolved to in the past, from a passive DNS history. It
// is shown while its host is in scope. It is never a current address: the scope, the inventory and
// the wildcard check read resolution records only.
var HistoricalAddress = define[HistoricalAddressAttrs](Kind{Name: "historical_address", HostAttr: "host"})

// HistoricalAddressAttrs: the hostname, the address, the record type ("A" or "AAAA";
// resolutions.csv shows it as "A-historical" or "AAAA-historical") and the dates (YYYY-MM-DD) the source first and last saw the
// pair. The dates are blank when the source gave none.
type HistoricalAddressAttrs struct {
	Host      string `json:"host"`
	Addr      string `json:"addr"`
	Type      string `json:"type"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// OriginCheck is what one GET of "/" to a candidate origin address, with a hostname behind a CDN or
// WAF as the server name and Host header, answered. Its key is "<host>|<address>".
var OriginCheck = define[OriginCheckAttrs](Kind{Name: "origin_check", HostAttr: "host"})

// OriginCheckAttrs: the scheme that answered ("https" or "http"), the response's status, its title
// and body length, and whether the certificate it presented names the host (always false for http).
// No field is omitted when empty, so a later check replaces what an earlier one stored.
type OriginCheckAttrs struct {
	Host          string `json:"host"`
	Addr          string `json:"addr"`
	Scheme        string `json:"scheme"`
	Status        int    `json:"status"`
	Title         string `json:"title"`
	BodyLen       int    `json:"body_len"`
	CertNamesHost bool   `json:"cert_names_host"`
}
