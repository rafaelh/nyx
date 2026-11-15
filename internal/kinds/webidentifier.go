package kinds

// WebIdentifier is one identifier found on the pages of a web service that can
// be pivoted on to related sites: a tracking ID, the hash of the favicon, or
// the copyright line of the root page. Each identifier is a record of its own,
// keyed "<service>|<type>|<value>", so the union over the pages the probe and
// the crawl fetched is the store's ordinary merge: each stage observes what it
// saw, and an identifier stays current while either still sees it. A record is
// shown while its host is in scope.
var WebIdentifier = define[WebIdentifierAttrs](Kind{Name: "web_identifier", HostAttr: "host"})

// The types of web identifier.
const (
	IdentifierAnalytics = "analytics" // a Google Analytics or Tag Manager ID
	IdentifierPixel     = "pixel"     // a Facebook pixel ID
	IdentifierFavicon   = "favicon"   // the Shodan favicon hash, as a decimal integer
	IdentifierCopyright = "copyright" // the first copyright line of the root page
)

// WebIdentifierAttrs: Service is the web service's origin (the web_service
// key), Host its host, Type one of the Identifier constants and Value the
// identifier.
type WebIdentifierAttrs struct {
	Service string `json:"service"`
	Host    string `json:"host"`
	Type    string `json:"type"`
	Value   string `json:"value"`
}
