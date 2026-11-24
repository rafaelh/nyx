package kinds

// WebIdentifier stores a tracking ID, favicon hash or root-page copyright line for related-site
// discovery. Keys use "<service>|<type>|<value>". Probe and crawl observations merge normally,
// keeping an identifier current while either sees it. Visibility follows the host's scope.
var WebIdentifier = defineJoined(Kind{Name: "web_identifier", HostAttr: "host"},
	func(a *WebIdentifierAttrs) []*string { return []*string{&a.Service, &a.Type, &a.Value} })

// The types of web identifier.
const (
	IdentifierAnalytics = "analytics" // a Google Analytics or Tag Manager ID
	IdentifierPixel     = "pixel"     // a Facebook pixel ID
	IdentifierFavicon   = "favicon"   // the Shodan favicon hash, as a decimal integer
	IdentifierCopyright = "copyright" // the first copyright line of the root page
)

// WebIdentifierAttrs identifies the service origin, host, identifier type and value.
type WebIdentifierAttrs struct {
	Service string `json:"service"`
	Host    string `json:"host"`
	Type    string `json:"type"`
	Value   string `json:"value"`
}
