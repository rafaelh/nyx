package kinds

import "github.com/rafaelh/nyx/internal/knowledge/weburl"

// WebIdentifier stores a tracking ID, favicon hash or root-page copyright line for related-site
// discovery. Keys use "<service>|<type>|<value>". Probe and crawl observations merge normally,
// keeping an identifier current while either sees it. Visibility follows the host's scope; the key
// does not carry the host, so a non-current record takes it from the service origin.
var WebIdentifier = defineKeyed(Kind{Name: "web_identifier", HostAttr: "host"},
	func(a WebIdentifierAttrs) string { return joinFields(webIdentifierFields(&a)) },
	func(key string, a *WebIdentifierAttrs) {
		fillFromKey(key, webIdentifierFields(a)...)
		if a.Host == "" {
			a.Host = weburl.HostOfURL(a.Service)
		}
	})

func webIdentifierFields(a *WebIdentifierAttrs) []*string {
	return []*string{&a.Service, &a.Type, &a.Value}
}

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
