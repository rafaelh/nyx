package kinds

// TextHostname remembers a hostname taken from the text of a web service's responses (its probe,
// its crawl and the scripts it serves), so that the number of names one service gives is capped
// across the engagement. Keys use "<service>|<name>". One is written beside each hostname
// observation of a name taken from a web service's text. It has no output file, no summary
// category and no change label; it is shown only while the name is in scope.
var TextHostname = defineJoined(Kind{Name: "text_hostname", HostAttr: "name"},
	func(a *TextHostnameAttrs) []*string { return []*string{&a.Service, &a.Name} })

// TextHostnameAttrs names the service origin whose responses named a hostname, and the name.
type TextHostnameAttrs struct {
	Service string `json:"service"`
	Name    string `json:"name"`
}
