package kinds

// ServerAddress supports ownership checks for out-of-scope name servers and mail hosts. It
// cannot make a server resolved, probeable or port-eligible. Keys use "<host>|<address>".
var ServerAddress = defineJoined(Kind{Name: "server_address"},
	func(a *ServerAddressAttrs) []*string { return []*string{&a.Host, &a.Addr} })

// ServerAddressAttrs: the server's name and one of its addresses.
type ServerAddressAttrs struct {
	Host string `json:"host"`
	Addr string `json:"addr"`
}
