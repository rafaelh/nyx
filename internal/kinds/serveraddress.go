package kinds

// ServerAddress is an address looked up for a name server or mail host that is
// outside the scope, so that it can be told whether the organisation runs the
// server itself. It exists only for that: nothing that decides what is resolved,
// probed or port-checked reads it, so a looked-up server never becomes any of them
// because of it. A record's key is "<host>|<address>".
var ServerAddress = defineJoined(Kind{Name: "server_address"},
	func(a *ServerAddressAttrs) []*string { return []*string{&a.Host, &a.Addr} })

// ServerAddressAttrs: the server's name and one of its addresses.
type ServerAddressAttrs struct {
	Host string `json:"host"`
	Addr string `json:"addr"`
}
