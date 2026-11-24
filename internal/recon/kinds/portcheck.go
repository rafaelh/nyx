package kinds

// PortCheck records nyx's result for a third-party-reported port it did not find open, keyed by
// address and port.
var PortCheck = define[PortCheckAttrs](Kind{Name: "port_check"})

// The port_check results.
const (
	PortClosed = "closed" // the connection was rejected
	PortSilent = "silent" // nothing answered within the connect timeout
)

// PortCheckAttrs: Result is PortClosed or PortSilent.
type PortCheckAttrs struct {
	Result string `json:"result"`
}
