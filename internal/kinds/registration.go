package kinds

// Registration identifies a registry allocation by "<registry>|<handle>", allowing addresses in
// the same allocation to share one record.
var Registration = defineJoined(Kind{Name: "registration"},
	func(a *RegistrationAttrs) []*string { return []*string{&a.Registry, &a.Handle} })

// RegistrationAttrs stores range endpoints, registrant, registry, allocation handle and the
// address looked up. Registrant is empty when absent; registry is arin, ripe, apnic, lacnic or
// afrinic.
type RegistrationAttrs struct {
	Start      string `json:"start"`
	End        string `json:"end"`
	Registrant string `json:"registrant"`
	Registry   string `json:"registry"`
	Handle     string `json:"handle"`
	Asked      string `json:"asked"`
}
