package kinds

// Registration is the registry's record of a netblock: who it is registered to.
// It is keyed "<registry>|<handle>", by the registry and the registry's handle
// for the range, so every address inside it shares one record.
var Registration = defineJoined(Kind{Name: "registration"},
	func(a *RegistrationAttrs) []*string { return []*string{&a.Registry, &a.Handle} })

// RegistrationAttrs: the first and last address of the registered range, the
// registrant's name as the registry gives it (empty when it names none), the
// registry ("arin", "ripe", "apnic", "lacnic" or "afrinic"), the registry's handle
// for the range and the address whose lookup returned it.
type RegistrationAttrs struct {
	Start      string `json:"start"`
	End        string `json:"end"`
	Registrant string `json:"registrant"`
	Registry   string `json:"registry"`
	Handle     string `json:"handle"`
	Asked      string `json:"asked"`
}
