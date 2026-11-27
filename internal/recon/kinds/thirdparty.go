package kinds

import (
	"strings"

	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/recon/store"
)

// ThirdParty records a root's external dependency or ownership verification and its mechanism.
// It is visible while the root is in scope and any named domain is outside scope; internal name
// servers are treated as hosts instead.
var ThirdParty = defineKeyed(Kind{
	Name: "third_party", Singular: "third party", Category: "third parties", Printed: true,
	HostAttr: "root", OutsideAttr: "domain", Found: thirdPartyFound, Change: "third party",
}, thirdPartyKey, rebuildThirdParty)

// Mechanisms of a third party.
const (
	MechanismNS              = "ns"
	MechanismTXTVerification = "txt-verification"
	MechanismSPF             = "spf"
	MechanismDMARC           = "dmarc"
	MechanismMX              = "mx"
	MechanismCNAME           = "cname"
	MechanismSRV             = "srv"
)

// ThirdPartyAttrs identifies the root, mechanism, external domain, provider and hop depth. TXT
// verifications omit the domain and keep tokens only in resolutions.csv, and so does a dependency
// on a provider that uses many registrable domains (provider.Family), which is one record however
// many of its domains the root names. Keys use "<root>|<mechanism>|<name>". SPF/DMARC retain exact
// domains, MX/SRV/NS use registrable domains, and CNAME uses the platform's suffix or, for a
// platform no entry lists, its registrable domain.
type ThirdPartyAttrs struct {
	Root      string `json:"root"`
	Mechanism string `json:"mechanism"`
	Domain    string `json:"domain,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Depth     int    `json:"depth"`
}

// Platform returns the provider name for display, falling back to the domain.
func (a ThirdPartyAttrs) Platform() string {
	if a.Provider != "" {
		return a.Provider
	}
	return a.Domain
}

// thirdPartyKey uses "<root>|<mechanism>|<name>". name is the dependency domain or, for a record
// with none (a TXT verification or a provider family), the provider.
func thirdPartyKey(a ThirdPartyAttrs) string {
	name := a.Domain
	if a.Mechanism == MechanismTXTVerification || name == "" {
		name = a.Provider
	}
	return strings.Join([]string{a.Root, a.Mechanism, name}, "|")
}

// rebuildThirdParty recovers the root, mechanism and domain/provider from non-current records'
// keys. Known domains regain their provider label. Depth is not encoded, so it remains zero.
func rebuildThirdParty(key string, a *ThirdPartyAttrs) {
	var name string
	fillFromKey(key, &a.Root, &a.Mechanism, &name)
	switch {
	case a.Mechanism == MechanismTXTVerification || provider.Default().IsFamily(name):
		if a.Provider == "" {
			a.Provider = name
		}
	default:
		if a.Domain == "" {
			a.Domain = name
		}
		if a.Provider == "" {
			a.Provider, _ = provider.Default().DomainOwner(a.Domain)
		}
	}
}

// ThirdPartyObs describes a domain dependency at the given hop depth, adding its known
// provider. A domain of a provider family is recorded by the provider alone. Use ThirdParty.Obs
// directly for domainless TXT verifications.
func ThirdPartyObs(root, mechanism, domain string, depth int) store.Obs {
	if family, ok := provider.Default().Family(domain); ok {
		return ThirdParty.Obs(ThirdPartyAttrs{Root: root, Mechanism: mechanism, Provider: family, Depth: depth})
	}
	owner, _ := provider.Default().DomainOwner(domain)
	return ThirdParty.Obs(ThirdPartyAttrs{Root: root, Mechanism: mechanism, Domain: domain, Provider: owner, Depth: depth})
}

func thirdPartyFound(r store.Record) map[string]any {
	var a ThirdPartyAttrs
	decode(r.Attrs, &a) // not ThirdParty.Attrs: ThirdParty refers to this function
	return map[string]any{"platform": a.Platform(), "mechanism": a.Mechanism, "root": a.Root,
		"text": "third-party " + a.Platform() + " via " + a.Mechanism + " on " + a.Root}
}
