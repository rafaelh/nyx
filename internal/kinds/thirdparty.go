package kinds

import (
	"strings"

	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/store"
)

// ThirdParty is an organisation the engagement's roots depend on or have
// verified ownership with, and how that was seen (the mechanism). It is shown
// while its root is in scope and, when it names a domain, only while that
// domain is not: a name server inside the scope is a host to examine, not a
// third party.
var ThirdParty = define[ThirdPartyAttrs](Kind{
	Name: "third_party", Singular: "third party", Category: "third parties", Printed: true,
	HostAttr: "root", OutsideAttr: "domain", Found: thirdPartyFound,
})

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

// ThirdPartyAttrs: the root that depends on it, how it was seen, the domain
// (for a name server, its registrable domain; empty for a TXT verification,
// whose token never leaves resolutions.csv), the provider when it is known and
// how many hops from the root it was found at (0 for the root's own records).
// A record's key is "<root>|<mechanism>|<name>". For spf and dmarc the domain is
// kept as written (_spf.google.com); for mx and srv it is the host's registrable
// domain, and for cname the suffix of the SaaS platform's names.
type ThirdPartyAttrs struct {
	Root      string `json:"root"`
	Mechanism string `json:"mechanism"`
	Domain    string `json:"domain,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Depth     int    `json:"depth"`
}

// Platform is the name a third party is announced and listed by: its provider
// when known, otherwise its domain.
func (a ThirdPartyAttrs) Platform() string {
	if a.Provider != "" {
		return a.Provider
	}
	return a.Domain
}

// ThirdPartyKey is the key of a third-party record: "<root>|<mechanism>|<name>",
// where the name is the domain, or the platform of a TXT verification.
func ThirdPartyKey(root, mechanism, name string) string {
	return root + "|" + mechanism + "|" + name
}

// ThirdPartyOf decodes a third party's attributes, filling in from its key what
// a record that is no longer current has lost: the store keeps attributes only
// from current observations, but the key says the root, the mechanism and the
// name (the domain of a name server, service target, mail or SaaS dependency, the
// platform of a verification). The depth is not in the key, so it shows 0.
func ThirdPartyOf(r store.Record) ThirdPartyAttrs {
	a := ThirdParty.Attrs(r)
	parts := strings.SplitN(r.Key, "|", 3)
	if len(parts) != 3 {
		return a
	}
	if a.Root == "" {
		a.Root = parts[0]
	}
	if a.Mechanism == "" {
		a.Mechanism = parts[1]
	}
	switch a.Mechanism {
	case MechanismTXTVerification:
		if a.Provider == "" {
			a.Provider = parts[2]
		}
	default:
		if a.Domain == "" {
			a.Domain = parts[2]
		}
		if a.Provider == "" {
			a.Provider, _ = provider.Default().DomainOwner(a.Domain)
		}
	}
	return a
}

func thirdPartyFound(r store.Record) map[string]any {
	var a ThirdPartyAttrs
	decode(r.Attrs, &a) // not ThirdParty.Attrs: ThirdParty refers to this function
	return map[string]any{"platform": a.Platform(), "mechanism": a.Mechanism, "root": a.Root,
		"text": "third-party " + a.Platform() + " via " + a.Mechanism + " on " + a.Root}
}
