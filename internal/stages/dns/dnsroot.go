package dns

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/stages/serveraddr"
)

// DNSRoot records the NS, SOA, TXT and CAA records of each in-scope input
// root, so later pivots can use them, and from them the third parties the root
// depends on: its name servers' operators, and the SaaS platforms its TXT
// records show domain ownership was verified with. It also asks for a fixed
// list of SRV names under the root (mail, identity, voice, collaboration and
// game services), as one more check per root. It asks the same public
// resolvers as resolve and never attempts a zone transfer.
//
// The NS check also looks up its name servers' addresses (serveraddr), for
// inventory.SelfHosted only; its key ends serveraddr.KeyToken.
type DNSRoot struct{ base }

// NewDNSRoot returns the dnsroot stage.
func NewDNSRoot() *DNSRoot { return &DNSRoot{base{"dnsroot"}} }

// rootTypes are the record types asked of each root, one check each, so a type
// that keeps failing never blocks the others.
type rootType struct {
	name string
	code uint16
}

var rootTypes = []rootType{
	{"NS", egress.TypeNS}, {"SOA", egress.TypeSOA}, {"TXT", egress.TypeTXT}, {"CAA", egress.TypeCAA},
}

type rootInput struct {
	root string
	t    rootType
	sc   *scope.Scope
}

// srvServices are the SRV names asked under each root. Editing the list changes
// srvKeyToken, so the SRV check is repeated and no other.
var srvServices = []string{
	"_sip._tls", "_sip._tcp", "_sipfederationtls._tcp", "_autodiscover._tcp", "_ldap._tcp",
	"_kerberos._tcp", "_xmpp-server._tcp", "_xmpp-client._tcp", "_caldav._tcp", "_carddav._tcp",
	"_imaps._tcp", "_submission._tcp", "_matrix._tcp", "_minecraft._tcp",
}

// srvKeyToken identifies the service list, so a changed list creates a new check.
var srvKeyToken = config.ListHash(srvServices)

// srvType is the type of a root's SRV check, which asks every name of
// srvServices rather than the root itself.
var srvType = rootType{"SRV", egress.TypeSRV}

// Checks yields one check per input root that is in scope and per record type,
// keyed "<root>|<TYPE>", and the root's SRV check, keyed "<root>|SRV|<hash of
// the service list>". SRV is not a row of rootTypes: its check makes one query
// per service name.
func (*DNSRoot) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, root := range v.InScopeRoots() {
			for _, t := range rootTypes {
				key := root + "|" + t.name
				if t.name == "NS" {
					key += serveraddr.KeyToken
				}
				c := run.Check{Key: key, Input: rootInput{root, t, v.Scope()}}
				if !yield(c, nil) {
					return
				}
			}
			if !yield(run.Check{Key: root + "|SRV|" + srvKeyToken, Input: rootInput{root, srvType, v.Scope()}}, nil) {
				return
			}
		}
	}
}

// Run queries one type of one root. NODATA and NXDOMAIN complete the check with
// no observations; SERVFAIL is a transient failure of this type only.
func (*DNSRoot) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(rootInput)
	if in.t == srvType {
		return runSRV(ctx, in, e)
	}
	res, err := lookup(ctx, e, in.root, in.t.code)
	if err != nil {
		return nil, err
	}
	if res.RCode == egress.RCodeServFail {
		return nil, fmt.Errorf("%s %s: resolver answered SERVFAIL", in.root, in.t.name)
	}
	var obs []run.Observation
	var servers []string // the name servers of an NS answer
	for _, a := range res.Answers {
		if a.Type != in.t.name || a.Value == "" {
			continue
		}
		// A root that is an alias has no name servers or SOA of its own: an
		// answer for its alias target's zone says nothing about the root.
		if (in.t.name == "NS" || in.t.name == "SOA") && a.Name != in.root {
			continue
		}
		obs = append(obs, kinds.Resolution.Obs(in.root+"|"+in.t.name+"|"+a.Value,
			kinds.ResolutionAttrs{Name: in.root, Type: in.t.name, Value: a.Value}))
		switch in.t.name {
		case "NS":
			servers = append(servers, a.Value)
			obs = append(obs, dependency(in, kinds.MechanismNS, a.Value)...)
		case "SOA":
			primary, _, _ := strings.Cut(a.Value, " ")
			obs = append(obs, dependency(in, "", primary)...) // an SOA primary outside the scope adds nothing
		case "TXT":
			if platform, ok := provider.Default().Verification(a.Value); ok {
				obs = append(obs, kinds.ThirdParty.Obs(kinds.ThirdPartyKey(in.root, kinds.MechanismTXTVerification, platform),
					kinds.ThirdPartyAttrs{Root: in.root, Mechanism: kinds.MechanismTXTVerification, Provider: platform}))
			}
		}
	}
	slices.Sort(servers)
	for _, host := range slices.Compact(servers) {
		addrs, err := serveraddr.Observations(ctx, e, in.sc, host)
		if err != nil {
			return nil, err
		}
		obs = append(obs, addrs...)
	}
	return obs, nil
}

// dependency is what a host a root's records name (an NS or SRV target, or an
// SOA primary) adds: an in-scope name is a hostname, resolved and probed like
// any other. Any other is a third party seen through mechanism, recorded by its
// registrable domain and never as a candidate; with no mechanism it adds nothing.
func dependency(in rootInput, mechanism, host string) []run.Observation {
	if host == "" {
		return nil
	}
	if in.sc.ClassifyHost(host).Class == scope.InScope {
		return []run.Observation{kinds.Hostname.Obs(host, kinds.HostnameAttrs{})}
	}
	if mechanism == "" {
		return nil
	}
	domain := dnsname.Registrable(host)
	owner, _ := provider.Default().DomainOwner(domain)
	return []run.Observation{kinds.ThirdParty.Obs(kinds.ThirdPartyKey(in.root, mechanism, domain),
		kinds.ThirdPartyAttrs{Root: in.root, Mechanism: mechanism, Domain: domain, Provider: owner})}
}

// runSRV asks each listed service name under the root. NXDOMAIN and NODATA are
// results; a SERVFAIL or a timeout on any name fails the whole check, so the
// next run asks them all again.
func runSRV(ctx context.Context, in rootInput, e egress.Clients) ([]run.Observation, error) {
	var obs []run.Observation
	for _, service := range srvServices {
		name := service + "." + in.root
		res, err := lookup(ctx, e, name, egress.TypeSRV)
		if err != nil {
			return nil, err
		}
		if res.RCode == egress.RCodeServFail {
			return nil, fmt.Errorf("%s SRV: resolver answered SERVFAIL", name)
		}
		for _, a := range res.Answers {
			if a.Type != "SRV" {
				continue
			}
			_, target, ok := dnsname.SRV(a.Value)
			if !ok { // "." is a service that is not offered
				continue
			}
			// The name is a service name, not a hostname: only A, AAAA and CNAME
			// rows reach the inventory, so it is never resolved or tested as a wildcard zone.
			obs = append(obs, kinds.Resolution.Obs(name+"|SRV|"+a.Value,
				kinds.ResolutionAttrs{Name: name, Type: "SRV", Value: a.Value}))
			obs = append(obs, dependency(in, kinds.MechanismSRV, target)...)
		}
	}
	return obs, nil
}
