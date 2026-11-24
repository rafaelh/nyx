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
	"github.com/rafaelh/nyx/internal/serveraddr"
)

// DNSRoot collects each in-scope input root's NS, SOA, TXT and CAA records for later pivots,
// plus external DNS/TXT-verification dependencies. A separate check queries a fixed SRV service
// list. All queries use public resolvers without zone transfers. NS checks also collect server
// addresses solely for SelfHosted decisions; serveraddr.KeyToken versions that work.
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

// srvType selects the multi-name SRV check rather than a root-level query.
var srvType = rootType{"SRV", egress.TypeSRV}

// Checks emits root/type checks and one root/SRV check. SRV keys include the service-list hash
// because that check queries several names rather than one record type at the root.
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

// Run completes empty for NXDOMAIN/NODATA. SERVFAIL retries only this root/type check.
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
		// An aliased root has no NS/SOA of its own; its target zone's records cannot
		// establish the root's dependencies.
		if (in.t.name == "NS" || in.t.name == "SOA") && a.Name != in.root {
			continue
		}
		obs = append(obs, kinds.Resolution.Obs(kinds.ResolutionAttrs{Name: in.root, Type: in.t.name, Value: a.Value}))
		switch in.t.name {
		case "NS":
			servers = append(servers, a.Value)
			obs = append(obs, dependency(in, kinds.MechanismNS, a.Value)...)
		case "SOA":
			primary, _, _ := strings.Cut(a.Value, " ")
			obs = append(obs, dependency(in, "", primary)...) // an SOA primary outside the scope adds nothing
		case "TXT":
			if platform, ok := provider.Default().Verification(a.Value); ok {
				obs = append(obs, kinds.ThirdParty.Obs(
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

// dependency records internal NS/SRV/SOA targets as hostnames for normal resolution. External
// targets become registrable-domain third parties when a mechanism is supplied; they never
// become candidates here.
func dependency(in rootInput, mechanism, host string) []run.Observation {
	if host == "" {
		return nil
	}
	if in.sc.HostInScope(host) {
		return []run.Observation{kinds.Hostname.Obs(host, kinds.HostnameAttrs{})}
	}
	if mechanism == "" {
		return nil
	}
	return []run.Observation{kinds.ThirdPartyObs(in.root, mechanism, dnsname.Registrable(host), 0)}
}

// runSRV treats NXDOMAIN/NODATA as results. A transient failure on any service name fails the
// whole check so all names are retried next run.
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
			// SRV service names are not hostnames. Only A/AAAA/CNAME answers feed
			// resolution and wildcard-zone discovery.
			obs = append(obs, kinds.Resolution.Obs(kinds.ResolutionAttrs{Name: name, Type: "SRV", Value: a.Value}))
			obs = append(obs, dependency(in, kinds.MechanismSRV, target)...)
		}
	}
	return obs, nil
}
