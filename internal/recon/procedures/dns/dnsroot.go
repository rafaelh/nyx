package dns

import (
	"context"
	"fmt"
	"iter"
	"slices"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/procedures/serveraddr"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// DNSRoot collects each in-scope input root's NS, SOA, TXT, CAA and MX records for later pivots,
// plus external DNS/TXT-verification dependencies. A separate job queries a fixed SRV service
// list. All queries use public resolvers without zone transfers. NS jobs also collect server
// addresses solely for SelfHosted decisions; serveraddr.KeyToken versions that work. The records
// become observations through the handler dnsrecords shares, and only records the root owns are
// kept.
type DNSRoot struct{ recordProcedure }

// NewDNSRoot returns the dnsroot procedure.
func NewDNSRoot() *DNSRoot { return &DNSRoot{recordProcedure{base{"dnsroot"}}} }

// rootType is a record type asked of a name, one job each, so a type that keeps failing never
// blocks the others.
type rootType struct {
	name string
	code uint16
}

var (
	nsType  = rootType{"NS", egress.TypeNS}
	soaType = rootType{"SOA", egress.TypeSOA}
	txtType = rootType{"TXT", egress.TypeTXT}
	caaType = rootType{"CAA", egress.TypeCAA}
	mxType  = rootType{"MX", egress.TypeMX}
)

// rootTypes are the record types asked of each root.
var rootTypes = []rootType{nsType, soaType, txtType, caaType, mxType}

// srvServices are the SRV names asked under each root and delegated zone. Editing the list
// changes srvKeyToken, so the SRV jobs are repeated and no other.
var srvServices = []string{
	"_sip._tls", "_sip._tcp", "_sipfederationtls._tcp", "_autodiscover._tcp", "_ldap._tcp",
	"_kerberos._tcp", "_xmpp-server._tcp", "_xmpp-client._tcp", "_caldav._tcp", "_carddav._tcp",
	"_imaps._tcp", "_submission._tcp", "_matrix._tcp", "_minecraft._tcp",
}

// srvKeyToken identifies the service list, so a changed list creates a new job.
var srvKeyToken = config.ListHash(srvServices)

// srvType selects the multi-name SRV job rather than a single query.
var srvType = rootType{"SRV", egress.TypeSRV}

// Jobs emits root/type jobs and one root/SRV job. SRV keys include the service-list hash
// because that job queries several names rather than one record type at the root. A root's spf
// and mx third parties are email's, which filters them its own way, so its jobs write none.
func (*DNSRoot) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		for _, root := range v.InScopeRoots() {
			in := recordInput{name: root, root: root, sc: v.Scope(), shared: v.SharedAddr, mxByEmail: true, servFailFails: true}
			for _, t := range rootTypes {
				key := root + "|" + t.name
				if t == nsType {
					key += serveraddr.KeyToken
				}
				in.t = t
				if !yield(run.Job{Key: key, Input: in}, nil) {
					return
				}
			}
			in.t = srvType
			if !yield(run.Job{Key: root + "|SRV|" + srvKeyToken, Input: in}, nil) {
				return
			}
		}
	}
}

// Run completes empty for NXDOMAIN/NODATA. SERVFAIL retries only this root/type job.
func (*DNSRoot) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(recordInput)
	obs, servers, err := runRecord(ctx, in, e)
	if err != nil || in.t != nsType {
		return obs, err
	}
	slices.Sort(servers) // the root's own name servers
	for _, host := range slices.Compact(servers) {
		addrs, err := serveraddr.Observations(ctx, e, in.sc, host)
		if err != nil {
			return nil, err
		}
		obs = append(obs, addrs...)
	}
	return obs, nil
}

// runSRV treats NXDOMAIN/NODATA as results, and SERVFAIL too unless the input says it fails. A
// transient failure on any service name fails the whole job so all names are retried next run.
func runSRV(ctx context.Context, in recordInput, e egress.Clients) ([]run.Observation, error) {
	var obs []run.Observation
	for _, service := range srvServices {
		name := service + "." + in.name
		res, err := lookup(ctx, e, name, egress.TypeSRV)
		if err != nil {
			return nil, err
		}
		if res.RCode == egress.RCodeServFail {
			if in.servFailFails {
				return nil, fmt.Errorf("%s SRV: resolver answered SERVFAIL", name)
			}
			continue
		}
		for _, a := range res.Answers {
			if a.Type != "SRV" || a.Name != name { // an alias's answer carries its target's records
				continue
			}
			_, target, ok := dnsname.SRV(a.Value)
			if !ok { // "." is a service that is not offered
				continue
			}
			// SRV service names are not hostnames. Only A/AAAA/CNAME answers feed
			// resolution and wildcard-zone discovery.
			obs = append(obs, kinds.Resolution.Obs(kinds.ResolutionAttrs{Name: name, Type: "SRV", Value: a.Value}))
			obs = append(obs, in.target(kinds.MechanismSRV, target)...)
		}
	}
	return obs, nil
}
