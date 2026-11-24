package run

import (
	"net/netip"

	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

// scopeKinds lists BuildScope's record dependencies. Candidate ranking shares this list so a
// scope change also triggers reranking. Ranking additionally reads the candidate kinds it
// produces; see newAnalyses.
var scopeKinds = []kinds.Named{kinds.Hostname, kinds.Root, kinds.Netblock, kinds.Resolution, kinds.Wildcard,
	kinds.IP, kinds.IPOwner, kinds.IPHostname, kinds.ProviderRange, kinds.PortCheck, kinds.Registration, kinds.ServerAddress}

// ScopeSource supplies records for scope classification. Runs read through the store; exports
// read a single snapshot. Both use the same classification code.
type ScopeSource interface {
	// CurrentRecords returns current records with attributes merged in procedure registry
	// order.
	CurrentRecords(kinds.Named) ([]store.Record, error)
	// Observations lists the observations of a kind made by a procedure.
	Observations(kind kinds.Named, procedure string) ([]store.ObsRow, error)
}

// rangeCache lets BuildScope reuse the provider-range index between builds. Other sources are
// indexed on each build.
type rangeCache interface {
	ProviderRanges() (*provider.Ranges, error)
}

// Built holds an engagement's scope, inventory and visibility rules.
type Built struct {
	Scope *scope.Scope
	Inv   *inventory.Inventory
	// Vis applies consistent visibility rules to counts, files, found events, findings and
	// exports.
	Vis *kinds.Visibility
}

// BuildScope classifies stored inputs and current records for runs and exports. ASNExpander
// procedures contribute input ASNs' netblocks to scope. This function only reads state; the runner
// handles netblock approval and egress policy changes.
func BuildScope(in input.Parsed, procedures []Procedure, src ScopeSource) (*Built, error) {
	excl, err := input.ParseExclusions(in.Exclusions)
	if err != nil {
		return nil, err
	}
	var blocks []netip.Prefix
	for _, c := range in.CIDRs {
		p, err := input.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, p)
	}
	asnBlocks, err := asnNetblocks(src, procedures, in)
	if err != nil {
		return nil, err
	}
	for k := range asnBlocks {
		if p, err := netip.ParsePrefix(k); err == nil {
			blocks = append(blocks, p.Masked())
		}
	}
	data, err := inventoryData(src)
	if err != nil {
		return nil, err
	}
	inv := inventory.New(data, provider.Default())
	sc := scope.New(scope.Config{Roots: in.Roots, Netblocks: blocks, Exclusions: excl, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly(),
		ASNs: in.ASNs, Orgs: in.Orgs})
	return &Built{Scope: sc, Inv: inv, Vis: kinds.NewVisibility(sc, inv)}, nil
}

// asnNetblocks maps netblocks observed by ASNExpander procedures to their input ASN. It uses job
// keys rather than mutable record attributes to establish that relationship.
func asnNetblocks(src ScopeSource, procedures []Procedure, in input.Parsed) (map[string]string, error) {
	want := map[string]bool{}
	for _, a := range in.ASNs {
		want[a] = true
	}
	out := map[string]string{}
	for _, s := range procedures {
		if _, ok := s.(ASNExpander); !ok {
			continue
		}
		rows, err := src.Observations(kinds.Netblock, s.Name())
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if want[row.JobKey] {
				out[row.Key] = row.JobKey
			}
		}
	}
	return out, nil
}

func inventoryData(src ScopeSource) (inventory.Data, error) {
	var d inventory.Data
	var err error
	if d.Hosts, err = currentAs(src, kinds.Hostname, hostOf); err != nil {
		return d, err
	}
	if d.Resolutions, err = currentAs(src, kinds.Resolution, resolutionOf); err != nil {
		return d, err
	}
	if d.Wildcards, err = currentAs(src, kinds.Wildcard, wildcardOf); err != nil {
		return d, err
	}
	if d.IPs, err = currentAs(src, kinds.IP, ipOf); err != nil {
		return d, err
	}
	if d.Owners, err = ipOwners(src); err != nil {
		return d, err
	}
	if d.Ranges, err = providerRanges(src); err != nil {
		return d, err
	}
	if d.ClosedPorts, err = currentAs(src, kinds.PortCheck, closedPortOf); err != nil {
		return d, err
	}
	if d.IPHostnames, err = currentAs(src, kinds.IPHostname, ipHostnameOf); err != nil {
		return d, err
	}
	if d.Registrations, err = currentAs(src, kinds.Registration, registrationOf); err != nil {
		return d, err
	}
	if d.ServerAddresses, err = currentAs(src, kinds.ServerAddress, serverAddressOf); err != nil {
		return d, err
	}
	return d, nil
}

// currentAs converts current records in order, dropping any that conv rejects.
func currentAs[T any](src ScopeSource, k kinds.Named, conv func(store.Record) (T, bool)) ([]T, error) {
	recs, err := src.CurrentRecords(k)
	if err != nil {
		return nil, err
	}
	var out []T
	for _, rec := range recs {
		if v, ok := conv(rec); ok {
			out = append(out, v)
		}
	}
	return out, nil
}

func hostOf(rec store.Record) (inventory.Host, bool) {
	return inventory.Host{Name: dnsname.Normalise(rec.Key), Producers: rec.Producers}, true
}

func resolutionOf(rec store.Record) (inventory.Resolution, bool) {
	a := kinds.Resolution.Attrs(rec)
	name := dnsname.Normalise(a.Name)
	return inventory.Resolution{Name: name, Type: a.Type, Value: a.Value}, name != ""
}

func wildcardOf(rec store.Record) (inventory.Wildcard, bool) {
	a := kinds.Wildcard.Attrs(rec)
	w := inventory.Wildcard{Zone: rec.Key, CNAME: a.CNAME}
	for _, s := range a.Addrs {
		if addr, err := netip.ParseAddr(s); err == nil {
			w.Addrs = append(w.Addrs, addr)
		}
	}
	return w, true
}

func ipOf(rec store.Record) (netip.Addr, bool) {
	a, err := netip.ParseAddr(rec.Key)
	return a.Unmap(), err == nil
}

// ipOwners indexes ip_owner records by address and always returns a non-nil map on success.
func ipOwners(src ScopeSource) (map[netip.Addr]provider.Owner, error) {
	recs, err := src.CurrentRecords(kinds.IPOwner)
	if err != nil {
		return nil, err
	}
	owners := map[netip.Addr]provider.Owner{}
	for _, rec := range recs {
		if addr, err := netip.ParseAddr(rec.Key); err == nil {
			a := kinds.IPOwner.Attrs(rec)
			owners[addr.Unmap()] = provider.Owner{ASN: a.ASN, Holder: a.Holder, Known: true}
		}
	}
	return owners, nil
}

func closedPortOf(rec store.Record) (netip.AddrPort, bool) {
	ap, ok := kinds.ParsePortKey(rec.Key)
	return ap, ok && kinds.PortCheck.Attrs(rec).Result == kinds.PortClosed
}

func ipHostnameOf(rec store.Record) (inventory.IPHostname, bool) {
	a := kinds.IPHostname.Attrs(rec)
	addr, err := netip.ParseAddr(a.IP)
	if err != nil {
		return inventory.IPHostname{}, false
	}
	return inventory.IPHostname{IP: addr.Unmap(), Hostname: dnsname.Normalise(a.Hostname), Source: a.Source}, true
}

func registrationOf(rec store.Record) (inventory.Registration, bool) {
	a := kinds.Registration.Attrs(rec)
	start, e1 := netip.ParseAddr(a.Start)
	end, e2 := netip.ParseAddr(a.End)
	if e1 != nil || e2 != nil {
		return inventory.Registration{}, false
	}
	return inventory.Registration{Key: rec.Key, Start: start.Unmap(), End: end.Unmap(),
		Registrant: a.Registrant, Registry: a.Registry}, true
}

func serverAddressOf(rec store.Record) (inventory.ServerAddress, bool) {
	a := kinds.ServerAddress.Attrs(rec)
	addr, err := netip.ParseAddr(a.Addr)
	return inventory.ServerAddress{Host: a.Host, Addr: addr}, err == nil
}

// providerRanges reuses a source's cached provider-range index when available.
func providerRanges(src ScopeSource) (*provider.Ranges, error) {
	if c, ok := src.(rangeCache); ok {
		return c.ProviderRanges()
	}
	recs, err := src.CurrentRecords(kinds.ProviderRange)
	if err != nil {
		return nil, err
	}
	return indexRanges(recs), nil
}

// indexRanges indexes provider_range records for the inventory.
func indexRanges(recs []store.Record) *provider.Ranges {
	var rs []provider.Range
	for _, rec := range recs {
		a := kinds.ProviderRange.Attrs(rec)
		if p, err := netip.ParsePrefix(a.Prefix); err == nil {
			rs = append(rs, provider.Range{Prefix: p.Masked(), Provider: a.Provider, Service: a.Service, Region: a.Region})
		}
	}
	return provider.NewRanges(rs)
}

// runnerSource reads a run's store through the Runner's caches.
type runnerSource struct{ r *Runner }

func (s runnerSource) CurrentRecords(k kinds.Named) ([]store.Record, error) {
	return s.r.currentRecords(k)
}

func (s runnerSource) Observations(k kinds.Named, procedure string) ([]store.ObsRow, error) {
	return s.r.st.Observations(k.Name(), procedure)
}

// ProviderRanges caches the index until the store's provider_range version changes. Scope is
// rebuilt after every procedure, so this avoids repeatedly indexing thousands of rows.
func (s runnerSource) ProviderRanges() (*provider.Ranges, error) {
	r := s.r
	ver := r.st.KindVersion(kinds.ProviderRange.Name())
	if r.ranges != nil && ver == r.rangesVer {
		return r.ranges, nil
	}
	recs, err := r.currentRecords(kinds.ProviderRange)
	if err != nil {
		return nil, err
	}
	r.ranges, r.rangesVer = indexRanges(recs), ver
	return r.ranges, nil
}
