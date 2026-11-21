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

// scopeKinds are the kinds BuildScope reads. The candidate-rank deriver reads the
// same list, so a kind added to the build is also added here, once, and the
// candidates are ranked again when it changes. It also reads the candidate kinds
// it ranks (see newDerivers).
var scopeKinds = []kinds.Named{kinds.Hostname, kinds.Root, kinds.Netblock, kinds.Resolution, kinds.Wildcard,
	kinds.IP, kinds.IPOwner, kinds.IPHostname, kinds.ProviderRange, kinds.PortCheck, kinds.Registration, kinds.ServerAddress}

// ScopeSource is what BuildScope reads: the engagement's records. A run reads
// them from its store as it works, and an export from one snapshot of it, so
// both classify with the same rules.
type ScopeSource interface {
	// CurrentRecords returns the current records of a scope kind, their
	// attributes merged in the registry's stage order.
	CurrentRecords(kinds.Named) ([]store.Record, error)
	// Observations lists the observations of a kind made by a stage.
	Observations(kind kinds.Named, stage string) ([]store.ObsRow, error)
}

// rangeCache is a ScopeSource that keeps the index of the provider_range
// records between builds. BuildScope indexes them itself for any other source.
type rangeCache interface {
	ProviderRanges() (*provider.Ranges, error)
}

// Built is the scope of an engagement and what is derived from it.
type Built struct {
	Scope *scope.Scope
	Inv   *inventory.Inventory
	// Vis is the showing rules for Scope and Inv: the decision behind every
	// count, file, found line and finding, and an export's shown.
	Vis *kinds.Visibility
}

// BuildScope builds the Scope and Inventory from the engagement's stored
// inputs and its current records, the same way for a run and for anything
// that reads an engagement afterwards. It reads, and writes nothing: the
// netblock-limit approval and the egress policy belong to the run.
func BuildScope(in input.Parsed, src ScopeSource) (*Built, error) {
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
	asnBlocks, err := asnNetblocks(src, in)
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

// asnNetblocks maps each current netblock observed by the asn stage under a
// check for an input ASN to that ASN. It never depends on a mutable attribute.
func asnNetblocks(src ScopeSource, in input.Parsed) (map[string]string, error) {
	rows, err := src.Observations(kinds.Netblock, "asn")
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, a := range in.ASNs {
		want[a] = true
	}
	out := map[string]string{}
	for _, row := range rows {
		if want[row.CheckKey] {
			out[row.Key] = row.CheckKey
		}
	}
	return out, nil
}

// inventoryData reads the current records the inventory is computed from.
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

// currentAs converts the current records of a kind with conv, keeping the
// values it accepts, in record order.
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
	return inventory.Host{Name: dnsname.Normalise(rec.Key), Stages: rec.Stages}, true
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

// ipOwners are the owners of addresses the ip_owner records name. The map is
// never nil.
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

// providerRanges is the index of the current provider_range records, from the
// source's cache when it keeps one.
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

func (s runnerSource) Observations(k kinds.Named, stage string) ([]store.ObsRow, error) {
	return s.r.st.Observations(k.Name(), stage)
}

// ProviderRanges re-reads the provider_range records only when the store says
// they have changed since the last call: there are thousands of them and a
// build follows every stage.
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
