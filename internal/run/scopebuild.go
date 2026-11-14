package run

import (
	"net/netip"

	"github.com/rafaelh/recon/internal/input"
	"github.com/rafaelh/recon/internal/inventory"
	"github.com/rafaelh/recon/internal/kinds"
	"github.com/rafaelh/recon/internal/provider"
	"github.com/rafaelh/recon/internal/scope"
	"github.com/rafaelh/recon/internal/store"
)

// scopeKinds are the kinds BuildScope reads. The candidate-rank deriver reads the
// same list, so a kind added to the build is also added here, once, and the
// candidates are ranked again when it changes.
var scopeKinds = []kinds.Named{kinds.Hostname, kinds.Root, kinds.Netblock, kinds.Resolution, kinds.Wildcard,
	kinds.IP, kinds.IPOwner, kinds.IPHostname, kinds.ProviderRange}

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
	// Candidates are the current hostnames and roots classified as candidates:
	// the names that are never contacted.
	Candidates map[string]bool
}

// BuildScope builds the Scope and Inventory from the engagement's stored
// inputs and its current records, the same way for a run and for anything
// that reads an engagement afterwards. It reads, and writes nothing: the
// netblock-limit approval and the egress policy belong to the run.
func BuildScope(in input.Parsed, src ScopeSource) (*Built, error) {
	var excl []input.Exclusion
	for _, e := range in.Exclusions {
		x, err := input.ParseExclusion(e)
		if err != nil {
			return nil, err
		}
		excl = append(excl, x)
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
	sc := scope.New(scope.Config{Roots: in.Roots, Netblocks: blocks, Exclusions: excl, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly()})

	roots, err := src.CurrentRecords(kinds.Root)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(data.Hosts)+len(roots))
	for _, h := range data.Hosts {
		names = append(names, h.Name)
	}
	for _, rec := range roots {
		names = append(names, input.NormaliseHost(rec.Key))
	}
	cands := map[string]bool{}
	for _, n := range names {
		if sc.ClassifyHost(n).Class == scope.Candidate {
			cands[n] = true
		}
	}
	return &Built{Scope: sc, Inv: inv, Vis: kinds.NewVisibility(sc, inv), Candidates: cands}, nil
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
	hosts, err := src.CurrentRecords(kinds.Hostname)
	if err != nil {
		return d, err
	}
	for _, rec := range hosts {
		d.Hosts = append(d.Hosts, inventory.Host{Name: input.NormaliseHost(rec.Key), Stages: rec.Stages})
	}
	recs, err := src.CurrentRecords(kinds.Resolution)
	if err != nil {
		return d, err
	}
	for _, rec := range recs {
		a := kinds.Resolution.Attrs(rec)
		if name := input.NormaliseHost(a.Name); name != "" {
			d.Resolutions = append(d.Resolutions, inventory.Resolution{Name: name, Type: a.Type, Value: a.Value})
		}
	}
	if recs, err = src.CurrentRecords(kinds.Wildcard); err != nil {
		return d, err
	}
	for _, rec := range recs {
		a := kinds.Wildcard.Attrs(rec)
		w := inventory.Wildcard{Zone: rec.Key, CNAME: a.CNAME}
		for _, s := range a.Addrs {
			if addr, err := netip.ParseAddr(s); err == nil {
				w.Addrs = append(w.Addrs, addr)
			}
		}
		d.Wildcards = append(d.Wildcards, w)
	}
	if recs, err = src.CurrentRecords(kinds.IP); err != nil {
		return d, err
	}
	for _, rec := range recs {
		if a, err := netip.ParseAddr(rec.Key); err == nil {
			d.IPs = append(d.IPs, a.Unmap())
		}
	}
	if recs, err = src.CurrentRecords(kinds.IPOwner); err != nil {
		return d, err
	}
	d.Owners = map[netip.Addr]provider.Owner{}
	for _, rec := range recs {
		if addr, err := netip.ParseAddr(rec.Key); err == nil {
			a := kinds.IPOwner.Attrs(rec)
			d.Owners[addr.Unmap()] = provider.Owner{ASN: a.ASN, Holder: a.Holder, Known: true}
		}
	}
	if d.Ranges, err = providerRanges(src); err != nil {
		return d, err
	}
	if recs, err = src.CurrentRecords(kinds.IPHostname); err != nil {
		return d, err
	}
	for _, rec := range recs {
		a := kinds.IPHostname.Attrs(rec)
		if addr, err := netip.ParseAddr(a.IP); err == nil {
			d.IPHostnames = append(d.IPHostnames, inventory.IPHostname{IP: addr.Unmap(), Hostname: input.NormaliseHost(a.Hostname), Source: a.Source})
		}
	}
	return d, nil
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
