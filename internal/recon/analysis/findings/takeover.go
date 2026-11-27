package findings

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/knowledge/cloudstorage"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/recon/kinds"
)

// evidence combines takeover signals into one finding per hostname or URL-only bucket target.
type evidence struct {
	types   map[string]bool
	details []string
	attrs   map[string]any
}

type evidenceSet map[string]*evidence

func (s evidenceSet) add(target, typ, detail string, attrs map[string]any) {
	e := s[target]
	if e == nil {
		e = &evidence{types: map[string]bool{}, attrs: map[string]any{}}
		s[target] = e
	}
	e.types[typ] = true
	if !slices.Contains(e.details, detail) {
		e.details = append(e.details, detail)
	}
	for k, v := range attrs {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		if _, set := e.attrs[k]; !set {
			e.attrs[k] = v
		}
	}
}

// takeovers derives the takeover candidates: DNS evidence needs no query
// of its own, so it is derived under --passive too.
func (d *calc) takeovers() []Finding {
	ev := evidenceSet{}
	d.dnsTakeovers(ev)
	d.danglingAliases(ev)
	d.httpTakeovers(ev)
	d.missingStorage(ev)
	var out []Finding
	for target, e := range ev {
		typ := strings.Join(slices.Sorted(maps.Keys(e.types)), ";")
		out = append(out, newFinding(Takeover, typ, Severity(Takeover, typ), target, strings.Join(e.details, "; "), e.attrs))
	}
	return out
}

// dnsTakeovers: a provider host that does not resolve (NXDOMAIN), matching a
// cname entry marked claimable.
func (d *calc) dnsTakeovers(ev evidenceSet) {
	nx := map[string]bool{}
	for _, r := range d.current(kinds.Unresolved) {
		if kinds.Unresolved.Attrs(r).RCode == "NXDOMAIN" {
			nx[r.Key] = true
		}
	}
	for _, ph := range d.in.Inv.ProviderHosts(d.in.Scope) {
		if ph.Evidence != "cname" || ph.Resolves || !ph.Entry.NXDomain || !nx[ph.Hostname] {
			continue
		}
		ev.add(ph.Hostname, "dns-nxdomain",
			fmt.Sprintf("%s is an alias of %s (%s %s), which does not exist and can be claimed", ph.Hostname, ph.CNAME, ph.Provider, ph.Service),
			map[string]any{"service": ph.Service, "cname": ph.CNAME, "provider": ph.Provider})
	}
}

// danglingAliases: a name whose alias leaves the input roots and leads to no address, once
// resolve has found that out. Nothing shows the target can be claimed, so it is a stale record
// and low; a name dnsTakeovers already reports is left to it.
func (d *calc) danglingAliases(ev evidenceSet) {
	unresolved := map[string]bool{} // answered with no address; a SERVFAIL is no answer
	for _, r := range d.current(kinds.Unresolved) {
		if rc := kinds.Unresolved.Attrs(r).RCode; rc == "NXDOMAIN" || rc == "NODATA" {
			unresolved[r.Key] = true
		}
	}
	for _, a := range d.in.Inv.DanglingAliases(d.in.Scope) {
		if _, claimable := ev[a.Hostname]; claimable || !unresolved[a.Hostname] {
			continue
		}
		ev.add(a.Hostname, "dangling-alias",
			fmt.Sprintf("%s is an alias of %s, which leads to no address", a.Hostname, a.Target),
			map[string]any{"cname": a.Target, "provider": dnsname.Registrable(a.Target)})
	}
}

// httpTakeovers: a provider-hosted service answering with its unclaimed-resource page.
func (d *calc) httpTakeovers(ev evidenceSet) {
	svcs := d.services()
	for _, r := range d.current(kinds.TakeoverHTTP) {
		a := kinds.TakeoverHTTP.Attrs(r)
		if _, ok := svcs[a.Service]; !ok {
			continue
		}
		ev.add(a.Host, "http-fingerprint",
			fmt.Sprintf("%s serves the page of an unclaimed %s resource (HTTP %d)", a.Service, a.ProviderService, a.Status),
			map[string]any{"service": a.ProviderService, "cname": a.CNAME, "provider": a.Provider})
	}
}

// missingStorage finds absent attributed buckets/accounts. CNAME references produce findings
// for their hostnames; URL-only references produce a bucket finding, downgraded to low when all
// are plain links.
func (d *calc) missingStorage(ev evidenceSet) {
	refs := d.references()
	missing := d.missingResources()
	if len(missing) == 0 {
		return
	}
	type use struct {
		cname []string // hostnames whose CNAME names it
		asset bool     // a page loads it, rather than only linking to it
	}
	uses := map[string]*use{}
	for _, ref := range refs {
		key := refKey(ref)
		if !missing[key] {
			continue
		}
		u := uses[key]
		if u == nil {
			u = &use{}
			uses[key] = u
		}
		switch ref.Via {
		case "cname":
			u.cname = append(u.cname, ref.From)
		case "link":
		default:
			u.asset = true
		}
	}
	for key, u := range uses {
		label := strings.Replace(key, "|", ":", 1)
		detail := fmt.Sprintf("%s does not exist and can be claimed", label)
		if len(u.cname) > 0 {
			for _, h := range u.cname {
				ev.add(h, "storage-missing", fmt.Sprintf("%s is an alias of %s", h, detail), nil)
			}
			continue
		}
		typ := "storage-missing"
		if !u.asset {
			typ = "storage-missing-link"
		}
		ev.add(label, typ, detail, nil)
	}
}

// refKey identifies the claimable resource: a bucket, or an Azure account. A missing Azure
// container alone is not claimable by outsiders.
func refKey(ref cloudstorage.Reference) string {
	if ref.Provider != cloudstorage.Azure {
		return cloudstorage.Key(ref.Provider, ref.Name, "")
	}
	return cloudstorage.AccountKey(ref.Name)
}

// missingResources are the storage keys known not to exist: a bucket, a
// container, or an Azure account (cloudstorage.AccountKey).
func (d *calc) missingResources() map[string]bool {
	out := map[string]bool{}
	for _, r := range d.current(kinds.Storage) {
		if e := kinds.Storage.Attrs(r).Exists; e != nil && !*e { // known not to exist, not merely unknown
			out[r.Key] = true
		}
	}
	for _, r := range d.current(kinds.StorageAccount) {
		if e := kinds.StorageAccount.Attrs(r).Exists; e != nil && !*e { // known not to exist
			out[cloudstorage.AccountKey(r.Key)] = true
		}
	}
	return out
}
