package kinds

import (
	"net/netip"
	"net/url"
	"sync"

	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

// Visibility applies the showing rules for one Scope and Inventory. The rules
// are evaluated on read, so an exclusion added later hides records found
// earlier:
//
//   - a web record (a kind with HostAttr) is shown while its host is in scope;
//   - a port record (PortKey) is shown while its address is port-eligible, so a
//     reassigned cloud address is not reported as the target's, and a port a
//     third party reported (ClosedHides) is not shown once nyx found it closed;
//   - a record keyed by a hostname (HostKey) is shown while that name is in scope;
//   - a record with an OutsideAttr is shown only while the domain it names is
//     not in scope, on top of any other rule;
//   - an entity record is never hidden: it is classified as in scope, a
//     candidate or excluded, which decides its summary category. An asn is a
//     candidate unless it is an input, and an organisation is counted as one
//     only while Inventory.RegistrantCandidate holds;
//   - a record of any other kind is always shown.
//
// The summary counts, the found lines, the files and the findings all ask the
// same Visibility, so their totals agree. It decides each web host once, and is
// safe for concurrent use. A nil *Visibility (no Scope built yet) shows only
// the kinds whose rules need no scope.
type Visibility struct {
	sc  *scope.Scope
	inv *inventory.Inventory

	mu    sync.Mutex
	hosts map[string]bool
}

// NewVisibility returns the Visibility of a Scope and Inventory, neither nil.
func NewVisibility(sc *scope.Scope, inv *inventory.Inventory) *Visibility {
	return &Visibility{sc: sc, inv: inv, hosts: map[string]bool{}}
}

// Shown reports whether a record of the kind is shown.
func (v *Visibility) Shown(kind Named, r store.Record) bool { return v.shown(kind.kind(), r) }

func (v *Visibility) shown(k Kind, r store.Record) bool {
	switch {
	case k.Entity:
		return true
	case v == nil:
		return !k.scoped()
	}
	return v.hostShown(k, r) && v.outside(k, r)
}

// hostShown applies a kind's rule for the host or address a record belongs to.
func (v *Visibility) hostShown(k Kind, r store.Record) bool {
	switch {
	case k.PortKey:
		ap, ok := ParsePortKey(r.Key)
		return ok && v.inv.PortEligible(ap.Addr(), v.sc) && (!k.ClosedHides || !v.inv.PortClosed(ap))
	case k.HostAttr != "":
		return v.webHostInScope(webHost(k.HostAttr, r))
	case k.HostKey:
		return v.sc.ClassifyHost(r.Key).Class == scope.InScope
	}
	return true
}

// outside reports whether the domain a record names is outside the scope, or
// the record names none.
func (v *Visibility) outside(k Kind, r store.Record) bool {
	if k.OutsideAttr == "" {
		return true
	}
	d := r.Str(k.OutsideAttr)
	return d == "" || v.sc.ClassifyHost(d).Class != scope.InScope
}

func (v *Visibility) webHostInScope(host string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	in, ok := v.hosts[host]
	if !ok {
		in = v.sc.WebHostInScope(host)
		v.hosts[host] = in
	}
	return in
}

// webHost is the host of a web record: its host attribute, or the host of its
// key when it has none.
func webHost(hostAttr string, r store.Record) string {
	host := r.Str(hostAttr)
	if host == "" {
		if u, err := url.Parse(r.Key); err == nil {
			host = u.Hostname()
		}
	}
	return host
}

// Printed reports whether a record seen for the first time is printed as a
// found line: a printed kind, and for an entity only while it is in scope. The
// kind is given by name, as the store reports a new record. A record of an
// unknown kind is not printed.
func (v *Visibility) Printed(kind string, r store.Record) bool {
	k, ok := Get(kind)
	switch {
	case !ok || !k.Printed:
		return false
	case v == nil:
		return !k.scoped()
	case k.Entity:
		return v.sc.ClassifyHost(r.Key).Class == scope.InScope
	}
	return v.shown(k, r)
}

// Category is the summary category a record of the kind is counted under, or
// "" if it is not counted (a kind without a category, or a hidden record).
func (v *Visibility) Category(kind Named, r store.Record) string {
	if v == nil {
		return ""
	}
	return v.category(kind.kind(), r)
}

func (v *Visibility) category(k Kind, r store.Record) string {
	if !k.Entity {
		if !v.shown(k, r) {
			return ""
		}
		return k.Category
	}
	switch k.Name {
	case "hostname", "root":
		switch v.placement(k, r) {
		case scope.InScope:
			if k.Name == "hostname" {
				return Hosts
			}
			return ""
		case scope.Candidate:
			return Candidates
		default:
			return Excluded
		}
	case "netblock":
		if _, err := netip.ParsePrefix(r.Key); err != nil {
			return ""
		}
		if v.placement(k, r) == scope.InScope {
			return Netblocks
		}
		return Candidates
	case "asn":
		if v.sc.HasASN(r.Key) {
			return ""
		}
		return Candidates
	case "organisation":
		if v.inv.RegistrantCandidate(v.sc, r.Key) {
			return Candidates
		}
		return ""
	}
	return k.Category
}

// Placement is where a record of an entity kind sits against the scope, the
// decision behind its summary category. A record of any other kind is shown or
// hidden instead (see Shown). The Visibility must not be nil.
func (v *Visibility) Placement(kind Named, r store.Record) scope.Class {
	return v.placement(kind.kind(), r)
}

func (v *Visibility) placement(k Kind, r store.Record) scope.Class {
	switch k.Name {
	case "hostname", "root":
		return v.sc.ClassifyHost(r.Key).Class
	case "netblock":
		if v.sc.HasNetblock(r.Key) {
			return scope.InScope
		}
		return scope.Candidate
	case "asn":
		if v.sc.HasASN(r.Key) {
			return scope.InScope
		}
		return scope.Candidate
	case "organisation":
		if v.sc.MatchesOrg(r.Key) {
			return scope.InScope
		}
		return scope.Candidate
	}
	return scope.Excluded // an address or name that triggered an exclusion
}

// Totals counts the current records by summary category. Hosts and the
// category of every non-entity kind are listed even when they are empty. An
// excluded value is counted once, however many records (a hostname, a root, a
// guard's excluded record) carry it, as excluded.csv lists it once.
func (v *Visibility) Totals(recs map[string][]store.Record) map[string]int {
	totals := map[string]int{Hosts: 0}
	excluded := map[string]bool{}
	// A port nyx confirmed is counted as confirmed only, whoever reported it.
	confirmed := map[netip.AddrPort]bool{}
	for _, r := range recs[OpenPort.Name()] {
		if ap, ok := ParsePortKey(r.Key); ok && r.Current {
			confirmed[ap] = true
		}
	}
	isConfirmed := func(key string) bool {
		ap, ok := ParsePortKey(key)
		return ok && confirmed[ap]
	}
	for _, k := range table {
		if k.Category == "" {
			continue
		}
		if !k.Entity {
			totals[k.Category] += 0
		}
		if v == nil {
			continue
		}
		for _, r := range recs[k.Name] {
			if !r.Current || k.ClosedHides && isConfirmed(r.Key) {
				continue
			}
			cat := v.category(k, r)
			if cat == Excluded {
				if excluded[r.Key] {
					continue
				}
				excluded[r.Key] = true
			}
			if cat != "" {
				totals[cat]++
			}
		}
	}
	return totals
}
