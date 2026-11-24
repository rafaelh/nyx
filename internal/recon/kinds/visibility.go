package kinds

import (
	"net/url"
	"sync"

	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/scope"
	"github.com/rafaelh/nyx/internal/recon/store"
)

// Visibility applies current scope and inventory rules when records are read, so later
// exclusions also hide earlier discoveries. Web and hostname records need an in-scope host;
// port records need a port-eligible address. Confirmed closed ports hide third-party reports.
// OutsideAttr additionally requires an external domain. Entities use their kind's placement
// rule; other records remain visible.
//
// Counts, events, files and findings share these decisions. Web-host results are cached and
// safe for concurrent access. A nil Visibility shows only kinds whose rules do not require
// scope.
type Visibility struct {
	sc  *scope.Scope
	inv *inventory.Inventory

	mu    sync.Mutex
	hosts map[string]bool
}

// NewVisibility binds visibility rules to a non-nil scope and inventory.
func NewVisibility(sc *scope.Scope, inv *inventory.Inventory) *Visibility {
	return &Visibility{sc: sc, inv: inv, hosts: map[string]bool{}}
}

// Shown reports whether a record of the kind is shown.
func (v *Visibility) Shown(kind Named, r store.Record) bool { return v.shown(kind.kind(), r) }

func (v *Visibility) shown(k Kind, r store.Record) bool {
	switch {
	case k.Entity():
		return true
	case v == nil:
		return !k.scoped()
	}
	return v.hostShown(k, r) && v.outside(k, r)
}

// hostShown applies the kind's host or address visibility rule.
func (v *Visibility) hostShown(k Kind, r store.Record) bool {
	switch {
	case k.PortKey:
		ap, ok := ParsePortKey(r.Key)
		return ok && v.inv.PortEligible(ap.Addr(), v.sc) && (!k.ClosedHides || !v.inv.PortClosed(ap))
	case k.HostAttr != "":
		return v.webHostInScope(webHost(k.HostAttr, r))
	case k.HostKey:
		return v.sc.HostInScope(r.Key)
	}
	return true
}

// outside accepts records naming no domain or a domain outside scope.
func (v *Visibility) outside(k Kind, r store.Record) bool {
	if k.OutsideAttr == "" {
		return true
	}
	d := r.Str(k.OutsideAttr)
	return d == "" || !v.sc.HostInScope(d)
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

// webHost reads a record's host attribute, falling back to the host in its URL key.
func webHost(hostAttr string, r store.Record) string {
	host := r.Str(hostAttr)
	if host == "" {
		if u, err := url.Parse(r.Key); err == nil {
			host = u.Hostname()
		}
	}
	return host
}

// Printed allows found events for printed kinds and, for entities, only in-scope records.
// Unknown kinds are never printed. It accepts a kind name because the store callback reports
// names.
func (v *Visibility) Printed(kind string, r store.Record) bool {
	k, ok := Get(kind)
	switch {
	case !ok || !k.Printed:
		return false
	case v == nil:
		return !k.scoped()
	case k.Entity():
		class, placed := v.placement(k, r)
		return placed && class == scope.InScope
	}
	return v.shown(k, r)
}

// Category returns the visible record's summary category, or "" for hidden or uncounted
// records.
func (v *Visibility) Category(kind Named, r store.Record) string {
	if v == nil {
		return ""
	}
	return v.category(kind.kind(), r)
}

func (v *Visibility) category(k Kind, r store.Record) string {
	if !k.Entity() {
		if !v.shown(k, r) {
			return ""
		}
		return k.Category
	}
	class, placed := v.placement(k, r)
	switch {
	case !placed:
		return ""
	case class == scope.Candidate:
		return Candidates
	case class == scope.Excluded:
		return Excluded
	}
	return k.Category // "" for an input
}

// Placement applies an entity kind's classification rule consistently with candidates.csv and
// summary counts. It returns false for unlisted entities, such as unqualified organisations or
// invalid CIDRs, and for non-entity kinds. Visibility must be non-nil.
func (v *Visibility) Placement(kind Named, r store.Record) (scope.Class, bool) {
	return v.placement(kind.kind(), r)
}

func (v *Visibility) placement(k Kind, r store.Record) (scope.Class, bool) {
	if k.place == nil {
		return 0, false
	}
	return k.place(v.sc, v.inv, r.Key)
}

// ChangeLabel returns the changes.csv label and scope column independently of current
// visibility. Entities use candidate/excluded labels or their in-scope kind label. Other kinds
// have scope="in-scope" when visibility depends on scope, otherwise blank. Unlisted kinds
// return "".
func (v *Visibility) ChangeLabel(kind Named, r store.Record) (label, place string) {
	k := kind.kind()
	if !k.Entity() {
		if k.Change != "" && k.scoped() {
			return k.Change, scope.InScope.String()
		}
		return k.Change, ""
	}
	if v == nil {
		return "", ""
	}
	class, placed := v.placement(k, r)
	switch {
	case !placed:
		return "", ""
	case class == scope.Candidate:
		return LabelCandidate, scope.Candidate.String()
	case class == scope.Excluded:
		return LabelExcluded, scope.Excluded.String()
	case k.Change == "":
		return "", ""
	}
	return k.Change, scope.InScope.String()
}

// Totals counts current visible records by summary category, retaining empty host and
// non-entity categories. Excluded values are deduplicated across kinds to match excluded.csv.
func (v *Visibility) Totals(recs map[string][]store.Record) map[string]int {
	totals := map[string]int{Hosts: 0}
	excluded := map[string]bool{}
	// Count a port confirmed by nyx once, regardless of third-party reports.
	confirmed := OpenedPorts(recs[OpenPort.Name()])
	isConfirmed := func(key string) bool {
		ap, ok := ParsePortKey(key)
		return ok && confirmed[ap]
	}
	for _, k := range table {
		if !k.Entity() {
			if k.Category == "" {
				continue
			}
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
