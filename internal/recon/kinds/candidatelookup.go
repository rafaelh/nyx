package kinds

import (
	"net/netip"

	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/scope"
)

// CandidateLookup holds the A and AAAA answer for a candidate hostname or root, keyed by the
// name. Scope reads it to decide whether the name is served from an in-scope netblock. It has no
// category, no output file and no change label, and is never printed.
var CandidateLookup = define[CandidateLookupAttrs](Kind{Name: "candidate_lookup"})

// CandidateLookupAttrs is a candidate lookup's answer: its addresses, sorted, and the CNAME links
// of its chain, in answer order. These attribute names are a stable interface.
type CandidateLookupAttrs struct {
	Addrs  []string    `json:"addrs"`
	CNAMEs []CNAMELink `json:"cnames"`
}

// CNAMELink is one link of a CNAME chain.
type CNAMELink struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}

// Addresses decodes the lookup's addresses, skipping any that do not parse.
func (a CandidateLookupAttrs) Addresses() []netip.Addr {
	var out []netip.Addr
	for _, s := range a.Addrs {
		if addr, err := netip.ParseAddr(s); err == nil {
			out = append(out, addr.Unmap())
		}
	}
	return out
}

// ByAddressHosts returns the current hostname records in scope by an address of their candidate
// lookup: the hostname rows of scope.csv and the summary's count. A name its resolved addresses
// exclude is left out, as ClassifyHost excludes it.
func ByAddressHosts(sc *scope.Scope, hostnames []store.Record) []store.Record {
	var out []store.Record
	for _, r := range hostnames {
		if r.Current && sc.InScopeByAddress(r.Key) && sc.HostInScope(r.Key) {
			out = append(out, r)
		}
	}
	return out
}
