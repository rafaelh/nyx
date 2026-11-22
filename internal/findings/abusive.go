package findings

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/kinds"
)

// abusiveNetworks derives one finding for each checked address that the snapshot lists, by its
// network or by the AS that announces it. It sends nothing and reads only the evidence, so it is
// derived under --passive too, and a snapshot rebuilt into a new binary changes the findings on the
// next run with no request.
//
// The checked addresses are those of the in-scope hostnames (a shared provider's and a
// wildcard-only name's included) and those of the current ip records inside an in-scope netblock
// that more than DNS history names, less any an exclusion refuses. A candidate's address outside
// the netblocks is never checked: only an in-scope name brings an address in.
func (d *deriver) abusiveNetworks() []Finding {
	snap := d.in.Abusive
	if snap == nil {
		return nil
	}
	names := d.abusiveHostnames()
	units := d.netblockOwners()
	var out []Finding
	for _, a := range d.abusiveAddrs() {
		nets := snap.Networks(a)
		var asn []abusive.ASNMatch
		if n := d.originAS(units, a); n > 0 {
			asn = snap.ASN(n)
		}
		if len(nets) == 0 && len(asn) == 0 {
			continue
		}
		out = append(out, abusiveFinding(a, names[a], nets, asn))
	}
	return out
}

// abusiveAddrs are the addresses the check applies to, in address order.
func (d *deriver) abusiveAddrs() []netip.Addr {
	sc, inv := d.in.Scope, d.in.Inv
	set := map[netip.Addr]bool{}
	for name, addrs := range inv.Addrs() {
		if sc.HostInScope(name) {
			for _, a := range addrs {
				set[a.Unmap()] = true
			}
		}
	}
	for _, r := range d.current(kinds.IP) {
		a, err := netip.ParseAddr(r.Key)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if sc.InScopeIP(a) && (d.in.HistoryOnly == nil || !d.in.HistoryOnly(a)) {
			set[a] = true
		}
	}
	for a := range set {
		if excluded, _ := sc.ExcludedFor(a, inv.Shared(a)); excluded {
			delete(set, a)
		}
	}
	return slices.SortedFunc(maps.Keys(set), netip.Addr.Compare)
}

// abusiveHostnames are the in-scope names behind each address: those that resolve to it (a
// wildcard-only name too) and those reverse DNS gave it.
func (d *deriver) abusiveHostnames() map[netip.Addr][]string {
	sc := d.in.Scope
	set := map[netip.Addr]map[string]bool{}
	add := func(a netip.Addr, name string) {
		a = a.Unmap()
		if set[a] == nil {
			set[a] = map[string]bool{}
		}
		set[a][name] = true
	}
	for a, names := range d.hostnamesByIP() {
		for _, n := range names {
			if sc.HostInScope(n) {
				add(a, n)
			}
		}
	}
	for name, addrs := range d.in.Inv.Addrs() {
		if sc.HostInScope(name) {
			for _, a := range addrs {
				add(a, name)
			}
		}
	}
	out := make(map[netip.Addr][]string, len(set))
	for a, names := range set {
		out[a] = slices.Sorted(maps.Keys(names))
	}
	return out
}

// netblockOwners are the origin ASes netblock_owner gives, by the unit's prefix.
func (d *deriver) netblockOwners() map[string]int {
	units := map[string]int{}
	for _, r := range d.current(kinds.NetblockOwner) {
		units[r.Key] = kinds.NetblockOwner.Attrs(r).ASN
	}
	return units
}

// originAS is the origin AS of the address, or 0 when none is known: its unit's netblock_owner for
// an address inside an in-scope netblock, its own ip_owner otherwise.
func (d *deriver) originAS(units map[string]int, a netip.Addr) int {
	if unit, ok := d.in.Scope.OwnerUnit(a); ok {
		return units[unit.String()]
	}
	return d.in.Inv.Owner(a).ASN
}

// abusiveFinding builds the finding of an address with at least one match. Matches carry the
// snapshot's text sanitised already. The rank is left out: it says nothing of this address.
func abusiveFinding(a netip.Addr, hostnames []string, nets []abusive.NetworkMatch, asn []abusive.ASNMatch) Finding {
	networks, asns := make([]string, 0, len(nets)), make([]string, 0, len(asn))
	var parts []string
	var netDate, asnDate string
	for _, m := range nets {
		networks = append(networks, entryText(m.Network, m.ScoreTag, m.AbuseScore, m.Org, m.OrgType))
		parts = append(parts, "abusive network "+entryDetail(m.Network, m.ScoreTag, m.AbuseScore, m.Org, m.OrgType, m.Updated))
		netDate = m.Updated
	}
	for _, m := range asn {
		id := "AS" + strconv.Itoa(m.ASN)
		asns = append(asns, entryText(id, m.ScoreTag, m.AbuseScore, m.Org, m.OrgType))
		parts = append(parts, "abusive "+entryDetail(id, m.ScoreTag, m.AbuseScore, m.Org, m.OrgType, m.Updated))
		asnDate = m.Updated
	}
	// The first match names the finding: the most specific network, else the AS.
	var typ, entry, org string
	if len(nets) > 0 {
		typ, entry, org = "network", nets[0].Network, nets[0].Org
	} else {
		typ, entry, org = "asn", "AS"+strconv.Itoa(asn[0].ASN), asn[0].Org
	}
	addr := a.String()
	return newFinding(AbusiveNetwork, typ, Severity(AbusiveNetwork, typ), addr,
		fmt.Sprintf("address %s is in %s", addr, strings.Join(parts, " and in ")),
		map[string]any{"ip": addr, "hostnames": strings.Join(hostnames, ";"), "networks": networks, "asn": asns,
			"networks_updated": netDate, "asns_updated": asnDate, "entry": entry, "org": org})
}

// entryText is a match as a cell of the risk file reads it.
func entryText(entry, tag string, score float64, org, typ string) string {
	return fmt.Sprintf("%s %s %s%% %s (%s)", entry, tag, abusive.ScoreText(score), org, typ)
}

// entryDetail is a match as the finding's detail reads it, with the date of its list.
func entryDetail(entry, tag string, score float64, org, typ, updated string) string {
	return fmt.Sprintf("%s (%s, %s%%, %s, %s, list of %s)", entry, tag, abusive.ScoreText(score), org, typ, updated)
}
