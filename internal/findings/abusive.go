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
	"github.com/rafaelh/nyx/internal/spamhaus"
)

// abusiveNetworks derives one finding for each checked address that Spamhaus's DROP lists or the
// ipapi.is snapshot list, by its network or by the AS that announces it. It sends nothing and
// reads only the evidence, so it is derived under --passive too, and data rebuilt into a new
// binary or updated by the user changes the findings on the next run with no request.
//
// The checked addresses are those of the in-scope hostnames (a shared provider's and a
// wildcard-only name's included) and those of the current ip records inside an in-scope netblock
// that more than DNS history names, less any an exclusion refuses. A candidate's address outside
// the netblocks is never checked: only an in-scope name brings an address in.
func (d *deriver) abusiveNetworks() []Finding {
	snap, drop := d.in.Abusive, d.in.Drop
	if snap == nil && drop == nil {
		return nil
	}
	names := d.abusiveHostnames()
	units := d.netblockOwners()
	var out []Finding
	for _, a := range d.abusiveAddrs() {
		var m abusiveMatches
		n := d.originAS(units, a)
		if snap != nil {
			m.nets = snap.Networks(a)
			if n > 0 {
				m.asn = snap.ASN(n)
			}
		}
		if drop != nil {
			m.dropNets = drop.Networks(a)
			if n > 0 {
				m.dropASN = drop.ASN(n)
			}
		}
		if m.none() {
			continue
		}
		out = append(out, abusiveFinding(a, names[a], m))
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

// abusiveMatches are what the lists say of one address: the DROP or DROPv6 entries that hold it,
// the ASN-DROP entry of its origin AS, and the same two from the ipapi.is snapshot.
type abusiveMatches struct {
	dropNets []spamhaus.NetworkMatch
	dropASN  []spamhaus.ASNMatch
	nets     []abusive.NetworkMatch
	asn      []abusive.ASNMatch
}

func (m abusiveMatches) none() bool {
	return len(m.dropNets) == 0 && len(m.dropASN) == 0 && len(m.nets) == 0 && len(m.asn) == 0
}

// abusiveFinding builds the finding of an address with at least one match. Matches carry the
// lists' text sanitised already. The rank is left out: it says nothing of this address. The first
// match of the strongest list names the finding, which is one whatever its type, so a type that
// rises or falls as the data changes is the same finding.
func abusiveFinding(a netip.Addr, hostnames []string, m abusiveMatches) Finding {
	dropNetworks, dropASNs := make([]string, 0, len(m.dropNets)), make([]string, 0, len(m.dropASN))
	networks, asns := make([]string, 0, len(m.nets)), make([]string, 0, len(m.asn))
	var parts []string
	var dropNetDate, dropASNDate, netDate, asnDate string
	for _, x := range m.dropNets {
		dropNetworks = append(dropNetworks, spaced(x.CIDR, x.SBLID, rirText(x.RIR)))
		parts = append(parts, "Spamhaus DROP network "+x.CIDR+" ("+commas(x.SBLID, x.RIR, "list of "+x.Updated)+")")
		dropNetDate = x.Updated
	}
	for _, x := range m.dropASN {
		dropASNs = append(dropASNs, spaced("AS"+strconv.Itoa(x.ASN), x.ASName, x.Country, x.Domain, rirText(x.RIR)))
		parts = append(parts, "Spamhaus ASN-DROP AS"+strconv.Itoa(x.ASN)+" ("+commas(x.ASName, x.Country, x.Domain, x.RIR, "list of "+x.Updated)+")")
		dropASNDate = x.Updated
	}
	for _, x := range m.nets {
		networks = append(networks, entryText(x.Network, x.ScoreTag, x.AbuseScore, x.Org, x.OrgType))
		parts = append(parts, "abusive network "+entryDetail(x.Network, x.ScoreTag, x.AbuseScore, x.Org, x.OrgType, x.Updated))
		netDate = x.Updated
	}
	for _, x := range m.asn {
		id := "AS" + strconv.Itoa(x.ASN)
		asns = append(asns, entryText(id, x.ScoreTag, x.AbuseScore, x.Org, x.OrgType))
		parts = append(parts, "abusive "+entryDetail(id, x.ScoreTag, x.AbuseScore, x.Org, x.OrgType, x.Updated))
		asnDate = x.Updated
	}
	// The first match of the strongest kind names the finding: the most specific network, else the AS.
	var typ, entry, org string
	switch {
	case len(m.dropNets) > 0:
		typ, entry, org = "drop-network", m.dropNets[0].CIDR, m.dropNets[0].SBLID
	case len(m.dropASN) > 0:
		typ, entry, org = "drop-asn", "AS"+strconv.Itoa(m.dropASN[0].ASN), m.dropASN[0].ASName
	case len(m.nets) > 0:
		typ, entry, org = "network", m.nets[0].Network, m.nets[0].Org
	default:
		typ, entry, org = "asn", "AS"+strconv.Itoa(m.asn[0].ASN), m.asn[0].Org
	}
	addr := a.String()
	return newFinding(AbusiveNetwork, typ, Severity(AbusiveNetwork, typ), addr,
		fmt.Sprintf("address %s is in %s", addr, strings.Join(parts, " and in ")),
		map[string]any{"ip": addr, "hostnames": strings.Join(hostnames, ";"),
			"drop_networks": dropNetworks, "drop_asn": dropASNs, "networks": networks, "asn": asns,
			"drop_networks_updated": dropNetDate, "drop_asn_updated": dropASNDate,
			"networks_updated": netDate, "asns_updated": asnDate, "entry": entry, "org": org})
}

// rirText is a registry as a cell of the risk file reads it, in parentheses, or "" when blank.
func rirText(rir string) string {
	if rir == "" {
		return ""
	}
	return "(" + rir + ")"
}

// spaced joins the non-blank parts with a space, so a field a list leaves empty leaves no gap.
func spaced(parts ...string) string { return joinNonBlank(parts, " ") }

// commas joins the non-blank parts with a comma and a space.
func commas(parts ...string) string { return joinNonBlank(parts, ", ") }

func joinNonBlank(parts []string, sep string) string {
	return strings.Join(slices.DeleteFunc(slices.Clone(parts), func(s string) bool { return s == "" }), sep)
}

// entryText is a match as a cell of the risk file reads it.
func entryText(entry, tag string, score float64, org, typ string) string {
	return fmt.Sprintf("%s %s %s%% %s (%s)", entry, tag, abusive.ScoreText(score), org, typ)
}

// entryDetail is a match as the finding's detail reads it, with the date of its list.
func entryDetail(entry, tag string, score float64, org, typ, updated string) string {
	return fmt.Sprintf("%s (%s, %s%%, %s, %s, list of %s)", entry, tag, abusive.ScoreText(score), org, typ, updated)
}
