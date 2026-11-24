// Package inventory derives shared views of stored records for output, procedures and egress
// policy. It identifies wildcard-only names, provider infrastructure and addresses eligible for
// port checks. These views are recalculated from records so new discoveries and updated
// provider data take effect immediately.
package inventory

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/scope"
)

// Host is a hostname record and the procedures currently observing it.
type Host struct {
	Name      string
	Producers []string
}

// Resolution represents a DNS answer. A/AAAA rows associate the queried name with an address;
// CNAME rows associate an alias with its target. SRV rows contain "priority weight port target"
// and advertise ports only; their service names are not hostnames.
type Resolution struct{ Name, Type, Value string }

// Wildcard is a zone that answers for names that do not exist.
type Wildcard struct {
	Zone  string
	Addrs []netip.Addr
	CNAME string
}

// IPHostname is a hostname seen for an address, by a source ("rdns", "shodan").
type IPHostname struct {
	IP               netip.Addr
	Hostname, Source string
}

// Registration describes a registry's address allocation found by looking up an address within
// it. Key combines the registry and its range handle.
type Registration struct {
	Key                  string
	Start, End           netip.Addr
	Registrant, Registry string
}

// Contains reports whether the address is inside the registered range.
func (r Registration) Contains(a netip.Addr) bool {
	return a.Compare(r.Start) >= 0 && a.Compare(r.End) <= 0
}

// ServerAddress supports name-server and mail-host ownership checks. It does not make the host
// resolved, eligible for probing or eligible for port checks.
type ServerAddress struct {
	Host string
	Addr netip.Addr
}

// Data supplies the records used to build an Inventory.
type Data struct {
	Hosts       []Host
	Resolutions []Resolution
	Wildcards   []Wildcard
	IPs         []netip.Addr
	Owners      map[netip.Addr]provider.Owner
	Ranges      *provider.Ranges
	IPHostnames []IPHostname
	// ClosedPorts contains ports rejected during nyx's own connection attempts.
	ClosedPorts   []netip.AddrPort
	Registrations []Registration
	// ServerAddresses are the addresses of name servers and mail hosts, for SelfHosted only.
	ServerAddresses []ServerAddress
}

// ProviderHost is a hostname that is on shared provider infrastructure.
type ProviderHost struct {
	Hostname, Provider, Service string
	Evidence                    string // cname, range or asn
	CNAME                       string // the matching chain target, for cname evidence
	Resolves                    bool
	// Entry is the providers.yaml match for CNAME evidence. Its fingerprint indicates
	// claimability. Range and ASN evidence leave it empty.
	Entry provider.Entry
}

// IPRow represents an ips.csv row. Service uses the provider's service name when available,
// otherwise its region.
type IPRow struct {
	IP                       netip.Addr
	ASN                      int
	Owner, Provider, Service string
	InScope, PortEligible    bool
	Hostnames                []string
	// Registry allocation containing this address, with its registrant and source registry.
	Registrant, RegistrantNetblock, Registry string
	// SRVPorts lists advertised ports for in-scope hostnames. These are reported without
	// connecting to them.
	SRVPorts []uint16
}

// Inventory is an immutable derived view of Data.
type Inventory struct {
	d    Data
	db   *provider.DB
	addr map[string][]netip.Addr // queried name -> addresses
	cn   map[string][]string     // alias -> targets
	srv  map[string][]uint16     // SRV target -> advertised ports
	wo   map[string]bool
	zone map[string]bool // zones with a current wildcard record
	// cnameShared marks addresses whose hostnames lead to a known provider through CNAMEs.
	cnameShared map[netip.Addr]provider.Match

	mu    sync.Mutex
	class map[netip.Addr]provider.Result
	regOf map[netip.Addr]int // cached regs index, or -1 when no registration matches

	closed map[netip.AddrPort]bool // ports nyx found closed, with unmapped addresses

	hosts map[*scope.Scope]map[netip.Addr][]string // see HostnamesByIP; guarded by mu

	servers map[string][]netip.Addr // name server or mail host -> looked-up addresses

	regs       []Registration // registrations ordered by descending start address for narrowest-match lookup
	registrant sync.Once
	byName     map[string]registrantInfo
}

// registrantInfo tracks the evidence needed to classify an organisation as a candidate.
type registrantInfo struct {
	ranges int  // distinct registered netblocks
	shared bool // whether any recorded address in these ranges uses shared infrastructure
}

func New(d Data, db *provider.DB) *Inventory {
	i := &Inventory{d: d, db: db, addr: map[string][]netip.Addr{}, cn: map[string][]string{}, srv: map[string][]uint16{},
		wo: map[string]bool{}, zone: map[string]bool{}, closed: map[netip.AddrPort]bool{},
		class: map[netip.Addr]provider.Result{}, regOf: map[netip.Addr]int{}, cnameShared: map[netip.Addr]provider.Match{}, servers: map[string][]netip.Addr{},
		hosts: map[*scope.Scope]map[netip.Addr][]string{}}
	for _, s := range d.ServerAddresses {
		host := dnsname.Normalise(s.Host)
		i.servers[host] = append(i.servers[host], s.Addr.Unmap())
	}
	for _, r := range d.Resolutions {
		switch r.Type {
		case "A", "AAAA":
			if a, err := netip.ParseAddr(r.Value); err == nil {
				i.addr[r.Name] = append(i.addr[r.Name], a.Unmap())
			}
		case "CNAME":
			i.cn[r.Name] = append(i.cn[r.Name], r.Value)
		case "SRV":
			// SRV port zero means the service is unavailable, like a null target.
			if port, target, ok := dnsname.SRV(r.Value); ok && port != 0 {
				i.srv[target] = append(i.srv[target], port)
			}
		}
	}
	for _, ap := range d.ClosedPorts {
		i.closed[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = true
	}
	i.regs = slices.Clone(d.Registrations)
	slices.SortFunc(i.regs, func(a, b Registration) int {
		return cmp.Or(b.Start.Compare(a.Start), a.End.Compare(b.End), strings.Compare(a.Key, b.Key))
	})
	wild := map[string]Wildcard{}
	for _, w := range d.Wildcards {
		wild[w.Zone] = w
		i.zone[w.Zone] = true
	}
	// Choose the first hostname in sorted order so shared-address labels remain stable
	// between runs.
	for _, name := range slices.Sorted(maps.Keys(i.addr)) {
		if m, ok := i.chainProvider(name); ok {
			for _, a := range i.addr[name] {
				if _, seen := i.cnameShared[a]; !seen {
					i.cnameShared[a] = m
				}
			}
		}
	}
	for _, h := range d.Hosts {
		if w, ok := wild[parent(h.Name)]; ok && i.matchesWildcard(h.Name, w) {
			i.wo[h.Name] = true
		}
	}
	return i
}

// chainProviders follows the first CNAME target for up to eight hops, yielding provider suffix
// matches until the callback stops.
func (i *Inventory) chainProviders(name string, yield func(target string, e provider.Entry) bool) {
	cur := name
	for range 8 {
		targets := i.cn[cur]
		if len(targets) == 0 {
			return
		}
		for _, t := range targets {
			if e, ok := i.db.CNAMEEntry(t); ok && !yield(t, e) {
				return
			}
		}
		cur = targets[0]
	}
}

// chainProvider finds the first provider match along a name's CNAME chain.
func (i *Inventory) chainProvider(name string) (m provider.Match, ok bool) {
	i.chainProviders(name, func(_ string, e provider.Entry) bool {
		m, ok = e.Match, true
		return false
	})
	return m, ok
}

func parent(name string) string {
	_, rest, _ := strings.Cut(name, ".")
	return rest
}

func (i *Inventory) matchesWildcard(name string, w Wildcard) bool {
	if w.CNAME != "" && slices.Contains(i.cn[name], w.CNAME) {
		return true
	}
	return slices.ContainsFunc(w.Addrs, func(wa netip.Addr) bool { return slices.Contains(i.addr[name], wa.Unmap()) })
}

// Addrs maps queried names to unmapped A/AAAA addresses. Treat the map as read-only.
func (i *Inventory) Addrs() map[string][]netip.Addr { return i.addr }

// WildcardOnly is the set of names that resolve only because of a wildcard.
func (i *Inventory) WildcardOnly() map[string]bool { return i.wo }

// Representatives chooses the alphabetically first resolving, in-scope wildcard-only name for
// each zone, ensuring the representative can be probed.
func (i *Inventory) Representatives(sc *scope.Scope) map[string]string {
	reps := map[string]string{}
	for name := range i.wo {
		if len(i.addr[name]) == 0 || !sc.HostInScope(name) {
			continue
		}
		zone := parent(name)
		if cur, ok := reps[zone]; !ok || name < cur {
			reps[zone] = name
		}
	}
	return reps
}

// WildcardZone identifies zones that answer for arbitrary names. Generating more names directly
// beneath them would not reveal distinct hosts.
func (i *Inventory) WildcardZone(name string) bool { return i.zone[name] }

// Seeds selects in-scope names observed by procedures other than the generator. It excludes
// wildcard-only names and names whose parent is outside scope or a wildcard zone. This avoids
// splitting an apex at its public suffix and feeding generated names back into discovery.
func (i *Inventory) Seeds(sc *scope.Scope, generator string) []string {
	var out []string
	for _, h := range i.d.Hosts {
		if i.wo[h.Name] || i.zone[parent(h.Name)] || !sc.HostInScope(h.Name) ||
			!sc.HostInScope(parent(h.Name)) {
			continue
		}
		if slices.ContainsFunc(h.Producers, func(s string) bool { return s != generator }) {
			out = append(out, h.Name)
		}
	}
	slices.Sort(out)
	return out
}

func (i *Inventory) result(a netip.Addr) provider.Result {
	a = a.Unmap()
	i.mu.Lock()
	defer i.mu.Unlock()
	if r, ok := i.class[a]; ok {
		return r
	}
	r := i.db.Classify(a, i.d.Owners[a], i.d.Ranges)
	// A provider CNAME establishes shared hosting even when range or ASN data suggests
	// dedicated hosting, as with Heroku on EC2.
	if m, ok := i.cnameShared[a]; ok && !r.Shared {
		r = provider.Result{Known: true, Shared: true, Provider: m.Provider, Service: m.Service, Evidence: "cname"}
	}
	i.class[a] = r
	return r
}

// RegistrationOf caches the narrowest registered range containing each address.
func (i *Inventory) RegistrationOf(a netip.Addr) (Registration, bool) {
	a = a.Unmap()
	i.mu.Lock()
	n, ok := i.regOf[a]
	if !ok {
		n = slices.IndexFunc(i.regs, func(r Registration) bool { return r.Contains(a) })
		i.regOf[a] = n
	}
	i.mu.Unlock()
	if n < 0 {
		return Registration{}, false
	}
	return i.regs[n], true
}

// RegistrantCandidate requires at least three distinct registered ranges, no recorded
// shared-provider address in those ranges, and no match to an --org input under orgname's word
// rules.
func (i *Inventory) RegistrantCandidate(sc *scope.Scope, name string) bool {
	i.registrant.Do(i.indexRegistrants)
	info := i.byName[name]
	return info.ranges >= 3 && !info.shared && !sc.MatchesOrg(name)
}

// indexRegistrants counts distinct ranges per registrant and flags ranges containing shared
// addresses.
func (i *Inventory) indexRegistrants() {
	i.byName = map[string]registrantInfo{}
	seen := map[string]bool{}
	for _, r := range i.regs {
		if r.Registrant != "" && !seen[r.Key] {
			seen[r.Key] = true
			info := i.byName[r.Registrant]
			info.ranges++
			i.byName[r.Registrant] = info
		}
	}
	if len(i.byName) == 0 {
		return
	}
	known := map[netip.Addr]bool{}
	for _, a := range i.d.IPs {
		known[a.Unmap()] = true
	}
	for _, as := range i.addr {
		for _, a := range as {
			known[a] = true
		}
	}
	for _, h := range i.d.IPHostnames {
		known[h.IP.Unmap()] = true
	}
	for a := range known {
		if !i.Shared(a) {
			continue
		}
		for _, r := range i.regs {
			if r.Registrant != "" && r.Contains(a) {
				info := i.byName[r.Registrant]
				info.shared = true
				i.byName[r.Registrant] = info
			}
		}
	}
}

// SelfHosted checks whether a mail host or name server appears to belong to the organisation,
// making its other users useful evidence. In-scope servers qualify directly. Others need
// AddressDecides and a port-eligible address: an in-scope netblock address, or a known
// dedicated address used by an in-scope host. Without an address record, only in-scope servers
// qualify.
func (i *Inventory) SelfHosted(host string, sc *scope.Scope) bool {
	host = dnsname.Normalise(host)
	if sc.HostInScope(host) {
		return true
	}
	return AddressDecides(host, sc, i.db) &&
		slices.ContainsFunc(i.servers[host], func(a netip.Addr) bool { return i.PortEligible(a, sc) })
}

// AddressDecides identifies servers that need address lookups for SelfHosted. In-scope servers
// already qualify; excluded servers and known managed DNS/mail providers cannot qualify through
// addresses.
func AddressDecides(host string, sc *scope.Scope, db *provider.DB) bool {
	if c := sc.ClassifyHost(host).Class; c == scope.InScope || c == scope.Excluded {
		return false
	}
	_, ok := db.DomainOwner(host)
	return !ok
}

// Shared reports whether the address is shared provider infrastructure.
func (i *Inventory) Shared(a netip.Addr) bool { return i.result(a).Shared }

// Owner returns origin-AS information from ip_owner; Known is false when no record exists.
func (i *Inventory) Owner(a netip.Addr) provider.Owner { return i.d.Owners[a.Unmap()] }

// OwnerKnown accepts addresses covered by an in-scope netblock, an owner record or a provider
// range.
func (i *Inventory) OwnerKnown(a netip.Addr, sc *scope.Scope) bool {
	return sc.InScopeIP(a.Unmap()) || i.result(a).Known
}

// PortEligible shares the port-checking decision used by the sweep, open-port visibility and
// ips.csv. Egress applies the same scope.PortEligible rules from its policy.
func (i *Inventory) PortEligible(a netip.Addr, sc *scope.Scope) bool {
	ok, _, _ := sc.PortEligible(a, i.owner)
	return ok
}

// PortEligible checks netblocks itself; this callback only supplies provider ownership.
func (i *Inventory) owner(a netip.Addr) (shared, known bool) {
	r := i.result(a)
	return r.Shared, r.Known
}

// PortClosed reports whether nyx found the port closed.
func (i *Inventory) PortClosed(ap netip.AddrPort) bool {
	return i.closed[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())]
}

// ProbeHostnames returns resolved in-scope names after exclusions, with one representative per
// wildcard zone instead of every wildcard-only name.
func (i *Inventory) ProbeHostnames(sc *scope.Scope) []string {
	set := map[string]bool{}
	for name, addrs := range i.addr {
		if len(addrs) > 0 && !i.wo[name] && sc.HostInScope(name) {
			set[name] = true
		}
	}
	for _, rep := range i.Representatives(sc) {
		set[rep] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// ProviderHosts identifies in-scope names on shared infrastructure using CNAME suffixes,
// address ranges or ASNs. CNAME evidence can identify dangling services too.
func (i *Inventory) ProviderHosts(sc *scope.Scope) []ProviderHost {
	names := map[string]bool{}
	for _, h := range i.d.Hosts {
		names[h.Name] = true
	}
	for n := range i.addr {
		names[n] = true
	}
	var out []ProviderHost
	for _, n := range slices.Sorted(maps.Keys(names)) {
		if i.wo[n] || !sc.HostInScope(n) {
			continue
		}
		resolves := len(i.addr[n]) > 0
		seen := map[string]bool{}
		add := func(p ProviderHost) {
			k := p.Provider + "|" + p.Service + "|" + p.Evidence + "|" + p.CNAME
			if !seen[k] {
				seen[k] = true
				out = append(out, p)
			}
		}
		i.chainProviders(n, func(t string, e provider.Entry) bool {
			add(ProviderHost{Hostname: n, Provider: e.Provider, Service: e.Service, Evidence: "cname", CNAME: t, Resolves: resolves, Entry: e})
			return true
		})
		for _, a := range i.addr[n] {
			if r := i.result(a); r.Shared && r.Provider != "" && r.Evidence != "cname" {
				add(ProviderHost{Hostname: n, Provider: r.Provider, Service: r.Service, Evidence: r.Evidence, Resolves: true})
			}
		}
	}
	return out
}

// SaaSServed identifies SaaS hosting through a CNAME chain, address range or ASN. IP literals
// are classified using their address alone.
func (i *Inventory) SaaSServed(host string) bool {
	_, ok := i.served(host,
		func(e provider.Entry) bool { return e.Class == provider.ClassSaaS },
		func(r provider.Result) bool { return r.Class == provider.ClassSaaS })
	return ok
}

// ProviderServed identifies shared hosting of any class, including CDN and SaaS, using CNAMEs
// or address ownership. IP literals use address evidence alone.
func (i *Inventory) ProviderServed(host string) bool {
	_, ok := i.served(host,
		func(provider.Entry) bool { return true },
		func(r provider.Result) bool { return r.Shared })
	return ok
}

// Fronted identifies CDN/WAF hosting and its provider from a matching CNAME or CDN-classified
// address.
func (i *Inventory) Fronted(host string) (string, bool) {
	return i.served(host,
		func(e provider.Entry) bool { return e.Class == provider.ClassCDN || e.Class == provider.ClassWAF },
		func(r provider.Result) bool { return r.Class == provider.ClassCDN && r.Provider != "" })
}

// served returns the first provider accepted by the CNAME or address predicate. IP literals use
// only byAddr.
func (i *Inventory) served(host string, byCNAME func(provider.Entry) bool, byAddr func(provider.Result) bool) (string, bool) {
	host = dnsname.Normalise(host)
	if a, ok := input.IPLiteral(host); ok {
		if r := i.result(a); byAddr(r) {
			return r.Provider, true
		}
		return "", false
	}
	name, found := "", false
	i.chainProviders(host, func(_ string, e provider.Entry) bool {
		if found = byCNAME(e); found {
			name = e.Provider
		}
		return !found
	})
	if found {
		return name, true
	}
	for _, a := range i.addr[host] {
		if r := i.result(a); byAddr(r) {
			return r.Provider, true
		}
	}
	return "", false
}

// HostnamesByIP maps known addresses to sorted, non-excluded DNS and rDNS names for ips.csv. It
// is cached per scope; treat the map and slices as read-only.
func (i *Inventory) HostnamesByIP(sc *scope.Scope) map[netip.Addr][]string {
	i.mu.Lock()
	out, ok := i.hosts[sc]
	i.mu.Unlock()
	if ok {
		return out
	}
	out = map[netip.Addr][]string{}
	for a, names := range i.namesByIP(sc) {
		out[a] = slices.Sorted(maps.Keys(names))
	}
	i.mu.Lock()
	i.hosts[sc] = out
	i.mu.Unlock()
	return out
}

// KnownAddrs returns the sorted addresses indexed by HostnamesByIP.
func (i *Inventory) KnownAddrs(sc *scope.Scope) []netip.Addr {
	return slices.SortedFunc(maps.Keys(i.HostnamesByIP(sc)), netip.Addr.Compare)
}

func (i *Inventory) namesByIP(sc *scope.Scope) map[netip.Addr]map[string]bool {
	byIP := map[netip.Addr]map[string]bool{}
	touch := func(a netip.Addr) map[string]bool {
		a = a.Unmap()
		if byIP[a] == nil {
			byIP[a] = map[string]bool{}
		}
		return byIP[a]
	}
	for _, a := range i.d.IPs {
		touch(a)
	}
	for _, h := range i.d.IPHostnames {
		names := touch(h.IP)
		if sc.ClassifyHost(h.Hostname).Class != scope.Excluded {
			names[h.Hostname] = true
		}
	}
	for name, addrs := range i.addr {
		if i.wo[name] || sc.ClassifyHost(name).Class == scope.Excluded {
			continue
		}
		for _, a := range addrs {
			touch(a)[name] = true
		}
	}
	return byIP
}

// IPRows adds ownership, provider labels and port eligibility to every known address, using the
// same eligibility decision as egress.
func (i *Inventory) IPRows(sc *scope.Scope) []IPRow {
	hostnames := i.HostnamesByIP(sc)
	rows := make([]IPRow, 0, len(hostnames))
	for a, names := range hostnames {
		res := i.result(a)
		owner := i.d.Owners[a]
		row := IPRow{IP: a, Provider: res.Provider, Service: cmp.Or(res.Service, res.Region), InScope: sc.InScopeIP(a),
			PortEligible: i.PortEligible(a, sc), Hostnames: names}
		switch {
		case owner.Known:
			row.ASN, row.Owner = owner.ASN, owner.Holder
			if row.Owner == "" {
				row.Owner = fmt.Sprintf("AS%d", owner.ASN)
			}
		case row.InScope:
			row.Owner = "in-scope netblock"
		case res.Provider != "":
			row.Owner = res.Provider
		}
		if row.Owner == "" {
			row.Owner = "unknown"
		}
		if reg, ok := i.RegistrationOf(a); ok {
			row.Registrant, row.Registry, row.RegistrantNetblock = reg.Registrant, reg.Registry, rangeText(reg.Start, reg.End)
		}
		row.SRVPorts = i.srvPorts(names, sc)
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(x, y IPRow) int { return x.IP.Compare(y.IP) })
	return rows
}

// srvPorts collects sorted, distinct advertised ports for in-scope names. Out-of-scope SRV
// targets do not contribute ports.
func (i *Inventory) srvPorts(names []string, sc *scope.Scope) []uint16 {
	var ports []uint16
	for _, n := range names {
		if p := i.srv[n]; len(p) > 0 && sc.HostInScope(n) {
			ports = append(ports, p...)
		}
	}
	slices.Sort(ports)
	return slices.Compact(ports)
}

// rangeText uses one CIDR when it exactly covers the registered range, otherwise its endpoints.
func rangeText(start, end netip.Addr) string {
	if t := input.RangeText(start, end); t != "" {
		return t
	}
	return start.Unmap().String() + "-" + end.Unmap().String() // preserve endpoints when the range is invalid
}
