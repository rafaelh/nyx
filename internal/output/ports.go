package output

import (
	"net/netip"
	"strconv"
	"strings"

	bannerparse "github.com/rafaelh/nyx/internal/banner"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/store"
)

var openPortColumns = []string{"ip", "port", "banner", "hostnames", "source", "confirmed", "shodan_last_seen", "product", "version"}

// portSources pairs nyx handshake evidence with a third-party report; either may be absent.
type portSources struct {
	open, reports *store.Record
}

// openPortRows merges nyx and third-party reports by canonical address/port key. It records
// sources and confirmation, prefers nyx's banner, and derives recognised SSH/FTP/SMTP product
// versions on read.
//
// Confirmed-closed reports remain as non-current history, while addresses ineligible for port
// checks are omitted entirely. Counts and findings use visibility to suppress closed reports.
func openPortRows(s Snapshot) []Row {
	vis := s.vis()
	byKey := portsByKey(s, vis)
	if len(byKey) == 0 {
		return nil
	}
	hostnames := s.Inv.HostnamesByIP(s.Scope)
	rows := make([]Row, 0, len(byKey))
	for ap, e := range byKey {
		rows = append(rows, e.row(ap, vis, hostnames[ap.Addr()]))
	}
	return rows
}

// portsByKey groups visible open ports and eligible reported ports by address/port.
func portsByKey(s Snapshot, vis *kinds.Visibility) map[netip.AddrPort]*portSources {
	byKey := map[netip.AddrPort]*portSources{}
	entry := func(ap netip.AddrPort) *portSources {
		e := byKey[ap]
		if e == nil {
			e = &portSources{}
			byKey[ap] = e
		}
		return e
	}
	for _, r := range s.of(kinds.OpenPort) {
		if ap, ok := kinds.ParsePortKey(r.Key); ok && vis.Shown(kinds.OpenPort, r) {
			entry(ap).open = &r
		}
	}
	for _, r := range s.of(kinds.ReportedPort) {
		// Use eligibility rather than full visibility so confirmed-closed reports
		// remain as historical rows.
		if ap, ok := kinds.ParsePortKey(r.Key); ok && s.Inv.PortEligible(ap.Addr(), s.Scope) {
			entry(ap).reports = &r
		}
	}
	return byKey
}

// row formats one address/port with its known hostnames.
func (e *portSources) row(ap netip.AddrPort, vis *kinds.Visibility, hostnames []string) Row {
	var banner, seen string
	var sources []string
	current := false
	var first, last string
	note := func(r *store.Record) {
		if first == "" || r.FirstSeen < first {
			first = r.FirstSeen
		}
		if r.LastSeen > last {
			last = r.LastSeen
		}
	}
	if e.reports != nil {
		sources = append(sources, "shodan")
		note(e.reports)
		if e.reports.Current {
			a := kinds.ReportedPort.Attrs(*e.reports)
			banner, seen = a.Banner, a.LastSeen
			current = vis.Shown(kinds.ReportedPort, *e.reports)
		}
	}
	if e.open != nil {
		sources = append([]string{"nyx"}, sources...)
		note(e.open)
		current = current || e.open.Current
		if b := kinds.OpenPort.Attrs(*e.open).Banner; b != "" {
			banner = b
		}
	}
	product, version, _ := bannerparse.Parse(kinds.DecodeBanner(banner))
	return Row{
		Cells: []string{ap.Addr().String(), strconv.Itoa(int(ap.Port())), banner, strings.Join(hostnames, ";"),
			strings.Join(sources, ";"), yesNo(e.open != nil && e.open.Current), seen, product, version},
		Current: current, FirstSeen: first, LastSeen: last,
	}
}
