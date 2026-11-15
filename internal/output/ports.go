package output

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/store"
)

var openPortColumns = []string{"ip", "port", "banner", "hostnames", "source", "confirmed", "shodan_last_seen"}

// portSources is what is known of one address and port: nyx's own handshake and
// the third party's report, either of which may be missing.
type portSources struct {
	open, reports *store.Record
}

// openPortRows lists the ports nyx found open and the ports a third party
// reports, one row for each address and port. source says who knows it (nyx,
// shodan, or nyx;shodan) and confirmed whether nyx completed a handshake. The
// banner is nyx's when it has one, else the third party's. The record keys are
// authoritative for the address and port.
//
// A reported port nyx found closed is still listed, as a row that is not
// current: the showing rule hides it from the counts and findings, and the file
// keeps what was once reported. A row for an address that may not be port-checked
// is not listed at all.
func openPortRows(s Snapshot) []Row {
	byKey := map[netip.AddrPort]*portSources{}
	entry := func(ap netip.AddrPort) *portSources {
		e := byKey[ap]
		if e == nil {
			e = &portSources{}
			byKey[ap] = e
		}
		return e
	}
	vis := s.vis()
	for _, r := range s.of(kinds.OpenPort) {
		if ap, ok := kinds.ParsePortKey(r.Key); ok && vis.Shown(kinds.OpenPort, r) {
			entry(ap).open = &r
		}
	}
	for _, r := range s.of(kinds.ReportedPort) {
		// Eligibility alone: the showing rule also drops a closed port, which this
		// file keeps as a row that is not current.
		if ap, ok := kinds.ParsePortKey(r.Key); ok && s.Inv.PortEligible(ap.Addr(), s.Scope) {
			entry(ap).reports = &r
		}
	}
	if len(byKey) == 0 {
		return nil
	}
	hostnames := s.Inv.HostnamesByIP(s.Scope)
	rows := make([]Row, 0, len(byKey))
	for ap, e := range byKey {
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
		rows = append(rows, Row{
			Cells: []string{ap.Addr().String(), strconv.Itoa(int(ap.Port())), banner, strings.Join(hostnames[ap.Addr()], ";"),
				strings.Join(sources, ";"), yesNo(e.open != nil && e.open.Current), seen},
			Current: current, FirstSeen: first, LastSeen: last,
		})
	}
	return rows
}
