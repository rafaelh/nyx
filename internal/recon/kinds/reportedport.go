package kinds

import (
	"net/netip"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/knowledge/webpage"
	"github.com/rafaelh/nyx/internal/recon/store"
)

// ReportedPort records a third party's open TCP service. It is visible while its address is
// port-eligible, but never grants permission to contact anything.
var ReportedPort = defineKeyed(Kind{Name: "reported_port", Singular: "reported port", Category: "open ports (third-party reported)", PortKey: true, ClosedHides: true, Change: "open port"},
	func(a ReportedPortAttrs) string { return portKey(a.IP, a.Port) },
	func(key string, a *ReportedPortAttrs) { rebuildPort(key, &a.IP, &a.Port) })

// ReportedPortAttrs holds a ShodanBanner-formatted banner and the source's last-seen date.
type ReportedPortAttrs struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Banner   string `json:"banner"`
	LastSeen string `json:"last_seen,omitempty"`
}

// ParsePortKey parses an address/port key and unmaps the address so all port kinds compare
// consistently.
func ParsePortKey(key string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(key)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// portKey formats the canonical address/port key, including brackets for IPv6.
func portKey(ip string, port int) string {
	if addr, err := netip.ParseAddr(ip); err == nil && port >= 0 && port <= 0xffff {
		return netip.AddrPortFrom(addr, uint16(port)).String()
	}
	return ip + ":" + strconv.Itoa(port)
}

// rebuildPort sets an empty *ip and *port from a port key.
func rebuildPort(key string, ip *string, port *int) {
	if *ip != "" {
		return
	}
	if ap, ok := ParsePortKey(key); ok {
		*ip = ap.Addr().String()
		if *port == 0 {
			*port = int(ap.Port())
		}
	}
}

// EncodeBanner preserves binary data and invalid UTF-8 through escaping while keeping text
// readable. DecodeBanner reverses it.
func EncodeBanner(b string) string {
	q := strconv.Quote(b)
	return q[1 : len(q)-1]
}

// DecodeBanner reverses EncodeBanner, leaving unrecognised stored text unchanged.
func DecodeBanner(b string) string {
	if s, err := strconv.Unquote(`"` + b + `"`); err == nil {
		return s
	}
	return b
}

// ShodanBanner keeps the first line or 256 characters, whichever is shorter, then applies the
// same escaping as nyx's own banners.
func ShodanBanner(b string) string {
	if i := strings.IndexAny(b, "\r\n"); i >= 0 {
		b = b[:i]
	}
	return EncodeBanner(webpage.CutRunes(b, maxReportedBanner))
}

// maxReportedBanner is how many characters of a third party's banner are kept.
const maxReportedBanner = 256

// OpenedPorts indexes current open_port records so confirmed ports can supersede third-party
// reports.
func OpenedPorts(recs []store.Record) map[netip.AddrPort]bool {
	opened := map[netip.AddrPort]bool{}
	for _, r := range recs {
		if ap, ok := ParsePortKey(r.Key); ok && r.Current {
			opened[ap] = true
		}
	}
	return opened
}
