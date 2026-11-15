package kinds

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ReportedPort is a TCP service a third party (Shodan) says is open on an
// address. It is shown like an open_port while its address is port-eligible,
// but nothing that decides contact ever reads it.
var ReportedPort = define[ReportedPortAttrs](Kind{Name: "reported_port", Singular: "reported port", Category: "open ports (third-party reported)", PortKey: true, ClosedHides: true})

// ReportedPortAttrs: the banner as cut and escaped by ShodanBanner, and the
// date (YYYY-MM-DD) the third party last saw the service.
type ReportedPortAttrs struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Banner   string `json:"banner"`
	LastSeen string `json:"last_seen,omitempty"`
}

// ParsePortKey parses the key of a PortKey kind ("<address>:<port>"), with the
// address unmapped so that the keys of every port kind compare equal.
func ParsePortKey(key string) (netip.AddrPort, bool) {
	ap, err := netip.ParseAddrPort(key)
	if err != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// EncodeBanner escapes a banner so it is lossless for binary greetings and
// invalid UTF-8, and readable for text. strconv.Unquote reverses it when the
// text is wrapped in double quotes again.
func EncodeBanner(b string) string {
	q := strconv.Quote(b)
	return q[1 : len(q)-1]
}

// ShodanBanner is a third party's banner as it is stored: cut to its first line
// or 256 characters, whichever is shorter, then escaped like nyx's own.
func ShodanBanner(b string) string {
	if i := strings.IndexAny(b, "\r\n"); i >= 0 {
		b = b[:i]
	}
	if utf8.RuneCountInString(b) > maxReportedBanner {
		b = string([]rune(b)[:maxReportedBanner])
	}
	return EncodeBanner(b)
}

// maxReportedBanner is how many characters of a third party's banner are kept.
const maxReportedBanner = 256
