// Package origin decides which addresses may be the origin server behind a hostname that a CDN or
// WAF fronts, and whether one that answered really is. Both decisions are pure: the origincheck
// stage and the findings call the same functions on the same records, so they cannot disagree.
package origin

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/scope"
)

// How a candidate was found, in the order a candidate lists them.
const (
	historical         = "historical"
	siblingCertificate = "sibling-certificate"
	siblingTitle       = "sibling-title"
)

var howOrder = []string{historical, siblingCertificate, siblingTitle}

// Front is an in-scope hostname behind a CDN or WAF: the provider and the title its probe saw.
type Front struct{ Host, Provider, Title string }

// HistoricalAddr is an address a fronted hostname once resolved to. LastSeen is YYYY-MM-DD or "".
type HistoricalAddr struct {
	Host     string
	Addr     netip.Addr
	LastSeen string
}

// Service is a probed web service of a hostname: its page title and the DNS names its certificate
// carries.
type Service struct {
	Host, Title string
	Names       []string
}

// Candidate is an address that may be the origin of Host, how it was found (in the order of the
// constants above) and whether it may be contacted: it is port-eligible, which is to say inside an
// in-scope netblock, or the current address of an in-scope host with a known, dedicated owner, and
// is not excluded.
type Candidate struct {
	Host, Provider string
	Addr           netip.Addr
	Found          []string
	Contactable    bool
}

// Candidates returns, for each fronted hostname in name order, up to max candidate addresses:
// historical addresses most recent first, then the addresses of siblings in sibling name order. An
// address qualifies only if its owner is known and it is not shared provider infrastructure. A
// sibling is another in-scope, non-wildcard-only hostname that is not itself behind a CDN or WAF
// and has a service whose certificate names the fronted host, or whose title is the fronted host's
// (neither empty nor on the list of CDN, WAF and default-server titles).
func Candidates(fronts []Front, hist []HistoricalAddr, services []Service, inv *inventory.Inventory, sc *scope.Scope, max int) []Candidate {
	fronts = slices.SortedFunc(slices.Values(fronts), func(a, b Front) int { return strings.Compare(a.Host, b.Host) })
	addrs := inv.Addrs()
	sibs := newSiblings(addrs, services, inv, sc)
	histOf := map[string][]HistoricalAddr{}
	for _, h := range hist {
		histOf[h.Host] = append(histOf[h.Host], h)
	}

	var out []Candidate
	for _, f := range fronts {
		c := &candidateSet{front: f, max: max, inv: inv, sc: sc, at: map[netip.Addr]int{}}
		mine := slices.Clone(histOf[f.Host])
		slices.SortStableFunc(mine, func(a, b HistoricalAddr) int {
			return cmp.Or(cmp.Compare(b.LastSeen, a.LastSeen), a.Addr.Compare(b.Addr))
		})
		for _, h := range mine {
			c.add(h.Addr, historical)
		}
		match := sibs.matches(f)
		for _, i := range slices.Sorted(maps.Keys(match)) {
			for _, a := range addrs[sibs.names[i]] {
				if match[i]&byCert != 0 {
					c.add(a, siblingCertificate)
				}
				if match[i]&byTitl != 0 {
					c.add(a, siblingTitle)
				}
			}
		}
		for i := range c.found {
			slices.SortStableFunc(c.found[i].Found, func(a, b string) int {
				return cmp.Compare(slices.Index(howOrder, a), slices.Index(howOrder, b))
			})
		}
		out = append(out, c.found...)
	}
	return out
}

// The ways a sibling matches a fronted host, as bits.
const byCert, byTitl = 1, 2

// siblings are the in-scope, non-wildcard-only hosts with an address that are not themselves
// fronted, in name order, and the siblings (by index, so in name order) that each certificate
// name and each title points at.
type siblings struct {
	names          []string
	bySAN, byTitle map[string][]int
}

func newSiblings(addrs map[string][]netip.Addr, services []Service, inv *inventory.Inventory, sc *scope.Scope) *siblings {
	s := &siblings{bySAN: map[string][]int{}, byTitle: map[string][]int{}}
	for _, name := range slices.Sorted(maps.Keys(addrs)) {
		if inv.WildcardOnly()[name] || !sc.HostInScope(name) {
			continue
		}
		if _, fronted := inv.Fronted(name); !fronted {
			s.names = append(s.names, name)
		}
	}
	index := make(map[string]int, len(s.names))
	for i, name := range s.names {
		index[name] = i
	}
	for _, svc := range services {
		i, ok := index[svc.Host]
		if !ok {
			continue
		}
		for _, n := range svc.Names {
			s.bySAN[strings.ToLower(n)] = append(s.bySAN[strings.ToLower(n)], i)
		}
		s.byTitle[svc.Title] = append(s.byTitle[svc.Title], i)
	}
	return s
}

// matches maps the index of each sibling that matches the fronted host to how it matches: a
// certificate that names the host, or the host's title (neither empty nor a default title).
func (s *siblings) matches(f Front) map[int]int {
	match := map[int]int{}
	for _, n := range CertNames(f.Host) {
		for _, i := range s.bySAN[n] {
			match[i] |= byCert
		}
	}
	if f.Title != "" && !DefaultTitle(f.Title) {
		for _, i := range s.byTitle[f.Title] {
			match[i] |= byTitl
		}
	}
	return match
}

// candidateSet collects the candidates of one fronted host, in the order they were found.
type candidateSet struct {
	front Front
	max   int
	inv   *inventory.Inventory
	sc    *scope.Scope
	found []Candidate
	at    map[netip.Addr]int // the index in found of each address
}

// add records that an address was found a way. An address qualifies only if its owner is known
// and it is not shared provider infrastructure.
func (c *candidateSet) add(a netip.Addr, how string) {
	a = a.Unmap()
	if i, ok := c.at[a]; ok {
		if !slices.Contains(c.found[i].Found, how) {
			c.found[i].Found = append(c.found[i].Found, how)
		}
		return
	}
	// Past the cap a new address is dropped; one already kept may still gain a way.
	if len(c.found) >= c.max || !c.inv.OwnerKnown(a, c.sc) || c.inv.Shared(a) {
		return
	}
	c.at[a] = len(c.found)
	c.found = append(c.found, Candidate{Host: c.front.Host, Provider: c.front.Provider, Addr: a, Found: []string{how}, Contactable: c.inv.PortEligible(a, c.sc)})
}

// Probe is what the probe saw of a fronted hostname: its status, title and body length.
type Probe struct {
	Status  int
	Title   string
	BodyLen int
}

// Answer is what a candidate origin answered for the hostname.
type Answer struct {
	Status        int
	Title         string
	BodyLen       int
	CertNamesHost bool
}

// What confirmed an exposure.
const (
	ByTitle = "title"
	ByBody  = "status-body-certificate"
)

// Confirmed reports whether the answer shows the candidate serves the hostname's site, and by what:
// a non-empty title equal to the probe's that is not a CDN, WAF or default-server title, or the
// same status, a body length within 10% of the probe's and a certificate that names the host. A
// certificate alone is not enough, and a redirect confirms nothing.
func Confirmed(p Probe, a Answer) (by string, ok bool) {
	if a.Status >= 300 && a.Status < 400 {
		return "", false
	}
	if a.Title != "" && a.Title == p.Title && !DefaultTitle(a.Title) {
		return ByTitle, true
	}
	if a.CertNamesHost && a.Status == p.Status && p.BodyLen > 0 && 10*abs(a.BodyLen-p.BodyLen) <= p.BodyLen {
		return ByBody, true
	}
	return "", false
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// defaultTitles are the phrases that mark a title as one a CDN, a WAF or a default server page
// shows, in lower case. A title that contains one is not evidence of anything: the same page is
// served to every host in front of that product.
var defaultTitles = []string{
	"attention required", "just a moment", "access denied", "access forbidden", "403 forbidden", "404 not found",
	"bad gateway", "gateway time-out", "service unavailable", "request blocked", "request rejected",
	"request unsuccessful", "domain not found", "site not found", "invalid url", "error 10", "error 52",
	"default web site", "iis windows server", "welcome to nginx", "welcome to openresty", "apache2",
	"test page for the apache", "fastly error", "incapsula", "sucuri website firewall", "ddos protection by",
	"checking your browser", "security check", "one moment, please",
}

// DefaultTitle reports whether a title is one a CDN, a WAF or a default server page shows.
func DefaultTitle(title string) bool {
	t := strings.ToLower(strings.TrimSpace(title))
	return t != "" && slices.ContainsFunc(defaultTitles, func(d string) bool { return strings.Contains(t, d) })
}

// CertNames are the certificate DNS names, in lower case, that name the host: the host itself and,
// if it has a parent, the wildcard that stands for its first label.
func CertNames(host string) []string {
	host = strings.ToLower(host)
	names := []string{host}
	if label, tail, ok := strings.Cut(host, "."); ok && label != "" {
		names = append(names, "*."+tail)
	}
	return names
}
