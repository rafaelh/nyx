// Package origin selects and confirms possible servers behind CDN/WAF hostnames. Stages and
// findings share these pure decisions so checked and reported origins agree.
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

// Service supplies a probed title and certificate names for sibling matching.
type Service struct {
	Host, Title string
	Names       []string
}

// Candidate pairs a fronted host with a possible origin address and discovery method. Contact
// requires port eligibility and no exclusion: an in-scope netblock or a known dedicated address
// used by an in-scope host.
type Candidate struct {
	Host, Provider string
	Addr           netip.Addr
	Found          []string
	Contactable    bool
}

// Candidates returns up to max addresses per fronted hostname in name order. Recent historical
// addresses precede sibling-derived addresses. Candidates need known, non-shared ownership.
// Siblings are in-scope, non-wildcard hosts outside CDN/WAF hosting whose certificate names the
// fronted host or whose meaningful page title matches it.
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

// siblings indexes unfronted in-scope hosts by certificate names and titles. Host indexes
// preserve name order for deterministic candidate selection.
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

// matches identifies siblings whose certificates name the fronted host or whose meaningful
// titles match it.
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

// add records a discovery method only for addresses with known, dedicated ownership.
func (c *candidateSet) add(a netip.Addr, how string) {
	a = a.Unmap()
	if i, ok := c.at[a]; ok {
		if !slices.Contains(c.found[i].Found, how) {
			c.found[i].Found = append(c.found[i].Found, how)
		}
		return
	}
	// After the cap, existing candidates can gain evidence but new addresses are dropped.
	if len(c.found) >= c.max || !c.inv.OwnerKnown(a, c.sc) || c.inv.Shared(a) {
		return
	}
	c.at[a] = len(c.found)
	c.found = append(c.found, Candidate{Host: c.front.Host, Provider: c.front.Provider, Addr: a, Found: []string{how}, Contactable: c.inv.PortEligible(a, c.sc)})
}

// Probe holds the fronted site's status, title and body length for comparison.
type Probe struct {
	Status  int
	Title   string
	BodyLen int
}

// Answer holds a candidate origin's response for the fronted hostname.
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

// Confirmed requires a meaningful matching title, or matching status plus body length within
// 10% and a certificate naming the host. Certificates alone and redirects do not confirm an
// origin.
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

// defaultTitles excludes generic CDN/WAF/server titles because the same page can appear for
// unrelated hosts.
var defaultTitles = []string{
	"attention required", "just a moment", "access denied", "access forbidden", "403 forbidden", "404 not found",
	"bad gateway", "gateway time-out", "service unavailable", "request blocked", "request rejected",
	"request unsuccessful", "domain not found", "site not found", "invalid url", "error 10", "error 52",
	"default web site", "iis windows server", "welcome to nginx", "welcome to openresty", "apache2",
	"test page for the apache", "fastly error", "incapsula", "sucuri website firewall", "ddos protection by",
	"checking your browser", "security check", "one moment, please",
}

// DefaultTitle identifies generic CDN/WAF/server pages unsuitable for matching.
func DefaultTitle(title string) bool {
	t := strings.ToLower(strings.TrimSpace(title))
	return t != "" && slices.ContainsFunc(defaultTitles, func(d string) bool { return strings.Contains(t, d) })
}

// CertNames returns lowercase exact and single-label wildcard certificate names that could
// cover host.
func CertNames(host string) []string {
	host = strings.ToLower(host)
	names := []string{host}
	if label, tail, ok := strings.Cut(host, "."); ok && label != "" {
		names = append(names, "*."+tail)
	}
	return names
}
