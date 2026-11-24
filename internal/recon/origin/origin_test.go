package origin_test

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/origin"
	"github.com/rafaelh/nyx/internal/scope"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// world builds an inventory and scope for example.com, with 198.51.100.0/24 in scope and
// 198.51.100.200 excluded.
type world struct {
	d inventory.Data
}

func (w *world) host(name string, addrs ...string) {
	for _, a := range addrs {
		w.d.Resolutions = append(w.d.Resolutions, inventory.Resolution{Name: name, Type: "A", Value: a})
		w.d.IPs = append(w.d.IPs, ip(a))
	}
	w.d.Hosts = append(w.d.Hosts, inventory.Host{Name: name, Producers: []string{"crtsh"}})
}

func (w *world) cname(name, target string) {
	w.d.Resolutions = append(w.d.Resolutions, inventory.Resolution{Name: name, Type: "CNAME", Value: target})
}

func (w *world) owner(asn int, addrs ...string) {
	if w.d.Owners == nil {
		w.d.Owners = map[netip.Addr]provider.Owner{}
	}
	for _, a := range addrs {
		w.d.Owners[ip(a)] = provider.Owner{ASN: asn, Holder: "ACME-NET", Known: true}
	}
}

func (w *world) build() (*inventory.Inventory, *scope.Scope) {
	w.d.Ranges = provider.NewRanges([]provider.Range{{Prefix: netip.MustParsePrefix("104.16.0.0/13"), Provider: "cloudflare"}})
	inv := inventory.New(w.d, provider.Default())
	x, _ := input.ParseExclusion("198.51.100.200")
	sc := scope.New(scope.Config{Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions: []input.Exclusion{x}, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly()})
	return inv, sc
}

func addrs(cs []origin.Candidate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Addr.String())
	}
	return out
}

func find(cs []origin.Candidate, a string) (origin.Candidate, bool) {
	for _, c := range cs {
		if c.Addr == ip(a) {
			return c, true
		}
	}
	return origin.Candidate{}, false
}

// standard is a world with one fronted host (www, behind CloudFront) and several others.
func standard() *world {
	w := &world{}
	w.cname("www.example.com", "d1.cloudfront.net")
	w.host("www.example.com", "203.0.113.1")
	w.host("origin.example.com", "198.51.100.10") // in a netblock: owner known without a record
	w.host("title.example.com", "203.0.113.50")
	w.host("api.example.com", "203.0.113.20")
	w.host("wild.example.com", "203.0.113.60") // the wildcard cert's host
	w.cname("cdn2.example.com", "x.cdn.cloudflare.net")
	w.host("cdn2.example.com", "203.0.113.30") // behind a CDN too
	w.host("x.w.example.com", "203.0.113.40")  // wildcard-only
	w.d.Wildcards = []inventory.Wildcard{{Zone: "w.example.com", Addrs: []netip.Addr{ip("203.0.113.40")}}}
	w.owner(64500, "203.0.113.20", "203.0.113.21", "203.0.113.22", "203.0.113.30", "203.0.113.40", "203.0.113.50", "203.0.113.60")
	w.owner(13335, "104.16.0.9")
	return w
}

var (
	front   = []origin.Front{{Host: "www.example.com", Provider: "aws", Title: "Acme"}}
	acmeSvc = []origin.Service{
		{Host: "origin.example.com", Title: "Acme", Names: []string{"www.example.com", "origin.example.com"}},
		{Host: "title.example.com", Title: "Acme", Names: []string{"title.example.com"}},
		{Host: "api.example.com", Title: "Acme Portal", Names: []string{"api.example.com"}},
		{Host: "wild.example.com", Title: "Other", Names: []string{"*.example.com"}},
		{Host: "cdn2.example.com", Title: "Acme", Names: []string{"www.example.com"}},
		{Host: "x.w.example.com", Title: "Acme", Names: []string{"www.example.com"}},
	}
)

// Candidate tests cover dedicated history/sibling evidence, history recency, sibling ordering
// and combined discovery methods.
func TestCandidates_SelectionAndOrder(t *testing.T) {
	t.Parallel()
	inv, sc := standard().build()
	hist := []origin.HistoricalAddr{
		{Host: "www.example.com", Addr: ip("203.0.113.21"), LastSeen: "2024-05-05"},
		{Host: "www.example.com", Addr: ip("198.51.100.77"), LastSeen: "2025-01-01"},
		{Host: "www.example.com", Addr: ip("203.0.113.22"), LastSeen: "2026-01-01"},
		{Host: "www.example.com", Addr: ip("203.0.113.50"), LastSeen: "2020-01-01"},   // also a sibling's address
		{Host: "www.example.com", Addr: ip("104.16.0.9"), LastSeen: "2026-06-01"},     // provider infrastructure
		{Host: "www.example.com", Addr: ip("203.0.113.23"), LastSeen: "2026-06-02"},   // owner unknown
		{Host: "www.example.com", Addr: ip("198.51.100.200"), LastSeen: "2019-01-01"}, // excluded
	}
	got := origin.Candidates(front, hist, acmeSvc, inv, sc, 20)
	want := []string{
		"203.0.113.22", "198.51.100.77", "203.0.113.21", "203.0.113.50", // historical, newest first (the dated 2020 one after 2024's)
		"198.51.100.200", // excluded, but still reported, last among the historical ones
		"198.51.100.10",  // origin.example.com: certificate and title
		"203.0.113.60",   // wild.example.com: a wildcard certificate names www
	}
	if !slices.Equal(addrs(got), want) {
		t.Fatalf("candidates = %v\nwant         %v", addrs(got), want)
	}
	for _, c := range got {
		if c.Host != "www.example.com" || c.Provider != "aws" {
			t.Errorf("%+v: host and provider come from the fronted host", c)
		}
	}
	for a, how := range map[string]string{
		"203.0.113.22":   "historical",
		"203.0.113.50":   "historical;sibling-title",
		"198.51.100.10":  "sibling-certificate;sibling-title",
		"203.0.113.60":   "sibling-certificate",
		"198.51.100.200": "historical",
	} {
		c, _ := find(got, a)
		if strings.Join(c.Found, ";") != how {
			t.Errorf("%s found %v, want %s", a, c.Found, how)
		}
	}
	for a, can := range map[string]bool{
		"198.51.100.10":  true,  // in an in-scope netblock
		"198.51.100.77":  true,  // so is this one, though only historical
		"203.0.113.50":   true,  // a historical address that is also title.example.com's current one
		"203.0.113.60":   true,  // a sibling's current address, owner known, dedicated
		"203.0.113.22":   false, // historical only: not in a netblock and no host's address
		"203.0.113.21":   false,
		"198.51.100.200": false, // excluded
	} {
		if c, _ := find(got, a); c.Contactable != can {
			t.Errorf("%s contactable = %v, want %v", a, c.Contactable, can)
		}
	}
	// Not candidates: the siblings that are behind a CDN, wildcard-only or whose title differs.
	for _, a := range []string{"203.0.113.30", "203.0.113.40", "203.0.113.20", "104.16.0.9", "203.0.113.23", "203.0.113.1"} {
		if _, ok := find(got, a); ok {
			t.Errorf("%s must not be a candidate", a)
		}
	}
}

// At most max candidates are kept for each fronted host: the first in the order above.
func TestCandidates_CapKeepsTheFirst(t *testing.T) {
	t.Parallel()
	inv, sc := standard().build()
	hist := []origin.HistoricalAddr{
		{Host: "www.example.com", Addr: ip("203.0.113.21"), LastSeen: "2024-05-05"},
		{Host: "www.example.com", Addr: ip("203.0.113.22"), LastSeen: "2026-01-01"},
	}
	if got := addrs(origin.Candidates(front, hist, acmeSvc, inv, sc, 3)); !slices.Equal(got, []string{"203.0.113.22", "203.0.113.21", "198.51.100.10"}) {
		t.Errorf("max 3 = %v: historical first, then the first sibling", got)
	}
	if got := addrs(origin.Candidates(front, hist, acmeSvc, inv, sc, 1)); !slices.Equal(got, []string{"203.0.113.22"}) {
		t.Errorf("max 1 = %v", got)
	}
	// The cap is per fronted host.
	w := standard()
	w.cname("shop.example.com", "d2.cloudfront.net")
	w.host("shop.example.com", "203.0.113.2")
	inv, sc = w.build()
	two := []origin.Front{{Host: "shop.example.com", Provider: "aws"}, {Host: "www.example.com", Provider: "aws", Title: "Acme"}}
	hist = append(hist, origin.HistoricalAddr{Host: "shop.example.com", Addr: ip("203.0.113.21"), LastSeen: "2022-01-01"})
	got := origin.Candidates(two, hist, acmeSvc, inv, sc, 1)
	if len(got) != 2 || got[0].Host != "shop.example.com" || got[1].Host != "www.example.com" {
		t.Errorf("one candidate for each of two fronted hosts, in name order: %+v", got)
	}
}

// Reject empty/default titles to avoid treating unrelated default pages as common-origin
// evidence.
func TestCandidates_TitleMatchNeedsARealTitle(t *testing.T) {
	t.Parallel()
	inv, sc := standard().build()
	for _, title := range []string{"", "Welcome to nginx!", "Attention Required! | Cloudflare"} {
		svcs := []origin.Service{{Host: "title.example.com", Title: title, Names: []string{"title.example.com"}}}
		fr := []origin.Front{{Host: "www.example.com", Provider: "aws", Title: title}}
		if got := origin.Candidates(fr, nil, svcs, inv, sc, 5); len(got) != 0 {
			t.Errorf("title %q matched: %v", title, addrs(got))
		}
	}
}

// A sibling's service on either scheme counts, and several services of one sibling give its
// address once.
func TestCandidates_SiblingAddressesOnce(t *testing.T) {
	t.Parallel()
	inv, sc := standard().build()
	svcs := []origin.Service{
		{Host: "title.example.com", Title: "Acme", Names: nil},
		{Host: "title.example.com", Title: "", Names: []string{"www.example.com"}},
	}
	got := origin.Candidates(front, nil, svcs, inv, sc, 5)
	if len(got) != 1 || got[0].Addr != ip("203.0.113.50") || strings.Join(got[0].Found, ";") != "sibling-certificate;sibling-title" {
		t.Errorf("got %+v", got)
	}
}

// A fronted host's own address, and a host that is no longer fronted, give no candidates.
func TestCandidates_NothingForAHostThatIsNotFronted(t *testing.T) {
	t.Parallel()
	inv, sc := standard().build()
	if got := origin.Candidates(nil, []origin.HistoricalAddr{{Host: "www.example.com", Addr: ip("203.0.113.22")}}, acmeSvc, inv, sc, 5); len(got) != 0 {
		t.Errorf("no fronted host, got %v", addrs(got))
	}
}

func TestConfirmed(t *testing.T) {
	t.Parallel()
	probe := origin.Probe{Status: 200, Title: "Acme Corp", BodyLen: 1000}
	for _, c := range []struct {
		name string
		a    origin.Answer
		by   string
	}{
		{"the title equals the probe's", origin.Answer{Status: 200, Title: "Acme Corp", BodyLen: 5}, origin.ByTitle},
		{"the title equals it on a different status and size", origin.Answer{Status: 404, Title: "Acme Corp", BodyLen: 5}, origin.ByTitle},
		{"same status, size 10% under, certificate names the host", origin.Answer{Status: 200, BodyLen: 900, CertNamesHost: true}, origin.ByBody},
		{"same status, size 10% over, certificate names the host", origin.Answer{Status: 200, BodyLen: 1100, CertNamesHost: true}, origin.ByBody},
		{"the certificate alone", origin.Answer{Status: 500, Title: "Other", BodyLen: 3, CertNamesHost: true}, ""},
		{"same status and size without the certificate", origin.Answer{Status: 200, BodyLen: 1000}, ""},
		{"size 11% off with the certificate", origin.Answer{Status: 200, BodyLen: 1111, CertNamesHost: true}, ""},
		{"size 11% under with the certificate", origin.Answer{Status: 200, BodyLen: 889, CertNamesHost: true}, ""},
		{"another status, same size, with the certificate", origin.Answer{Status: 403, BodyLen: 1000, CertNamesHost: true}, ""},
		{"another title", origin.Answer{Status: 200, Title: "Other", BodyLen: 5}, ""},
		{"no title", origin.Answer{Status: 200, BodyLen: 5}, ""},
		{"a redirect confirms nothing, whatever it says", origin.Answer{Status: 302, Title: "Acme Corp", BodyLen: 1000, CertNamesHost: true}, ""},
	} {
		if by, ok := origin.Confirmed(probe, c.a); by != c.by || ok != (c.by != "") {
			t.Errorf("%s: Confirmed = %q, %v; want %q", c.name, by, ok, c.by)
		}
	}
	// A probe with no title never confirms by title, and no body length never by size.
	if by, ok := origin.Confirmed(origin.Probe{Status: 200, BodyLen: 0}, origin.Answer{Status: 200, BodyLen: 0, CertNamesHost: true}); ok {
		t.Errorf("an unknown probe length confirmed by %q", by)
	}
	if by, ok := origin.Confirmed(origin.Probe{Status: 200}, origin.Answer{Status: 200}); ok {
		t.Errorf("two empty titles confirmed by %q", by)
	}
	// A title on the built-in list does not confirm, even when both pages carry it.
	cf := origin.Probe{Status: 403, Title: "Attention Required! | Cloudflare", BodyLen: 100}
	if by, ok := origin.Confirmed(cf, origin.Answer{Status: 403, Title: "Attention Required! | Cloudflare", BodyLen: 5}); ok {
		t.Errorf("a CDN's block page title confirmed by %q", by)
	}
}

func TestDefaultTitle(t *testing.T) {
	t.Parallel()
	for title, want := range map[string]bool{
		"Attention Required! | Cloudflare":      true,
		"Just a moment...":                      true,
		"Access Denied":                         true,
		"403 Forbidden":                         true,
		"404 Not Found":                         true,
		"Welcome to nginx!":                     true,
		"WELCOME TO NGINX!":                     true,
		"Apache2 Ubuntu Default Page: It works": true,
		"IIS Windows Server":                    true,
		"Error 1020":                            true,
		"Domain not found":                      true,
		"Fastly error: unknown domain acme.com": true,
		"Acme":                                  false,
		"Acme Portal":                           false,
		"Forbidden fruit: a history":            false,
		"":                                      false,
	} {
		if got := origin.DefaultTitle(title); got != want {
			t.Errorf("DefaultTitle(%q) = %v, want %v", title, got, want)
		}
	}
}

// A certificate names a host by the host itself or by a wildcard standing for its first label.
func TestCertNames(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		names []string
		host  string
		want  bool
	}{
		{[]string{"www.example.com"}, "www.example.com", true},
		{[]string{"WWW.Example.com"}, "www.example.com", true},
		{[]string{"*.example.com"}, "www.example.com", true},
		{[]string{"*.example.com"}, "a.b.example.com", false},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"example.com", "api.example.com"}, "www.example.com", false},
		{[]string{"203.0.113.5"}, "www.example.com", false},
		{nil, "www.example.com", false},
	} {
		got := slices.ContainsFunc(c.names, func(n string) bool { return slices.Contains(origin.CertNames(c.host), strings.ToLower(n)) })
		if got != c.want {
			t.Errorf("CertNames(%s) against %v = %v, want %v", c.host, c.names, got, c.want)
		}
	}
}
