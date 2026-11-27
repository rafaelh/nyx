package cli_test

import (
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// A name in scope by address is only the name. Its registrable domain does not become a root:
// no source is asked about it, nothing is guessed, learned or asked under or beside it, it gives no
// third party, and names under its domain in its pages are ignored. The domain is a root candidate
// whose source is in-netblock. Each test also checks that the name is in scope by address, so
// that the absence of a request means something.

// nmBlock is the in-scope netblock of these tests.
const nmBlock = "198.51.100.0/28"

// nmDNSTypes are the query types a lookup under or beside a name could use.
var nmDNSTypes = []string{"A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA", "SRV"}

// nmProbeLabel is the 16 hex characters of a wildcard check's random label.
var nmProbeLabel = regexp.MustCompile(`^[0-9a-f]{16}$`)

// nmWantByAddress fails unless each name is a hostname row of scope.csv and is in subdomains.txt.
func nmWantByAddress(t *testing.T, w *world, names ...string) {
	t.Helper()
	rows, subs := w.table(eng, "scope.csv"), w.lines(eng, "subdomains.txt")
	for _, n := range names {
		if !slices.ContainsFunc(rows, func(r map[string]string) bool { return r["type"] == "hostname" && r["value"] == n }) {
			t.Errorf("scope.csv has no hostname row for %s, which resolves into %s:\n%s", n, nmBlock, w.file(eng, "scope.csv"))
		}
		if !slices.Contains(subs, n) {
			t.Errorf("%s is not in subdomains.txt: %v", n, subs)
		}
	}
}

// nmUnder reports whether name is domain or below it.
func nmUnder(name, domain string) bool { return name == domain || strings.HasSuffix(name, "."+domain) }

// nmSecurityTrails sets the SecurityTrails key and answers every request with an empty result
// that each of its procedures can read (subdomains, DNS history and the domain search).
func nmSecurityTrails(x *web) {
	x.h.setKey("securitytrails", securityTrailsKey)
	x.handle("api.securitytrails.com", func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`{"endpoint":"/v1/domains/list","pages":1,"record_count":0,"records":[],"subdomains":[]}`))
	})
}

// nmShodan sets the Shodan key and serves its host lookups (hosts, by address; any other
// address is a 404), an empty search and, when dnsBody is set, the domain listing.
func nmShodan(x *web, hosts map[string]string, dnsBody string) {
	x.h.setKey("shodan", shodanKey)
	x.handle("api.shodan.io", func(rw http.ResponseWriter, r *http.Request) {
		switch p := r.URL.Path; {
		case p == "/shodan/host/search":
			_, _ = rw.Write([]byte(searchJSON(0)))
		case strings.HasPrefix(p, "/shodan/host/"):
			body, ok := hosts[strings.TrimPrefix(p, "/shodan/host/")]
			if !ok {
				http.NotFound(rw, r)
				return
			}
			_, _ = rw.Write([]byte(body))
		case strings.HasPrefix(p, "/dns/domain/") && dnsBody != "":
			_, _ = rw.Write([]byte(dnsBody))
		default:
			http.NotFound(rw, r)
		}
	})
}

// No subdomain source, no DNS history request and no Shodan pivot names a name in scope by
// address, its registrable domain or an identifier seen only on its pages, while the
// same sources are asked about rooted names.
func TestInNetblockNames_NoSourceIsAskedAboutIt(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	nmSecurityTrails(x)
	x.pivot()
	x.hackerTarget()
	// In scope by address: a PTR name in the netblock that resolves there, with an identifier
	// on its page, and a name behind a CDN whose address is in the netblock.
	x.dns.PTR("198.51.100.5", "www.other.org")
	x.host("www.other.org", "198.51.100.5")
	other := x.plain("198.51.100.5", 80, routes(map[string]http.HandlerFunc{
		"/": page(`<html><head><title>Other</title><script>gtag('config','G-NMOTHER1')</script></head><body>other</body></html>`)}))
	x.dns.PTR("198.51.100.6", "edge.fronted.org")
	x.dns.CNAME("edge.fronted.org", "nm.global.fastly.net")
	x.host("nm.global.fastly.net", "198.51.100.6")
	// Under the root, the same kinds of name.
	x.names("a.example.com", "cdn.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.plain("203.0.113.5", 80, routes(map[string]http.HandlerFunc{
		"/": page(`<html><head><title>Rooted</title><script>gtag('config','G-NMROOTED1')</script></head><body>rooted</body></html>`)}))
	x.dns.CNAME("cdn.example.com", "y.global.fastly.net")
	x.host("y.global.fastly.net", "203.0.113.10")
	x.mustRun("--cidr", nmBlock)

	nmWantByAddress(t, x.world, "www.other.org", "edge.fronted.org")
	if hosts := other.hostHeaders(); !slices.Contains(hosts, "www.other.org") {
		t.Errorf("the page of www.other.org was not fetched by its name (Host headers %v)", hosts)
	}
	// The sources are on: the rooted identifier is searched and the rooted CDN name's history asked.
	if q := x.queries(); !slices.Contains(q, `http.html:"G-NMROOTED1"`) {
		t.Errorf("Shodan searches = %q, want the identifier of a.example.com", q)
	}
	if !slices.ContainsFunc(x.requests("api.securitytrails.com"), func(r loggedReq) bool {
		return strings.HasPrefix(r.path(), "/v1/history/cdn.example.com/")
	}) {
		t.Error("SecurityTrails was not asked for the DNS history of cdn.example.com, a rooted name behind a CDN")
	}
	for pattern, s := range x.src {
		for _, r := range s.requestLog() {
			for _, named := range []string{"other.org", "fronted.org", "G-NMOTHER1"} {
				if strings.Contains(r.URI, named) || strings.Contains(r.Body, named) {
					t.Errorf("%s was asked about %s: %s %s %s", pattern, named, r.Method, r.URI, r.Body)
				}
			}
		}
	}
}

// Nothing is guessed, learned or asked under or beside a name in scope by address: no
// permutation, learned name, parent, NS, MX or TXT lookup, and no TXT of an SPF include. The only
// lookups under its registrable domain are the candidate lookups of the names in scope by address
// and the wildcard check of the domain, which is itself in scope by address.
func TestInNetblockNames_NothingIsGuessedOrAskedBesideIt(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	inScope := []string{"other.org", "www.other.org", "spf.other.org"}
	for i, n := range inScope {
		addr := []string{"198.51.100.4", "198.51.100.5", "198.51.100.8"}[i]
		w.dns.PTR(addr, n)
		w.dns.A(n, addr)
	}
	// Records that a lookup of the names' own records would find.
	w.dns.MX("www.other.org", 10, "mx.other.org")
	w.dns.TXT("www.other.org", "v=spf1 -all")
	w.dns.TXT("spf.other.org", "v=spf1 ip4:198.51.100.0/28 -all")
	w.dns.TXT("example.com", "v=spf1 include:_spf.example.com include:spf.other.org -all")
	w.dns.TXT("_spf.example.com", "v=spf1 -all")
	w.crtsh(map[string][]string{"example.com": {"a.example.com"}}, nil)
	w.dns.A("a.example.com", "203.0.113.5")
	// Permutations and learned names are on.
	if code := w.run("--passive", "--cidr", nmBlock, "example.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stdout.String())
	}

	nmWantByAddress(t, w, inScope...)
	// The rooted name is a seed and has its records asked, and the in-scope include is followed.
	if !slices.ContainsFunc(w.h.completed(eng, "permutations"), func(k string) bool { return strings.HasPrefix(k, "seed|a.example.com|") }) {
		t.Errorf("a.example.com was not a permutation seed: %v", w.h.completed(eng, "permutations"))
	}
	if !slices.ContainsFunc(w.h.completed(eng, "dnsrecords"), func(k string) bool { return strings.HasPrefix(k, "a.example.com|") }) {
		t.Errorf("a.example.com's records were not asked: %v", w.h.completed(eng, "dnsrecords"))
	}
	if n := w.dns.Count("_spf.example.com", "TXT"); n == 0 {
		t.Error("the in-scope SPF include _spf.example.com was not asked for TXT")
	}

	for _, typ := range nmDNSTypes {
		for _, n := range w.dns.Queried(typ) {
			if !nmUnder(n, "other.org") {
				continue
			}
			label, parent, _ := strings.Cut(n, ".")
			own := slices.Contains(inScope, n)
			probe := nmProbeLabel.MatchString(label) && parent == "other.org"
			if typ != "A" && typ != "AAAA" || !own && !probe {
				t.Errorf("%s was asked %s: only the candidate lookups and the wildcard check reach other.org", n, typ)
			}
		}
	}
	for _, procedure := range []string{"permutations", "learned-names", "dnsrecords"} {
		for _, k := range w.h.completed(eng, procedure) {
			if strings.Contains(k, "other.org") {
				t.Errorf("%s has a job %s beside a name in scope by address", procedure, k)
			}
		}
	}
	for _, k := range w.h.completed(eng, "resolve") {
		if strings.HasPrefix(k, "parent|") && strings.Contains(k, "other.org") {
			t.Errorf("resolve has a parent job %s of a name in scope by address", k)
		}
	}
}

// A name in scope by address gives no third party, and the names under its registrable domain in
// its page stay ignored, while a rooted name under the root in the same page is taken. Another
// name under that domain stays a candidate unless its own lookup brings it in. The registrable
// domain is a root candidate whose only source is in-netblock.
func TestInNetblockNames_ItsDomainIsOnlyACandidateRoot(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.dns.PTR("198.51.100.5", "www.other.org")
	x.host("www.other.org", "198.51.100.5")
	other := x.plain("198.51.100.5", 80, routes(map[string]http.HandlerFunc{
		"/": page(`<html><head><title>Other</title></head><body><p>See api.other.org, mail.other.org and b.example.com.</p></body></html>`)}))
	// A name in scope by address on a SaaS provider, and a rooted one on another.
	// Another name under its registrable domain, which resolves outside the netblock.
	x.dns.PTR("198.51.100.9", "legacy.other.org")
	x.host("legacy.other.org", "192.0.2.50")
	x.dns.PTR("198.51.100.7", "shop.brand.org")
	x.dns.CNAME("shop.brand.org", "nmshop.zendesk.com")
	x.host("nmshop.zendesk.com", "198.51.100.7")
	x.names("store.example.com")
	x.dns.CNAME("store.example.com", "nmstore.myshopify.com")
	x.host("nmstore.myshopify.com", "203.0.113.11")
	x.mustRun("--cidr", nmBlock)

	nmWantByAddress(t, x.world, "www.other.org", "shop.brand.org")
	if hosts := other.hostHeaders(); !slices.Contains(hosts, "www.other.org") {
		t.Errorf("the page of www.other.org was not fetched by its name (Host headers %v)", hosts)
	}
	if !x.hostnameSet()["b.example.com"] {
		t.Error("b.example.com, under the root in the page of www.other.org, was not taken as a hostname")
	}
	for _, n := range []string{"api.other.org", "mail.other.org"} {
		x.wantNoHostname(n, "a name under the registrable domain of a name in scope by address is ignored in its pages")
	}
	if c := x.candidate("legacy.other.org"); c == nil || c["type"] != "hostname" {
		t.Errorf("legacy.other.org = %v, want still a candidate hostname: it resolves outside the netblock", c)
	}
	if slices.Contains(x.lines(eng, "subdomains.txt"), "legacy.other.org") {
		t.Error("legacy.other.org, which resolves outside the netblock, is in subdomains.txt")
	}

	rows := x.table(eng, "third-parties.csv")
	if find(rows, "domain", "myshopify.com") == nil {
		t.Errorf("third-parties.csv has no row for the rooted store.example.com:\n%s", x.file(eng, "third-parties.csv"))
	}
	for _, r := range rows {
		if r["domain"] == "zendesk.com" || strings.Contains(r["root"], "brand.org") {
			t.Errorf("a name in scope by address gave a third party: %v", r)
		}
	}

	// other.org also inherits the rdns evidence of its candidate hostname legacy.other.org.
	for root, exact := range map[string]bool{"other.org": false, "brand.org": true} {
		c := x.candidate(root)
		if c == nil || c["type"] != "root" || !slices.Contains(strings.Split(c["sources"], ";"), "in-netblock") ||
			exact && c["sources"] != "in-netblock" {
			t.Errorf("candidate %s = %v, want a root with the source in-netblock\n%s", root, c, x.file(eng, "candidates.csv"))
		}
	}
}

// When a zone is itself in scope by address and has a wildcard, the names under it that only the
// wildcard answers are wildcard-only, the zone's wildcard check is made and one representative is
// probed.
func TestInNetblockNames_AWildcardZoneInScopeByAddress(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.dns.PTR("198.51.100.10", "wild.org")
	w.dns.A("wild.org", "198.51.100.10")
	w.dns.Wildcard("wild.org", "198.51.100.9")
	w.dns.PTR("198.51.100.3", "a.wild.org")
	w.dns.PTR("198.51.100.4", "b.wild.org")
	if code := w.run("--passive", "--no-permutations", "--cidr", nmBlock, "example.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stdout.String())
	}

	nmWantByAddress(t, w, "wild.org")
	probes := 0
	for _, n := range w.dns.Queried("A") {
		if label, parent, _ := strings.Cut(n, "."); parent == "wild.org" && nmProbeLabel.MatchString(label) {
			probes++
		}
	}
	if probes != 2 {
		t.Errorf("wild.org's wildcard check asked %d random names, want 2", probes)
	}
	if got := w.lines(eng, "wildcard-excluded.txt"); !slices.Contains(got, "a.wild.org") || !slices.Contains(got, "b.wild.org") {
		t.Errorf("wildcard-excluded.txt = %v, want a.wild.org and b.wild.org", got)
	}
	if got, want := w.probed(), []string{"a.wild.org", "example.com", "wild.org"}; !slices.Equal(got, want) {
		t.Errorf("probed = %v, want %v: the zone, the root and one representative of the wildcard", got, want)
	}
}

// What reverseip, shodan-host, shodan-dns and github record for a name does not change when the
// name enters scope by address: a name under no root is not taken as a hostname, and where
// the procedure keeps roots its registrable domain stays a root candidate. Each procedure is run
// again once the name is in scope.
func TestInNetblockNames_SourcesDoNotTakeItAsAHostname(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		procedure string
		install   func(x *web)
		control   func(t *testing.T, x *web)
	}{
		{"reverseip", func(x *web) {
			x.hackerTarget().set("203.0.113.7", "www.other.org")
		}, nmWantRootFrom("reverseip")},
		{"shodan-host", func(x *web) {
			nmShodan(x, map[string]string{"203.0.113.7": hostJSON("203.0.113.7", []string{"www.other.org"})}, "")
		}, nmWantRootFrom("shodan-host")},
		{"shodan-dns", func(x *web) {
			nmShodan(x, nil, `{"domain":"example.com","subdomains":["ghost","alias"],"more":false,"data":[
				{"subdomain":"ghost","type":"CNAME","value":"www.other.org"},
				{"subdomain":"alias","type":"CNAME","value":"app.example.com"}]}`)
		}, nmWantHostnameFrom("shodan-dns", "app.example.com")},
		{"github", func(x *web) {
			x.h.setKey("github", githubKey)
			x.handle("api.github.com", newGH(map[string][]ghFile{"example.com": {
				{repo: "acme/infra", path: "deploy/hosts.yml", fragments: []string{"web: www.other.org\nvpn: vpn.example.com"}},
			}}).serve)
		}, nmWantHostnameFrom("github", "vpn.example.com")},
	} {
		t.Run(c.procedure, func(t *testing.T) {
			t.Parallel()
			x := newWeb(t)
			x.dns.PTR("198.51.100.5", "www.other.org")
			x.host("www.other.org", "198.51.100.5")
			x.names("app.example.com")
			x.host("app.example.com", "203.0.113.7")
			x.owner("203.0.113.7", 64500, "ACME-NET")
			c.install(x)
			x.mustPassive("--cidr", nmBlock)
			nmWantByAddress(t, x.world, "www.other.org")
			x.mustPassive("--cidr", nmBlock, "--redo", c.procedure)

			if got := x.observedBy("hostname", c.procedure); slices.Contains(got, "www.other.org") {
				t.Errorf("%s took www.other.org, under no root, as a hostname: %v", c.procedure, got)
			}
			c.control(t, x)
		})
	}
}

// nmWantRootFrom checks that other.org is a root candidate with the procedure among its sources.
func nmWantRootFrom(procedure string) func(t *testing.T, x *web) {
	return func(t *testing.T, x *web) {
		t.Helper()
		c := x.candidate("other.org")
		if c == nil || c["type"] != "root" || !slices.Contains(strings.Split(c["sources"], ";"), procedure) {
			t.Errorf("candidate other.org = %v, want a root found by %s\n%s", c, procedure, x.file(eng, "candidates.csv"))
		}
	}
}

// nmWantHostnameFrom checks that the procedure took the rooted name as a hostname.
func nmWantHostnameFrom(procedure, name string) func(t *testing.T, x *web) {
	return func(t *testing.T, x *web) {
		t.Helper()
		if got := x.observedBy("hostname", procedure); !slices.Contains(got, name) {
			t.Errorf("%s did not take %s, under the root, as a hostname: %v", procedure, name, got)
		}
	}
}
