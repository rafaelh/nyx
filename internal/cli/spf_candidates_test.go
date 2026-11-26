package cli_test

import (
	"fmt"
	"math/big"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/knowledge/addrkind"
)

// SPF candidate tests use addresses addrkind calls public: the documentation ranges the other
// tests resolve names to are not, so an SPF term naming one gives no candidate.

// spfWorld is a passive world in which each named label is an in-scope hostname under
// example.com, found by crt.sh, with an address of its own.
func spfWorld(t *testing.T, labels ...string) *world {
	t.Helper()
	w := newWorld(t)
	spfNames(w, labels...)
	return w
}

// spfNames makes each label an in-scope hostname under example.com with an address.
func spfNames(w *world, labels ...string) {
	var names []string
	for i, l := range labels {
		name := l + ".example.com"
		addr := fmt.Sprintf("203.0.113.%d", 20+i)
		names = append(names, name)
		w.dns.A(name, addr)
		w.owner(addr, 64500, "ACME-NET")
	}
	w.crtsh(map[string][]string{"example.com": names}, nil)
}

// spfLast is the last address of a prefix.
func spfLast(p netip.Prefix) netip.Addr {
	p = p.Masked()
	b := p.Addr().AsSlice()
	n := new(big.Int).SetBytes(b)
	host := len(b)*8 - p.Bits()
	n.Or(n, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(host)), big.NewInt(1)))
	out := make([]byte, len(b))
	n.FillBytes(out)
	a, _ := netip.AddrFromSlice(out)
	return a
}

// spfPublic fails unless addrkind calls the first and last address of each prefix public, so
// that a fixture tests the rule it is meant to and not the public-address one.
func spfPublic(t *testing.T, prefixes ...string) {
	t.Helper()
	for _, s := range prefixes {
		p := netip.MustParsePrefix(s).Masked()
		for _, a := range []netip.Addr{p.Addr(), spfLast(p)} {
			if k := addrkind.Of(a); k != addrkind.Public {
				t.Fatalf("fixture %s: addrkind calls %s %q, not public", s, a, k)
			}
		}
	}
}

// spfNotPublic fails if addrkind calls the first address of a prefix public.
func spfNotPublic(t *testing.T, prefixes ...string) {
	t.Helper()
	for _, s := range prefixes {
		if a := netip.MustParsePrefix(s).Masked().Addr(); addrkind.Of(a) == addrkind.Public {
			t.Fatalf("fixture %s: addrkind calls %s public", s, a)
		}
	}
}

// spfNetblocks are the values of the netblock rows of candidates.csv, sorted.
func spfNetblocks(w *world) []string {
	var out []string
	for _, r := range w.table(eng, "candidates.csv") {
		if r["type"] == "netblock" {
			out = append(out, r["value"])
		}
	}
	slices.Sort(out)
	return out
}

// spfCandidate is the netblock row of candidates.csv for value; the test fails without one.
func spfCandidate(t *testing.T, w *world, value string) map[string]string {
	t.Helper()
	for _, r := range w.table(eng, "candidates.csv") {
		if r["type"] == "netblock" && r["value"] == value {
			return r
		}
	}
	t.Fatalf("candidates.csv has no netblock %s:\n%s", value, w.file(eng, "candidates.csv"))
	return nil
}

// spfScopeRows are the scope.csv rows that name value, as "type value".
func spfScopeRows(w *world, value string) []string {
	var out []string
	for _, r := range w.table(eng, "scope.csv") {
		if r["value"] == value {
			out = append(out, r["type"]+" "+r["value"])
		}
	}
	return out
}

// spfWant fails unless the netblock candidates are exactly want.
func spfWant(t *testing.T, w *world, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := spfNetblocks(w); !slices.Equal(got, want) {
		t.Errorf("netblock candidates = %v, want %v\n%s", got, want, w.file(eng, "candidates.csv"))
	}
}

// --- what is a candidate ---

// A range in the root's SPF record is a netblock candidate from the spf source, supported by
// one item, and so low; it is not in scope.
func TestSPFCandidates_RootRangeIsALowNetblockCandidate(t *testing.T) {
	t.Parallel()
	spfPublic(t, "192.0.3.0/24")
	w := spfWorld(t)
	w.dns.TXT("example.com", "v=spf1 ip4:192.0.3.0/24 -all")
	runRoot(t, w)

	r := spfCandidate(t, w, "192.0.3.0/24")
	wantRow(t, r, "spf", "1", "low")
	if r["current"] != "true" {
		t.Errorf("row = %v, want current", r)
	}
	if got := spfScopeRows(w, "192.0.3.0/24"); len(got) != 0 {
		t.Errorf("an SPF range entered scope: %v", got)
	}
	if n := w.h.total("candidates"); n < 1 {
		t.Errorf("summary candidates = %d, want the SPF range counted", n)
	}
}

// The same range in a subdomain's record is a second item of the same source: the count rises
// to two, with one source and one family, so the candidate stays low.
func TestSPFCandidates_SameRangeInTwoRecordsIsOneFamily(t *testing.T) {
	t.Parallel()
	spfPublic(t, "192.0.3.0/24")
	w := spfWorld(t, "mail")
	w.dns.TXT("example.com", "v=spf1 ip4:192.0.3.0/24 -all")
	w.dns.TXT("mail.example.com", "v=spf1 ip4:192.0.3.0/24 -all")
	runRoot(t, w)

	wantRow(t, spfCandidate(t, w, "192.0.3.0/24"), "spf", "2", "low")
}

// A single address is a /32 or /128, host bits are masked off, and the mechanism name and the
// + qualifier are read in any case.
func TestSPFCandidates_TermShapes(t *testing.T) {
	t.Parallel()
	spfPublic(t, "203.0.114.9/32", "2a03:2880::5/128", "198.51.101.0/24", "192.0.3.0/25", "2a00:1450:4000::/40")
	w := spfWorld(t, "mail")
	w.dns.TXT("example.com", "v=spf1 ip4:203.0.114.9 ip6:2a03:2880::5 -all")
	w.dns.TXT("mail.example.com", "v=spf1 IP4:198.51.101.77/24 +ip4:192.0.3.0/25 ip6:2a00:1450:4000::1/40 -all")
	runRoot(t, w)

	spfWant(t, w, "203.0.114.9/32", "2a03:2880::5/128", "198.51.101.0/24", "192.0.3.0/25", "2a00:1450:4000::/40")
	for _, v := range spfNetblocks(w) {
		if r := find(w.table(eng, "candidates.csv"), "value", v); r["sources"] != "spf" {
			t.Errorf("%s: sources = %q, want spf", v, r["sources"])
		}
	}
}

// No candidate from a term qualified -, ~ or ?, a range wider than /16 or /32, a range that is
// not public, a malformed term, or a name with two SPF records. A /16 and an IPv6 /32 are
// candidates.
func TestSPFCandidates_TermsThatGiveNone(t *testing.T) {
	t.Parallel()
	// Each excluded term would otherwise be a candidate: these are public.
	spfPublic(t, "192.0.3.1/32", "192.0.3.2/32", "192.0.3.3/32", "198.0.0.0/15", "2a00::/31", "203.1.0.0/16", "2a01::/32",
		"203.0.114.0/24", "198.51.101.0/24")
	// Private, loopback, documentation, multicast and unique-local.
	spfNotPublic(t, "10.1.2.0/24", "127.0.0.1/32", "192.0.2.0/24", "2001:db8::/48", "224.1.2.0/24", "ff02::1/128", "fd12:3456::/48")

	w := spfWorld(t, "a", "b", "c")
	w.dns.TXT("example.com", "v=spf1 -ip4:192.0.3.1 ~ip4:192.0.3.2 ?ip4:192.0.3.3 ip4:198.0.0.0/15 ip6:2a00::/31 ip4:203.1.0.0/16 ip6:2a01::/32 -all")
	w.dns.TXT("a.example.com", "v=spf1 ip4:10.1.2.0/24 ip4:127.0.0.1 ip4:192.0.2.0/24 ip6:2001:db8::/48 ip4:224.1.2.0/24 ip6:ff02::1 ip6:fd12:3456::/48 -all")
	w.dns.TXT("b.example.com", "v=spf1 ip4:192.0.3.300 ip4:198.51.101.0/33 ip6:192.0.3.9 ip4:2a00:1450::1 ip4: ip4:203.0.114.0/x -all")
	w.dns.TXT("c.example.com", "v=spf1 ip4:203.0.114.0/24 -all")
	w.dns.TXT("c.example.com", "v=spf1 ip4:198.51.101.0/24 -all")
	runRoot(t, w)

	spfWant(t, w, "203.1.0.0/16", "2a01::/32")
}

// A range whose first and last addresses are a shared provider's gives no candidate; a single
// address there does.
func TestSPFCandidates_ProviderRanges(t *testing.T) {
	t.Parallel()
	// Cloudflare and Fastly from the world's provider-range fixture.
	spfPublic(t, "104.16.0.0/24", "104.16.0.5/32", "2606:4700::/48", "2606:4700::1/128", "151.101.0.0/16", "203.0.114.0/24")
	w := spfWorld(t, "mail")
	w.dns.TXT("example.com", "v=spf1 ip4:104.16.0.0/24 ip4:104.16.0.5 ip6:2606:4700::/48 ip6:2606:4700::1 -all")
	w.dns.TXT("mail.example.com", "v=spf1 ip4:151.101.0.0/16 ip4:203.0.114.0/24 -all")
	runRoot(t, w)
	if got := w.h.completed(eng, "providerranges"); !slices.Equal(got, allRangeJobs) {
		t.Fatalf("providerranges completed %v, want every list", got)
	}

	spfWant(t, w, "104.16.0.5/32", "2606:4700::1/128", "203.0.114.0/24")
}

// An in-scope include: or redirect= is followed, and its terms are candidates with the included
// domain as the item, so two includers count once. One outside scope is never asked.
func TestSPFCandidates_IncludedDomainsAreFollowed(t *testing.T) {
	t.Parallel()
	spfPublic(t, "198.51.101.0/24", "203.0.114.0/24", "192.0.3.0/24")
	w := spfWorld(t, "mail")
	w.dns.TXT("example.com", "v=spf1 include:_spf.example.com include:spf.sender.test -all")
	w.dns.TXT("mail.example.com", "v=spf1 include:_spf.example.com redirect=_spf2.example.com")
	w.dns.TXT("_spf.example.com", "v=spf1 ip4:198.51.101.0/24 -all")
	w.dns.TXT("_spf2.example.com", "v=spf1 ip4:203.0.114.0/24 ~all")
	w.dns.TXT("spf.sender.test", "v=spf1 ip4:192.0.3.0/24 -all")
	runRoot(t, w)

	wantRow(t, spfCandidate(t, w, "198.51.101.0/24"), "spf", "1", "low")
	wantRow(t, spfCandidate(t, w, "203.0.114.0/24"), "spf", "1", "low")
	spfWant(t, w, "198.51.101.0/24", "203.0.114.0/24")
	for _, n := range []string{"_spf.example.com", "_spf2.example.com"} {
		if c := w.dns.Count(n, "TXT"); c != 1 {
			t.Errorf("%s TXT asked %d times, want once", n, c)
		}
	}
	for _, ty := range spfQueryTypes {
		if c := w.dns.Count("spf.sender.test", ty); c != 0 {
			t.Errorf("an included domain outside scope was asked %s %d times", ty, c)
		}
	}
}

// Mechanisms after all are never evaluated: an ip4 term written after all gives no candidate, and
// an include after it is not followed.
func TestSPFCandidates_TermsAfterAllGiveNone(t *testing.T) {
	t.Parallel()
	spfPublic(t, "203.0.114.0/24", "198.51.101.0/24", "192.0.3.0/24")
	w := spfWorld(t, "mail")
	w.dns.TXT("example.com", "v=spf1 ip4:203.0.114.0/24 -all ip4:198.51.101.0/24")
	w.dns.TXT("mail.example.com", "v=spf1 ~all include:_late.example.com")
	w.dns.TXT("_late.example.com", "v=spf1 ip4:192.0.3.0/24 -all")
	runRoot(t, w)

	spfWant(t, w, "203.0.114.0/24")
	if c := w.dns.Count("_late.example.com", "TXT"); c > 1 {
		t.Errorf("an include after all was followed: _late.example.com TXT asked %d times", c)
	}
}

// --- placement ---

// An SPF candidate inside a --cidr added on a later run leaves candidates.csv and the count,
// with no --redo; one outside it stays. The same holds when the --cidr is given at once.
func TestSPFCandidates_InsideALaterCIDRLeaves(t *testing.T) {
	t.Parallel()
	spfPublic(t, "192.0.3.16/28", "198.51.101.0/24")
	w := spfWorld(t)
	w.dns.TXT("example.com", "v=spf1 ip4:192.0.3.16/28 ip4:198.51.101.0/24 -all")
	runRoot(t, w)
	spfCandidate(t, w, "192.0.3.16/28")
	spfCandidate(t, w, "198.51.101.0/24")
	before := w.h.total("candidates")

	runRoot(t, w, "-e", eng, "--cidr", "192.0.3.0/26")
	if r := find(w.table(eng, "candidates.csv"), "value", "192.0.3.16/28"); r != nil {
		t.Errorf("a candidate inside an in-scope netblock is still listed: %v", r)
	}
	spfCandidate(t, w, "198.51.101.0/24")
	if after := w.h.total("candidates"); after != before-1 {
		t.Errorf("summary candidates = %d after the --cidr, want %d", after, before-1)
	}

	// Given in the first run, the range is never listed.
	w2 := spfWorld(t)
	w2.dns.TXT("example.com", "v=spf1 ip4:192.0.3.16/28 ip4:198.51.101.0/24 -all")
	runRoot(t, w2, "--cidr", "192.0.3.0/26")
	spfWant(t, w2, "198.51.101.0/24")
}

// An rdap candidate inside a --cidr added on a later run leaves candidates.csv and the count too.
func TestSPFCandidates_RDAPCandidateInsideALaterCIDRLeaves(t *testing.T) {
	t.Parallel()
	x := newRDAP(t)
	x.entities(hostARIN, false, rdapEntity{handle: "ACME-1", name: "Acme Widgets", nets: []rdapNet{
		{"198.51.101.16", "198.51.101.31", "NET-IN", ""}, {"198.51.101.128", "198.51.101.255", "NET-OUT", ""}}})
	x.mustScan("--org", "Acme Widgets")
	if x.candidate("198.51.101.16/28") == nil || x.candidate("198.51.101.128/25") == nil {
		t.Fatalf("candidates = %v", x.candidateTypes())
	}
	before := x.h.total("candidates")

	x.mustScan("-e", eng, "--cidr", "198.51.101.0/27")
	if r := x.candidate("198.51.101.16/28"); r != nil {
		t.Errorf("an rdap candidate inside an in-scope netblock is still listed: %v", r)
	}
	if x.candidate("198.51.101.128/25") == nil {
		t.Errorf("the candidate outside the --cidr left too: %v", x.candidateTypes())
	}
	if after := x.h.total("candidates"); after != before-1 {
		t.Errorf("summary candidates = %d after the --cidr, want %d", after, before-1)
	}
}

// An in-scope netblock nested in another stays in scope and counted: an ASN's more-specific
// prefix, ASN prefixes inside a --cidr, and a --cidr inside another.
func TestSPFCandidates_NestedInScopeNetblocksStay(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.handle("stat.ripe.net", func(rw http.ResponseWriter, r *http.Request) {
		_, _ = rw.Write([]byte(`{"status":"ok","data":{"prefixes":[{"prefix":"192.0.3.0/26"},{"prefix":"192.0.3.0/28"}]}}`))
	})
	runRoot(t, w, "--asn", "AS64500", "--cidr", "192.0.3.0/25", "--cidr", "192.0.3.0/27")

	var got []string
	for _, r := range w.table(eng, "scope.csv") {
		if r["type"] == "netblock" || r["type"] == "cidr" {
			got = append(got, r["type"]+" "+r["value"])
		}
	}
	slices.Sort(got)
	if want := []string{"cidr 192.0.3.0/25", "cidr 192.0.3.0/27", "netblock 192.0.3.0/26", "netblock 192.0.3.0/28"}; !slices.Equal(got, want) {
		t.Errorf("scope.csv netblocks = %v, want %v", got, want)
	}
	// The summary counts the netblocks the ASN announces.
	if n := w.h.total("netblocks"); n != 2 {
		t.Errorf("summary netblocks = %d, want 2 (each nested netblock counted)", n)
	}
	if got := spfNetblocks(w); len(got) != 0 {
		t.Errorf("an in-scope netblock is a candidate: %v", got)
	}
}

// --- nothing in a candidate is contacted ---

// spfQueryTypes are the DNS types a lookup could name an address in.
var spfQueryTypes = []string{"A", "AAAA", "CNAME", "PTR", "TXT", "MX", "NS", "SOA", "CAA", "SRV", "ANY", "HTTPS", "SVCB", "DS", "DNSKEY", "NAPTR", "SPF"}

// spfAddrOf is the address a query name names: an address literal, a reverse name
// (in-addr.arpa, ip6.arpa) or a Team Cymru origin name, which start with the address reversed.
func spfAddrOf(name string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(name); err == nil {
		return a, true
	}
	labels := strings.Split(name, ".")
	if len(labels) >= 4 {
		if a, err := netip.ParseAddr(labels[3] + "." + labels[2] + "." + labels[1] + "." + labels[0]); err == nil && a.Is4() {
			return a, true
		}
	}
	if len(labels) >= 32 {
		var hex strings.Builder
		for i := 31; i >= 0; i-- {
			if len(labels[i]) != 1 {
				return netip.Addr{}, false
			}
			hex.WriteString(labels[i])
			if i%4 == 0 && i > 0 {
				hex.WriteString(":")
			}
		}
		if a, err := netip.ParseAddr(hex.String()); err == nil {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// spfQueriesInto are the DNS queries that name an address inside one of the prefixes, or the
// reverse zone of an IPv4 one, as "TYPE name".
func spfQueriesInto(w *world, prefixes []netip.Prefix) []string {
	var out []string
	for _, ty := range spfQueryTypes {
		for _, n := range w.dns.Queried(ty) {
			a, ok := spfAddrOf(n)
			for _, p := range prefixes {
				zone := ""
				if p.Addr().Is4() {
					o := p.Addr().As4()
					zone = fmt.Sprintf("%d.%d.%d.in-addr.arpa", o[2], o[1], o[0])
				}
				if ok && p.Contains(a) || zone != "" && strings.HasSuffix(n, zone) {
					out = append(out, ty+" "+n)
				}
			}
		}
	}
	return out
}

// spfAddrs are the addresses of the prefixes.
func spfAddrs(prefixes []netip.Prefix) []string {
	var out []string
	for _, p := range prefixes {
		for a := p.Masked().Addr(); p.Contains(a); a = a.Next() {
			out = append(out, a.String())
		}
	}
	return out
}

// After a run that lists SPF candidates, no lookup names an address in them and nothing in them
// is connected to, passive or authorised.
func TestSPFCandidates_NothingInThemIsContacted(t *testing.T) {
	t.Parallel()
	const rootSPF = "v=spf1 ip4:192.0.3.0/28 ip4:198.51.101.7 ip6:2a00:1450:4000::/126 -all"
	const mailSPF = "v=spf1 ip4:203.0.114.0/29 -all"
	values := []string{"192.0.3.0/28", "198.51.101.7/32", "2a00:1450:4000::/126", "203.0.114.0/29"}
	spfPublic(t, values...)
	var prefixes []netip.Prefix
	for _, v := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(v))
	}

	check := func(t *testing.T, w *world) {
		t.Helper()
		spfWant(t, w, values...)
		if got := spfQueriesInto(w, prefixes); len(got) != 0 {
			t.Errorf("lookups named an address in an SPF candidate: %v", got)
		}
		if n := w.h.network(); n != 0 {
			t.Errorf("a harness canary saw %d requests", n)
		}
	}

	t.Run("passive", func(t *testing.T) {
		t.Parallel()
		w := spfWorld(t, "mail")
		w.dns.TXT("example.com", rootSPF)
		w.dns.TXT("mail.example.com", mailSPF)
		runRoot(t, w)
		check(t, w)
	})

	t.Run("authorised", func(t *testing.T) {
		t.Parallel()
		p := newPorts(t)
		p.names("mail.example.com")
		p.host("mail.example.com", "203.0.113.20")
		p.owner("203.0.113.20", 64500, "ACME-NET")
		p.dns.TXT("example.com", rootSPF)
		p.dns.TXT("mail.example.com", mailSPF)
		ports := []int{80, 443, 8080}
		canary := p.listen("spf", "CANARY\r\n", 0)
		for _, a := range spfAddrs(prefixes) {
			for _, port := range ports {
				p.mapTo(a, port, canary.ln.Addr().String())
			}
		}
		p.sweep([]int{8080})
		check(t, p.world)
		if n := canary.conns.Load(); n != 0 {
			t.Errorf("%d connections to addresses in SPF candidates: %v", n, p.sequence())
		}
		// Control: the sweep did run, on the in-scope addresses.
		if got := p.checked(); !slices.Contains(got, "203.0.113.20:8080") {
			t.Errorf("ports checked = %v, want the in-scope mail host", got)
		}
	})
}

// --- the docs ---

// docs/candidates.md lists spf among the sources that are each a family of their own.
func TestSPFCandidates_DocsNameTheSourceAsItsOwnFamily(t *testing.T) {
	t.Parallel()
	unit := docUnit(docPage(t, "candidates.md"), "a family of their own")
	if unit == "" {
		t.Fatal("docs/candidates.md has no sentence of the sources that are each a family of their own")
	}
	if !strings.Contains(unit, "`spf`") {
		t.Errorf("the sources that are a family of their own do not include `spf`: %q", unit)
	}
}
