package cli_test

import (
	"context"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/nyx/internal/knowledge/addrkind"
)

// The records of every name: the in-scope names below the input roots are asked for their NS, MX
// and TXT records (dnsrecords), a delegated one for its SOA, CAA and SRV records too, and the
// names and third parties those records show are listed. The roots keep dnsroot, which gains MX.

// drAddr and drAddr2 are the addresses the tests give their names; drWorld gives them an owner.
const (
	drAddr  = "203.0.113.10"
	drAddr2 = "203.0.113.11"
)

// drTypes are the types asked of every listed name.
var drTypes = []string{"NS", "MX", "TXT"}

// drWorld is a world whose crt.sh returns found under example.com.
func drWorld(t *testing.T, found ...string) *world {
	t.Helper()
	return drWorldFrom(t, newWorld(t), found...)
}

// drWorldFrom gives a world crt.sh's names and the owners of drAddr and drAddr2.
func drWorldFrom(t *testing.T, w *world, found ...string) *world {
	t.Helper()
	w.crtsh(map[string][]string{"example.com": found}, nil)
	// Each address has an AS of its own: Team Cymru's answer for an AS grows with each owner
	// call, and the fake answers over UDP only.
	w.owner(drAddr, 64510, "ACME-NET")
	w.owner(drAddr2, 64511, "ACME-NET")
	return w
}

// drRun runs a passive engagement for example.com with name guessing off, so that names come only
// from crt.sh and from the records.
func drRun(t *testing.T, w *world, extra ...string) {
	t.Helper()
	runRoot(t, w, append([]string{"--no-permutations"}, extra...)...)
}

// drJobs are the completed dnsrecords jobs, with the SRV key's hash of the service list cut off
// ("<name>|SRV").
func drJobs(w *world) []string {
	var out []string
	for _, k := range w.h.completed(eng, "dnsrecords") {
		if name, _, ok := strings.Cut(k, "|SRV|"); ok {
			k = name + "|SRV"
		}
		out = append(out, k)
	}
	return out
}

// drCounts are the queries of name for each type, as "TYPE=n".
func drCounts(w *world, name string, types ...string) []string {
	var out []string
	for _, ty := range types {
		out = append(out, ty+"="+strconv.Itoa(w.dns.Count(name, ty)))
	}
	return out
}

// drWantCounts checks that name was asked n times for each type.
func drWantCounts(t *testing.T, w *world, name string, n int, why string, types ...string) {
	t.Helper()
	for _, ty := range types {
		if got := w.dns.Count(name, ty); got != n {
			t.Errorf("%s asked %d times for %s, want %d (%s); all: %v", name, got, ty, n, why, drCounts(w, name, types...))
		}
	}
}

// drAsked is the number of queries of name, of every type.
func drAsked(w *world, name string) int {
	n := 0
	for _, ty := range mdns.TypeToString {
		n += w.dns.Count(name, ty)
	}
	return n
}

// drRows are the resolutions.csv rows of a name and type.
func drRows(w *world, name, typ string) []map[string]string {
	var out []map[string]string
	for _, r := range w.table(eng, "resolutions.csv") {
		if r["name"] == name && r["type"] == typ {
			out = append(out, r)
		}
	}
	return out
}

// drRow is the resolutions.csv row of a name, type and value, nil when there is none.
func drRow(w *world, name, typ, value string) map[string]string {
	for _, r := range drRows(w, name, typ) {
		if r["value"] == value {
			return r
		}
	}
	return nil
}

// drPublic fails the test unless the first address of each prefix is public, as an SPF
// candidate's must be.
func drPublic(t *testing.T, prefixes ...string) {
	t.Helper()
	for _, s := range prefixes {
		if k := addrkind.Of(netip.MustParsePrefix(s).Addr()); k != addrkind.Public {
			t.Fatalf("setup: %s is %s, not public", s, k)
		}
	}
}

// --- Which names are asked ---

// A subdomain with an address is asked for NS, MX and TXT once each; the input root is asked by
// dnsroot only, which asks its MX too; a second run sends no lookup.
func TestDNSRecords_SubdomainIsAskedOnceForEachType(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "app.example.com")
	w.dns.A("app.example.com", drAddr)
	drRun(t, w)

	if st, reason := stateOf(w, "dnsrecords"); st != "done" {
		t.Errorf("dnsrecords under --passive = %q (%s), want done", st, reason)
	}
	drWantCounts(t, w, "app.example.com", 1, "a subdomain with an address", drTypes...)
	jobs := drJobs(w)
	for _, k := range []string{"app.example.com|NS", "app.example.com|MX", "app.example.com|TXT"} {
		if !slices.Contains(jobs, k) {
			t.Errorf("dnsrecords has no completed job %s: %v", k, jobs)
		}
	}
	// The root keeps dnsroot's lookups, MX among them, and dnsrecords asks it nothing.
	drWantCounts(t, w, "example.com", 1, "the input root, by dnsroot alone", drTypes...)
	for _, k := range jobs {
		if strings.HasPrefix(k, "example.com|") {
			t.Errorf("dnsrecords asked the input root: %s", k)
		}
	}
	if done := w.h.completed(eng, "dnsroot"); !slices.Contains(done, "example.com|MX") {
		t.Errorf("dnsroot has no MX job for the root: %v", done)
	}

	before := w.dns.Total()
	drRun(t, w, "-e", eng)
	if got := w.dns.Total() - before; got != 0 {
		t.Errorf("the second run sent %d DNS queries, want 0", got)
	}
}

// Not asked: a name answered NXDOMAIN, a wildcard-only name, an alias, a candidate hostname and an
// excluded name.
func TestDNSRecords_NamesThatAreNotAsked(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "app.example.com", "gone.example.com", "x.wz.example.com", "al.example.com", "secret.example.com")
	w.dns.A("app.example.com", drAddr) // a control: it is asked
	// gone.example.com has no records: NXDOMAIN.
	w.dns.Wildcard("wz.example.com", "203.0.113.60")
	w.owner("203.0.113.60", 64512, "ACME-NET")
	w.dns.CNAME("al.example.com", "edge.cdn-host.test")
	w.dns.A("edge.cdn-host.test", "203.0.113.50")
	w.owner("203.0.113.50", 64513, "ACME-NET")
	w.dns.A("secret.example.com", drAddr)
	// A PTR name in an in-scope netblock that resolves into it, under no input root: in scope by
	// its address, but not a name whose records are asked for.
	w.dns.PTR("198.51.100.2", "host.deep.other.org")
	w.dns.A("host.deep.other.org", "198.51.100.2")
	drRun(t, w, "--cidr", "198.51.100.0/30", "-x", "secret.example.com")

	if find(w.table(eng, "scope.csv"), "value", "host.deep.other.org") == nil {
		t.Fatalf("setup: the PTR name is not in scope by address: %s", w.file(eng, "scope.csv"))
	}
	if !slices.Contains(w.lines(eng, "wildcard-excluded.txt"), "x.wz.example.com") {
		t.Fatalf("setup: x.wz.example.com is not wildcard-only: %v", w.lines(eng, "wildcard-excluded.txt"))
	}
	if !slices.Contains(w.lines(eng, "unresolved.txt"), "gone.example.com") {
		t.Fatalf("setup: gone.example.com did not answer NXDOMAIN: %v", w.lines(eng, "unresolved.txt"))
	}
	drWantCounts(t, w, "app.example.com", 1, "control: a subdomain with an address", drTypes...)
	for name, why := range map[string]string{
		"gone.example.com":    "answered NXDOMAIN",
		"x.wz.example.com":    "wildcard-only",
		"al.example.com":      "an alias",
		"edge.cdn-host.test":  "an alias's target outside scope",
		"secret.example.com":  "excluded",
		"host.deep.other.org": "in scope by address, under no input root",
	} {
		drWantCounts(t, w, name, 0, why, drTypes...)
	}
}

// A name answered NODATA (it has only an MX record) is asked, and its record is a row.
func TestDNSRecords_NameWithNoAddressIsAsked(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "mailonly.example.com")
	w.dns.MX("mailonly.example.com", 10, "mx.mailhost.test")
	drRun(t, w)

	drWantCounts(t, w, "mailonly.example.com", 1, "answered NODATA, not NXDOMAIN", drTypes...)
	if drRow(w, "mailonly.example.com", "MX", "10 mx.mailhost.test") == nil {
		t.Errorf("resolutions.csv has no MX row for mailonly.example.com:\n%s", w.file(eng, "resolutions.csv"))
	}
}

// A parent name that does not resolve is asked, and only its own records' rows list it; one that
// resolves is asked once, as the hostname it is.
func TestDNSRecords_ParentNamesAreAsked(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "a.p.example.com", "a.q.example.com")
	w.dns.A("a.p.example.com", drAddr)
	w.dns.A("a.q.example.com", drAddr)
	w.dns.TXT("p.example.com", "parent-p-text") // p.example.com has no address: NODATA
	w.dns.A("q.example.com", drAddr2)
	drRun(t, w)

	if !slices.Contains(w.lines(eng, "subdomains.txt"), "q.example.com") {
		t.Fatalf("setup: the resolving parent q.example.com is not a hostname: %v", w.lines(eng, "subdomains.txt"))
	}
	drWantCounts(t, w, "p.example.com", 1, "a parent that does not resolve", drTypes...)
	drWantCounts(t, w, "q.example.com", 1, "a parent that resolves", drTypes...)
	if drRow(w, "p.example.com", "TXT", "parent-p-text") == nil {
		t.Errorf("resolutions.csv has no TXT row for the parent p.example.com:\n%s", w.file(eng, "resolutions.csv"))
	}
	if slices.Contains(w.lines(eng, "subdomains.txt"), "p.example.com") {
		t.Errorf("subdomains.txt = %v, want no parent that does not resolve", w.lines(eng, "subdomains.txt"))
	}
}

// A name in a zone whose wildcard check fails is not asked; after a run in which the check
// succeeds, it is.
func TestDNSRecords_NameWaitsForItsZonesWildcardCheck(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "h.z.example.com")
	w.dns.A("h.z.example.com", drAddr)
	probes := learnFixedProbes(t, w, "z.example.com")
	wguardServfail(w, probes)
	w.h.partialFailed(w.run("--passive", "--no-permutations", "example.com"), "wildcard", 1)
	drWantCounts(t, w, "h.z.example.com", 0, "its zone's wildcard check failed", drTypes...)

	wguardClear(w, probes)
	drRun(t, w, "-e", eng)
	drWantCounts(t, w, "h.z.example.com", 1, "asked once its zone's check succeeded", drTypes...)
}

// --- Own records only ---

// An alias is not asked, and nothing of its target's records is the alias's: no row, target,
// third party or SPF term. An included SPF domain that is an alias gives nothing either.
func TestDNSRecords_OwnRecordsOnly(t *testing.T) {
	t.Parallel()
	drPublic(t, "192.0.3.0/24", "198.51.101.0/24")
	w := drWorld(t, "al.example.com", "app.example.com")
	w.dns.CNAME("al.example.com", "edge.cdn-host.test")
	w.dns.A("edge.cdn-host.test", "203.0.113.50")
	w.owner("203.0.113.50", 64513, "ACME-NET")
	w.dns.NS("edge.cdn-host.test", "ns1.cdn-dns.test")
	w.dns.MX("edge.cdn-host.test", 10, "mx.cdn-mail.test")
	w.dns.TXT("edge.cdn-host.test", "v=spf1 ip4:192.0.3.0/24 include:spf.cdn-mail.test -all")
	w.dns.TXT("edge.cdn-host.test", "google-site-verification=cdntoken")
	// app.example.com includes _spf.example.com, an alias of a mail vendor's record.
	w.dns.A("app.example.com", drAddr)
	w.dns.TXT("app.example.com", "v=spf1 include:_spf.example.com -all")
	w.dns.CNAME("_spf.example.com", "spf.mailvendor.test")
	w.dns.TXT("spf.mailvendor.test", "v=spf1 ip4:198.51.101.0/24 include:deep.mailvendor.test -all")
	drRun(t, w)

	if drRow(w, "app.example.com", "TXT", "v=spf1 include:_spf.example.com -all") == nil {
		t.Errorf("control: app.example.com's own TXT is not a row:\n%s", w.file(eng, "resolutions.csv"))
	}
	if n := w.dns.Count("_spf.example.com", "TXT"); n == 0 {
		t.Error("control: the included domain _spf.example.com was never asked for TXT")
	}
	for _, ty := range drTypes {
		if rows := drRows(w, "al.example.com", ty); len(rows) != 0 {
			t.Errorf("the alias target's %s records are the alias's: %v", ty, rows)
		}
	}
	if rows := drRows(w, "_spf.example.com", "TXT"); len(rows) != 0 {
		t.Errorf("the included alias's target's TXT records are rows of the alias: %v", rows)
	}
	for _, r := range w.table(eng, "third-parties.csv") {
		if strings.Contains(r["domain"], "cdn-dns.test") || strings.Contains(r["domain"], "cdn-mail.test") ||
			strings.Contains(r["domain"], "mailvendor.test") || r["provider"] == "Google" {
			t.Errorf("a third party came from an alias target's records: %v", r)
		}
	}
	for _, c := range []string{"192.0.3.0/24", "198.51.101.0/24"} {
		if r := find(w.table(eng, "candidates.csv"), "value", c); r != nil {
			t.Errorf("an alias target's SPF term is a candidate: %v", r)
		}
	}
	for _, n := range []string{"deep.mailvendor.test", "spf.cdn-mail.test", "ns1.cdn-dns.test", "mx.cdn-mail.test"} {
		if got := drAsked(w, n); got != 0 {
			t.Errorf("%s, named only by an alias target's records, was queried %d times", n, got)
		}
	}
}

// --- Rows ---

// A subdomain's NS, MX and TXT records, a root's MX, an included domain's TXT and a null MX are
// rows of resolutions.csv; self_hosted is filled on a root's NS row only.
func TestDNSRecords_RecordsAreRows(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "app.example.com", "nullmx.example.com")
	w.dns.A("app.example.com", drAddr)
	w.dns.NS("app.example.com", "ns1.example.com")
	w.dns.MX("app.example.com", 10, "mx.mailhost.test")
	w.dns.TXT("app.example.com", "hello from app")
	w.dns.TXT("app.example.com", "v=spf1 include:_spf.example.com -all")
	w.dns.TXT("_spf.example.com", "v=spf1 -all")
	w.dns.A("nullmx.example.com", drAddr)
	w.dns.MX("nullmx.example.com", 0, ".")
	w.dns.NS("example.com", "ns1.example.com")
	w.dns.MX("example.com", 10, "mx.mailhost.test")
	w.dns.A("ns1.example.com", drAddr2)
	drRun(t, w)

	for _, want := range [][3]string{
		{"app.example.com", "NS", "ns1.example.com"},
		{"app.example.com", "MX", "10 mx.mailhost.test"},
		{"app.example.com", "TXT", "hello from app"},
		{"app.example.com", "TXT", "v=spf1 include:_spf.example.com -all"},
		{"example.com", "MX", "10 mx.mailhost.test"},
		{"_spf.example.com", "TXT", "v=spf1 -all"},
		{"nullmx.example.com", "MX", "0 ."},
	} {
		r := drRow(w, want[0], want[1], want[2])
		if r == nil || r["source"] != "resolve" || r["current"] != "true" {
			t.Errorf("resolutions.csv row %v = %v, want a current row of source resolve:\n%s", want, r, w.file(eng, "resolutions.csv"))
		}
	}
	if r := drRow(w, "example.com", "NS", "ns1.example.com"); r == nil || r["self_hosted"] == "" {
		t.Errorf("the root's NS row = %v, want self_hosted filled", r)
	}
	if r := drRow(w, "app.example.com", "NS", "ns1.example.com"); r == nil || r["self_hosted"] != "" {
		t.Errorf("the subdomain's NS row = %v, want self_hosted blank", r)
	}
	// The included domain is asked for TXT only, and is not a hostname.
	drWantCounts(t, w, "_spf.example.com", 1, "an included domain", "TXT")
	drWantCounts(t, w, "_spf.example.com", 0, "an included domain is asked for TXT only", "NS", "MX", "A", "AAAA")
	if _, ok := w.obsAttrs(eng, "hostname")["_spf.example.com"]; ok {
		t.Error("the included domain _spf.example.com is a hostname")
	}
	// A null MX names no host.
	if got := domains(tpRows(w, "mx")); !slices.Equal(got, []string{"mailhost.test"}) {
		t.Errorf("mx third parties = %v, want only mailhost.test (a null MX names no host)", got)
	}
}

// A Shodan MX claim, which holds the host without its preference, merges into nyx's own MX row,
// for the root and for a subdomain.
func TestDNSRecords_ShodanMXClaimMergesIntoTheRow(t *testing.T) {
	t.Parallel()
	w := drWorld(t)
	w.h.setKey("shodan", shodanKey)
	w.handle("api.shodan.io", func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/dns/domain/example.com") {
			_, _ = rw.Write([]byte(`{"domain":"example.com","subdomains":["app"],"more":false,"data":[
				{"subdomain":"","type":"MX","value":"mx.mailhost.test"},
				{"subdomain":"app","type":"MX","value":"mx2.mailhost.test"}]}`))
			return
		}
		http.NotFound(rw, r)
	})
	w.dns.MX("example.com", 10, "mx.mailhost.test")
	w.dns.A("app.example.com", drAddr)
	w.dns.MX("app.example.com", 20, "mx2.mailhost.test")
	drRun(t, w)

	for name, host := range map[string]string{"example.com": "mx.mailhost.test", "app.example.com": "mx2.mailhost.test"} {
		rows := drRows(w, name, "MX")
		if len(rows) != 1 || rows[0]["source"] != "resolve;shodan" || !strings.HasSuffix(rows[0]["value"], " "+host) {
			t.Errorf("MX rows of %s = %v, want one row of %s with source resolve;shodan", name, rows, host)
		}
	}
}

// --- Names in scope ---

// An in-scope NS target, MX target, CNAME target and a name written in a TXT value are listed,
// resolved and asked for their own records, all in the invocation that found them.
func TestDNSRecords_TargetsBecomeHostnames(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "app.example.com", "www.example.com")
	w.dns.A("app.example.com", drAddr)
	w.dns.NS("app.example.com", "ns9.example.com")
	w.dns.MX("app.example.com", 10, "mx9.example.com")
	w.dns.TXT("app.example.com", "portal at https://portal9.example.com/login")
	w.dns.CNAME("www.example.com", "lb9.example.com")
	targets := []string{"ns9.example.com", "mx9.example.com", "portal9.example.com", "lb9.example.com"}
	for _, n := range targets {
		w.dns.A(n, drAddr2)
	}
	drRun(t, w)

	subs := w.lines(eng, "subdomains.txt")
	for _, n := range targets {
		if !slices.Contains(subs, n) {
			t.Errorf("%s is not in subdomains.txt: %v", n, subs)
		}
		if got := w.dns.Count(n, "A"); got != 1 {
			t.Errorf("%s asked for A %d times, want once", n, got)
		}
		if resolutionRow(w, n, "A") == nil {
			t.Errorf("%s has no address row", n)
		}
		drWantCounts(t, w, n, 1, "a hostname found from a record, in the same invocation", drTypes...)
	}
	drWantCounts(t, w, "www.example.com", 0, "an alias", drTypes...)
}

// A CNAME target that does not resolve is listed as unresolved; one that is also a parent name is
// resolved by its own job and not by a parent job as well.
func TestDNSRecords_CNAMETargets(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "www2.example.com", "x.pc.example.com")
	w.dns.CNAME("www2.example.com", "gone2.example.com") // gone2.example.com: NXDOMAIN
	w.dns.CNAME("x.pc.example.com", "pc.example.com")
	w.dns.A("pc.example.com", drAddr)
	drRun(t, w)

	if got := w.lines(eng, "unresolved.txt"); !slices.Contains(got, "gone2.example.com") {
		t.Errorf("unresolved.txt = %v, want the dangling CNAME target gone2.example.com", got)
	}
	if got := w.lines(eng, "subdomains.txt"); !slices.Contains(got, "gone2.example.com") || !slices.Contains(got, "pc.example.com") {
		t.Errorf("subdomains.txt = %v, want both CNAME targets", got)
	}
	done := w.h.completed(eng, "resolve")
	if !slices.Contains(done, "pc.example.com") || slices.Contains(done, "parent|pc.example.com") {
		t.Errorf("resolve jobs = %v, want pc.example.com resolved by its own job and no parent job", done)
	}
	if n := w.dns.Count("pc.example.com", "A"); n != 1 {
		t.Errorf("pc.example.com asked for A %d times, want once", n)
	}
}

// A target outside scope, an excluded target and a target with a label that starts with _ are not
// hostnames, and are not resolved.
func TestDNSRecords_TargetsThatAreNotHostnames(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "app.example.com", "www3.example.com")
	w.dns.A("app.example.com", drAddr)
	w.dns.NS("app.example.com", "ns.dnshost.test")
	w.dns.MX("app.example.com", 10, "mx.mailhost.test")
	w.dns.MX("app.example.com", 20, "excl.example.com")
	w.dns.MX("app.example.com", 30, "_bounce.example.com")
	w.dns.CNAME("www3.example.com", "_edge.example.com")
	w.dns.A("_edge.example.com", drAddr2)
	w.dns.A("excl.example.com", drAddr2)
	drRun(t, w, "-x", "excl.example.com")

	if drRow(w, "app.example.com", "MX", "20 excl.example.com") == nil {
		t.Errorf("control: app.example.com's MX records are not rows:\n%s", w.file(eng, "resolutions.csv"))
	}
	hosts := w.obsAttrs(eng, "hostname")
	subs := w.lines(eng, "subdomains.txt")
	for _, n := range []string{"ns.dnshost.test", "mx.mailhost.test", "excl.example.com", "_bounce.example.com", "_edge.example.com"} {
		if _, ok := hosts[n]; ok {
			t.Errorf("%s is a hostname", n)
		}
		if slices.Contains(subs, n) {
			t.Errorf("%s is in subdomains.txt", n)
		}
		if got := w.dns.Count(n, "A") + w.dns.Count(n, "AAAA"); got != 0 {
			t.Errorf("%s was resolved (%d queries)", n, got)
		}
	}
}

// Names in a TXT value: read in lower case, whole (a name followed by labels outside scope gives
// nothing), never with a label that starts with _, and after @, : or //.
func TestDNSRecords_NamesInTXTValues(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "txt.example.com")
	w.dns.A("txt.example.com", drAddr)
	for _, v := range []string{
		"see API.Example.COM",
		"fwd www.example.com.evil.net",
		"_dmarc.example.com",
		"sel._domainkey.example.com",
		"*.cdn.example.com",
		"ops@mailer.example.com",
		"host:db.example.com",
		"https://cdnx.example.com/x",
	} {
		w.dns.TXT("txt.example.com", v)
	}
	drRun(t, w)

	subs := w.lines(eng, "subdomains.txt")
	for _, n := range []string{"api.example.com", "cdn.example.com", "mailer.example.com", "db.example.com", "cdnx.example.com"} {
		if !slices.Contains(subs, n) {
			t.Errorf("%s, written in a TXT value, is not in subdomains.txt: %v", n, subs)
		}
		if got := w.dns.Count(n, "A"); got != 1 {
			t.Errorf("%s asked for A %d times, want once", n, got)
		}
	}
	for _, s := range subs {
		if s != strings.ToLower(s) {
			t.Errorf("subdomains.txt has a name not in lower case: %s", s)
		}
	}
	hosts := w.obsAttrs(eng, "hostname")
	for _, n := range []string{"www.example.com", "www.example.com.evil.net", "_dmarc.example.com", "dmarc.example.com",
		"sel._domainkey.example.com", "_domainkey.example.com", "domainkey.example.com"} {
		if _, ok := hosts[n]; ok {
			t.Errorf("%s is a hostname", n)
		}
		if got := w.dns.Count(n, "A"); got != 0 {
			t.Errorf("%s was resolved (%d queries)", n, got)
		}
	}
	for _, n := range []string{"www.example.com.evil.net", "example.com.evil.net", "evil.net"} {
		if got := drAsked(w, n); got != 0 {
			t.Errorf("%s was queried %d times", n, got)
		}
	}
}

// --- Names outside scope ---

// A subdomain's NS and MX targets outside scope are ns and mx third parties of its root, a
// verification TXT is a txt-verification row, and its SPF domains are spf rows at depth 0 (1 for
// those of an in-scope domain it includes); none is a candidate or ever queried.
func TestDNSRecords_DependenciesOutsideScope(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "app.example.com", "app2.example.com")
	w.dns.A("app.example.com", drAddr)
	w.dns.NS("app.example.com", "ns1.dnshost.test")
	w.dns.MX("app.example.com", 10, "mx.mailhost.test")
	w.dns.TXT("app.example.com", "google-site-verification=apptoken")
	w.dns.TXT("app.example.com", "v=spf1 include:_spf.vendor1.test include:_spf.example.com a:a.vendor3.test "+
		"mx:m.vendor4.test exists:e.vendor5.test redirect=beside.vendor9.test -all")
	w.dns.TXT("_spf.example.com", "v=spf1 include:inc.vendor6.test a:ia.vendor7.test -all")
	w.dns.A("app2.example.com", drAddr)
	w.dns.TXT("app2.example.com", "v=spf1 redirect=redir.vendor2.test")
	drRun(t, w)

	for mech, domain := range map[string]string{"ns": "dnshost.test", "mx": "mailhost.test"} {
		r := tpRows(w, mech)[domain]
		if r == nil || r["root"] != "example.com" || r["depth"] != "0" || r["current"] != "true" {
			t.Errorf("%s row for %s = %v, want one under example.com at depth 0:\n%s", mech, domain, r, w.file(eng, "third-parties.csv"))
		}
	}
	if r := find(w.table(eng, "third-parties.csv"), "provider", "Google"); r == nil || r["mechanism"] != "txt-verification" || r["root"] != "example.com" {
		t.Errorf("the subdomain's verification TXT = %v, want a txt-verification row under example.com", r)
	}
	spf := tpRows(w, "spf")
	want := map[string]string{
		"_spf.vendor1.test": "0", "a.vendor3.test": "0", "m.vendor4.test": "0", "e.vendor5.test": "0", "redir.vendor2.test": "0",
		"inc.vendor6.test": "1", "ia.vendor7.test": "1",
	}
	if len(spf) != len(want) {
		t.Errorf("spf rows = %v, want %d (no redirect beside all, no in-scope domain):\n%s", domains(spf), len(want), w.file(eng, "third-parties.csv"))
	}
	for d, depth := range want {
		if r := spf[d]; r == nil || r["root"] != "example.com" || r["depth"] != depth {
			t.Errorf("spf row for %s = %v, want under example.com at depth %s", d, r, depth)
		}
	}
	for _, c := range w.table(eng, "candidates.csv") {
		if strings.Contains(c["value"], "vendor") || strings.Contains(c["value"], "dnshost") || strings.Contains(c["value"], "mailhost") {
			t.Errorf("a dependency outside scope is a candidate: %v", c)
		}
	}
	for _, n := range []string{"ns1.dnshost.test", "dnshost.test", "mx.mailhost.test", "mailhost.test",
		"_spf.vendor1.test", "a.vendor3.test", "m.vendor4.test", "e.vendor5.test", "redir.vendor2.test",
		"beside.vendor9.test", "inc.vendor6.test", "ia.vendor7.test"} {
		if got := drAsked(w, n); got != 0 {
			t.Errorf("%s, outside scope, was queried %d times", n, got)
		}
	}
}

// A root's own SPF third parties still come from email only: without email the root's SPF names
// none, and with it the row is email's alone.
func TestDNSRecords_RootSPFThirdPartiesComeFromEmailOnly(t *testing.T) {
	t.Parallel()
	const spf = "v=spf1 include:root.vendor8.test -all"
	w := drWorld(t)
	w.dns.TXT("example.com", spf)
	drRun(t, w)
	if resolutionRow(w, "example.com", "TXT") == nil {
		t.Fatalf("setup: the root's TXT is not a row:\n%s", w.file(eng, "resolutions.csv"))
	}
	if rows := tpRows(w, "spf"); len(rows) != 0 {
		t.Errorf("without email the root's SPF gives spf rows: %v", domains(rows))
	}
	if n := drAsked(w, "root.vendor8.test"); n != 0 {
		t.Errorf("the root's SPF include outside scope was queried %d times", n)
	}

	e := drWorldFrom(t, newWorldWith(t, "email"))
	e.dns.TXT("example.com", spf)
	drRun(t, e)
	if r := tpRows(e, "spf")["root.vendor8.test"]; r == nil || r["root"] != "example.com" || r["depth"] != "0" {
		t.Errorf("the root's spf row = %v, want one under example.com at depth 0", r)
	}
	producers := queryStrings(t, e.h.openDB(eng), "SELECT DISTINCT producer FROM observations WHERE kind = 'third_party' AND key LIKE ?", "%root.vendor8.test%")
	if !slices.Equal(producers, []string{"email"}) {
		t.Errorf("the root's spf third party was observed by %v, want email alone", producers)
	}
}

// --- Delegated zones ---

// A name with NS records of its own gets the SOA, CAA and SRV lookups in the invocation that found
// them, a parent that does not resolve too; a name without gets none. Its SRV targets are hostnames
// or srv third parties of its root, and it gets no email posture.
func TestDNSRecords_DelegatedZones(t *testing.T) {
	t.Parallel()
	w := drWorldFrom(t, newWorldWith(t, "email"), "dz.example.com", "app.example.com", "h.pz.example.com")
	healthy().apply(w.dns, "example.com")
	w.dns.A("dz.example.com", drAddr)
	w.dns.NS("dz.example.com", "ns1.dz-host.test")
	w.dns.MX("dz.example.com", 10, "mx.mailhost.test")
	w.dns.TXT("dz.example.com", "v=spf1 +all")
	w.dns.SRV("_sip._tls.dz.example.com", 10, 60, 5061, "sip.dz.example.com")
	w.dns.SRV("_xmpp-server._tcp.dz.example.com", 5, 0, 5269, "xmpp.chat-host.test")
	w.dns.A("sip.dz.example.com", drAddr2)
	w.dns.A("app.example.com", drAddr)
	w.dns.A("h.pz.example.com", drAddr)
	w.dns.NS("pz.example.com", "ns1.dz-host.test") // a parent with no address, delegated
	drRun(t, w)

	jobs := drJobs(w)
	for _, zone := range []string{"dz.example.com", "pz.example.com"} {
		drWantCounts(t, w, zone, 1, "a delegated zone", "SOA", "CAA")
		for _, s := range srvServices {
			if n := w.dns.Count(s+"."+zone, "SRV"); n != 1 {
				t.Errorf("%s.%s asked for SRV %d times, want once", s, zone, n)
			}
		}
		for _, k := range []string{zone + "|SOA", zone + "|CAA", zone + "|SRV"} {
			if !slices.Contains(jobs, k) {
				t.Errorf("dnsrecords has no completed job %s: %v", k, jobs)
			}
		}
	}
	drWantCounts(t, w, "app.example.com", 0, "not delegated", "SOA", "CAA")
	for _, s := range srvServices {
		if n := w.dns.Count(s+".app.example.com", "SRV"); n != 0 {
			t.Errorf("%s.app.example.com asked for SRV %d times, want none", s, n)
		}
	}

	if drRow(w, "_sip._tls.dz.example.com", "SRV", "10 60 5061 sip.dz.example.com") == nil {
		t.Errorf("the delegated zone's SRV record is not a row:\n%s", w.file(eng, "resolutions.csv"))
	}
	if !slices.Contains(w.lines(eng, "subdomains.txt"), "sip.dz.example.com") || resolutionRow(w, "sip.dz.example.com", "A") == nil {
		t.Errorf("the in-scope SRV target sip.dz.example.com is not a resolved hostname: %v", w.lines(eng, "subdomains.txt"))
	}
	if r := tpRows(w, "srv")["chat-host.test"]; r == nil || r["root"] != "example.com" {
		t.Errorf("the SRV target outside scope = %v, want an srv row under example.com", r)
	}

	drNoEmailPosture(t, w, "dz.example.com", "pz.example.com")
}

// drNoEmailPosture checks that email gave the root a posture and none of names one: no
// email_posture record and no row of email-posture.csv or risk-email.csv.
func drNoEmailPosture(t *testing.T, w *world, names ...string) {
	t.Helper()
	if len(w.table(eng, "email-posture.csv")) == 0 {
		t.Fatalf("setup: email gave the root no posture")
	}
	named := func(v string) bool {
		return slices.ContainsFunc(names, func(n string) bool { return strings.Contains(v, n) })
	}
	for k := range w.obsAttrs(eng, "email_posture") {
		if named(k) {
			t.Errorf("an email posture record names a subdomain: %s", k)
		}
	}
	for _, f := range []string{"email-posture.csv", "risk-email.csv"} {
		for _, r := range w.table(eng, f) {
			for _, v := range r {
				if named(v) {
					t.Errorf("%s has a row for a subdomain: %v", f, r)
				}
			}
		}
	}
}

// --- Failures ---

// A timeout fails only that name's lookup of that type: its other rows are recorded, the run
// exits 7 naming dnsrecords 1, and the next run asks only that lookup.
func TestDNSRecords_TimeoutFailsOnlyThatLookup(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "app.example.com")
	w.dns.A("app.example.com", drAddr)
	w.dns.NS("app.example.com", "ns1.dnshost.test")
	w.dns.MX("app.example.com", 10, "mx.mailhost.test")
	w.dns.TXT("app.example.com", "hello from app")
	w.dns.DropType("app.example.com", "TXT")
	w.h.partialFailed(w.run("--passive", "--no-permutations", "example.com"), "dnsrecords", 1)

	jobs := drJobs(w)
	if !slices.Contains(jobs, "app.example.com|NS") || !slices.Contains(jobs, "app.example.com|MX") || slices.Contains(jobs, "app.example.com|TXT") {
		t.Errorf("dnsrecords jobs = %v, want NS and MX completed and TXT not", jobs)
	}
	if drRow(w, "app.example.com", "NS", "ns1.dnshost.test") == nil || drRow(w, "app.example.com", "MX", "10 mx.mailhost.test") == nil {
		t.Errorf("the name's other lookups recorded no rows:\n%s", w.file(eng, "resolutions.csv"))
	}
	if rows := drRows(w, "app.example.com", "TXT"); len(rows) != 0 {
		t.Errorf("the timed-out TXT lookup recorded %v", rows)
	}

	w.dns.UndropType("app.example.com", "TXT")
	before := w.dns.Total()
	drRun(t, w, "-e", eng)
	if got := w.dns.Total() - before; got != 1 {
		t.Errorf("the next run sent %d DNS queries, want the one TXT lookup", got)
	}
	if n := w.dns.Count("app.example.com", "TXT"); n != 2 {
		t.Errorf("app.example.com asked for TXT %d times, want twice", n)
	}
	if !slices.Contains(drJobs(w), "app.example.com|TXT") || drRow(w, "app.example.com", "TXT", "hello from app") == nil {
		t.Errorf("the retried TXT lookup did not complete or record its row: %v", drJobs(w))
	}
}

// SERVFAIL, NXDOMAIN and an empty answer are results: each completes its job with no rows, for
// NS, MX, TXT, SOA, CAA and the SRV job, and the run exits 0.
func TestDNSRecords_NegativeAnswersCompleteTheJob(t *testing.T) {
	t.Parallel()
	for name, rc := range map[string]int{"SERVFAIL": mdns.RcodeServerFailure, "NXDOMAIN": mdns.RcodeNameError, "empty": mdns.RcodeSuccess} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := drWorld(t, "fns.example.com", "fmx.example.com", "ftxt.example.com", "fz.example.com")
			for _, n := range []string{"fns.example.com", "fmx.example.com", "ftxt.example.com", "fz.example.com"} {
				w.dns.A(n, drAddr)
			}
			w.dns.NS("fns.example.com", "ns1.dnshost.test")
			w.dns.MX("fmx.example.com", 10, "mx.mailhost.test")
			w.dns.TXT("ftxt.example.com", "answered-away")
			w.dns.NS("fz.example.com", "ns1.dnshost.test")
			w.dns.SOA("fz.example.com", "ns1.dnshost.test", "hostmaster.fz.example.com")
			w.dns.CAA("fz.example.com", 0, "issue", "letsencrypt.org")
			w.dns.SRV("_sip._tls.fz.example.com", 10, 60, 5061, "sip.fz.example.com")
			forced := []struct{ name, typ string }{
				{"fns.example.com", "NS"}, {"fmx.example.com", "MX"}, {"ftxt.example.com", "TXT"},
				{"fz.example.com", "SOA"}, {"fz.example.com", "CAA"}, {"_sip._tls.fz.example.com", "SRV"},
			}
			for _, f := range forced {
				w.dns.RcodeType(f.name, f.typ, rc)
			}
			drRun(t, w)

			if resolutionRow(w, "fz.example.com", "NS") == nil {
				t.Fatalf("control: fz.example.com's NS record is not a row:\n%s", w.file(eng, "resolutions.csv"))
			}
			jobs := drJobs(w)
			for _, k := range []string{"fns.example.com|NS", "fmx.example.com|MX", "ftxt.example.com|TXT", "fz.example.com|SOA", "fz.example.com|CAA", "fz.example.com|SRV"} {
				if !slices.Contains(jobs, k) {
					t.Errorf("job %s did not complete: %v", k, jobs)
				}
			}
			for _, f := range forced {
				if rows := drRows(w, f.name, f.typ); len(rows) != 0 {
					t.Errorf("%s %s answered %s, yet recorded %v", f.name, f.typ, name, rows)
				}
			}
			if rows := tpRows(w, "mx"); len(rows) != 0 {
				t.Errorf("mx third parties = %v, want none", domains(rows))
			}
			if slices.Contains(w.lines(eng, "subdomains.txt"), "sip.fz.example.com") {
				t.Error("the target of an SRV record that was not answered is a hostname")
			}
		})
	}
}

// --- Passive, skip and redo ---

// --skip dnsrecords sends none of its lookups and leaves dnsroot's; a later run asks them, and
// --redo dnsrecords asks them again without repeating dnsroot's.
func TestDNSRecords_SkipAndRedo(t *testing.T) {
	t.Parallel()
	w := drWorld(t, "app.example.com")
	w.dns.A("app.example.com", drAddr)
	w.dns.TXT("app.example.com", "hello from app")
	drRun(t, w, "--skip", "dnsrecords")
	drWantCounts(t, w, "app.example.com", 0, "dnsrecords is skipped", drTypes...)
	drWantCounts(t, w, "example.com", 1, "dnsroot is not skipped", drTypes...)
	if st, _ := stateOf(w, "dnsroot"); st != "done" {
		t.Errorf("dnsroot = %q, want done", st)
	}
	if jobs := drJobs(w); len(jobs) != 0 {
		t.Errorf("a skipped dnsrecords completed %v", jobs)
	}

	drRun(t, w, "-e", eng)
	drWantCounts(t, w, "app.example.com", 1, "dnsrecords is no longer skipped", drTypes...)
	drRun(t, w, "--redo", "dnsrecords", "-e", eng)
	drWantCounts(t, w, "app.example.com", 2, "--redo dnsrecords", drTypes...)
	drWantCounts(t, w, "example.com", 1, "--redo dnsrecords repeats none of dnsroot's", drTypes...)
}

// --- Interrupt ---

// An interrupted run keeps the lookups it completed, and the re-run asks only the rest.
func TestDNSRecords_InterruptKeepsCompletedLookups(t *testing.T) {
	t.Parallel()
	names := []string{"i1.example.com", "i2.example.com", "i3.example.com", "i4.example.com"}
	w := drWorld(t, names...)
	for _, n := range names {
		w.dns.A(n, drAddr)
	}
	w.dns.Slow(50*time.Millisecond, names...)
	asked := func() int {
		n := 0
		for _, name := range names {
			for _, ty := range drTypes {
				n += w.dns.Count(name, ty)
			}
		}
		return n
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := make(chan struct{})
	go func() {
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if asked() >= 3 { // two lookups answered, the third in flight
					cancel()
					return
				}
			}
		}
	}()
	code := w.h.execCtx(ctx, "--json", "--rate-per-source", "1000", "--rate-dns", "100000",
		"--passive", "--no-permutations", "--concurrency", "1", "example.com")
	close(stop)
	if code != 130 {
		t.Fatalf("exit %d, want 130 (interrupted while asking the names' records)\n%s", code, w.h.stderr.String())
	}
	var all []string
	for _, n := range names {
		for _, ty := range drTypes {
			all = append(all, n+"|"+ty)
		}
	}
	kept := slices.DeleteFunc(drJobs(w), func(k string) bool { return !slices.Contains(all, k) })
	if len(kept) == 0 || len(kept) >= len(all) {
		t.Fatalf("the interrupted run completed %v, want some but not all of %v", kept, all)
	}
	before := map[string]int{}
	for _, k := range kept {
		name, ty, _ := strings.Cut(k, "|")
		before[k] = w.dns.Count(name, ty)
	}

	drRun(t, w, "-e", eng)
	for k, n := range before {
		name, ty, _ := strings.Cut(k, "|")
		if got := w.dns.Count(name, ty); got != n {
			t.Errorf("the re-run asked %s again: %d queries, was %d", k, got, n)
		}
	}
	jobs := drJobs(w)
	for _, k := range all {
		if !slices.Contains(jobs, k) {
			t.Errorf("job %s is not completed after the re-run: %v", k, jobs)
		}
	}
}

// --- Documentation ---

// drDocRow is the row of the output files table for file.
func drDocRow(t *testing.T, page, file string) string {
	t.Helper()
	for line := range strings.SplitSeq(page, "\n") {
		if strings.HasPrefix(line, "| `"+file+"` |") {
			return line
		}
	}
	t.Fatalf("docs/output.md has no row for %s", file)
	return ""
}

// drBelowRoots matches wording that says names below the roots, not just the roots, are meant.
var drBelowRoots = regexp.MustCompile(`subdomain|below (a|an|the|its|each) (input )?root`)

// docs/output.md names MX among the types of resolutions.csv and says the records of the names
// below the roots are listed, there and in third-parties.csv.
func TestDNSRecords_OutputDocsDescribeTheRows(t *testing.T) {
	t.Parallel()
	page := docPage(t, "output.md")
	res := drDocRow(t, page, "resolutions.csv")
	if !regexp.MustCompile(`\bMX\b`).MatchString(res) {
		t.Errorf("the resolutions.csv row does not name MX among its types: %s", res)
	}
	if !drBelowRoots.MatchString(strings.ToLower(res)) {
		t.Errorf("the resolutions.csv row does not say the records of names below the roots are listed: %s", res)
	}
	if tp := drDocRow(t, page, "third-parties.csv"); !drBelowRoots.MatchString(strings.ToLower(tp)) {
		t.Errorf("the third-parties.csv row does not say a subdomain's dependencies are listed under its root: %s", tp)
	}
}
