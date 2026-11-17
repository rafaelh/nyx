package cli_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

// Service records and well-known hostnames. The dnsroot stage asks each
// in-scope root for a fixed list of SRV names, as one check, and the
// permutations stage always tries a few well-known labels under each root.

var srvServices = []string{
	"_sip._tls", "_sip._tcp", "_sipfederationtls._tcp", "_autodiscover._tcp", "_ldap._tcp",
	"_kerberos._tcp", "_xmpp-server._tcp", "_xmpp-client._tcp", "_caldav._tcp", "_carddav._tcp",
	"_imaps._tcp", "_submission._tcp", "_matrix._tcp", "_minecraft._tcp",
}

var wellKnownLabels = []string{"autodiscover", "lyncdiscover", "enterpriseenrollment", "enterpriseregistration", "mta-sts"}

// srvChecks are the completed dnsroot checks of the SRV list: "<root>|SRV|<hash>".
func srvChecks(w *world) []string {
	var out []string
	for _, k := range w.h.completed(eng, "dnsroot") {
		if strings.Contains(k, "|SRV|") {
			out = append(out, k)
		}
	}
	return out
}

// Each answer is a resolutions.csv row with the priority, weight, port and
// target; every listed service name is asked once, and a name is never
// treated as a hostname.
func TestSRV_AnswersAreRows(t *testing.T) {
	w := newWorld(t)
	w.dns.SRV("_sip._tls.example.com", 10, 60, 5061, "sip.example.com")
	w.dns.SRV("_sip._tls.example.com", 20, 40, 5061, "sipfallback.example.com")
	w.dns.SRV("_xmpp-server._tcp.example.com", 5, 0, 5269, "xmpp.chat-host.test")
	w.dns.SRV("_ldap._tcp.example.com", 0, 0, 0, ".")
	runRoot(t, w)

	got := map[string]bool{}
	for _, r := range w.table(eng, "resolutions.csv") {
		if r["type"] == "SRV" {
			got[r["name"]+"|"+r["value"]] = r["source"] == "resolve"
		}
	}
	for _, want := range []string{
		"_sip._tls.example.com|10 60 5061 sip.example.com",
		"_sip._tls.example.com|20 40 5061 sipfallback.example.com",
		"_xmpp-server._tcp.example.com|5 0 5269 xmpp.chat-host.test",
	} {
		if !got[want] {
			t.Errorf("resolutions.csv lacks SRV row %q (got %v):\n%s", want, got, w.file(eng, "resolutions.csv"))
		}
	}
	// A null target says the service is not offered: it records nothing.
	if len(got) != 3 {
		t.Errorf("SRV rows = %v, want the three with a real target", got)
	}
	if r := resolutionRow(w, "_ldap._tcp.example.com", "SRV"); r != nil {
		t.Errorf("a null target was recorded: %v", r)
	}
	for _, s := range srvServices {
		if n := w.dns.Count(s+".example.com", "SRV"); n != 1 {
			t.Errorf("%s.example.com queried for SRV %d times, want once", s, n)
		}
		for _, ty := range []string{"A", "AAAA", "CNAME"} {
			if n := w.dns.Count(s+".example.com", ty); n != 0 {
				t.Errorf("service name %s.example.com was resolved as a host (%s, %d queries)", s, ty, n)
			}
		}
	}
	if k := srvChecks(w); len(k) != 1 || !strings.HasPrefix(k[0], "example.com|SRV|") {
		t.Errorf("SRV checks = %v, want one for the root", k)
	}
}

// An in-scope target is a hostname; any other is a third party recorded by its
// registrable domain, never a candidate and never resolved.
func TestSRV_Targets(t *testing.T) {
	w := newWorld(t)
	w.dns.SRV("_sip._tls.example.com", 10, 60, 5061, "sip.example.com")
	w.dns.SRV("_caldav._tcp.example.com", 1, 1, 443, "cal.cloudflare.com")
	w.dns.SRV("_carddav._tcp.example.com", 1, 1, 443, "card.cloudflare.com") // same domain: one row
	w.dns.SRV("_xmpp-server._tcp.example.com", 5, 0, 5269, "xmpp.chat-host.test")
	w.dns.SRV("_ldap._tcp.example.com", 0, 0, 0, ".")
	w.dns.A("sip.example.com", "203.0.113.11")
	w.owner("203.0.113.11", 64500, "ACME-NET")
	runRoot(t, w)

	if !slices.Contains(w.lines(eng, "subdomains.txt"), "sip.example.com") {
		t.Errorf("an in-scope target is not a hostname: %v", w.lines(eng, "subdomains.txt"))
	}
	if !slices.Contains(w.probed(), "sip.example.com") {
		t.Errorf("sip.example.com was not offered for probing: %v", w.probed())
	}
	if resolutionRow(w, "sip.example.com", "A") == nil {
		t.Error("an in-scope target was not resolved")
	}

	tp := w.table(eng, "third-parties.csv")
	if len(tp) != 2 {
		t.Fatalf("third-parties.csv = %s", w.file(eng, "third-parties.csv"))
	}
	cf := find(tp, "domain", "cloudflare.com")
	if cf == nil || cf["mechanism"] != "srv" || cf["provider"] != "Cloudflare" || cf["root"] != "example.com" || cf["depth"] != "0" {
		t.Errorf("cloudflare row = %v", cf)
	}
	unk := find(tp, "domain", "chat-host.test")
	if unk == nil || unk["mechanism"] != "srv" || unk["provider"] != "" || unk["root"] != "example.com" {
		t.Errorf("a target of unknown provider is recorded by domain: %v", unk)
	}
	for _, r := range w.table(eng, "candidates.csv") {
		if strings.Contains(r["value"], "cloudflare") || strings.Contains(r["value"], "chat-host") {
			t.Errorf("an out-of-scope target became a candidate: %v", r)
		}
	}
	for _, n := range []string{"cal.cloudflare.com", "xmpp.chat-host.test", "chat-host.test"} {
		if c := w.dns.Count(n, "A") + w.dns.Count(n, "AAAA"); c != 0 {
			t.Errorf("out-of-scope %s was resolved (%d queries)", n, c)
		}
	}
}

// A SERVFAIL or a timeout on any service fails the SRV check, and only it; the
// next run retries it and repeats nothing else.
func TestSRV_FailureFailsOnlyTheSRVCheck(t *testing.T) {
	for name, fail := range map[string]func(w *world){
		"servfail": func(w *world) { w.dns.RcodeType("_matrix._tcp.example.com", "SRV", egress.RCodeServFail) },
		"timeout":  func(w *world) { w.dns.Drop("_matrix._tcp.example.com") },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			w.dns.NS("example.com", "ns1.dns-host.test")
			w.dns.SRV("_sip._tls.example.com", 10, 60, 5061, "sip.example.com")
			fail(w)
			runRoot(t, w)

			if k := srvChecks(w); len(k) != 0 {
				t.Errorf("a failed lookup completed the SRV check: %v", k)
			}
			done := w.h.completed(eng, "dnsroot")
			for _, k := range []string{"example.com|NS|addrs", "example.com|SOA", "example.com|TXT", "example.com|CAA"} {
				if !slices.Contains(done, k) {
					t.Errorf("check %s did not complete: %v", k, done)
				}
			}
			if e := lastState(w.h.events(), "dnsroot"); e.num("failed") != 1 {
				t.Errorf("dnsroot state = %v, want exactly the SRV check failed", e)
			}

			w.dns.ClearRcodeType("_matrix._tcp.example.com", "SRV")
			w.dns.Undrop("_matrix._tcp.example.com")
			runRoot(t, w, "-e", eng)
			if k := srvChecks(w); len(k) != 1 {
				t.Errorf("the failed SRV check was not retried: %v", k)
			}
			if resolutionRow(w, "_sip._tls.example.com", "SRV") == nil {
				t.Errorf("the retried check recorded nothing:\n%s", w.file(eng, "resolutions.csv"))
			}
			if n := w.dns.Count("example.com", "NS"); n != 1 {
				t.Errorf("NS queried %d times; completed checks must not repeat", n)
			}
		})
	}
}

// An engagement that already has the four record types runs the SRV check once
// and asks nothing it already holds.
func TestSRV_ExistingEngagementRunsOnlyTheNewCheck(t *testing.T) {
	w := newWorld(t)
	w.dns.NS("example.com", "ns1.dns-host.test")
	runRoot(t, w)
	// The engagement as an older release left it: no SRV check.
	if _, err := w.h.openDB(eng).Exec(`DELETE FROM checks WHERE stage = 'dnsroot' AND key LIKE '%|SRV|%'`); err != nil {
		t.Fatal(err)
	}
	if k := srvChecks(w); len(k) != 0 {
		t.Fatalf("setup: %v", k)
	}
	w.dns.SRV("_sip._tls.example.com", 10, 60, 5061, "sip.example.com")
	runRoot(t, w, "-e", eng)

	if k := srvChecks(w); len(k) != 1 {
		t.Errorf("SRV checks = %v, want the new one", k)
	}
	if resolutionRow(w, "_sip._tls.example.com", "SRV") == nil {
		t.Errorf("the new check recorded nothing:\n%s", w.file(eng, "resolutions.csv"))
	}
	for _, ty := range []string{"NS", "SOA", "TXT", "CAA"} {
		if n := w.dns.Count("example.com", ty); n != 1 {
			t.Errorf("%s queried %d times, want once: the check was already done", ty, n)
		}
	}
	for _, s := range srvServices {
		if n := w.dns.Count(s+".example.com", "SRV"); n != 2 {
			t.Errorf("%s queried %d times in all, want once before and once after", s, n)
		}
	}
	runRoot(t, w, "-e", eng)
	if n := w.dns.Count("_sip._tls.example.com", "SRV"); n != 2 {
		t.Errorf("a further run repeated the SRV check: %d queries", n)
	}
}

// ips.csv gives the ports SRV records advertise for an address's hostnames,
// and nyx still connects only to the configured ports.
func TestSRV_PortsReportedNeverConnected(t *testing.T) {
	p := newPorts(t)
	p.host("sip.example.com", "203.0.113.7")
	p.owner("203.0.113.7", 64500, "ACME-NET")
	p.host("voip.example.com", "203.0.113.7") // a second name for the same address
	p.host("other.example.com", "203.0.113.8")
	p.owner("203.0.113.8", 64500, "ACME-NET")
	p.dns.SRV("_sip._tls.example.com", 10, 60, 5061, "sip.example.com")
	p.dns.SRV("_sipfederationtls._tcp.example.com", 10, 60, 5061, "sip.example.com")
	p.dns.SRV("_xmpp-server._tcp.example.com", 5, 0, 5269, "voip.example.com")
	p.dns.SRV("_xmpp-client._tcp.example.com", 5, 0, 600, "voip.example.com")
	p.dns.SRV("_matrix._tcp.example.com", 5, 0, 8448, "other.example.com")
	// A name outside the scope that an address points back to (rDNS) is no host of ours:
	// the port its SRV record gives is not attached to that address.
	p.dns.SRV("_ldap._tcp.example.com", 5, 0, 389, "voice.chat-host.test")
	p.dns.PTR("198.51.100.1", "voice.chat-host.test")
	p.addrs("198.51.100.0", "198.51.100.1", "198.51.100.2", "198.51.100.3")
	p.names("sip.example.com", "voip.example.com", "other.example.com")

	// Every SRV port, on every address, is a canary that must never be dialled.
	var never []*portSrv
	for _, ip := range []string{"203.0.113.7", "203.0.113.8", "203.0.113.250", "198.51.100.1"} {
		never = append(never, p.canary(ip, []int{5061, 5269, 600, 8448, 389}))
	}
	p.serve("203.0.113.7", 8080, hello)
	p.sweep([]int{8080}, "--cidr", "198.51.100.0/30")

	rows := p.table(eng, "ips.csv")
	for ip, want := range map[string]string{"203.0.113.7": "600;5061;5269", "203.0.113.8": "8448", "203.0.113.250": "", "198.51.100.1": ""} {
		r := find(rows, "ip", ip)
		if r == nil {
			t.Errorf("no ips.csv row for %s:\n%s", ip, p.file(eng, "ips.csv"))
			continue
		}
		if r["srv_ports"] != want {
			t.Errorf("srv_ports of %s = %q, want %q", ip, r["srv_ports"], want)
		}
	}
	if r := find(rows, "ip", "198.51.100.1"); r == nil || !strings.Contains(r["hostnames"], "voice.chat-host.test") {
		t.Errorf("control: the out-of-scope rDNS name is not listed for 198.51.100.1: %v", r)
	}
	for i, s := range never {
		if s.conns.Load() != 0 {
			t.Errorf("canary %d: an SRV port was connected to", i)
		}
	}
	for _, k := range p.checked() {
		if !strings.HasSuffix(k, ":8080") {
			t.Errorf("a port outside the configured list was checked: %s", k)
		}
	}
	for _, k := range p.openPortKeys() {
		if !strings.HasSuffix(k, ":8080") {
			t.Errorf("an SRV port is a port row: %s", k)
		}
	}
	hdr, _, _ := strings.Cut(p.file(eng, "ips.csv"), "\n")
	if !strings.Contains(hdr, "registry,srv_ports,current,") {
		t.Errorf("ips.csv header = %q, want srv_ports after the registry column", hdr)
	}
}

// A service name is not a hostname: it is never tested as a wildcard zone, and
// rows of type SRV from any source do not name zones or addresses.
func TestSRV_NoWildcardCheckForServiceNames(t *testing.T) {
	w := newWorld(t)
	w.dns.SRV("_sip._tls.example.com", 10, 60, 5061, "sip.example.com")
	w.dns.A("sip.example.com", "203.0.113.11")
	w.owner("203.0.113.11", 64500, "ACME-NET")
	feed := &testkit.Stage{StageName: "feed", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return []run.Check{{Key: "x"}} },
		RunFn: func(context.Context, run.Check, egress.Clients) ([]run.Observation, error) {
			return []run.Observation{
				resolutionObs("_imaps._tcp.example.com", "SRV", "0 1 993 mail.example.com"),
				// A control: the same shape as a CNAME does name a zone.
				resolutionObs("_c._ctl.example.com", "CNAME", "target.example.net"),
			}, nil
		}}
	w.h.stages = append(w.h.stages, feed)
	runRoot(t, w)

	done := w.h.completed(eng, "wildcard")
	if !slices.Contains(done, "_ctl.example.com") {
		t.Fatalf("control: a CNAME row's parent was not checked: %v", done)
	}
	for _, k := range done {
		if strings.Contains(k, "_") && k != "_ctl.example.com" {
			t.Errorf("a wildcard check was made for a service name: %s (all: %v)", k, done)
		}
	}
	for _, n := range []string{"_sip._tls.example.com", "_imaps._tcp.example.com", "_tls.example.com", "_tcp.example.com"} {
		if c := w.dns.Count(n, "A") + w.dns.Count(n, "AAAA"); c != 0 {
			t.Errorf("%s was resolved as a host (%d queries)", n, c)
		}
	}
	if !slices.Contains(w.probed(), "sip.example.com") || slices.ContainsFunc(w.probed(), func(h string) bool { return strings.HasPrefix(h, "_") }) {
		t.Errorf("probed = %v", w.probed())
	}
}

// A new third party is announced like any other, and a row that is no longer
// current still shows its root, mechanism and domain.
func TestSRV_ThirdPartyAnnouncedAndKeptWhenNotCurrent(t *testing.T) {
	w := newWorld(t)
	w.dns.SRV("_xmpp-server._tcp.example.com", 5, 0, 5269, "xmpp.chat-host.test")
	w.dns.SRV("_caldav._tcp.example.com", 1, 1, 443, "cal.cloudflare.com")
	if code := w.h.exec("--passive", "--rate-dns", "100000", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := strings.Join(w.h.logMsgs("INFO"), "\n")
	for _, want := range []string{"+ third-party Cloudflare via srv on example.com", "+ third-party chat-host.test via srv on example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("console lacks %q:\n%s", want, out)
		}
	}

	w.dns.RcodeType("_xmpp-server._tcp.example.com", "SRV", egress.RCodeNXDomain)
	runRoot(t, w, "--redo", "dnsroot", "-e", eng)
	r := find(w.table(eng, "third-parties.csv"), "domain", "chat-host.test")
	if r == nil || r["current"] != "false" || r["mechanism"] != "srv" || r["root"] != "example.com" {
		t.Errorf("a vanished SRV target is not listed as not current with its key's columns: %v\n%s", r, w.file(eng, "third-parties.csv"))
	}
	if r := find(w.table(eng, "third-parties.csv"), "domain", "cloudflare.com"); r == nil || r["current"] != "true" {
		t.Errorf("a target still answered is current: %v", r)
	}
	row := find(w.table(eng, "resolutions.csv"), "value", "5 0 5269 xmpp.chat-host.test")
	if row == nil || row["current"] != "false" || row["name"] != "_xmpp-server._tcp.example.com" || row["type"] != "SRV" {
		t.Errorf("the vanished SRV row = %v", row)
	}
}

// --- well-known labels ---

// The five labels are tried under each root with a wordlist that lacks them,
// once even when the wordlist has them, and not at all without permutations or
// under a wildcard zone.
func TestSRV_WellKnownLabelsAreAlwaysTried(t *testing.T) {
	w := newWorld(t)
	wl := writeFile(t, t.TempDir(), "words.txt", "dev\ntest\nmta-sts\n")
	w.dns.Wildcard("corp.net", "203.0.113.99")
	if code := w.run("--passive", "--wordlist", wl, "example.com", "corp.net"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, l := range wellKnownLabels {
		if n := w.dns.Count(l+".example.com", "A"); n != 1 {
			t.Errorf("%s.example.com queried %d times, want once (a wordlist that has it must not double it)", l, n)
		}
		if n := w.dns.Count(l+".corp.net", "A"); n != 0 {
			t.Errorf("%s.corp.net queried %d times; a wildcard zone is not permuted", l, n)
		}
	}

	// A well-known name that exists is a hostname like any other permutation.
	found := newWorld(t)
	found.dns.A("autodiscover.example.com", "203.0.113.30")
	found.owner("203.0.113.30", 64500, "ACME-NET")
	if code := found.run("--passive", "--wordlist", wl, "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !slices.Contains(found.lines(eng, "subdomains.txt"), "autodiscover.example.com") {
		t.Errorf("a well-known name that exists is not a hostname: %v", found.lines(eng, "subdomains.txt"))
	}

	off := newWorld(t)
	words := writeFile(t, t.TempDir(), "words.txt", "dev\ntest\n")
	if code := off.run("--passive", "--wordlist", words, "--no-permutations", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, l := range wellKnownLabels {
		if n := off.dns.Count(l+".example.com", "A"); n != 0 {
			t.Errorf("--no-permutations: %s.example.com queried %d times", l, n)
		}
	}
}

// The labels are part of the root check, which prices them: with a cap that
// takes one root of four words and five labels, the other is deferred.
func TestSRV_WellKnownLabelsAreCosted(t *testing.T) {
	w := newWorld(t)
	wl := writeFile(t, t.TempDir(), "words.txt", fourWords)
	if code := w.run("--passive", "--concurrency", "1", "--wordlist", wl, "--permutations-max-names", "9", "example.com", "corp.net"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	// Roots go in name order: corp.net takes the whole cap.
	for _, l := range append([]string{"dev", "test", "beta", "old"}, wellKnownLabels...) {
		if n := w.dns.Count(l+".corp.net", "A"); n != 1 {
			t.Errorf("%s.corp.net queried %d times, want once", l, n)
		}
		if n := w.dns.Count(l+".example.com", "A"); n != 0 {
			t.Errorf("%s.example.com queried %d times; its check does not fit the cap", l, n)
		}
	}
	if n := deferredOf(t, w.h, "permutations"); n != 9 {
		t.Errorf("deferred = %d, want the 9 names of the second root", n)
	}
}

// Adding the labels to an engagement repeats the root check once, and no seed check.
func TestSRV_WellKnownLabelsRepeatRootChecksOnce(t *testing.T) {
	w, wl := worldWithSeeds(t, fourWords)
	permRun(w, wl, "--permutations-max", "5")
	checks := w.h.completed(eng, "permutations")
	var rootKey string
	for _, k := range checks {
		if strings.HasPrefix(k, "root|") {
			rootKey = k
		} else if strings.Contains(k, "|wk=") {
			// Seed checks do not use the labels, so their keys are what an older release wrote.
			t.Errorf("a seed check key carries the labels, so an upgrade would repeat it: %s", k)
		}
	}
	// The engagement as an older release left it: its root key has no token of the labels.
	legacy, _, ok := strings.Cut(rootKey, "|wk=")
	if len(checks) != 3 || !ok {
		t.Fatalf("setup: the root key does not carry the labels: %v", checks)
	}
	if _, err := w.h.openDB(eng).Exec(`UPDATE checks SET key = ? WHERE stage = 'permutations' AND key = ?`, legacy, rootKey); err != nil {
		t.Fatal(err)
	}
	seedName := derived(w, "api")[0]
	before := w.dns.Count(seedName, "A")

	permRun(w, wl, "--permutations-max", "5")
	if got := w.h.completed(eng, "permutations"); len(got) != 4 || !slices.Contains(got, legacy) || !slices.Contains(got, rootKey) {
		t.Errorf("checks after the upgrade = %v, want the old three and the new root key %s", got, rootKey)
	}
	for _, name := range []string{"dev.example.com", "mta-sts.example.com"} {
		if n := w.dns.Count(name, "A"); n != 2 {
			t.Errorf("%s queried %d times, want once before and once after", name, n)
		}
	}
	if n := w.dns.Count(seedName, "A"); n != before {
		t.Errorf("seed name %s queried %d times, was %d: no seed check may repeat", seedName, n, before)
	}
	permRun(w, wl, "--permutations-max", "5")
	if n := w.dns.Count("dev.example.com", "A"); n != 2 {
		t.Errorf("a further run repeated the root check: %d queries", n)
	}
}
