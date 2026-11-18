package cli_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

// emailWorld is a passive world with the email stage kept in the stage list.
func emailWorld(t *testing.T) *world { return newWorldWith(t, "email") }

// tpRows are the third-parties.csv rows of one mechanism, by domain.
func tpRows(w *world, mechanism string) map[string]map[string]string {
	w.t.Helper()
	out := map[string]map[string]string{}
	for _, r := range w.table(eng, "third-parties.csv") {
		if r["mechanism"] == mechanism {
			out[r["domain"]] = r
		}
	}
	return out
}

func domains(rows map[string]map[string]string) []string { return slices.Sorted(maps.Keys(rows)) }

// Every domain the SPF walk follows, and every a:, mx: and exists: argument at
// any level, is a row; the depth counts from 0; macros are skipped.
func TestEmailThirdParties_SPFDepthAndMechanisms(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.TXT("example.com", "v=spf1 include:a.mailer.test a:host.vendor.test mx:mx.vendor2.test/24 exists:chk.vendor3.test include:%{d}.macro.test exists:%{i}.macro2.test a mx -all")
	w.dns.TXT("a.mailer.test", "v=spf1 include:b.deep.test -all")
	w.dns.TXT("b.deep.test", "v=spf1 a:inner.vendor4.test -all")
	runRoot(t, w)

	rows := tpRows(w, "spf")
	want := map[string]string{
		"a.mailer.test": "0", "host.vendor.test": "0", "mx.vendor2.test": "0", "chk.vendor3.test": "0",
		"b.deep.test": "1", "inner.vendor4.test": "2",
	}
	if len(rows) != len(want) {
		t.Errorf("spf rows = %v, want %d:\n%s", domains(rows), len(want), w.file(eng, "third-parties.csv"))
	}
	for d, depth := range want {
		r := rows[d]
		if r == nil || r["root"] != "example.com" || r["depth"] != depth || r["current"] != "true" {
			t.Errorf("row for %s = %v, want depth %s", d, r, depth)
		}
	}
	for _, d := range domains(rows) {
		if strings.Contains(d, "macro") || strings.Contains(d, "%") {
			t.Errorf("a macro argument is a row: %s", d)
		}
	}
}

// An include that has no SPF record is still listed.
func TestEmailThirdParties_IncludeWithoutSPFIsListed(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.TXT("example.com", "v=spf1 include:gone.vendor.test -all")
	runRoot(t, w)
	if r := tpRows(w, "spf")["gone.vendor.test"]; r == nil || r["depth"] != "0" {
		t.Errorf("rows:\n%s", w.file(eng, "third-parties.csv"))
	}
	if n := len(w.h.completed(eng, "email")); n != 1 {
		t.Errorf("the check did not complete: %d", n)
	}
}

// A redirect that the record's own all makes unreachable is not followed, so it is not listed.
func TestEmailThirdParties_IgnoredRedirectIsNotListed(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.TXT("example.com", "v=spf1 -all redirect=r.vendor.test")
	runRoot(t, w)
	if got := tpRows(w, "spf"); len(got) != 0 {
		t.Errorf("rows = %v", domains(got))
	}
	w2 := emailWorld(t)
	w2.dns.TXT("example.com", "v=spf1 redirect=r.vendor.test")
	w2.dns.TXT("r.vendor.test", "v=spf1 a:inner.vendor2.test -all")
	runRoot(t, w2)
	rows := tpRows(w2, "spf")
	if rows["r.vendor.test"] == nil || rows["r.vendor.test"]["depth"] != "0" || rows["inner.vendor2.test"] == nil || rows["inner.vendor2.test"]["depth"] != "1" {
		t.Errorf("a followed redirect: %v\n%s", domains(rows), w2.file(eng, "third-parties.csv"))
	}
}

// A SERVFAIL on any include fails the check, so the run records no third parties for the root.
func TestEmailThirdParties_IncludeServfailRecordsNothing(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.TXT("example.com", "v=spf1 include:ok.vendor.test include:broken.vendor2.test -all")
	w.dns.TXT("ok.vendor.test", "v=spf1 -all")
	w.dns.Rcode("broken.vendor2.test", mdns.RcodeServerFailure)
	w.dns.TXT("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:r@rep.vendor3.test")
	w.dns.MX("example.com", 10, "mx.vendor4.test")
	runRootPartial(t, w, "email", 1)
	if got := w.file(eng, "third-parties.csv"); got != "" {
		t.Errorf("a failed check recorded third parties:\n%s", got)
	}
	w.dns.ClearRcode("broken.vendor2.test")
	w.dns.TXT("broken.vendor2.test", "v=spf1 -all")
	runRoot(t, w, "-e", eng)
	if len(tpRows(w, "spf")) != 2 || len(tpRows(w, "dmarc")) != 1 || len(tpRows(w, "mx")) != 1 {
		t.Errorf("after the retry:\n%s", w.file(eng, "third-parties.csv"))
	}
}

// A domain that shares the registrable domain of its root is not a third party.
func TestEmailThirdParties_SameRegistrableDomainDropped(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.TXT("example.com", "v=spf1 include:_spf.example.com a:mail.example.com include:other.vendor.test -all")
	w.dns.TXT("_spf.example.com", "v=spf1 -all")
	w.dns.TXT("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:d@example.com,mailto:d@vendor.test")
	runRoot(t, w)
	if got := domains(tpRows(w, "spf")); !slices.Equal(got, []string{"other.vendor.test"}) {
		t.Errorf("spf rows = %v", got)
	}
	if got := domains(tpRows(w, "dmarc")); !slices.Equal(got, []string{"vendor.test"}) {
		t.Errorf("dmarc rows = %v", got)
	}
	// The same holds for a subdomain root: its organisational domain is its registrable domain.
	w2 := emailWorld(t)
	w2.dns.TXT("sub.example.com", "v=spf1 include:_spf.example.com include:x.vendor.test -all")
	w2.dns.TXT("_spf.example.com", "v=spf1 -all")
	runRoot(t, w2, "-e", eng, "sub.example.com")
	if got := domains(tpRows(w2, "spf")); !slices.Equal(got, []string{"x.vendor.test"}) {
		t.Errorf("subdomain root spf rows = %v", got)
	}
}

// Several rua and ruf URIs, a size suffix and a non-mailto URI.
func TestEmailThirdParties_DMARCReportAddresses(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.TXT("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:a@rep.vendor.test!10m,mailto:b@rep2.vendor.test,https://web.vendor3.test/report; ruf=MAILTO:f@forensic.vendor4.test!50k, mailto:g@rep.vendor.test")
	runRoot(t, w)
	rows := tpRows(w, "dmarc")
	if got := domains(rows); !slices.Equal(got, []string{"forensic.vendor4.test", "rep.vendor.test", "rep2.vendor.test"}) {
		t.Errorf("dmarc rows = %v\n%s", got, w.file(eng, "third-parties.csv"))
	}
	for d, r := range rows {
		if r["root"] != "example.com" || r["depth"] != "0" {
			t.Errorf("row for %s = %v", d, r)
		}
	}
}

// A policy found at the organisational domain belongs to the root that used it.
func TestEmailThirdParties_DMARCInheritedFromOrganisationalDomain(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.TXT("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:a@rep.vendor.test")
	runRoot(t, w, "-e", eng, "sub.example.com")
	rows := tpRows(w, "dmarc")
	if r := rows["rep.vendor.test"]; r == nil || r["root"] != "sub.example.com" || len(rows) != 1 {
		t.Errorf("rows:\n%s", w.file(eng, "third-parties.csv"))
	}
}

// An MX row uses the host's registrable domain; one in the scope is not listed,
// nor is an address an MX record wrongly names.
func TestEmailThirdParties_MX(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.MX("example.com", 5, "192.0.2.25")
	w.dns.MX("example.com", 10, "mx1.mailvendor.test")
	w.dns.MX("example.com", 20, "mx2.mailvendor.test")
	w.dns.MX("example.com", 30, "mail.example.com")
	w.dns.MX("example.com", 40, "example-com.mail.protection.outlook.com")
	runRoot(t, w)
	rows := tpRows(w, "mx")
	if got := domains(rows); !slices.Equal(got, []string{"mailvendor.test", "outlook.com"}) {
		t.Errorf("mx rows = %v\n%s", got, w.file(eng, "third-parties.csv"))
	}
	if r := rows["outlook.com"]; r == nil || r["provider"] != "Microsoft 365" || r["root"] != "example.com" {
		t.Errorf("outlook row = %v", r)
	}
	if r := rows["mailvendor.test"]; r == nil || r["provider"] != "" {
		t.Errorf("mailvendor row = %v", r)
	}
}

// A domain under another in-scope root is hidden, whether that root was given
// with the first or added later, and a not-current row is hidden too.
func TestEmailThirdParties_DomainUnderInScopeRootIsHidden(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.TXT("example.com", "v=spf1 include:_spf.partner.test include:_spf.vendor.test -all")
	w.dns.MX("example.com", 10, "mx.partner.test")
	runRoot(t, w, "-e", eng, "example.com", "partner.test")
	if got := domains(tpRows(w, "mx")); len(got) != 0 {
		t.Errorf("mx rows = %v, under a root in scope", got)
	}
	if got := domains(tpRows(w, "spf")); !slices.Equal(got, []string{"_spf.vendor.test"}) {
		t.Errorf("spf rows = %v", got)
	}

	w2 := emailWorld(t)
	w2.dns.TXT("example.com", "v=spf1 include:_spf.partner.test -all")
	w2.dns.TXT("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:r@dmarc.partner.test")
	w2.dns.MX("example.com", 10, "mx.partner.test")
	runRoot(t, w2)
	if len(w2.table(eng, "third-parties.csv")) != 3 {
		t.Fatalf("first run:\n%s", w2.file(eng, "third-parties.csv"))
	}
	runRoot(t, w2, "--skip", "email", "-e", eng, "partner.test")
	if got := w2.file(eng, "third-parties.csv"); got != "" {
		t.Errorf("a root added later did not hide the rows:\n%s", got)
	}
}

// The cname mechanism lists SaaS chains of in-scope, non-wildcard names only.
func TestEmailThirdParties_CNAMEMechanism(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.crtsh(map[string][]string{"example.com": {
		"shop.example.com", "shop2.example.com", "site.example.com", "cdn.example.com", "x.wild.example.com", "excl.example.com", "chain.example.com",
	}}, nil)
	w.dns.CNAME("shop.example.com", "stores.myshopify.com")
	w.dns.A("stores.myshopify.com", "203.0.113.60")
	w.dns.CNAME("shop2.example.com", "stores2.myshopify.com")
	w.dns.A("stores2.myshopify.com", "203.0.113.60")
	w.dns.CNAME("site.example.com", "acme.github.io")
	w.dns.A("acme.github.io", "203.0.113.61")
	w.dns.CNAME("cdn.example.com", "d1.cloudfront.net") // a CDN is not SaaS
	w.dns.A("d1.cloudfront.net", "203.0.113.62")
	w.dns.WildcardCNAME("wild.example.com", "w.myshopify.com")
	w.dns.A("w.myshopify.com", "203.0.113.63")
	w.dns.CNAME("excl.example.com", "ex.zendesk.com")
	w.dns.A("ex.zendesk.com", "203.0.113.64")
	w.dns.CNAME("chain.example.com", "hop.example.net") // a chain that ends at a SaaS entry
	w.dns.CNAME("hop.example.net", "end.readme.io")
	w.dns.A("end.readme.io", "203.0.113.65")
	runRoot(t, w, "--exclude", "excl.example.com")

	rows := tpRows(w, "cname")
	if got := domains(rows); !slices.Equal(got, []string{"github.io", "myshopify.com", "readme.io"}) {
		t.Errorf("cname rows = %v\n%s", got, w.file(eng, "third-parties.csv"))
	}
	for d, want := range map[string]string{"github.io": "GitHub", "myshopify.com": "Shopify", "readme.io": "ReadMe"} {
		r := rows[d]
		if r == nil || r["root"] != "example.com" || r["provider"] != want || r["depth"] != "0" || r["current"] != "true" {
			t.Errorf("row for %s = %v, want provider %s", d, r, want)
		}
	}
	// provider-hosts.csv is not touched: the CDN and the other names still list.
	if find(w.table(eng, "provider-hosts.csv"), "hostname", "cdn.example.com") == nil {
		t.Errorf("provider-hosts.csv lost a row:\n%s", w.file(eng, "provider-hosts.csv"))
	}
}

// A cname row whose hostname stops pointing at the platform goes not current
// on --redo resolve, and still shows its root, mechanism and domain.
func TestEmailThirdParties_CNAMERowGoesNotCurrent(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.crtsh(map[string][]string{"example.com": {"site.example.com"}}, nil)
	w.dns.CNAME("site.example.com", "acme.github.io")
	w.dns.A("acme.github.io", "203.0.113.61")
	runRoot(t, w)
	if r := tpRows(w, "cname")["github.io"]; r == nil || r["current"] != "true" {
		t.Fatalf("first run:\n%s", w.file(eng, "third-parties.csv"))
	}
	w.dns.CNAME("site.example.com", "site.hosting.test")
	w.dns.A("site.hosting.test", "203.0.113.66")
	runRoot(t, w, "--redo", "resolve", "-e", eng)
	r := tpRows(w, "cname")["github.io"]
	if r == nil || r["current"] != "false" || r["root"] != "example.com" || r["mechanism"] != "cname" || r["provider"] != "GitHub" {
		t.Errorf("row = %v\n%s", r, w.file(eng, "third-parties.csv"))
	}
}

// One row per root, mechanism and domain, the provider shown beside the domain.
func TestEmailThirdParties_OneRowAndProvider(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.TXT("example.com", "v=spf1 include:_spf.google.com include:x.vendor.test a:x.vendor.test mx:x.vendor.test -all")
	w.dns.TXT("_spf.google.com", "v=spf1 include:x.vendor.test -all")
	w.dns.TXT("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:r@x.vendor.test")
	runRoot(t, w)

	spf := tpRows(w, "spf")
	if got := domains(spf); !slices.Equal(got, []string{"_spf.google.com", "x.vendor.test"}) {
		t.Fatalf("spf rows = %v\n%s", got, w.file(eng, "third-parties.csv"))
	}
	if r := spf["_spf.google.com"]; r["provider"] != "Google" || r["domain"] != "_spf.google.com" {
		t.Errorf("google row = %v: the domain is never replaced", r)
	}
	if r := spf["x.vendor.test"]; r["provider"] != "" || r["depth"] != "0" {
		t.Errorf("a domain named at depth 0 and 1 keeps the nearer: %v", r)
	}
	if len(tpRows(w, "dmarc")) != 1 { // the same domain under another mechanism is its own row
		t.Errorf("dmarc rows:\n%s", w.file(eng, "third-parties.csv"))
	}
	for _, r := range w.table(eng, "candidates.csv") {
		if strings.Contains(r["value"], "vendor.test") || strings.Contains(r["value"], "google.com") {
			t.Errorf("a third party became a candidate: %v", r)
		}
	}
}

// The new third parties are announced and counted, and the stage runs under --passive.
func TestEmailThirdParties_FoundLineCountAndPassive(t *testing.T) {
	t.Parallel()
	seed := func(w *world) {
		w.dns.TXT("example.com", "v=spf1 include:_spf.google.com -all")
		w.dns.TXT("_spf.google.com", "v=spf1 -all")
		w.dns.MX("example.com", 10, "mx.vendor.test")
	}
	w := emailWorld(t)
	seed(w)
	if code := w.h.exec("--passive", "--rate-dns", "100000", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := strings.Join(w.h.logMsgs("INFO"), "\n")
	for _, want := range []string{"+ third-party Google via spf on example.com", "+ third-party vendor.test via mx on example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("console lacks %q:\n%s", want, out)
		}
	}

	w2 := emailWorld(t)
	seed(w2)
	runRoot(t, w2)
	if st, reason := stateOf(w2, "email"); st != "done" {
		t.Errorf("email under --passive = %s (%s)", st, reason)
	}
	evs := ofType(w2.h.events(), "summary")
	totals, _ := evs[len(evs)-1]["totals"].(map[string]any)
	if n, _ := totals["third parties"].(float64); n != 2 {
		t.Errorf("totals = %v, want 2 third parties", totals)
	}
	// Re-running announces nothing new.
	runRoot(t, w2, "-e", eng)
	for _, e := range ofType(w2.h.events(), "found") {
		if e.str("platform") != "" {
			t.Errorf("a known third party was announced again: %v", e)
		}
	}
}

// --redo email marks a third party the root no longer references as not current,
// and the row still shows its root, mechanism and domain.
func TestEmailThirdParties_RedoEmailRetires(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.TXT("example.com", "v=spf1 include:_spf.vendor.test -all")
	w.dns.TXT("_spf.vendor.test", "v=spf1 -all")
	w.dns.TXT("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:r@rep.vendor2.test")
	w.dns.MX("example.com", 10, "mx.vendor3.test")
	runRoot(t, w)
	if len(w.table(eng, "third-parties.csv")) != 3 {
		t.Fatalf("first run:\n%s", w.file(eng, "third-parties.csv"))
	}
	w.dns.ClearRoot("example.com")
	w.dns.TXT("example.com", "v=spf1 -all")
	runRoot(t, w, "--redo", "email", "-e", eng)
	if r := tpRows(w, "spf")["_spf.vendor.test"]; r == nil || r["current"] != "false" || r["root"] != "example.com" || r["mechanism"] != "spf" {
		t.Errorf("spf row = %v\n%s", r, w.file(eng, "third-parties.csv"))
	}
	if r := tpRows(w, "dmarc")["rep.vendor2.test"]; r == nil || r["current"] != "true" {
		t.Errorf("a third party still referenced stays current: %v", r)
	}
}

// --- MTA-STS ---

func postureRow(w *world, root string) map[string]string {
	return find(w.table(eng, "email-posture.csv"), "root", root)
}

func TestEmailMTASTS_PresentAndAbsent(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		txt  []string
		want string
	}{
		{"present", []string{"v=STSv1; id=20260101"}, "present"},
		{"absent", nil, "absent"},
		{"two records are not exactly one", []string{"v=STSv1; id=1", "v=STSv1; id=2"}, "absent"},
		{"another record is not a policy", []string{"google-site-verification=x"}, "absent"},
		{"one policy among others", []string{"google-site-verification=x", "v=STSv1; id=3"}, "present"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := emailWorld(t)
			m := healthy()
			m.mtasts = c.txt
			m.apply(w.dns, "example.com")
			runRoot(t, w)
			r := postureRow(w, "example.com")
			if r == nil || r["mta_sts"] != c.want {
				t.Fatalf("mta_sts = %v, want %s\n%s", r, c.want, w.file(eng, "email-posture.csv"))
			}
			wantTypes := []string(nil)
			if c.want == "absent" {
				wantTypes = []string{"mta-sts-missing"}
			}
			if got := col(current(w.table(eng, "risk-email.csv")), "type"); !slices.Equal(got, wantTypes) {
				t.Errorf("risk-email.csv types = %v, want %v", got, wantTypes)
			}
			if n := w.dns.Count("_mta-sts.example.com", "TXT"); n != 1 {
				t.Errorf("_mta-sts queried %d times, want once", n)
			}
			if c.name != "absent" {
				return
			}
			// The finding is low and says what is missing; the column heads email-posture.csv's new end.
			f := find(w.table(eng, "risk-email.csv"), "type", "mta-sts-missing")
			if f == nil || f["severity"] != "low" || f["root"] != "example.com" || !strings.Contains(strings.ToLower(f["detail"]), "mta-sts") {
				t.Errorf("finding = %v\n%s", f, w.file(eng, "risk-email.csv"))
			}
			header := csvRows(t, w.file(eng, "email-posture.csv"))[0]
			if header[len(header)-6] != "dkim_selectors" || header[len(header)-5] != "mta_sts" || header[len(header)-4] != "mx_self_hosted" || header[len(header)-3] != "current" {
				t.Errorf("header = %v", header)
			}
		})
	}
}

// A root without a mail host has no value and no lookup, and no finding.
func TestEmailMTASTS_EmptyWithoutMX(t *testing.T) {
	t.Parallel()
	for name, mx := range map[string][]string{"no MX": nil, "null MX": {"0 ."}} {
		t.Run(name, func(t *testing.T) {
			w := emailWorld(t)
			m := healthy()
			m.mx, m.spf, m.mtasts = mx, []string{"v=spf1 -all"}, nil
			m.apply(w.dns, "example.com")
			runRoot(t, w)
			r := postureRow(w, "example.com")
			if r == nil || r["mta_sts"] != "" {
				t.Errorf("mta_sts = %v", r)
			}
			if n := w.dns.Count("_mta-sts.example.com", "TXT"); n != 0 {
				t.Errorf("_mta-sts queried %d times without MX", n)
			}
			if got := col(current(w.table(eng, "risk-email.csv")), "type"); len(got) != 0 {
				t.Errorf("findings = %v", got)
			}
		})
	}
}

// A subdomain root's value is its own: the organisational domain's policy does not count.
func TestEmailMTASTS_NoFallbackForSubdomainRoot(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	w.dns.MX("sub.example.com", 10, "mail.example.com")
	w.dns.TXT("sub.example.com", "v=spf1 -all")
	w.dns.TXT("_dmarc.example.com", "v=DMARC1; p=reject")
	w.dns.TXT("_mta-sts.example.com", "v=STSv1; id=1")
	runRoot(t, w, "-e", eng, "sub.example.com")
	r := postureRow(w, "sub.example.com")
	if r == nil || r["mta_sts"] != "absent" {
		t.Errorf("mta_sts = %v", r)
	}
	if n := w.dns.Count("_mta-sts.example.com", "TXT"); n != 0 {
		t.Errorf("the organisational domain's _mta-sts was asked %d times", n)
	}
	if got := col(current(w.table(eng, "risk-email.csv")), "type"); !slices.Equal(got, []string{"mta-sts-missing"}) {
		t.Errorf("findings = %v", got)
	}
}

// A SERVFAIL on the lookup fails the check, which is retried.
func TestEmailMTASTS_ServfailFailsTheCheck(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	healthy().apply(w.dns, "example.com")
	w.dns.Rcode("_mta-sts.example.com", mdns.RcodeServerFailure)
	runRootPartial(t, w, "email", 1)
	if st := lastState(w.h.events(), "email"); st.str("state") != "failed" || st.num("failed") != 1 {
		t.Errorf("state = %v", st)
	}
	if len(w.h.completed(eng, "email")) != 0 || w.file(eng, "email-posture.csv") != "" {
		t.Errorf("a failed check recorded a result")
	}
	w.dns.ClearRcode("_mta-sts.example.com")
	runRoot(t, w, "-e", eng)
	if r := postureRow(w, "example.com"); r == nil || r["mta_sts"] != "present" {
		t.Errorf("after the retry: %v", r)
	}
}

// The check key gains a token, so an engagement from before re-runs its email
// checks once; the policy file over HTTPS is never fetched.
func TestEmailMTASTS_ExistingEngagementRerunsOnce(t *testing.T) {
	t.Parallel()
	w := emailWorld(t)
	healthy().apply(w.dns, "example.com")
	runRoot(t, w, "--no-permutations") // permutations legitimately try mta-sts.<root>
	keys := w.h.completed(eng, "email")
	if len(keys) != 1 || !strings.HasSuffix(keys[0], "|mta-sts|addrs") || !strings.HasPrefix(keys[0], "example.com|dkim=") {
		t.Fatalf("check keys = %v", keys)
	}
	runRoot(t, w, "-e", eng, "--no-permutations")
	if n := w.dns.Count("_mta-sts.example.com", "TXT"); n != 1 {
		t.Fatalf("an unchanged engagement asked again: %d", n)
	}

	// Make the checks look like the ones an earlier build stored.
	db := w.h.openDB(eng)
	if _, err := db.Exec("UPDATE checks SET key = replace(key, '|mta-sts', '') WHERE stage = 'email'"); err != nil {
		t.Fatal(err)
	}
	runRoot(t, w, "-e", eng, "--no-permutations")
	if n := w.dns.Count("_mta-sts.example.com", "TXT"); n != 2 {
		t.Errorf("the old check was not run again: %d lookups", n)
	}
	if got := w.h.completed(eng, "email"); len(got) < 1 || !strings.HasSuffix(got[len(got)-1], "|mta-sts|addrs") {
		t.Errorf("check keys = %v", got)
	}
	runRoot(t, w, "-e", eng, "--no-permutations")
	if n := w.dns.Count("_mta-sts.example.com", "TXT"); n != 2 {
		t.Errorf("the checks ran a third time: %d lookups", n)
	}

	// Nothing but DNS: no policy file request, and no name under mta-sts. is resolved.
	if w.h.httpHits.Load() != 0 || w.h.tcpHits.Load() != 0 {
		t.Errorf("network canaries hit: http %d, tcp %d", w.h.httpHits.Load(), w.h.tcpHits.Load())
	}
	for _, ty := range []string{"A", "AAAA"} {
		if n := w.dns.Count("mta-sts.example.com", ty); n != 0 {
			t.Errorf("mta-sts.example.com resolved (%s) %d times", ty, n)
		}
	}
	for _, r := range w.requests("crt.sh") {
		if strings.Contains(r.URI, "mta-sts") {
			t.Errorf("request %s", r.URI)
		}
	}
}
