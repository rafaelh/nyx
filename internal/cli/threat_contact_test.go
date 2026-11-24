package cli_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/keycheck"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// Counting source fakes verify threat providers are contacted only for explicit updates, never
// ordinary lookup/matching.

// The fakes see a request sent to either host, so a count of zero means nothing was sent.
func TestThreatHosts_TheCanariesSeeARequest(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	c := newThreatCanaries(t, h)
	tp := egress.New(h.eopts).Clients(false, []string{threatdata.SpamhausHost, threatdata.IpapiHost}).ThirdParty
	for _, u := range []string{"https://" + threatdata.SpamhausHost + "/drop/drop_v4.json", "https://" + threatdata.IpapiHost + "/most-abusive-asn.html"} {
		if _, err := tp.Do(context.Background(), egress.ThirdPartyRequest{Method: http.MethodGet, URL: u}); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}
	if c.spamhaus.Load() != 1 || c.ipapi.Load() != 1 {
		t.Errorf("the fakes saw %d and %d requests, want one each", c.spamhaus.Load(), c.ipapi.Load())
	}
}

// An authorised keyed recon run still sends nothing to threat-data source hosts.
func TestThreatHosts_ReconSendsThemNothing(t *testing.T) { // mutation target
	t.Parallel()
	x := newWebWith(t, riskProcedures...)
	for _, k := range []string{"shodan", "censys", "chaos", "securitytrails", "virustotal", "whoisxml", "github", "certspotter"} {
		x.h.setKey(k, "key-SECRET-"+k)
	}
	x.names("app.example.com")
	x.host("app.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	x.dns.PTR("198.51.100.5", "p5.example.com")
	c := newThreatCanaries(t, x.h)
	if code := x.run("--cidr", "198.51.100.0/24"); code != 0 && code != 7 {
		t.Fatalf("exit %d: %s", code, x.h.stderr.String())
	}
	c.untouched(t, "recon")
	if code := x.passive("--cidr", "198.51.100.0/24"); code != 0 && code != 7 {
		t.Fatalf("--passive: exit %d: %s", code, x.h.stderr.String())
	}
	c.untouched(t, "recon --passive")
}

// nyx ip with every key, --active included, sends neither host anything, for an address the
// built-in lists hold or not.
func TestThreatHosts_IPSendsThemNothing(t *testing.T) { // mutation target
	t.Parallel()
	w := newIPWorld(t)
	w.h.abusive, w.h.drop = nil, nil // the embedded copies
	w.seed("8.8.4.4")
	w.dns.A("host.example.org", "8.8.4.4")
	w.sealProbes([]string{"8.8.4.4"})
	c := newThreatCanaries(t, w.h)
	for _, args := range [][]string{{"8.8.4.4", "host.example.org", "--fields", "all"}, {"8.8.4.4", "--active", "--fields", "all"}} {
		if code := w.runJSON(args...); code != 0 && code != 7 {
			t.Fatalf("%v: exit %d: %s", args, code, w.h.stderr.String())
		}
	}
	c.untouched(t, "nyx ip")
}

// nyx cve sends neither host anything.
func TestThreatHosts_CVESendsThemNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	nvd := newNVD(t, h)
	nvd.entry("CVE-2021-44228")
	c := newThreatCanaries(t, h) // after newNVD, which replaces SourceBaseURLs
	if code := h.cveRun(true, "CVE-2021-44228"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	c.untouched(t, "nyx cve")
}

// No key test sends either host anything: each sends its one request to its own source.
func TestThreatHosts_KeyTestsSendThemNothing(t *testing.T) { // mutation target
	t.Parallel()
	h := newHarness(t)
	ok := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(`{}`)) }))
	t.Cleanup(ok.Close)
	h.eopts.SourceBaseURLs = map[string]string{}
	for _, host := range []string{"api.securitytrails.com", "api.shodan.io", "www.virustotal.com", "user.whoisxmlapi.com",
		"api.platform.censys.io", "dns.projectdiscovery.io", "api.github.com", "api.certspotter.com", "services.nvd.nist.gov"} {
		h.eopts.SourceBaseURLs[host] = ok.URL
	}
	c := newThreatCanaries(t, h)
	for _, name := range keycheck.Sources() {
		keycheck.Run(context.Background(), h.eopts, name, config.Secret("key-SECRET-"+name))
	}
	c.untouched(t, "the key tests")
}
