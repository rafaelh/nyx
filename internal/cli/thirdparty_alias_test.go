package cli_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

// A name whose alias leaves the root for a domain no provider entry lists is a third party's
// platform: it is asked for no sensitive path, has no posture finding and is a cname third party
// of the root. A name on a listed cloud platform is the organisation's own workload and is asked.
func TestThirdPartyAlias_NotAskedForSensitivePaths(t *testing.T) {
	t.Parallel()
	x := newRisk(t, "sensitive-paths")
	x.names("learn.example.com", "app.example.com", "www.example.com")
	x.dns.CNAME("learn.example.com", "cl2.vendor-lms.test")
	x.host("cl2.vendor-lms.test", "203.0.113.31")
	x.dns.CNAME("app.example.com", "acme.azurecontainerapps.io")
	x.host("acme.azurecontainerapps.io", "203.0.113.32")
	x.host("www.example.com", "203.0.113.33")
	vendor := x.plain("203.0.113.31", 80, leaky)
	cloud := x.plain("203.0.113.32", 80, leaky)
	own := x.plain("203.0.113.33", 80, leaky)
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(pathsYAML))

	if n := vendor.count("/.env"); n != 0 {
		t.Errorf("a third party's platform was asked for /.env %d times", n)
	}
	for name, s := range map[string]*site{"the cloud-hosted name": cloud, "the organisation's own name": own} {
		if n := s.count("/.env"); n != 1 {
			t.Errorf("%s was asked for /.env %d times, want 1", name, n)
		}
	}
	for _, r := range current(x.rows("risk-sensitive-paths.csv")) {
		if strings.Contains(r["url"], "learn.example.com") {
			t.Errorf("a sensitive-path finding on a third party's platform: %v", r)
		}
	}
	for _, r := range current(x.rows("risk-web-posture.csv")) {
		if strings.Contains(r["url"], "learn.example.com") {
			t.Errorf("a posture finding on a third party's platform: %v", r)
		}
	}
	tp := find(x.rows("third-parties.csv"), "domain", "vendor-lms.test")
	if tp == nil || tp["mechanism"] != "cname" || tp["root"] != "example.com" || tp["current"] != "true" {
		t.Errorf("third-parties.csv = %v, want vendor-lms.test by cname", x.rows("third-parties.csv"))
	}
	if find(x.rows("third-parties.csv"), "domain", "azurecontainerapps.io") != nil {
		t.Error("a cloud platform that runs the organisation's own workload is listed as a SaaS third party")
	}
	ph := find(x.rows("provider-hosts.csv"), "hostname", "learn.example.com")
	if ph == nil || ph["provider"] != "vendor-lms.test" || ph["evidence"] != "cname" || ph["cname"] != "cl2.vendor-lms.test" {
		t.Errorf("provider-hosts.csv row = %v", ph)
	}
}

// An HTTP service that only redirects to the HTTPS service of the same host is not asked for the
// sensitive paths as well: the HTTPS service is.
func TestSensitivePaths_HTTPThatRedirectsToHTTPSIsNotAskedToo(t *testing.T) {
	t.Parallel()
	x := newRisk(t, "sensitive-paths")
	x.names("www.example.com", "both.example.com")
	x.host("www.example.com", "203.0.113.5")
	x.host("both.example.com", "203.0.113.6")
	up := x.plain("203.0.113.5", 80, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example.com"+r.URL.Path, http.StatusMovedPermanently)
	})
	tlsSite := x.secure("203.0.113.5", 443, selfSigned(t, leafSpec{cn: "www.example.com", dns: []string{"www.example.com"}}), leaky)
	// A host that serves both without redirecting is two services, each asked.
	plain := x.plain("203.0.113.6", 80, leaky)
	plainTLS := x.secure("203.0.113.6", 443, selfSigned(t, leafSpec{cn: "both.example.com", dns: []string{"both.example.com"}}), leaky)
	x.mustRun("--crawl-pages", "0", "--sensitive-paths", x.pathsFile(pathsYAML))

	if n := up.count("/.env"); n != 0 {
		t.Errorf("the redirecting HTTP service was asked for /.env %d times", n)
	}
	for name, s := range map[string]*site{"the HTTPS service": tlsSite, "the HTTP service that serves pages": plain, "its HTTPS service": plainTLS} {
		if n := s.count("/.env"); n != 1 {
			t.Errorf("%s was asked for /.env %d times, want 1", name, n)
		}
	}
	urls := col(current(x.rows("risk-sensitive-paths.csv")), "url")
	if !slices.Contains(urls, "https://www.example.com/.env") || slices.Contains(urls, "http://www.example.com/.env") {
		t.Errorf("sensitive-path findings = %v, want the HTTPS service's and not the HTTP one's", urls)
	}
}

// A certificate that does not name a host on a third party's platform is the platform's own: the
// names beside it belong to its other customers and are no candidates. A certificate that names
// the host gives its other names, as before.
func TestProbe_ForeignCertificateNamesAreNotCandidates(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("feedback.example.com", "www.example.com")
	x.dns.CNAME("feedback.example.com", "tenant.vendor-feedback.test")
	x.host("tenant.vendor-feedback.test", "203.0.113.41")
	x.host("www.example.com", "203.0.113.42")
	x.secure("203.0.113.41", 443, selfSigned(t, leafSpec{cn: "default.vendor-feedback.test",
		dns: []string{"default.vendor-feedback.test", "feedback.customer-one.test", "feedback.customer-two.test", "other.example.com"}}),
		page("<title>vendor</title>"))
	x.secure("203.0.113.42", 443, selfSigned(t, leafSpec{cn: "www.example.com",
		dns: []string{"www.example.com", "www.example-group.test"}}), page("<title>own</title>"))
	x.mustRun("--crawl-pages", "0")

	cand := x.table(eng, "candidates.csv")
	for _, v := range []string{"feedback.customer-one.test", "feedback.customer-two.test", "default.vendor-feedback.test"} {
		if c := find(cand, "value", v); c != nil {
			t.Errorf("a name from the platform's own certificate is a candidate: %v", c)
		}
	}
	if c := find(cand, "value", "www.example-group.test"); c == nil || c["type"] != "hostname" {
		t.Errorf("candidates.csv = %v, want the other name of the organisation's own certificate", cand)
	}
	if !slices.Contains(hostnameKeys(x), "other.example.com") {
		t.Error("an in-scope name on the platform's certificate was not taken")
	}
	// The certificate itself is still recorded as seen.
	svc := find(x.table(eng, "web-services.csv"), "url", "https://feedback.example.com")
	if svc == nil || !strings.Contains(svc["tls_sans"], "feedback.customer-one.test") {
		t.Errorf("web-services.csv row = %v, want the certificate's names as they were seen", svc)
	}
}

// A candidate under a known provider's domain is not listed: it is the provider's name or a
// tenant's, and the dependency is a third party.
func TestCandidates_KnownProviderNamesAreNotListed(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("mfa.example.com", "go.example.com")
	x.host("mfa.example.com", "203.0.113.51")
	x.host("go.example.com", "203.0.113.52")
	x.plain("203.0.113.51", 80, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://login.microsoftonline.com/setup", http.StatusFound)
	})
	x.plain("203.0.113.52", 80, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://www.example-group.test/", http.StatusFound)
	})
	x.mustRun("--crawl-pages", "0")

	cand := x.table(eng, "candidates.csv")
	if c := find(cand, "value", "login.microsoftonline.com"); c != nil {
		t.Errorf("a known provider's name is a candidate: %v", c)
	}
	if c := find(cand, "value", "www.example-group.test"); c == nil {
		t.Errorf("candidates.csv = %v, want the redirect target no provider operates", cand)
	}
}
