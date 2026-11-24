package cli_test

import (
	"crypto/tls"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// TLS tests cover negotiated metadata, legacy versions and hostname mismatch findings.

// cbcSuite is the one suite the legacy fake servers offer; it works at every version from 1.0.
const cbcSuite = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"

// oldTLS is a server configuration that speaks only version v, with a CBC suite.
func oldTLS(cert tls.Certificate, v uint16) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: v, MaxVersion: v,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}}
}

func (x *web) certRows() []map[string]string { return x.table(eng, "risk-certificates.csv") }

// certTypes are the "type=url" of the current certificate findings, sorted.
func (x *web) certTypes() []string { return typeURLs(x.certRows()) }

// selfFor is a self-signed certificate naming host.
func selfFor(t *testing.T, host string) tls.Certificate {
	t.Helper()
	return selfSigned(t, leafSpec{cn: host, dns: []string{host}})
}

// Legacy-only services remain probeable/crawlable and yield low findings; modern versions do
// not.
func TestTLS_LegacyServicesAreRecordedCrawledAndChecked(t *testing.T) {
	t.Parallel()
	x := newRisk(t, "sensitive-paths")
	x.names("old10.example.com", "old11.example.com", "new.example.com")
	x.host("old10.example.com", "203.0.113.10")
	x.host("old11.example.com", "203.0.113.11")
	x.host("new.example.com", "203.0.113.12")
	c10, c11, c12 := oldTLS(selfFor(t, "old10.example.com"), tls.VersionTLS10), oldTLS(selfFor(t, "old11.example.com"), tls.VersionTLS11),
		&tls.Config{Certificates: []tls.Certificate{selfFor(t, "new.example.com")}, MaxVersion: tls.VersionTLS12}
	home := page(`<title>Old</title><a href="/about">about</a>`)
	old10 := x.secureConfig("203.0.113.10", 443, func() *tls.Config { return c10 }, routes(map[string]http.HandlerFunc{
		"/": home, "/about": page("<title>About</title>"), "/.env": page(secretBody),
	}))
	old11 := x.secureConfig("203.0.113.11", 443, func() *tls.Config { return c11 }, home)
	x.secureConfig("203.0.113.12", 443, func() *tls.Config { return c12 }, home)
	x.mustRun("--sensitive-paths", x.pathsFile(pathsYAML))

	for host, want := range map[string]struct{ version, cipher string }{
		"old10": {"TLS 1.0", cbcSuite}, "old11": {"TLS 1.1", cbcSuite}, "new": {"TLS 1.2", ""},
	} {
		r := x.service("https://" + host + ".example.com")
		if r["status"] != "200" || r["tls_version"] != want.version || r["tls_trust"] != "self-signed" ||
			(want.cipher != "" && r["tls_cipher"] != want.cipher) || !strings.HasPrefix(r["tls_cipher"], "TLS_") {
			t.Errorf("%s: %v", host, r)
		}
	}
	if old10.count("/about") != 1 || !slices.Contains(x.urlSet(), "https://old10.example.com/about") {
		t.Errorf("a legacy service is crawled: /about requested %d times; urls %v", old10.count("/about"), x.urlSet())
	}
	if old10.count("/.env") != 1 || old11.count("/.env") != 1 {
		t.Errorf("a legacy service is checked for sensitive paths: /.env requested %d and %d times", old10.count("/.env"), old11.count("/.env"))
	}
	if r := find(current(x.rows("risk-sensitive-paths.csv")), "path", "/.env"); r == nil || !strings.HasPrefix(r["url"], "https://old10.example.com/") {
		t.Errorf("the .env on the legacy service is flagged: %v", x.rows("risk-sensitive-paths.csv"))
	}
	want := []string{"legacy-tls;self-signed=https://old10.example.com", "legacy-tls;self-signed=https://old11.example.com", "self-signed=https://new.example.com"}
	if got := x.certTypes(); !slices.Equal(got, want) {
		t.Errorf("certificate findings = %v, want %v", got, want)
	}
	for _, r := range current(x.certRows()) {
		if r["severity"] != "low" {
			t.Errorf("severity of %v", r)
		}
	}
}

// TLS columns use the first applicable trust classification.
func TestTLS_ColumnsAndTrustValues(t *testing.T) {
	t.Parallel()
	x := newRisk(t)
	ca := newCA(t, "Test Root CA")
	hosts := map[string]struct {
		spec leafSpec
		self bool
		want string
	}{
		"expired":  {leafSpec{notAfter: longAgo}, false, "expired"},
		"selfsign": {leafSpec{}, true, "self-signed"},
		"mismatch": {leafSpec{dns: []string{"other.example.com"}}, false, "hostname-mismatch"},
		"chain":    {leafSpec{}, false, "untrusted-chain"},
		"both":     {leafSpec{dns: []string{"other.example.com"}}, true, "hostname-mismatch"},
	}
	names := []string{"plain.example.com"}
	ip := 20
	for name, c := range hosts {
		host := name + ".example.com"
		names = append(names, host)
		x.host(host, "203.0.113."+strconv.Itoa(ip))
		spec := c.spec
		spec.cn = host
		if spec.dns == nil {
			spec.dns = []string{host}
		}
		cert := ca.issue(t, spec)
		if c.self {
			cert = selfSigned(t, spec)
		}
		x.secure("203.0.113."+strconv.Itoa(ip), 443, cert, page("<title>"+name+"</title>"))
		ip++
	}
	x.plain("203.0.113.40", 80, page("<title>plain</title>"))
	x.host("plain.example.com", "203.0.113.40")
	x.names(names...)
	x.mustRun("--crawl-pages", "0")

	for name, c := range hosts {
		r := x.service("https://" + name + ".example.com")
		if r["tls_trust"] != c.want || r["tls_version"] != "TLS 1.3" || !strings.HasPrefix(r["tls_cipher"], "TLS_") {
			t.Errorf("%s: trust %q version %q cipher %q, want trust %q", name, r["tls_trust"], r["tls_version"], r["tls_cipher"], c.want)
		}
	}
	if r := x.service("http://plain.example.com"); r["tls_version"] != "" || r["tls_cipher"] != "" || r["tls_trust"] != "" {
		t.Errorf("a plain http service has no TLS columns: %v", r)
	}
	// The mismatch and the expired certificate are findings; an untrusted chain alone is not.
	want := []string{"expired=https://expired.example.com", "hostname-mismatch;self-signed=https://both.example.com", "hostname-mismatch=https://mismatch.example.com", "self-signed=https://selfsign.example.com"}
	if got := x.certTypes(); !slices.Equal(got, want) {
		t.Errorf("certificate findings = %v, want %v", got, want)
	}
}

// The values come from the service's own first response, not from where it redirects.
func TestTLS_ValuesComeFromTheFirstResponse(t *testing.T) {
	t.Parallel()
	x := newRisk(t)
	x.names("a.example.com", "b.example.com")
	x.host("a.example.com", "203.0.113.5")
	x.host("b.example.com", "203.0.113.6")
	ca := newCA(t, "Test Root CA")
	a := ca.issue(t, leafSpec{cn: "a.example.com", dns: []string{"a.example.com"}})
	b := selfFor(t, "b.example.com")
	x.secureConfig("203.0.113.5", 443, func() *tls.Config { return oldTLS(a, tls.VersionTLS11) }, redirectTo(302, "https://b.example.com/"))
	x.secure("203.0.113.6", 443, b, page("<title>B</title>"))
	x.mustRun("--crawl-pages", "0")

	ra, rb := x.service("https://a.example.com"), x.service("https://b.example.com")
	if ra["title"] != "B" || ra["tls_version"] != "TLS 1.1" || ra["tls_trust"] != "untrusted-chain" || !strings.Contains(ra["tls_issuer"], "Test Root CA") {
		t.Errorf("a took its values from the redirect target: %v", ra)
	}
	if rb["tls_version"] != "TLS 1.3" || rb["tls_trust"] != "self-signed" {
		t.Errorf("b: %v", rb)
	}
	if got := x.certTypes(); !slices.Equal(got, []string{"legacy-tls=https://a.example.com", "self-signed=https://b.example.com"}) {
		t.Errorf("certificate findings = %v", got)
	}
}

// A service whose handshake fails is not recorded and has no TLS finding, including one that
// offers only RC4, which is not offered.
func TestTLS_FailedHandshakeIsNotRecorded(t *testing.T) {
	t.Parallel()
	x := newRisk(t)
	x.names("rc4.example.com")
	x.host("rc4.example.com", "203.0.113.5")
	cert := selfFor(t, "rc4.example.com")
	s := x.secureConfig("203.0.113.5", 443, func() *tls.Config {
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA}}
	}, page("never served"))
	x.mustRun("--crawl-pages", "0")
	if got := x.serviceURLs(); len(got) != 0 {
		t.Errorf("web services = %v, want none", got)
	}
	if got := x.certTypes(); len(got) != 0 {
		t.Errorf("certificate findings = %v, want none", got)
	}
	if s.hits() != 0 {
		t.Errorf("%d requests reached a service that cannot negotiate", s.hits())
	}
}

// Older records infer trust but need redo before negotiated version/cipher can be collected.
func TestTLS_ExistingRecordsHaveDerivedTrustAndNoVersionUntilRedo(t *testing.T) {
	t.Parallel()
	x := newRisk(t)
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	s := x.secure("203.0.113.5", 443, selfFor(t, "www.example.com"), page("<title>Home</title>"))
	x.mustRun("--crawl-pages", "0")
	if r := x.service("https://www.example.com"); r["tls_version"] != "TLS 1.3" {
		t.Fatalf("precondition: %v", r)
	}

	// Make the engagement look as it did before: no version, cipher or trust, and the old error and flag.
	db := x.h.openDB(eng)
	if _, err := db.Exec(`UPDATE observations SET attrs = json_set(json_remove(attrs, '$.tls_version', '$.tls_cipher', '$.tls_trust'),
		'$.tls_error', 'x509: certificate signed by unknown authority', '$.tls_self_signed', json('true')) WHERE kind = 'web_service'`); err != nil {
		t.Fatal(err)
	}
	before := s.hits()
	x.mustRun("--crawl-pages", "0")
	if s.hits() != before {
		t.Errorf("a plain re-run sent %d requests to a probed service", s.hits()-before)
	}
	if r := x.service("https://www.example.com"); r["tls_version"] != "" || r["tls_cipher"] != "" || r["tls_trust"] != "self-signed" {
		t.Errorf("old record = %v, want no version or cipher and a derived trust", r)
	}

	x.mustRun("--crawl-pages", "0", "--redo", "httpprobe")
	if s.hits() == before {
		t.Fatal("--redo httpprobe did not probe again")
	}
	if r := x.service("https://www.example.com"); r["tls_version"] != "TLS 1.3" || !strings.HasPrefix(r["tls_cipher"], "TLS_") || r["tls_trust"] != "self-signed" {
		t.Errorf("after the redo = %v", r)
	}
}

// Modern TLS and renewed matching certificates retire prior findings on redo.
func TestTLS_FindingsGoNotCurrentAfterRedoAgainstFixedService(t *testing.T) {
	t.Parallel()
	x := newRisk(t)
	x.names("www.example.com")
	x.host("www.example.com", "203.0.113.5")
	ca := newCA(t, "Test Root CA")
	wrong := ca.issue(t, leafSpec{cn: "other.example.com", dns: []string{"other.example.com"}})
	right := ca.issue(t, leafSpec{cn: "www.example.com", dns: []string{"www.example.com"}})
	var fixed atomic.Bool
	x.secureConfig("203.0.113.5", 443, func() *tls.Config {
		if fixed.Load() {
			return &tls.Config{Certificates: []tls.Certificate{right}}
		}
		return oldTLS(wrong, tls.VersionTLS10)
	}, page("<title>Home</title>"))
	x.mustRun("--crawl-pages", "0")
	if got := x.certTypes(); !slices.Equal(got, []string{"hostname-mismatch;legacy-tls=https://www.example.com"}) {
		t.Fatalf("precondition: findings = %v\n%s", got, x.file(eng, "risk-certificates.csv"))
	}

	fixed.Store(true)
	x.mustRun("--crawl-pages", "0") // not probed again: nothing changes
	if len(x.certTypes()) != 1 {
		t.Errorf("a plain re-run changed the findings: %v", x.certTypes())
	}
	x.mustRun("--crawl-pages", "0", "--redo", "httpprobe")
	if got := x.certTypes(); len(got) != 0 {
		t.Errorf("current findings after the redo = %v", got)
	}
	rows := x.certRows()
	if len(rows) != 1 || rows[0]["current"] != "false" || rows[0]["type"] != "hostname-mismatch;legacy-tls" {
		t.Errorf("the finding stays on record, not current: %v", rows)
	}
	if r := x.service("https://www.example.com"); r["tls_version"] != "TLS 1.3" || r["tls_trust"] != "untrusted-chain" {
		t.Errorf("after the redo = %v", r)
	}
}
