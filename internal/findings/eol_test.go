package findings_test

import (
	"maps"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/store"
)

// nginx118End is the day Nginx 1.18's security support ended; it is in the past for every date
// these tests use, and the tests move the run date around it.
const nginx118End = "2021-04-20"

// eolService adds a probed web service of host with the technologies a probe stored.
func (f *fixture) eolService(host, technologies string) {
	f.add(rec("web_service", "https://"+host, "host", host, "scheme", "https", "technologies", technologies))
}

// eolFindings are the end-of-life findings among fs.
func eolFindings(fs []findings.Finding) []findings.Finding {
	var out []findings.Finding
	for _, x := range fs {
		if x.Category == findings.EOLSoftware {
			out = append(out, x)
		}
	}
	return out
}

func (f *fixture) eol(t *testing.T) []findings.Finding {
	t.Helper()
	return eolFindings(f.derive(t))
}

// date moves a YYYY-MM-DD date by n days.
func date(t *testing.T, d string, n int) string {
	t.Helper()
	v, err := time.Parse(time.DateOnly, d)
	if err != nil {
		t.Fatal(err)
	}
	return v.AddDate(0, 0, n).Format(time.DateOnly)
}

// A technology whose version is past the end of security support is a medium finding of
// type eol, one for each product on the service, with the columns of risk-eol-software.csv.
func TestEOL_WebTechnologiesPastTheEnd(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.eolService("www.example.com", "Nginx:1.18.0;PHP:5.6.40;Apache HTTP Server:2.4.58;jQuery;Unknown Thing:1.0")
	got := f.eol(t)
	wantSet(t, got, "eol-software/eol=medium", "eol-software/eol=medium")
	byProduct := map[string]findings.Finding{}
	for _, x := range got {
		byProduct[x.Attrs["product"].(string)] = x
	}
	n, ok := byProduct["Nginx"]
	if !ok {
		t.Fatalf("no Nginx finding in %+v", got)
	}
	for k, want := range map[string]any{
		"type": "eol", "severity": "medium", "target": "https://www.example.com", "hostnames": "", "product": "Nginx",
		"version": "1.18.0", "end_date": nginx118End, "seen": "web", "confirmed": "yes", "category": "eol-software",
	} {
		if n.Attrs[k] != want {
			t.Errorf("Nginx %s = %v, want %v", k, n.Attrs[k], want)
		}
	}
	if n.Key() != "eol-software|eol|https://www.example.com|Nginx" {
		t.Errorf("key = %q", n.Key())
	}
	if !strings.Contains(n.Detail, "Nginx 1.18.0") || !strings.Contains(n.Detail, nginx118End) {
		t.Errorf("detail = %q", n.Detail)
	}
	if p, ok := byProduct["PHP"]; !ok || p.Attrs["end_date"] != "2018-12-31" || p.Key() == n.Key() {
		t.Errorf("PHP finding = %+v", p)
	}
}

// A cycle that ended on no known date is past its end: a finding with no end date.
func TestEOL_CycleWithNoKnownEndDate(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.eolService("www.example.com", "jQuery:1.12.4")
	got := f.eol(t)
	wantSet(t, got, "eol-software/eol=medium")
	if len(got) == 1 && (got[0].Attrs["end_date"] != "" || got[0].Attrs["version"] != "1.12.4") {
		t.Errorf("finding = %+v", got[0])
	}
}

// The run date is compared with the end date as a UTC day: on the end date the version is
// end of life; the day before it is approaching, within eol_warn_days; and beyond the window
// there is nothing. A warning window of 0 turns the approaching type off and leaves eol.
func TestEOL_DateBoundaryAndWarnWindow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		today string
		warn  int
		want  []string
	}{
		{"the day after", date(t, nginx118End, 1), 90, []string{"eol-software/eol=medium"}},
		{"on the end date", nginx118End, 90, []string{"eol-software/eol=medium"}},
		{"the day before", date(t, nginx118End, -1), 90, []string{"eol-software/eol-approaching=low"}},
		{"on the edge of the window", date(t, nginx118End, -90), 90, []string{"eol-software/eol-approaching=low"}},
		{"one day outside the window", date(t, nginx118End, -91), 90, nil},
		{"a narrower window", date(t, nginx118End, -30), 29, nil},
		{"a narrower window, inside it", date(t, nginx118End, -29), 29, []string{"eol-software/eol-approaching=low"}},
		{"warning off, before the end", date(t, nginx118End, -1), 0, nil},
		{"warning off, on the end", nginx118End, 0, []string{"eol-software/eol=medium"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.today, f.set.EOLWarnDays = tc.today, tc.warn
			f.host("www.example.com", "203.0.113.5")
			f.eolService("www.example.com", "Nginx:1.18.0")
			wantSet(t, f.eol(t), tc.want...)
		})
	}
}

// A cycle with no end announced, a version no cycle matches and a technology with no
// version give no finding.
func TestEOL_NoFindingWithoutAMatch(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.eolService("www.example.com", "Apache HTTP Server:2.4.58;Nginx:0.1.0;PHP;Nginx 2:3")
	wantSet(t, f.eol(t))
}

// A version carrying a distribution suffix is one step lower, with distribution build in
// the detail; low stays low.
func TestEOL_DistributionBuildIsOneStepLower(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.eolService("www.example.com", "PHP:7.4.3-4ubuntu2.19;Nginx:1.18.0")
	got := f.eol(t)
	wantSet(t, got, "eol-software/eol=low", "eol-software/eol=medium")
	for _, x := range got {
		has := strings.Contains(x.Detail, "distribution build")
		if has != (x.Attrs["product"] == "PHP") {
			t.Errorf("%s: detail %q", x.Attrs["product"], x.Detail)
		}
	}

	g := newFixture()
	g.today = date(t, nginx118End, -10)
	g.host("www.example.com", "203.0.113.5")
	g.eolService("www.example.com", "Nginx:1.18.0-6ubuntu14.4")
	wantSet(t, g.eol(t), "eol-software/eol-approaching=low")
}

// Wappalyzer reports a header's version without its distribution suffix, so the Server and
// X-Powered-By values that carry the version decide whether it is a distribution build.
func TestEOL_DistributionBuildFromTheHeaders(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, server, poweredBy, techs string
		want                           map[string]string // product: severity
	}{
		{"Server and X-Powered-By", "nginx/1.18.0 (Ubuntu)", "PHP/7.4.3-4ubuntu2.19", "Nginx:1.18.0;PHP:7.4.3",
			map[string]string{"Nginx": "low", "PHP": "low"}},
		{"the suffix of another product", "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.3.33", "", "Apache HTTP Server:2.4.6;OpenSSL:1.0.2k;PHP:7.3.33",
			map[string]string{"OpenSSL": "medium", "PHP": "medium"}},
		{"no suffix", "nginx/1.18.0", "PHP/5.6.40", "Nginx:1.18.0;PHP:5.6.40",
			map[string]string{"Nginx": "medium", "PHP": "medium"}},
		{"a comment of several words", "Apache/2.2.15 (Red Hat Enterprise Linux) PHP/5.6.40", "", "Apache HTTP Server:2.2.15;PHP:5.6.40",
			map[string]string{"Apache HTTP Server": "low", "PHP": "medium"}},
		{"a longer version", "nginx/1.18.10 (Ubuntu)", "", "Nginx:1.18.1",
			map[string]string{"Nginx": "medium"}},
		{"a script, not a header", "nginx/1.18.0 (Ubuntu)", "", "jQuery:1.12.4",
			map[string]string{"jQuery": "medium"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture()
			f.host("www.example.com", "203.0.113.5")
			f.add(rec("web_service", "https://www.example.com", "host", "www.example.com", "scheme", "https",
				"server", tc.server, "technologies", tc.techs))
			disclosed := strings.Trim(tc.server+";"+tc.poweredBy, ";")
			f.add(rec("web_posture", "https://www.example.com", "host", "www.example.com", "version_disclosure", disclosed))
			got := map[string]string{}
			for _, x := range f.eol(t) {
				got[x.Attrs["product"].(string)] = x.Severity
				if strings.Contains(x.Detail, "distribution build") != (x.Severity == "low") {
					t.Errorf("%s: detail %q", x.Attrs["product"], x.Detail)
				}
			}
			if !maps.Equal(got, tc.want) {
				t.Errorf("severities = %v, want %v", got, tc.want)
			}
		})
	}
}

// A banner in open-ports is assessed by its parsed product and version, with the address and
// port as the target and the hostnames behind the address.
func TestEOL_PortBanners(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.host("ftp.example.com", "198.51.100.5")
	f.add(rec("open_port", "198.51.100.5:21", "ip", "198.51.100.5", "port", 21.0, "banner", `220 ProFTPD 1.3.5e Server (ProFTPD) [198.51.100.5]\r\n`))
	f.add(rec("open_port", "198.51.100.5:25", "ip", "198.51.100.5", "port", 25.0, "banner", `220 mail.example.com ESMTP Postfix 3.4.13`))
	f.add(rec("open_port", "198.51.100.5:22", "ip", "198.51.100.5", "port", 22.0, "banner", `SSH-2.0-OpenSSH_8.2p1`)) // recognised, not tracked
	f.add(rec("open_port", "198.51.100.5:80", "ip", "198.51.100.5", "port", 80.0, "banner", ""))
	got := f.eol(t)
	wantSet(t, got, "eol-software/eol=medium", "eol-software/eol=medium")
	for _, x := range got {
		want := map[string]map[string]any{
			"ProFTPD": {"target": "198.51.100.5:21", "version": "1.3.5e", "end_date": "2020-07-20"},
			"Postfix": {"target": "198.51.100.5:25", "version": "3.4.13", "end_date": "2023-04-17"},
		}[x.Attrs["product"].(string)]
		if want == nil {
			t.Errorf("unexpected finding %+v", x)
			continue
		}
		for k, v := range want {
			if x.Attrs[k] != v {
				t.Errorf("%s %s = %v, want %v", x.Attrs["product"], k, x.Attrs[k], v)
			}
		}
		if x.Attrs["seen"] != "banner" || x.Attrs["confirmed"] != "yes" || x.Attrs["hostnames"] != "ftp.example.com" {
			t.Errorf("%s = %+v", x.Attrs["product"], x.Attrs)
		}
	}
}

// A distribution build on a banner is one step lower too.
func TestEOL_PortBannerDistributionBuild(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.add(rec("open_port", "198.51.100.5:21", "ip", "198.51.100.5", "port", 21.0, "banner", `220 ProFTPD 1.3.5e Server (Debian) [::ffff:198.51.100.5]`))
	got := f.eol(t)
	wantSet(t, got, "eol-software/eol=low")
	if len(got) == 1 && !strings.Contains(got[0].Detail, "distribution build") {
		t.Errorf("detail = %q", got[0].Detail)
	}
}

// A version known only from a Shodan port report is one step lower and unconfirmed; once
// nyx opens the port with a banner it is the full severity and confirmed. A banner nyx
// received that names no version does not hide the one Shodan reports.
func TestEOL_VersionReportedByAThirdParty(t *testing.T) {
	t.Parallel()
	const shodan = `220 ProFTPD 1.3.5e Server (ProFTPD)`
	reported := func(f *fixture) {
		f.add(rec("reported_port", "198.51.100.5:21", "ip", "198.51.100.5", "port", 21.0, "banner", shodan, "last_seen", "2026-10-30"))
	}
	t.Run("reported only", func(t *testing.T) {
		f := newFixture()
		reported(f)
		got := f.eol(t)
		wantSet(t, got, "eol-software/eol=low")
		if len(got) == 1 && (got[0].Attrs["confirmed"] != "no" || got[0].Attrs["seen"] != "banner" ||
			!strings.Contains(got[0].Detail, "Shodan") || got[0].Key() != "eol-software|eol|198.51.100.5:21|ProFTPD") {
			t.Errorf("finding = %+v", got[0])
		}
	})
	t.Run("confirmed by nyx", func(t *testing.T) {
		f := newFixture()
		reported(f)
		f.add(rec("open_port", "198.51.100.5:21", "ip", "198.51.100.5", "port", 21.0, "banner", `220 ProFTPD 1.3.5e Server (ProFTPD)`))
		got := f.eol(t)
		wantSet(t, got, "eol-software/eol=medium")
		if len(got) == 1 && got[0].Attrs["confirmed"] != "yes" {
			t.Errorf("finding = %+v", got[0])
		}
	})
	t.Run("nyx got no banner", func(t *testing.T) {
		f := newFixture()
		reported(f)
		f.add(rec("open_port", "198.51.100.5:21", "ip", "198.51.100.5", "port", 21.0, "banner", ""))
		got := f.eol(t)
		wantSet(t, got, "eol-software/eol=low")
		if len(got) == 1 && got[0].Attrs["confirmed"] != "no" {
			t.Errorf("finding = %+v", got[0])
		}
	})
	t.Run("approaching stays low", func(t *testing.T) {
		f := newFixture()
		f.today = date(t, "2020-07-20", -5)
		reported(f)
		wantSet(t, f.eol(t), "eol-software/eol-approaching=low")
	})
	t.Run("nyx found it closed", func(t *testing.T) {
		f := newFixture()
		reported(f)
		in := f.input(t)
		in.Inv = inventory.New(inventory.Data{ClosedPorts: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.5:21")}}, provider.Default())
		wantSet(t, eolFindings(derive(in)))
	})
}

// Only in-scope web services and port-eligible addresses are assessed, and only current
// records.
func TestEOL_OnlyShownServicesAndEligibleAddresses(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.host("www.example.com", "203.0.113.5")
	f.host("www.other.net", "203.0.113.6") // not in scope
	f.eolService("www.example.com", "Nginx:1.18.0")
	f.eolService("www.other.net", "Nginx:1.18.0")
	f.add(rec("open_port", "203.0.113.9:21", "ip", "203.0.113.9", "port", 21.0, "banner", `220 ProFTPD 1.3.5e Server`)) // not in the netblock
	f.add(rec("reported_port", "203.0.113.9:25", "ip", "203.0.113.9", "port", 25.0, "banner", `220 x ESMTP Postfix 3.4.13`))
	stale := rec("web_service", "https://old.example.com", "host", "old.example.com", "technologies", "Nginx:1.18.0")
	stale.Current = false
	f.add(stale)
	got := f.eol(t)
	wantSet(t, got, "eol-software/eol=medium")
	if len(got) == 1 && got[0].Target != "https://www.example.com" {
		t.Errorf("target = %s", got[0].Target)
	}
}

// A service excluded from scope is not assessed.
func TestEOL_ExcludedServiceIsNotAssessed(t *testing.T) {
	t.Parallel()
	f := newFixture()
	f.excl = []string{"www.example.com"}
	f.host("www.example.com", "203.0.113.5")
	f.eolService("www.example.com", "Nginx:1.18.0")
	wantSet(t, f.eol(t))
}

// The key is eol-software|<type>|<target>|<product>; ParseKey gives the category, type and
// target, and a finding no longer derived still lists its type, target and product from the key.
func TestEOL_KeyAndFile(t *testing.T) {
	t.Parallel()
	x := findings.Finding{Category: findings.EOLSoftware, Type: "eol-approaching", Target: "198.51.100.5:25",
		Attrs: map[string]any{"product": "Postfix"}}
	if x.Key() != "eol-software|eol-approaching|198.51.100.5:25|Postfix" {
		t.Errorf("key = %q", x.Key())
	}
	if cat, typ, target := findings.ParseKey(x.Key()); cat != "eol-software" || typ != "eol-approaching" || target != "198.51.100.5:25" {
		t.Errorf("ParseKey = %q %q %q", cat, typ, target)
	}
	eolFile := file(t, "risk-eol-software.csv")
	want := "severity target hostnames type product version end_date seen confirmed"
	if got := strings.Join(eolFile.Columns, " "); got != want {
		t.Errorf("columns = %q, want %q", got, want)
	}
	gone := srec("finding", "eol-software|eol|https://www.example.com|Nginx", false)
	rows := eolFile.Rows(findings.Listing{Records: map[string][]store.Record{"finding": {gone}}})
	if len(rows) != 1 {
		t.Fatalf("rows = %v", rows)
	}
	if cells := cellMap(eolFile, rows[0]); cells["target"] != "https://www.example.com" || cells["type"] != "eol" || cells["product"] != "Nginx" || cells["severity"] != "" {
		t.Errorf("cells = %v", cells)
	}
}

// Both types are in the severity table and the help, with the documented severities.
func TestEOL_SeverityTable(t *testing.T) {
	t.Parallel()
	if findings.Severity(findings.EOLSoftware, "eol") != "medium" || findings.Severity(findings.EOLSoftware, "eol-approaching") != "low" {
		t.Error("severities of eol and eol-approaching")
	}
	help := findings.HelpTable()
	for _, w := range []string{"eol-software", "eol-approaching"} {
		if !strings.Contains(help, w) {
			t.Errorf("help table lacks %q", w)
		}
	}
}

// The console names the product and version of a new end-of-life finding, so two products on
// one service are not two identical lines.
func TestEOL_FoundText(t *testing.T) {
	t.Parallel()
	x := findings.Finding{Category: findings.EOLSoftware, Type: "eol", Target: "https://www.example.com",
		Attrs: map[string]any{"product": "Nginx", "version": "1.18.0"}}
	if got := x.FoundText(); got != "end-of-life Nginx 1.18.0 on https://www.example.com" {
		t.Errorf("FoundText = %q", got)
	}
	x.Type = "eol-approaching"
	if got := x.FoundText(); got != "end of support approaching for Nginx 1.18.0 on https://www.example.com" {
		t.Errorf("FoundText = %q", got)
	}
}
