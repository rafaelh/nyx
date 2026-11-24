package cli_test

import (
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/eol"
)

// End-of-life tests derive findings from stored web/banner versions and the current date.

const eolFile = "risk-eol-software.csv"

func (x *web) eolRows() []map[string]string { return x.table(eng, eolFile) }

// eolKeys are "type=target product" of the current end-of-life findings, sorted.
func eolKeys(rows []map[string]string) []string {
	var out []string
	for _, r := range current(rows) {
		out = append(out, r["type"]+"="+r["target"]+" "+r["product"])
	}
	slices.Sort(out)
	return out
}

// serverNamed serves a page that names its server and PHP version in the headers.
func serverNamed(server, php string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", server)
		if php != "" {
			w.Header().Set("X-Powered-By", "PHP/"+php)
		}
		page("<title>Home</title>")(w, r)
	}
}

// day is midnight UTC of a date.
func day(t *testing.T, d string) time.Time {
	t.Helper()
	v, err := time.Parse(time.DateOnly, d)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Verify EOL file columns, distribution downgrades, headline selection and derived port
// product/version fields.
func TestEOL_FindingsFromTechnologiesAndBanners(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "198.51.100.5")
	x.plain("198.51.100.5", 80, serverNamed("nginx/1.18.0", "5.6.40"))
	x.open("198.51.100.5:21", "220 ProFTPD 1.3.5e Server (Debian) [::ffff:198.51.100.5]")
	x.open("198.51.100.5:22", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
	x.open("198.51.100.5:25", "220 mail.example.com ESMTP Postfix 3.4.13")
	x.mustRun("--crawl-pages", "0", "--cidr", "198.51.100.0/24")

	want := []string{
		"eol=198.51.100.5:21 ProFTPD", "eol=198.51.100.5:25 Postfix",
		"eol=http://www.example.com Nginx", "eol=http://www.example.com PHP",
	}
	got := eolKeys(x.eolRows())
	if !slices.Equal(got, want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
	rows := map[string]map[string]string{}
	for _, r := range current(x.eolRows()) {
		rows[r["target"]+" "+r["product"]] = r
	}
	n := rows["http://www.example.com Nginx"]
	for k, v := range map[string]string{"severity": "medium", "version": "1.18.0", "end_date": "2021-04-20", "seen": "web", "confirmed": "yes", "hostnames": ""} {
		if n[k] != v {
			t.Errorf("Nginx %s = %q, want %q", k, n[k], v)
		}
	}
	f := rows["198.51.100.5:21 ProFTPD"]
	for k, v := range map[string]string{"severity": "low", "version": "1.3.5e", "end_date": "2020-07-20", "seen": "banner", "confirmed": "yes", "hostnames": "www.example.com"} {
		if f[k] != v {
			t.Errorf("ProFTPD %s = %q, want %q", k, f[k], v)
		}
	}
	if rows["198.51.100.5:25 Postfix"]["severity"] != "medium" {
		t.Errorf("Postfix = %v", rows["198.51.100.5:25 Postfix"])
	}

	// open-ports.csv: product and version where the banner is recognised, blank otherwise.
	p := &pworld{web: x}
	for port, want := range map[int][2]string{21: {"ProFTPD", "1.3.5e"}, 22: {"OpenSSH", "8.2p1"}, 25: {"Postfix", "3.4.13"}} {
		if r := p.openRow("198.51.100.5", port); r["product"] != want[0] || r["version"] != want[1] {
			t.Errorf("open-ports.csv port %d: product %q version %q, want %v", port, r["product"], r["version"], want)
		}
	}

	// The summary lists the medium findings and not the low one.
	targets := (&risk{x}).summaryTargets()
	for _, w := range []string{"http://www.example.com=medium", "198.51.100.5:25=medium"} {
		if !slices.Contains(targets, w) {
			t.Errorf("summary %v lacks %s", targets, w)
		}
	}
	if slices.Contains(targets, "198.51.100.5:21=low") {
		t.Errorf("summary %v lists a low finding", targets)
	}
}

// Recover distribution suffixes from headers when Wappalyzer returns only the upstream version.
func TestEOL_DistributionBuildFromTheProbe(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "198.51.100.5")
	x.plain("198.51.100.5", 80, serverNamed("nginx/1.18.0 (Ubuntu)", "7.4.3-4ubuntu2.19"))
	x.mustRun("--crawl-pages", "0")
	rows := current(x.eolRows())
	if len(rows) != 2 {
		t.Fatalf("rows = %v", rows)
	}
	for _, r := range rows {
		if r["severity"] != "low" || r["type"] != "eol" {
			t.Errorf("%s = %v, want a low eol finding", r["product"], r)
		}
	}
}

// Unknown banners leave version fields empty; old engagements gain derived columns without
// contact.
func TestEOL_PortColumnsOnAnExistingEngagement(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "198.51.100.5")
	x.plain("198.51.100.5", 80, page("<title>Home</title>"))
	x.open("198.51.100.5:22", "SSH-2.0-OpenSSH_9.6")
	x.open("198.51.100.5:23", "login:")
	x.mustRun("--crawl-pages", "0", "--cidr", "198.51.100.0/24")

	// Put the file back as an earlier version wrote it.
	path := filepath.Join(x.h.eng(eng), "open-ports.csv")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old := strings.Split(string(b), "\n")
	for i, line := range old {
		cells := strings.Split(line, ",")
		old[i] = strings.Join(cells[:min(len(cells), 7)], ",")
	}
	if err := os.WriteFile(path, []byte(strings.Join(old, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	before := x.h.network()
	x.mustRun("--crawl-pages", "0", "--cidr", "198.51.100.0/24")
	if x.h.network() != before {
		t.Errorf("the re-run made %d network requests", x.h.network()-before)
	}
	p := &pworld{web: x}
	if r := p.openRow("198.51.100.5", 22); r["product"] != "OpenSSH" || r["version"] != "9.6" {
		t.Errorf("port 22 = %v", r)
	}
	if r := p.openRow("198.51.100.5", 23); r == nil || r["product"] != "" || r["version"] != "" {
		t.Errorf("port 23 = %v", r)
	}
}

// Advancing the clock changes approaching findings to ended-support findings, including passive
// reruns.
func TestEOL_ClockMovesFindingsWithNoContact(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "198.51.100.5")
	site := x.plain("198.51.100.5", 80, serverNamed("nginx/1.18.0", ""))
	x.h.now = day(t, "2021-04-01") // Nginx 1.18 ends on 2021-04-20
	x.mustRun("--crawl-pages", "0")
	rows := current(x.eolRows())
	if len(rows) != 1 || rows[0]["type"] != "eol-approaching" || rows[0]["severity"] != "low" || rows[0]["end_date"] != "2021-04-20" {
		t.Fatalf("before the end date: %v", rows)
	}
	hits := site.hits()

	x.h.now = day(t, "2021-04-20") // on the end date
	x.mustPassive("--crawl-pages", "0")
	if site.hits() != hits {
		t.Errorf("--passive sent %d requests to the service", site.hits()-hits)
	}
	if got := eolKeys(x.eolRows()); !slices.Equal(got, []string{"eol=http://www.example.com Nginx"}) {
		t.Errorf("on the end date = %v", got)
	}
	all := x.eolRows()
	if len(all) != 2 {
		t.Fatalf("rows = %d, want the old approaching row (not current) and the eol row", len(all))
	}
	for _, r := range all {
		if r["type"] == "eol-approaching" && (r["current"] != "false" || r["target"] != "http://www.example.com" || r["product"] != "Nginx") {
			t.Errorf("approaching row = %v", r)
		}
	}
	if r := current(all)[0]; r["severity"] != "medium" {
		t.Errorf("eol row = %v", r)
	}
	if got := (&risk{x}).summaryTargets(); !slices.Contains(got, "http://www.example.com=medium") {
		t.Errorf("summary = %v", got)
	}
}

// --eol-warn-days 0 turns the approaching finding off and keeps the end-of-life one.
func TestEOL_WarnDaysFlag(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "198.51.100.5")
	x.plain("198.51.100.5", 80, serverNamed("nginx/1.18.0", ""))
	x.h.now = day(t, "2021-04-01")
	x.mustRun("--crawl-pages", "0", "--eol-warn-days", "0")
	if got := eolKeys(x.eolRows()); len(got) != 0 {
		t.Errorf("with warning off = %v", got)
	}
	x.mustRun("--crawl-pages", "0", "--eol-warn-days", "19") // 2021-04-01 plus 19 days is the 20th
	if got := eolKeys(x.eolRows()); !slices.Equal(got, []string{"eol-approaching=http://www.example.com Nginx"}) {
		t.Errorf("with 19 days = %v", got)
	}
	x.h.now = day(t, "2021-04-21")
	x.mustRun("--crawl-pages", "0", "--eol-warn-days", "0")
	if got := eolKeys(x.eolRows()); !slices.Equal(got, []string{"eol=http://www.example.com Nginx"}) {
		t.Errorf("past the end with warning off = %v", got)
	}
	if code := x.run("--eol-warn-days", "-1"); code == 0 {
		t.Error("--eol-warn-days -1 was accepted")
	}
}

// A redo of the probe that no longer shows the version marks its finding not current.
func TestEOL_RedoProbeWithANewVersion(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names("www.example.com")
	x.host("www.example.com", "198.51.100.5")
	var server atomic.Value
	server.Store("nginx/1.18.0")
	x.plain("198.51.100.5", 80, func(w http.ResponseWriter, r *http.Request) { serverNamed(server.Load().(string), "")(w, r) })
	x.mustRun("--crawl-pages", "0")
	if got := eolKeys(x.eolRows()); !slices.Equal(got, []string{"eol=http://www.example.com Nginx"}) {
		t.Fatalf("first run = %v", got)
	}
	server.Store("nginx/99.0.0") // no release cycle of that version
	x.mustRun("--crawl-pages", "0", "--redo", "httpprobe")
	if got := eolKeys(x.eolRows()); len(got) != 0 {
		t.Errorf("after the redo, current = %v", got)
	}
	rows := x.eolRows()
	if len(rows) != 1 || rows[0]["current"] != "false" || rows[0]["product"] != "Nginx" || rows[0]["type"] != "eol" ||
		rows[0]["target"] != "http://www.example.com" || rows[0]["version"] != "" {
		t.Errorf("rows after the redo = %v, want one row not current, holding only what its key does", rows)
	}
}

// A run warns once when the embedded data is more than twelve months old, with no flag, and
// not before.
func TestEOL_StaleDataWarning(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.names()
	taken := day(t, eol.DataDate())
	for _, tc := range []struct {
		name string
		now  time.Time
		warn bool
	}{
		{"on the day", taken, false},
		{"a year on", taken.AddDate(1, 0, 0), false},
		{"a day over a year", taken.AddDate(1, 0, 1), true},
	} {
		x.h.now = tc.now
		x.mustRun("--crawl-pages", "0")
		got := x.h.messages("warning", "end-of-life")
		if tc.warn != (len(got) == 1) || len(got) > 1 {
			t.Errorf("%s: warnings = %v", tc.name, got)
		}
		if tc.warn && !strings.Contains(got[0], eol.DataDate()) {
			t.Errorf("%s: warning %q does not give the date of the data", tc.name, got[0])
		}
	}
}

// Keep product and data sources, recognised banners, output and finding settings documented.
func TestEOL_DocumentedInDocsAndHelp(t *testing.T) {
	t.Parallel()
	docs := docsText(t)
	for _, want := range []string{eolFile, "eol_warn_days", "--eol-warn-days", "eol-approaching"} {
		if !strings.Contains(docs, want) {
			t.Errorf("the docs do not mention %q", want)
		}
	}
	h := newHarness(t, noop())
	if code := h.exec("--help"); code != 0 || !strings.Contains(h.stdout.String(), "--eol-warn-days") {
		t.Errorf("--help = %d, lacks --eol-warn-days", code)
	}
	h.execRoot("help", "findings")
	for _, w := range []string{"eol-software", "eol-approaching"} {
		if !strings.Contains(h.stdout.String(), w) {
			t.Errorf("nyx help findings lacks %q", w)
		}
	}
}
