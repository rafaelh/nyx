package cli_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/cve"
	"github.com/rafaelh/nyx/internal/iplookup"
	"github.com/rafaelh/nyx/internal/keycheck"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// Pin documentation to all five embedded list dates so refreshes cannot silently leave the
// guide stale.
func TestAbusiveDocs_GiveTheSnapshotDates(t *testing.T) {
	t.Parallel()
	docs := docsText(t)
	d := abusive.Default()
	for _, l := range []struct{ name, date string }{{"networks", d.Nets.Updated}, {"asns", d.ASNs.Updated}} {
		if l.date == "" {
			t.Errorf("the built-in ipapi.is %s list has no date", l.name)
		} else if !strings.Contains(docs, l.date) {
			t.Errorf("the docs do not give the built-in ipapi.is %s list's date, %s", l.name, l.date)
		}
	}
	lists, err := spamhaus.ParseBundle(spamhaus.Builtin())
	if err != nil {
		t.Fatalf("the built-in Spamhaus bundle: %v", err)
	}
	for _, l := range []struct {
		name string
		at   time.Time
	}{{spamhaus.ListV4, lists.V4.Meta.Timestamp}, {spamhaus.ListV6, lists.V6.Meta.Timestamp}, {spamhaus.ListASN, lists.ASNs.Meta.Timestamp}} {
		if l.at.IsZero() {
			t.Errorf("the built-in Spamhaus %s list has no date", l.name)
			continue
		}
		// A Spamhaus list is dated to the second; the docs may give the timestamp or its UTC day.
		stamp, day := l.at.UTC().Format(time.RFC3339), l.at.UTC().Format(time.DateOnly)
		if !strings.Contains(docs, stamp) && !strings.Contains(docs, day) {
			t.Errorf("the docs do not give the built-in Spamhaus %s list's date, %s (or %s)", l.name, stamp, day)
		}
	}
	for _, want := range []string{
		"ipapi.is", "Spamhaus", "make threat-data", "risk-abusive-network.csv", "abusive-network",
		"abusive_networks", "abusive_asn", "drop_networks", "drop_asn", "drop-network", "drop-asn",
		"netblockowner", "Most Abusive Networks", "Most Abusive ASNs", "ASN-DROP", "DROPv6", "Team Cymru",
	} {
		if !strings.Contains(docs, want) {
			t.Errorf("the docs do not mention %q", want)
		}
	}
	flat := flatWords(docs)
	for _, want := range []string{"medium", "once for each covering /24"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the docs do not say %q", want)
		}
	}
}

// nyx help findings lists both types, nyx help procedures the netblockowner procedure, and nyx ip --help
// both keys among the --fields names.
func TestAbusiveDocs_Help(t *testing.T) {
	t.Parallel()
	h := newHarness(t, cli.DefaultDeps().Procedures...)
	if code := h.execRoot("help", "findings"); code != 0 {
		t.Fatalf("help findings: exit %d", code)
	}
	var found int
	for line := range strings.SplitSeq(h.stdout.String(), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "abusive-network" && (f[1] == "network" && f[2] == "medium" || f[1] == "asn" && f[2] == "low") {
			found++
		}
	}
	if found != 2 {
		t.Errorf("nyx help findings lists %d of the two abusive-network rows:\n%s", found, h.stdout.String())
	}
	h2 := newHarness(t, cli.DefaultDeps().Procedures...)
	if code := h2.execRoot("help", "procedures"); code != 0 {
		t.Fatalf("help procedures: exit %d", code)
	}
	if out := h2.stdout.String(); !strings.Contains(out, "netblockowner") || !strings.Contains(out, "Team Cymru") {
		t.Errorf("nyx help procedures lacks netblockowner:\n%s", out)
	}
	h3 := newHarness(t)
	if code := h3.execRoot("ip", "--help"); code != 0 {
		t.Fatalf("ip --help: exit %d", code)
	}
	out := h3.stdout.String()
	for _, k := range []string{"abusive_networks", "abusive_asn"} {
		if !strings.Contains(out, k) {
			t.Errorf("nyx ip --help lacks %s:\n%s", k, out)
		}
	}
	if i, j := strings.Index(out, "reverse_ip_count"), strings.Index(out, "abusive_networks"); i < 0 || j < i {
		t.Errorf("the new keys do not follow reverse_ip_count in nyx ip --help:\n%s", out)
	}
}

// Check that make threat-data downloads all lists before refreshing and cleans temporary files,
// including on failure.
func TestAbusiveDocs_MakefileTarget(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Contains(text, "abusive-data") {
		t.Error("the Makefile still names abusive-data")
	}
	_, recipe, ok := strings.Cut(text, "\nthreat-data:")
	if !ok {
		t.Fatal("the Makefile has no threat-data target")
	}
	_, recipe, _ = strings.Cut(recipe, "\n") // past any prerequisites
	for i, line := range strings.Split(recipe, "\n") {
		if line != "" && !strings.HasPrefix(line, "\t") {
			recipe = strings.Join(strings.Split(recipe, "\n")[:i], "\n")
			break
		}
	}
	for _, want := range []string{"set -e", "mktemp -d", "trap", "rm -rf", "EXIT",
		"https://www.spamhaus.org/drop/drop_v4.json", "https://www.spamhaus.org/drop/drop_v6.json",
		"https://www.spamhaus.org/drop/asndrop.json",
		"https://ipapi.is/most-abusive-networks.html", "https://ipapi.is/most-abusive-asn.html",
		"go run ./internal/threatdata/refresh", "-spamhaus internal/spamhaus/builtin.jsonl",
		"-ipapi internal/abusive/snapshot.json", "-allow-shrink"} {
		if !strings.Contains(recipe, want) {
			t.Errorf("the recipe lacks %q:\n%s", want, recipe)
		}
	}
	// The tool reads the fetched files from -dir by these names.
	for _, name := range []string{"drop_v4.json", "drop_v6.json", "asndrop.json", "networks.html", "asns.html"} {
		if !regexp.MustCompile(`-o\s+"?\S*/` + regexp.QuoteMeta(name) + `"?\s`).MatchString(recipe) {
			t.Errorf("the recipe does not fetch into a file named %s:\n%s", name, recipe)
		}
	}
	if !regexp.MustCompile(`-dir\s+\S+`).MatchString(recipe) {
		t.Errorf("the recipe does not give the refresh its -dir:\n%s", recipe)
	}
	if !strings.Contains(text, "ALLOW_SHRINK") {
		t.Error("the Makefile does not read ALLOW_SHRINK")
	}
	if i, j := strings.LastIndex(recipe, "curl"), strings.Index(recipe, "go run"); j < 0 || i > j {
		t.Error("the refresh runs before every list is fetched")
	}
	if n := strings.Count(recipe, "curl "); n != 5 || strings.Count(recipe, "curl -fsS --retry 3 -o") != 5 {
		t.Errorf("the recipe has %d curl calls, want 5, each failing on an HTTP error and retrying:\n%s", n, recipe)
	}
	_, afterPhony, _ := strings.Cut(text, ".PHONY:")
	if phony, _, _ := strings.Cut(afterPhony, "\n"); !strings.Contains(phony, "threat-data") {
		t.Error("threat-data is not .PHONY")
	}
}

// Only explicit threat-data updates may contact either provider; ordinary commands and key
// tests must not.
func TestAbusiveDocs_NoCommandContactsTheThreatDataHosts(t *testing.T) { // mutation target
	t.Parallel()
	if threatdata.SpamhausHost != "www.spamhaus.org" || threatdata.IpapiHost != "ipapi.is" {
		t.Fatalf("the threat-data hosts are %q and %q", threatdata.SpamhausHost, threatdata.IpapiHost)
	}
	// Every host or source name each command asks, with what asks it.
	var asked [][2]string
	for _, s := range cli.DefaultDeps().Procedures {
		for _, src := range s.Sources() {
			asked = append(asked, [2]string{"procedure " + s.Name() + " declares", src})
		}
	}
	for _, host := range iplookup.SourceHosts() {
		asked = append(asked, [2]string{"nyx ip asks", host})
	}
	for name := range iplookup.SourceRates() {
		asked = append(asked, [2]string{"nyx ip paces", name})
	}
	asked = append(asked, [2]string{"nyx cve asks", cve.Host})
	for _, src := range keycheck.Sources() {
		asked = append(asked, [2]string{"nyx setup tests a key for", src})
	}
	for _, a := range asked {
		if namesAThreatDataHost(a[1]) {
			t.Errorf("%s %s", a[0], a[1])
		}
	}
	for _, dir := range []string{"egress", "keycheck"} {
		for name, text := range sourceFiles(t, "../"+dir) {
			for _, word := range []string{"spamhaus", "ipapi"} {
				if strings.Contains(strings.ToLower(text), word) {
					t.Errorf("internal/%s/%s names %s", dir, name, word)
				}
			}
		}
	}
}

// namesAThreatDataHost reports whether a host, host pattern or source name is Spamhaus or ipapi.is.
func namesAThreatDataHost(s string) bool {
	s = strings.ToLower(s)
	if strings.Contains(s, "spamhaus") || strings.Contains(s, "ipapi") {
		return true
	}
	for _, h := range []string{threatdata.SpamhausHost, threatdata.IpapiHost} {
		if s == h || strings.HasPrefix(s, "*.") && strings.HasSuffix(h, s[1:]) {
			return true
		}
	}
	return false
}

// sourceFiles are the non-test Go files of the package in dir, by name.
func sourceFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), "_test.go") || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile(dir + "/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}
