package cli_test

import (
	"os"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/cli"
	"github.com/rafaelh/nyx/internal/iplookup"
)

// The README names ipapi.is as the source, gives both lists' dates, says how to refresh the snapshot
// and covers the finding, its file, the keys, the stage and the passive boundary.
func TestAbusiveDocs_ReadmeGivesTheSnapshotDates(t *testing.T) {
	t.Parallel()
	readme := readmeText(t)
	d := abusive.Default()
	for _, want := range []string{
		d.Nets.Updated, d.ASNs.Updated, "ipapi.is", "make abusive-data", "risk-abusive-network.csv", "abusive-network",
		"abusive_networks", "abusive_asn", "netblockowner", "Most Abusive Networks", "Most Abusive ASNs",
		"No command contacts ipapi.is", "Team Cymru",
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("README does not mention %q", want)
		}
	}
	flat := flatWords(readme)
	for _, want := range []string{"nyx never contacts ipapi.is", "medium", "only its as is listed", "once for each covering /24"} {
		if !strings.Contains(flat, want) {
			t.Errorf("README does not say %q", want)
		}
	}
}

// nyx help findings lists both types, nyx help stages the netblockowner stage, and nyx ip --help
// both keys among the --fields names.
func TestAbusiveDocs_Help(t *testing.T) {
	t.Parallel()
	h := newHarness(t, cli.DefaultDeps().Stages...)
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
	h2 := newHarness(t, cli.DefaultDeps().Stages...)
	if code := h2.execRoot("help", "stages"); code != 0 {
		t.Fatalf("help stages: exit %d", code)
	}
	if out := h2.stdout.String(); !strings.Contains(out, "netblockowner") || !strings.Contains(out, "Team Cymru") {
		t.Errorf("nyx help stages lacks netblockowner:\n%s", out)
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

// make abusive-data fetches the two pages with curl into a temporary directory that is removed
// however the target ends, runs the parser, and stops before it when a fetch fails.
func TestAbusiveDocs_MakefileTarget(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	_, recipe, ok := strings.Cut(text, "\nabusive-data:\n")
	if !ok {
		t.Fatal("the Makefile has no abusive-data target")
	}
	for i, line := range strings.Split(recipe, "\n") {
		if line != "" && !strings.HasPrefix(line, "\t") {
			recipe = strings.Join(strings.Split(recipe, "\n")[:i], "\n")
			break
		}
	}
	for _, want := range []string{"set -e", "mktemp -d", "trap", "rm -rf", "EXIT",
		"https://ipapi.is/most-abusive-networks.html", "https://ipapi.is/most-abusive-asn.html",
		"go run ./internal/abusive/refresh", "-snapshot internal/abusive/snapshot.json"} {
		if !strings.Contains(recipe, want) {
			t.Errorf("the recipe lacks %q:\n%s", want, recipe)
		}
	}
	if strings.Index(recipe, "curl") > strings.Index(recipe, "go run") {
		t.Error("the parser runs before the pages are fetched")
	}
	if n := strings.Count(recipe, "curl "); n != 2 || strings.Count(recipe, "curl -fsS --retry 3 -o") != 2 {
		t.Errorf("the recipe has %d curl calls, want 2, each failing on an HTTP error and retrying:\n%s", n, recipe)
	}
	_, afterPhony, _ := strings.Cut(text, ".PHONY:")
	if phony, _, _ := strings.Cut(afterPhony, "\n"); !strings.Contains(phony, "abusive-data") {
		t.Error("abusive-data is not .PHONY")
	}
}

// No command contacts ipapi.is: no stage, the lookup's sources or the egress defaults name it.
func TestAbusiveDocs_NoCommandContactsIpapi(t *testing.T) { // mutation target
	t.Parallel()
	for _, s := range cli.DefaultDeps().Stages {
		for _, src := range s.Sources() {
			if strings.Contains(strings.ToLower(src), "ipapi") {
				t.Errorf("stage %s declares the source %s", s.Name(), src)
			}
		}
	}
	for _, host := range iplookup.SourceHosts() {
		if strings.Contains(strings.ToLower(host), "ipapi") {
			t.Errorf("nyx ip asks %s", host)
		}
	}
	for name := range iplookup.SourceRates() {
		if strings.Contains(strings.ToLower(name), "ipapi") {
			t.Errorf("nyx ip paces %s", name)
		}
	}
	entries, err := os.ReadDir("../egress")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), "_test.go") || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile("../egress/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(b)), "ipapi") {
			t.Errorf("internal/egress/%s names ipapi.is", e.Name())
		}
	}
}
