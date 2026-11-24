package cli_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/cli"
)

// docPage is one page of the user guide, docs/<name>.
func docPage(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// unitBreak ends a sentence, a paragraph, a list item or a table cell.
var unitBreak = regexp.MustCompile(`[.;:]\s|\n\s*\n|\n\s*[-*]\s|\|`)

// docUnit finds a sentence/list/table unit containing every normalised word, accepting spaced
// or hyphenated threat data.
func docUnit(text string, words ...string) string {
	for _, u := range unitBreak.Split(text, -1) {
		u = flatWords(u)
		alt := strings.ReplaceAll(u, "threat-data", "threat data")
		all := true
		for _, w := range words {
			if !strings.Contains(u, w) && !strings.Contains(alt, w) {
				all = false
				break
			}
		}
		if all {
			return u
		}
	}
	return ""
}

// tableRow is the first line of text that is a table row and holds cell.
func tableRow(text, cell string) string {
	for line := range strings.SplitSeq(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "|") && strings.Contains(line, cell) {
			return line
		}
	}
	return ""
}

// Keep Spamhaus credit beside documented matches/findings and in guide/README credits.
func TestThreatDocs_CreditSpamhaus(t *testing.T) {
	t.Parallel()
	row := strings.ToLower(tableRow(docPage(t, "output.md"), "`risk-abusive-network.csv`"))
	for _, want := range []string{"spamhaus", "drop_networks", "drop_asn"} {
		if !strings.Contains(row, want) {
			t.Errorf("docs/output.md's row for risk-abusive-network.csv lacks %q: %s", want, row)
		}
	}
	abusive := docPage(t, "abusive-networks.md")
	for _, want := range []string{"(c) The Spamhaus Project SLU", "https://www.spamhaus.org/drop/terms/"} {
		if !strings.Contains(abusive, want) {
			t.Errorf("docs/abusive-networks.md lacks Spamhaus's credit %q", want)
		}
	}
	credits, _ := docsSection(t, "# Credits")
	if !strings.Contains(credits, "spamhaus") {
		t.Errorf("the README's credits do not name Spamhaus:\n%s", credits)
	}

	h := newHarness(t, cli.DefaultDeps().Procedures...)
	if code := h.execRoot("help", "findings"); code != 0 {
		t.Fatalf("help findings: exit %d", code)
	}
	want := map[string]string{"drop-network": "high", "drop-asn": "medium"}
	for line := range strings.SplitSeq(h.stdout.String(), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "abusive-network" {
			continue
		}
		if sev, ok := want[f[1]]; ok {
			if f[2] != sev {
				t.Errorf("nyx help findings gives %s the severity %s, want %s", f[1], f[2], sev)
			}
			if !strings.Contains(line, "Spamhaus") {
				t.Errorf("nyx help findings does not name Spamhaus for %s: %s", f[1], line)
			}
			delete(want, f[1])
		}
	}
	if len(want) > 0 {
		t.Errorf("nyx help findings does not list the abusive-network types %v:\n%s", want, h.stdout.String())
	}
}

// The abusive-networks page names where the downloaded copy is kept, and says that deleting the
// directory brings back the built-in data.
func TestThreatDocs_Location(t *testing.T) {
	t.Parallel()
	page := docPage(t, "abusive-networks.md")
	for _, want := range []string{"threat-data", "$XDG_CONFIG_HOME/nyx", "~/.config/nyx"} {
		if !strings.Contains(page, want) {
			t.Errorf("docs/abusive-networks.md does not name %q", want)
		}
	}
	if docUnit(page, "delet", "threat-data", "built") == "" {
		t.Error("docs/abusive-networks.md does not say that deleting the threat-data directory restores the built-in data")
	}
}

// Document source contact as explicit-update-only and remove obsolete claims that no contact
// ever occurs.
func TestThreatDocs_PassiveBoundary(t *testing.T) {
	t.Parallel()
	boundary, whole := docsSection(t, "## Passive boundary")
	for _, host := range []string{"www.spamhaus.org", "ipapi.is"} {
		if !strings.Contains(boundary, host) {
			t.Errorf("the passive boundary does not name %s", host)
		}
	}
	if docUnit(boundary, "spamhaus", "ipapi.is", "only", "update") == "" {
		t.Error("the passive boundary does not say that nyx contacts Spamhaus and ipapi.is only when you ask for an update")
	}
	flat := flatWords(whole)
	for _, gone := range []string{"never contacts ipapi.is", "no command contacts ipapi.is", "no command sends anything to ipapi.is"} {
		if strings.Contains(flat, gone) {
			t.Errorf("the docs still say %q", gone)
		}
	}
	abusive := docPage(t, "abusive-networks.md")
	for _, want := range []string{"--update-threat-data", "www.spamhaus.org", "ipapi.is", "DROP"} {
		if !strings.Contains(abusive, want) {
			t.Errorf("docs/abusive-networks.md does not describe %q", want)
		}
	}
}

// Document non-interactive updates, their exit codes and files separately from config editing.
func TestThreatDocs_SetupPage(t *testing.T) {
	t.Parallel()
	section, _ := docsSection(t, "## Setup")
	if !strings.Contains(section, "--update-threat-data") {
		t.Fatal("the setup page does not name --update-threat-data")
	}
	if docUnit(section, "update-threat-data", "terminal") == "" && docUnit(section, "update-threat-data", "interactive") == "" &&
		docUnit(section, "update-threat-data", "editor") == "" {
		t.Error("the setup page does not describe the update as setup's use without the editor or a terminal")
	}
	if docUnit(section, "update", "exit", "7") == "" {
		t.Error("the setup page does not give the update's exit codes")
	}
	if !strings.Contains(section, "threat-data") || !strings.Contains(strings.ReplaceAll(section, "--update-threat-data", ""), "threat-data") {
		t.Error("the setup page does not name the threat-data directory the update writes")
	}
}

// Setup help describes both editing and updates, including additional files and outcome codes.
func TestThreatDocs_SetupHelp(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if code := h.execRoot("setup", "--help"); code != 0 {
		t.Fatalf("setup --help: exit %d", code)
	}
	long, _, ok := strings.Cut(h.stdout.String(), "\nUsage:")
	if !ok {
		t.Fatalf("nyx setup --help has no usage:\n%s", h.stdout.String())
	}
	var kept []string
	for line := range strings.SplitSeq(long, "\n") {
		if strings.HasPrefix(line, "  nyx ") || strings.TrimSpace(line) == "Examples:" {
			continue
		}
		kept = append(kept, line)
	}
	text := flatWords(strings.Join(kept, "\n"))
	if !strings.Contains(text, "--update-threat-data") {
		t.Errorf("the description of nyx setup does not name --update-threat-data:\n%s", text)
	}
	rest := strings.ReplaceAll(text, "--update-threat-data", "")
	if !strings.Contains(rest, "threat-data") && !strings.Contains(rest, "threat data") {
		t.Errorf("the description of nyx setup does not name the threat data the update writes:\n%s", text)
	}
	if !strings.Contains(rest, "exit") {
		t.Errorf("the description of nyx setup does not mention the update's exit codes:\n%s", text)
	}
	if strings.Contains(text, "edits only the config file") {
		t.Errorf("the description of nyx setup still says it edits only the config file:\n%s", text)
	}
}

// Contributor notes name current refresh targets/packages and both lock users.
func TestThreatDocs_ContributorNotes(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../CLAUDE.md")
	if err != nil {
		t.Fatal(err)
	}
	notes := string(b)
	for _, want := range []string{"make threat-data", "spamhaus", "threatdata"} {
		if !strings.Contains(notes, want) {
			t.Errorf("CLAUDE.md does not name %q", want)
		}
	}
	if docUnit(notes, "flock", "internal/engagement", "internal/threatdata") == "" {
		t.Error("CLAUDE.md's unix allowlist does not give flock to both internal/engagement and internal/threatdata")
	}
	for name, text := range map[string]string{"CLAUDE.md": notes, "the user guide": docsText(t)} {
		if strings.Contains(text, "abusive-data") {
			t.Errorf("%s still names make abusive-data", name)
		}
	}
}
