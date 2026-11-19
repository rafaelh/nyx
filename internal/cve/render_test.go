package cve

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/palette"
)

func log4shell() Record {
	score := 10.0
	return Record{
		ID:           "CVE-2021-44228",
		Status:       "Analyzed",
		Published:    Timestamp{time.Date(2021, 12, 10, 10, 15, 9, 0, time.UTC)},
		LastModified: Timestamp{time.Date(2025, 10, 27, 17, 40, 33, 0, time.UTC)},
		Description:  new("Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."),
		CVSSVersion:  new("3.1"),
		CVSSScore:    &score,
		CVSSSeverity: new("CRITICAL"),
		CVSSVector:   new("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
		CVSSSource:   new("nvd@nist.gov"),
		Weaknesses:   []string{"CWE-502"},
		AffectedProducts: []AffectedProduct{{
			CPE: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", Vendor: new("apache"), Product: new("log4j"),
			VersionStartIncluding: new("2.0.1"), VersionEndExcluding: new("2.3.1"),
		}},
		References: []Reference{{URL: "https://logging.apache.org/log4j/2.x/security.html", Tags: []string{"Vendor Advisory"}}},
	}
}

func selectFields(t *testing.T, spec string) Fields {
	t.Helper()
	f, unknown := Select(spec)
	if unknown != nil {
		t.Fatal(unknown)
	}
	return f
}

func render(t *testing.T, recs []Record, spec string, d palette.Depth, width int) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, recs, selectFields(t, spec), d, width); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// log4shellText is the cve tool's layout of log4shell, with every field.
const log4shellText = `CVE-2021-44228  [CRITICAL]

Status & Dates
Status: Analyzed
Published: 2021-12-10T10:15:09Z
Last Modified: 2025-10-27T17:40:33Z

Description
Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.

CVSS Score
Base Score: 10.0 (CRITICAL)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
Version: 3.1
Source: nvd@nist.gov

Weaknesses
- CWE-502

Affected Products
- apache log4j (>= 2.0.1, < 2.3.1)

References
https://logging.apache.org/log4j/2.x/security.html [Vendor Advisory]
`

func TestRender_EverySectionWithoutColour(t *testing.T) {
	t.Parallel()
	if got := render(t, []Record{log4shell()}, "all", palette.None, 100); got != log4shellText {
		t.Errorf("got\n%s\nwant\n%s", got, log4shellText)
	}
}

func TestRender_OnlyTheSelectedSections(t *testing.T) {
	t.Parallel()
	got := render(t, []Record{log4shell()}, "cvss_score,cvss_severity", palette.None, 100)
	want := "CVE-2021-44228  [CRITICAL]\n\nCVSS Score\nBase Score: 10.0 (CRITICAL)\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// The severity alone needs no section: the badge shows it. Without it, no badge.
	if got := render(t, []Record{log4shell()}, "cvss_severity", palette.None, 100); got != "CVE-2021-44228  [CRITICAL]\n" {
		t.Errorf("severity alone: %q", got)
	}
	if got := render(t, []Record{log4shell()}, "id,status", palette.None, 100); got != "CVE-2021-44228\n\nStatus & Dates\nStatus: Analyzed\n" {
		t.Errorf("status alone: %q", got)
	}
}

func TestRender_FallsBackForEmptySections(t *testing.T) {
	t.Parallel()
	empty := Record{ID: "CVE-2026-0001", Weaknesses: []string{}, AffectedProducts: []AffectedProduct{}, References: []Reference{}}
	want := `CVE-2026-0001  [UNKNOWN]

Status & Dates
Status: Unknown
Published: Unknown
Last Modified: Unknown

Description
No description available.

CVSS Score
No CVSS score.

Weaknesses
- No weaknesses listed.

Affected Products
- No affected products listed.

References
No references listed.
`
	// The cve tool writes the fallback of an empty list without a bullet.
	want = strings.Replace(want, "- No weaknesses listed.", "No weaknesses listed.", 1)
	want = strings.Replace(want, "- No affected products listed.", "No affected products listed.", 1)
	if got := render(t, []Record{empty}, "all", palette.None, 100); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestRender_RecordsAreSeparatedByABlankLine(t *testing.T) {
	t.Parallel()
	second := log4shell()
	second.ID = "CVE-2021-45046"
	got := render(t, []Record{log4shell(), second}, "id", palette.None, 100)
	if got != "CVE-2021-44228\n\nCVE-2021-45046\n" {
		t.Errorf("got %q", got)
	}
	if got := render(t, nil, "all", palette.None, 100); got != "" {
		t.Errorf("no records: %q, want nothing", got)
	}
}

// Text wraps at spaces to the width, and a bullet's continuation lines are indented.
func TestRender_Wraps(t *testing.T) {
	t.Parallel()
	r := Record{ID: "CVE-2026-0001", Description: new(strings.Repeat("abcd ", 15)), Weaknesses: []string{strings.Repeat("wxyz ", 15)}}
	got := render(t, []Record{r}, "description,weaknesses", palette.None, 60)
	want := "CVE-2026-0001\n\nDescription\n" +
		strings.TrimSpace(strings.Repeat("abcd ", 12)) + "\nabcd abcd abcd\n\nWeaknesses\n" +
		"- " + strings.TrimSpace(strings.Repeat("wxyz ", 11)) + "\n  wxyz wxyz wxyz wxyz\n"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

// injected is NVD text that would act on a terminal: escape sequences, a
// newline and a tab. Each word is 13 bytes with its escapes and 4 without.
var injected = strings.Repeat("\x1b[31mword\x1b[0m ", 30)

// The NVD's text is cleaned before it is wrapped: newlines and tabs become
// spaces and escape sequences go, so lines are as wide as what shows. At a
// colour depth the palette's own codes are kept.
func TestRender_CleansBeforeWrapping(t *testing.T) {
	t.Parallel()
	r := log4shell()
	r.Description = new(injected)
	r.Weaknesses = []string{"CWE-79\nInjected:\tline"}
	r.References = []Reference{{URL: "https://example.com/\x1b]8;;https://evil.example/\x07x", Tags: []string{"Pa\x1b[2Jtch"}}}
	line12 := strings.TrimSpace(strings.Repeat("word ", 12))
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		got := render(t, []Record{r}, "description,weaknesses,references,cvss_severity", d, 60)
		if !strings.Contains(got, "\n"+line12+"\n") {
			t.Errorf("depth %d: the description is not wrapped at 60 shown characters:\n%q", d, got)
		}
		for _, bad := range []string{"\x1b[31m", "\x1b[2J", "\x1b]8", "\t", "CWE-79\n"} {
			if strings.Contains(got, bad) {
				t.Errorf("depth %d: %q reached the output:\n%q", d, bad, got)
			}
		}
		if !strings.Contains(got, "CWE-79 Injected: line") {
			t.Errorf("depth %d: the weakness's newline and tab are not spaces:\n%q", d, got)
		}
		if d == palette.None {
			if strings.Contains(got, "\x1b") {
				t.Errorf("an escape at depth None:\n%q", got)
			}
			continue
		}
		for _, want := range []string{
			d.Bold("CVE-2021-44228") + "  " + d.Badge(palette.Severity, "CRITICAL"),
			d.Bold("Description"),
			d.Text(palette.Semantic, "info", "https://example.com/x"),
			d.Text(palette.Chrome, "TIMESTAMP", "[Patch]"),
		} {
			if !strings.Contains(got, want) {
				t.Errorf("depth %d: the palette's %q is not in the output:\n%q", d, want, got)
			}
		}
	}
}

func TestRender_ColourKeysAndBadges(t *testing.T) {
	t.Parallel()
	d := palette.Color256
	got := render(t, []Record{log4shell()}, "all", d, 100)
	for _, want := range []string{d.Bold("Status:") + " Analyzed", d.Bold("Base Score:") + " 10.0 (CRITICAL)", "- apache log4j (>= 2.0.1, < 2.3.1)"} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%q", want, got)
		}
	}
	none := Record{ID: "CVE-2026-0001"}
	got = render(t, []Record{none}, "cvss_severity", d, 100)
	if want := d.Bold("CVE-2026-0001") + "  " + d.Badge(palette.Severity, "UNKNOWN") + "\n"; got != want {
		t.Errorf("unknown severity: %q, want %q", got, want)
	}
}

func TestWidth(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]int{"": 100, "80": 80, " 120 ": 120, "40": 60, "0": 100, "-5": 100, "wide": 100} { //nolint:gocritic // " 120 " tests trimming
		if got := Width(in); got != want {
			t.Errorf("Width(%q) = %d, want %d", in, got, want)
		}
	}
}
