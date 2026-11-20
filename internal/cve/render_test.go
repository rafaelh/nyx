package cve

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/layout"
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

// stream is a stream that reports width cells, with colour depth d.
func stream(terminal bool, d palette.Depth, width int) layout.Stream {
	return layout.Stream{Terminal: terminal, Depth: d, Width: func() int { return width }}
}

func renderTo(t *testing.T, recs []Record, spec string, s layout.Stream) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, recs, selectFields(t, spec), s, nil); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// render is the layout for a stream that is not a terminal.
func render(t *testing.T, recs []Record, spec string, d palette.Depth, width int) string {
	t.Helper()
	return renderTo(t, recs, spec, stream(false, d, width))
}

// renderTerm is the layout for a terminal.
func renderTerm(t *testing.T, recs []Record, spec string, d palette.Depth, width int) string {
	t.Helper()
	return renderTo(t, recs, spec, stream(true, d, width))
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

var sgr = regexp.MustCompile("\x1b\\[[0-9;]*m")

func strip(s string) string { return sgr.ReplaceAllString(s, "") }

// widest is the widest line of s in cells.
func widest(s string) int {
	w := 0
	for l := range strings.SplitSeq(s, "\n") {
		w = max(w, layout.Measure(l))
	}
	return w
}

var colourDepths = []palette.Depth{palette.TrueColor, palette.Color256, palette.Color16}

// The bar is as wide as the layout: the ID at the left and the severity label
// at the right, all in the severity's badge style.
func TestBar_Coloured(t *testing.T) {
	t.Parallel()
	for _, d := range colourDepths {
		for _, c := range []struct{ severity, label string }{
			{"CRITICAL", "CRITICAL"}, {"HIGH", "HIGH"}, {"MEDIUM", "MEDIUM"}, {"LOW", "LOW"},
			{"", "UNKNOWN"}, {"NONE", "NONE"},
		} {
			s := stream(true, d, 80)
			got := Bar(s, "CVE-2021-44228", c.severity, true)
			plain := " CVE-2021-44228" + strings.Repeat(" ", 80-1-len("CVE-2021-44228")-len(c.label)-1) + c.label + " "
			if want := d.BadgeText(palette.Severity, c.label, plain); got != want {
				t.Errorf("depth %d, severity %q: got %q, want %q", d, c.severity, got, want)
			}
			if w := layout.Measure(got); w != 80 {
				t.Errorf("depth %d, severity %q: the bar is %d cells wide, want 80", d, c.severity, w)
			}
		}
		// The two that the palette does not know take the DEBUG style, a label it does not hold.
		for _, sev := range []string{"", "NONE"} {
			got := Bar(stream(true, d, 70), "CVE-1", sev, true)
			if !strings.HasPrefix(got, strings.TrimSuffix(d.BadgeText(palette.Severity, "no such label", "x"), "x\x1b[0m")) {
				t.Errorf("depth %d, severity %q: not the DEBUG style: %q", d, sev, got)
			}
		}
	}
}

// The width is the stream's, so a wider terminal gives a wider bar, and never under 60.
func TestBar_Width(t *testing.T) {
	t.Parallel()
	for in, want := range map[int]int{120: 120, 60: 60, 40: 60, 0: 100} {
		if got := layout.Measure(Bar(stream(true, palette.TrueColor, in), "CVE-1", "HIGH", true)); got != want {
			t.Errorf("a width of %d gives a bar of %d cells, want %d", in, got, want)
		}
		if got := layout.Measure(Bar(stream(true, palette.None, in), "CVE-1", "HIGH", true)); got != want {
			t.Errorf("uncoloured: a width of %d gives a bar of %d cells, want %d", in, got, want)
		}
	}
}

// Without cvss_severity the bar holds only the ID, in the DEBUG style.
func TestBar_WithoutSeverity(t *testing.T) {
	t.Parallel()
	for _, d := range colourDepths {
		got := Bar(stream(true, d, 80), "CVE-2021-44228", "CRITICAL", false)
		want := d.BadgeText(palette.Severity, "no such label", " CVE-2021-44228"+strings.Repeat(" ", 80-15))
		if got != want {
			t.Errorf("depth %d: got %q, want %q", d, got, want)
		}
	}
	if got := Bar(stream(true, palette.None, 80), "CVE-2021-44228", "CRITICAL", false); got != "CVE-2021-44228" {
		t.Errorf("uncoloured: got %q, want the ID alone", got)
	}
}

// Uncoloured, the bar is the ID and [LABEL] at either end of the line, with no escape.
func TestBar_Uncoloured(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ severity, label string }{{"HIGH", "HIGH"}, {"", "UNKNOWN"}, {"NONE", "NONE"}} {
		got := Bar(stream(true, palette.None, 80), "CVE-2021-44228", c.severity, true)
		tag := "[" + c.label + "]"
		want := "CVE-2021-44228" + strings.Repeat(" ", 80-14-len(tag)) + tag
		if got != want {
			t.Errorf("severity %q: got %q, want %q", c.severity, got, want)
		}
	}
}

// The ID and the severity are cleaned: neither can bring an escape sequence into the bar.
func TestBar_Cleans(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		got := Bar(stream(true, d, 80), "CVE\x1b[2J-1\x1b]8;;x\x07", "HI\x1b[31mGH\u202e", true)
		for _, bad := range []string{"[2J", "]8", "[31m", "\u202e", "\x07"} {
			if strings.Contains(got, bad) {
				t.Errorf("depth %d: %q reached the bar: %q", d, bad, got)
			}
		}
		if !strings.Contains(strip(got), "CVE-1") || !strings.Contains(strip(got), "HIGH") {
			t.Errorf("depth %d: the text is lost: %q", d, got)
		}
		if d == palette.None && strings.Contains(got, "\x1b") {
			t.Errorf("an escape at depth None: %q", got)
		}
	}
}

// terminalLog4shell is log4shell on an uncoloured terminal at 80 columns, every field.
func terminalLog4shell() string {
	bar := "CVE-2021-44228" + strings.Repeat(" ", 80-14-len("[CRITICAL]")) + "[CRITICAL]"
	return bar + `

Status & Dates
  Status         Analyzed
  Published      2021-12-10T10:15:09Z
  Last Modified  2025-10-27T17:40:33Z

Description
  Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.

CVSS Score
  Base Score  10.0 (CRITICAL)
  Vector      CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
  Version     3.1
  Source      nvd@nist.gov

Weaknesses
  - CWE-502

Affected Products
  - apache log4j (>= 2.0.1, < 2.3.1)

References
  https://logging.apache.org/log4j/2.x/security.html [Vendor Advisory]
`
}

// A record on a terminal: the bar, headings with no rule, labels without a colon
// and values at one column in each section, and indented text.
func TestRender_Terminal(t *testing.T) {
	t.Parallel()
	got := renderTerm(t, []Record{log4shell()}, "all", palette.None, 80)
	if want := terminalLog4shell(); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("an escape on an uncoloured terminal: %q", got)
	}
}

func TestRender_TerminalFallbacks(t *testing.T) {
	t.Parallel()
	empty := Record{ID: "CVE-2026-0001", Weaknesses: []string{}, AffectedProducts: []AffectedProduct{}, References: []Reference{}}
	want := "CVE-2026-0001" + strings.Repeat(" ", 80-13-len("[UNKNOWN]")) + "[UNKNOWN]" + `

Status & Dates
  Status         Unknown
  Published      Unknown
  Last Modified  Unknown

Description
  No description available.

CVSS Score
  No CVSS score.

Weaknesses
  No weaknesses listed.

Affected Products
  No affected products listed.

References
  No references listed.
`
	if got := renderTerm(t, []Record{empty}, "all", palette.None, 80); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

func TestRender_TerminalSelectedFields(t *testing.T) {
	t.Parallel()
	bar := "CVE-2021-44228" + strings.Repeat(" ", 80-14-len("[CRITICAL]")) + "[CRITICAL]"
	for spec, want := range map[string]string{
		"cvss_score,cvss_severity": bar + "\n\nCVSS Score\n  Base Score  10.0 (CRITICAL)\n",
		"cvss_severity":            bar + "\n",
		"id,status":                "CVE-2021-44228\n\nStatus & Dates\n  Status  Analyzed\n",
		"cvss_vector":              "CVE-2021-44228\n\nCVSS Score\n  Vector  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H\n",
	} {
		if got := renderTerm(t, []Record{log4shell()}, spec, palette.None, 80); got != want {
			t.Errorf("%s: got %q, want %q", spec, got, want)
		}
	}
}

// Records are separated by one blank line.
func TestRender_TerminalRecordsAreSeparatedByABlankLine(t *testing.T) {
	t.Parallel()
	second := log4shell()
	second.ID = "CVE-2021-45046"
	got := renderTerm(t, []Record{log4shell(), second}, "id", palette.None, 80)
	if got != "CVE-2021-44228\n\nCVE-2021-45046\n" {
		t.Errorf("got %q", got)
	}
	d := palette.TrueColor
	got = renderTerm(t, []Record{log4shell(), second}, "id", d, 80)
	b1, b2 := Bar(stream(true, d, 80), "CVE-2021-44228", "", false), Bar(stream(true, d, 80), "CVE-2021-45046", "", false)
	if got != b1+"\n\n"+b2+"\n" {
		t.Errorf("coloured: got %q", got)
	}
	if got := renderTo(t, nil, "all", stream(true, d, 80)); got != "" {
		t.Errorf("no records: %q, want nothing", got)
	}
}

// Coloured, the record opens with the severity's bar and its headings and labels take the
// palette's styles: bold info for a heading, bold for a label, no rule.
func TestRender_TerminalColour(t *testing.T) {
	t.Parallel()
	for _, d := range colourDepths {
		got := renderTerm(t, []Record{log4shell()}, "all", d, 80)
		if !strings.HasPrefix(got, Bar(stream(true, d, 80), "CVE-2021-44228", "CRITICAL", true)+"\n\n") {
			t.Errorf("depth %d: no bar at the start: %q", d, got)
		}
		for _, want := range []string{
			"\n\n" + d.BoldText(palette.Semantic, "info", "Status & Dates") + "\n",
			"\n\n" + d.BoldText(palette.Semantic, "info", "References") + "\n",
			"\n  " + d.Bold("Last Modified") + "  2025",
			"\n  " + d.Bold("Status") + "         Analyzed",
			"\n  " + d.Bold("Base Score") + "  10.0 (CRITICAL)",
			"\n  " + d.Text(palette.Semantic, "info", "https://logging.apache.org/log4j/2.x/security.html") +
				" " + d.Text(palette.Chrome, "TIMESTAMP", "[Vendor Advisory]") + "\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("depth %d: lacks %q:\n%q", d, want, got)
			}
		}
		// Stripped of colour it is the uncoloured layout, apart from the bar's own padding.
		if want := strings.SplitN(terminalLog4shell(), "\n", 2)[1]; !strings.HasSuffix(strip(got), want) {
			t.Errorf("depth %d: stripped of colour the body differs:\n%s", d, strip(got))
		}
	}
}

// No heading has a rule beneath it, coloured or not.
func TestRender_TerminalHeadingsHaveNoRule(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		got := renderTerm(t, []Record{log4shell()}, "all", d, 80)
		for l := range strings.SplitSeq(strip(got), "\n") {
			if l != "" && strings.Trim(l, "-─") == "" {
				t.Errorf("depth %d: a rule: %q", d, l)
			}
		}
	}
}

// Long text wraps to the width with continuation lines under their text.
func TestRender_TerminalWraps(t *testing.T) {
	t.Parallel()
	r := Record{ID: "CVE-2026-0001", Description: new(strings.Repeat("abcd ", 30)), Weaknesses: []string{strings.Repeat("wxyz ", 15)}}
	got := renderTerm(t, []Record{r}, "description,weaknesses", palette.None, 60)
	line := func(word string, n int) string { return strings.TrimSpace(strings.Repeat(word+" ", n)) }
	want := "CVE-2026-0001\n\nDescription\n" +
		"  " + line("abcd", 11) + "\n  " + line("abcd", 11) + "\n  " + line("abcd", 8) +
		"\n\nWeaknesses\n" +
		"  - " + line("wxyz", 11) + "\n    " + line("wxyz", 4) + "\n"
	if got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

// A long field value wraps under the value column.
func TestRender_TerminalFieldValueWraps(t *testing.T) {
	t.Parallel()
	r := log4shell()
	r.CVSSSource = new(strings.Repeat("source ", 20))
	got := renderTerm(t, []Record{r}, "cvss_score,cvss_source", palette.None, 60)
	valueCol := strings.Repeat(" ", 2+len("Base Score")+2)
	lines := strings.Split(strings.TrimSpace(got), "\n")
	var cont int
	for _, l := range lines[5:] {
		if !strings.HasPrefix(l, valueCol) || strings.HasPrefix(l, valueCol+" ") {
			t.Errorf("a continuation line is not at the value column: %q", l)
		}
		cont++
	}
	if cont < 2 || widest(got) > 60 {
		t.Errorf("%d continuation lines, widest %d:\n%s", cont, widest(got), got)
	}
}

// A reference's URL stays whole, and its tags wrap at spaces with continuation lines at 4.
func TestRender_TerminalReferenceWraps(t *testing.T) {
	t.Parallel()
	url := "https://example.com/advisories/" + strings.Repeat("a", 9)
	r := Record{ID: "CVE-2026-0001", References: []Reference{{URL: url, Tags: []string{"Vendor Advisory", "Third Party Advisory", "Patch"}}}}
	const tags = "[Vendor Advisory, Third Party Advisory, Patch]"
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		got := renderTerm(t, []Record{r}, "references", d, 60)
		lines := strings.Split(strings.TrimSpace(strip(got)), "\n")[3:]
		if len(lines) < 2 || lines[0] != "  "+url+" [Vendor Advisory," {
			t.Errorf("depth %d: the URL line is %q (of %d lines)", d, lines[0], len(lines))
		}
		var rejoined []string
		for _, l := range lines[1:] {
			if !strings.HasPrefix(l, "    ") || strings.HasPrefix(l, "     ") {
				t.Errorf("depth %d: a continuation line is not at 4: %q", d, l)
			}
			rejoined = append(rejoined, strings.TrimSpace(l))
		}
		if all := "[Vendor Advisory, " + strings.Join(rejoined, " "); all != tags {
			t.Errorf("depth %d: the tags read %q, want %q", d, all, tags)
		}
		if widest(got) > 60 {
			t.Errorf("depth %d: widest line %d:\n%s", d, widest(got), got)
		}
		if d == palette.None {
			continue
		}
		// Each line's coloured runs are closed on the line they begin on.
		for l := range strings.SplitSeq(got, "\n") {
			if opens, closes := len(sgr.FindAllString(l, -1)), strings.Count(l, "\x1b[0m"); opens != 2*closes {
				t.Errorf("a line with %d sequences and %d resets: %q", opens, closes, l)
			}
		}
		if !strings.Contains(got, d.Text(palette.Semantic, "info", url)+" "+d.Text(palette.Chrome, "TIMESTAMP", "[Vendor Advisory,")) {
			t.Errorf("the URL is not whole in info, with the tags in the timestamp colour: %q", got)
		}
	}
}

// A URL wider than the width is left whole rather than broken.
func TestRender_TerminalLongURLStaysWhole(t *testing.T) {
	t.Parallel()
	url := "https://example.com/" + strings.Repeat("x", 90)
	r := Record{ID: "CVE-2026-0001", References: []Reference{{URL: url, Tags: []string{"Patch"}}}}
	got := renderTerm(t, []Record{r}, "references", palette.TrueColor, 60)
	if !strings.Contains(got, palette.TrueColor.Text(palette.Semantic, "info", url)) {
		t.Errorf("the URL is broken: %q", got)
	}
}

// The goal: at 80 columns no line is wider than 80 cells, for records with no word that cannot wrap.
func TestRender_TerminalFitsTheWidth(t *testing.T) {
	t.Parallel()
	long := log4shell()
	long.Description = new(strings.Repeat("A long description that goes on and on, with words. ", 12))
	long.Weaknesses = []string{strings.Repeat("a weakness that is rather wordy ", 8), "CWE-79"}
	long.AffectedProducts = append(long.AffectedProducts, AffectedProduct{
		Vendor: new("a vendor"), Product: new("a product with a long name"), Version: new("1.2.3"),
		VersionStartIncluding: new("0.1"), VersionEndExcluding: new("9.9.9"), VersionEndIncluding: new("9.9.8"),
	})
	long.References = []Reference{
		{URL: "https://example.com/a/fairly/long/path/to/an/advisory", Tags: []string{"Vendor Advisory", "Third Party Advisory", "Exploit", "Patch", "Mailing List"}},
		{URL: "https://example.com/short"},
	}
	other := log4shell()
	other.CVSSSeverity = new("NONE")
	for _, d := range []palette.Depth{palette.None, palette.TrueColor, palette.Color16} {
		for _, cols := range []int{80, 60} {
			got := renderTerm(t, []Record{long, other, {ID: "CVE-2026-0002"}}, "all", d, cols)
			if w := widest(got); w > cols {
				t.Errorf("depth %d, %d columns: a line is %d cells wide:\n%s", d, cols, w, got)
			}
		}
	}
}

// Every escape sequence in the output is one the palette writes.
func TestRender_TerminalWritesOnlyPaletteSequences(t *testing.T) {
	t.Parallel()
	for _, d := range colourDepths {
		allowed := map[string]bool{"\x1b[0m": true}
		add := func(styled string) { allowed[sgr.FindString(styled)] = true }
		add(d.Bold("x"))
		add(d.BoldText(palette.Semantic, "info", "x"))
		add(d.Text(palette.Semantic, "info", "x"))
		add(d.Text(palette.Chrome, "TIMESTAMP", "x"))
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"} {
			add(d.BadgeText(palette.Severity, sev, "x"))
		}
		other := log4shell()
		other.CVSSSeverity = new("NONE")
		got := renderTerm(t, []Record{log4shell(), other, {ID: "CVE-2026-0002"}}, "all", d, 70)
		seen := sgr.FindAllString(got, -1)
		if len(seen) == 0 {
			t.Fatalf("depth %d: no colour at all", d)
		}
		for _, s := range seen {
			if !allowed[s] {
				t.Errorf("depth %d: %q is not a sequence the palette writes", d, s)
			}
		}
		if n := strings.Count(strip(got), "\x1b"); n != 0 {
			t.Errorf("depth %d: %d escape bytes that are not colour", d, n)
		}
	}
}

// The NVD's text is cleaned before it is wrapped and laid out, so no layout lets
// an escape sequence, an OSC or a bidi override through, wherever the lines break.
func TestRender_TerminalCleansTheNVDText(t *testing.T) {
	t.Parallel()
	injected := strings.Repeat("\x1b[31mword\x1b[0m\u202e ", 30) + strings.Repeat("a\x1b[2Jb\x1b]8;;https://evil.example/\x07c", 30) +
		strings.Repeat(" tail\u2066\u2069 ", 10)
	r := log4shell()
	r.Description = new(injected)
	r.Weaknesses = []string{injected, "CWE-79\nInjected:\tline"}
	r.References = []Reference{{URL: "https://example.com/\x1b]8;;https://evil.example/\x07x", Tags: []string{"Pa\x1b[2Jtch", "Third\u202e Party"}}}
	r.CVSSVector = new(injected)
	r.CVSSSeverity = new("HI\x1b[31mGH")
	r.ID = "CVE\x1b[2J-2026-1"
	for _, d := range []palette.Depth{palette.None, palette.TrueColor, palette.Color16} {
		for _, cols := range []int{60, 80} {
			got := renderTerm(t, []Record{r}, "all", d, cols)
			for _, bad := range []string{"\x1b[31m\x1b[0m", "[2J", "\x1b]8", "evil.example/\x07", "\t", "\u202e", "\u2066", "\u2069", "\x07"} {
				if strings.Contains(got, bad) {
					t.Errorf("depth %d, %d columns: %q reached the output", d, cols, bad)
				}
			}
			if strings.Contains(strip(got), "\x1b") {
				t.Errorf("depth %d, %d columns: an escape that is not the palette's", d, cols)
			}
			if d == palette.None && strings.Contains(got, "\x1b") {
				t.Errorf("an escape at depth None: %q", got)
			}
			if !strings.Contains(got, "CWE-79 Injected: line") {
				t.Errorf("depth %d: the weakness's newline and tab are not spaces", d)
			}
		}
	}
}

// Under a stream that is not a terminal, the records are today's layout whatever the depth
// the stream reports, wrapped at the width it reports (100 when it reports none).
func TestRender_NotATerminalKeepsTheOldLayout(t *testing.T) {
	t.Parallel()
	for _, width := range []int{0, 200} {
		got := renderTo(t, []Record{log4shell()}, "all", layout.Stream{Width: func() int { return width }})
		if got != log4shellText {
			t.Errorf("width %d: got\n%s", width, got)
		}
	}
	got := renderTo(t, []Record{log4shell()}, "all", layout.Stream{Width: func() int { return 70 }})
	if want := strings.Replace(log4shellText, "controlled LDAP.", "controlled\nLDAP.", 1); got != want {
		t.Errorf("width 70: got\n%s", got)
	}
}

// pieces are each run of n characters of key.
func pieces(key string, n int) []string {
	var out []string
	for i := 0; i+n <= len(key); i++ {
		out = append(out, key[i:i+n])
	}
	return out
}

func renderRedacted(t *testing.T, r Record, s layout.Stream, red *config.Redactor) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, []Record{r}, selectFields(t, "all"), s, red); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// A configured key in the NVD's text never reaches the output, whole or in part,
// wherever the layout breaks a line, with or without a terminal. A key inside a
// long word is masked before the word is broken, and a key that cleaning joins
// back together (a control character, an escape sequence or a bidi override in
// the middle) is masked too, in every field.
func TestRender_RedactsKeys(t *testing.T) {
	t.Parallel()
	const key = "sk-live-Qx7Rt2Zk9Vb4Nm8Lp3"
	red := config.NewRedactor(key)
	split := key[:9] + "\x1b[31m" + key[9:14] + "\u202e\x07" + key[14:]
	words := strings.Repeat("filler ", 8)
	cases := map[string]string{
		"hard-broken word": strings.Repeat("a", 45) + key + strings.Repeat("b", 45),
		"among words":      words + key + " " + words,
		"split":            words + split + " " + words,
		"split in a word":  strings.Repeat("c", 50) + split + strings.Repeat("d", 50),
	}
	for name, text := range cases {
		r := log4shell()
		r.Description = &text
		r.Weaknesses = []string{text}
		r.CVSSVector = &text
		r.CVSSSource = &text
		r.Status = text
		r.References = []Reference{{URL: "https://example.com/" + text, Tags: []string{text}}}
		r.AffectedProducts = []AffectedProduct{{CPE: text, Vendor: &text, Product: &text, Version: &text, VersionEndExcluding: &text}}
		for _, terminal := range []bool{true, false} {
			for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
				for _, cols := range []int{60, 80} {
					got := renderRedacted(t, r, stream(terminal, d, cols), red)
					assertNoKey(t, fmt.Sprintf("%s (terminal %v, depth %d, %d columns)", name, terminal, d, cols), got, key)
				}
			}
		}
	}
}

// assertNoKey fails when any piece of key of 8 characters, or the key whole, is in
// the output stripped of colour, or when nothing was masked.
func assertNoKey(t *testing.T, name, got, key string) {
	t.Helper()
	plain := strip(got)
	for _, p := range append(pieces(key, 8), key) {
		if strings.Contains(plain, p) {
			t.Errorf("%s: %q of the key reached the output", name, p)
			return
		}
	}
	if !strings.Contains(plain, "****") {
		t.Errorf("%s: nothing was masked:\n%s", name, got)
	}
}

// Without a key in the text, a redactor changes nothing, and neither does none.
func TestRender_RedactorLeavesOtherTextAlone(t *testing.T) {
	t.Parallel()
	red := config.NewRedactor("sk-live-Qx7Rt2Zk9Vb4Nm8Lp3")
	for _, s := range []layout.Stream{stream(false, palette.None, 100), stream(true, palette.None, 80), stream(true, palette.TrueColor, 70)} {
		want := renderTo(t, []Record{log4shell()}, "all", s)
		if got := renderRedacted(t, log4shell(), s, red); got != want {
			t.Errorf("a redactor changed the output:\n%s\nwant\n%s", got, want)
		}
		if got := renderRedacted(t, log4shell(), s, nil); got != want {
			t.Errorf("a nil redactor changed the output:\n%s", got)
		}
	}
	empty := Record{ID: "CVE-2026-0001"}
	if got, want := renderRedacted(t, empty, stream(false, palette.None, 100), red), render(t, []Record{empty}, "all", palette.None, 100); got != want {
		t.Errorf("a record of nulls: %q, want %q", got, want)
	}
}
