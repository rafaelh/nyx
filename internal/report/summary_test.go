package report_test

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/report"
)

func writeSummary(d palette.Depth, env report.Envelope) string {
	var buf bytes.Buffer
	report.WriteSummary(&buf, d, env)
	return buf.String()
}

func withData(s report.Summary) report.Envelope { return report.Envelope{Data: s} }

func candidateRow(value, promote string, n int) report.CandidateRow {
	return report.CandidateRow{Kind: "root", Value: value, Sources: []string{"crtsh", "whoisxml"}, EvidenceCount: n, Confidence: "high", Promote: promote}
}

func headlineRows() []report.FindingRow {
	return []report.FindingRow{
		{Severity: "high", Category: "exposed-admin", Target: "https://a.example.com/admin", Detail: strPtr("login page")},
		{Severity: "medium", Category: "banner", Target: "10.0.0.1:21", Detail: strPtr("ftp")},
	}
}

// A run with something in every block is the summary of today, in order, with
// one trailing newline.
func TestWriteSummary_PlainText(t *testing.T) {
	t.Parallel()
	env := report.Envelope{
		Data: report.Summary{
			Engagement: "acme", Directory: "/x",
			Counts:                []report.CountRow{{Category: "hosts", N: 12}, {Category: "open ports", N: 5}, {Category: "urls", N: 340}},
			FailedChecks:          []report.StageCount{{Stage: "asn", N: 2}},
			Deferred:              []report.StageCount{{Stage: "shodan", N: 4}},
			NotConfigured:         []report.StageReason{{Stage: "ports", Reason: "passive-only"}}, // not in the human text
			Findings:              headlineRows(),
			Candidates:            []report.CandidateRow{candidateRow("x.org", "-d x.org", 2)},
			CandidatesTotal:       1,
			UnconfirmedRiskyPorts: 3,
			Notes:                 []string{"shodan: truncated"},
		},
		Meta: report.Meta{DeadlineExceeded: true, ChecksCompleted: 7, ChecksCancelled: 2},
	}
	want := "Summary\n" +
		"  hosts            12\n" +
		"  open ports       5\n" +
		"  urls             340\n" +
		"  3 risky ports reported by Shodan, unconfirmed\n" +
		"  shodan: truncated\n" +
		"  Stopped by the deadline: 7 checks completed, 2 cancelled\n" +
		"Failed checks (retried on the next run; --debug shows each failure)\n" +
		"  asn              2\n" +
		"Deferred to the next run\n" +
		"  shodan           4\n" +
		"Findings (high and medium)\n" +
		"  high     exposed-admin https://a.example.com/admin - login page\n" +
		"  medium   banner 10.0.0.1:21 - ftp\n" +
		"Candidates worth promoting (high confidence)\n" +
		"  x.org  2 evidence (crtsh;whoisxml)  promote: -d x.org\n"
	if got := writeSummary(palette.None, env); got != want {
		t.Errorf("summary\n got %q\nwant %q", got, want)
	}
}

// The bare summary is a heading and the counts.
func TestWriteSummary_Minimal(t *testing.T) {
	t.Parallel()
	if got, want := writeSummary(palette.None, report.Envelope{}), "Summary\n"; got != want {
		t.Errorf("zero envelope = %q, want %q", got, want)
	}
	got := writeSummary(palette.None, withData(report.Summary{Counts: []report.CountRow{{Category: "hosts", N: 1}}}))
	if want := "Summary\n  hosts            1\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A category longer than 16 widens the column of its own block, and only that.
func TestWriteSummary_CountColumnWidth(t *testing.T) {
	t.Parallel()
	got := writeSummary(palette.None, withData(report.Summary{
		Counts:       []report.CountRow{{Category: "a very long category", N: 1}, {Category: "b", N: 22}},
		FailedChecks: []report.StageCount{{Stage: "dns", N: 3}},
	}))
	for _, w := range []string{"  a very long category 1\n", "  b                    22\n", "  dns              3\n"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in\n%s", w, got)
		}
	}
}

// Rows come out in the order given: the caller sorts them.
func TestWriteSummary_KeepsRowOrder(t *testing.T) {
	t.Parallel()
	got := writeSummary(palette.None, withData(report.Summary{Counts: []report.CountRow{{Category: "b", N: 1}, {Category: "a", N: 2}}}))
	if strings.Index(got, "  b ") > strings.Index(got, "  a ") {
		t.Errorf("rows were reordered:\n%s", got)
	}
}

// The notes follow the counts, and the unconfirmed risky ports get a line only
// when there are some.
func TestWriteSummary_NotesAndUnconfirmedRiskyPorts(t *testing.T) {
	t.Parallel()
	out := writeSummary(palette.None, withData(report.Summary{
		Counts:                []report.CountRow{{Category: "hosts", N: 1}},
		Notes:                 []string{"shodan: the search of 198.51.100.0/24 was truncated at 10 pages"},
		UnconfirmedRiskyPorts: 3,
	}))
	for _, w := range []string{"  shodan: the search of 198.51.100.0/24 was truncated at 10 pages\n", "  3 risky ports reported by Shodan, unconfirmed\n"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
	out = writeSummary(palette.None, withData(report.Summary{Counts: []report.CountRow{{Category: "hosts", N: 1}}}))
	if strings.Contains(out, "risky ports reported") {
		t.Errorf("a zero count printed a line:\n%s", out)
	}
}

// The deadline line comes straight after the notes and before the first block,
// and only when the deadline ended the run.
func TestWriteSummary_DeadlineLine(t *testing.T) {
	t.Parallel()
	s := report.Summary{
		Counts:       []report.CountRow{{Category: "hosts", N: 1}},
		Notes:        []string{"a note"},
		FailedChecks: []report.StageCount{{Stage: "dns", N: 1}},
	}
	env := report.Envelope{Data: s, Meta: report.Meta{DeadlineExceeded: true, ChecksCompleted: 12, ChecksCancelled: 34}}
	out := writeSummary(palette.None, env)
	const line = "Stopped by the deadline: 12 checks completed, 34 cancelled"
	if !strings.Contains(out, "  a note\n  "+line+"\nFailed checks") {
		t.Errorf("the line is not straight after the notes:\n%s", out)
	}
	env.Meta.DeadlineExceeded = false
	if out := writeSummary(palette.None, env); strings.Contains(out, "Stopped") {
		t.Errorf("a run the deadline did not end has the line:\n%s", out)
	}
	// With no notes it follows the counts and the risky ports line.
	env = report.Envelope{Data: report.Summary{Counts: s.Counts, UnconfirmedRiskyPorts: 1}, Meta: report.Meta{DeadlineExceeded: true}}
	if out := writeSummary(palette.None, env); !strings.Contains(out, "unconfirmed\n  Stopped by the deadline: 0 checks completed, 0 cancelled\n") {
		t.Errorf("line placement:\n%s", out)
	}
}

// Failed and deferred blocks are left out when empty.
func TestWriteSummary_EmptyBlocksAreLeftOut(t *testing.T) {
	t.Parallel()
	out := writeSummary(palette.None, withData(report.Summary{
		Counts:       []report.CountRow{{Category: "hosts", N: 1}},
		FailedChecks: []report.StageCount{},
		Findings:     []report.FindingRow{},
		Candidates:   []report.CandidateRow{},
	}))
	for _, bad := range []string{"Failed", "Deferred", "Findings", "Candidates", "Since last run"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q in\n%s", bad, out)
		}
	}
}

// Findings print with their badge and detail; one with no detail has no dash.
func TestWriteSummary_FindingsWithAndWithoutDetail(t *testing.T) {
	t.Parallel()
	out := writeSummary(palette.None, withData(report.Summary{Findings: []report.FindingRow{
		{Severity: "high", Category: "exposed-admin", Target: "https://a/admin", Detail: strPtr("login page")},
		{Severity: "medium", Category: "banner", Target: "10.0.0.1:21"},
		{Severity: "medium", Category: "empty", Target: "t", Detail: strPtr("")},
		{Severity: "medium", Category: "escape", Target: "t", Detail: strPtr("\x1b[31m")},
	}}))
	want := "Findings (high and medium)\n" +
		"  high     exposed-admin https://a/admin - login page\n" +
		"  medium   banner 10.0.0.1:21\n" +
		"  medium   empty t\n" +
		"  medium   escape t\n"
	if !strings.HasSuffix(out, want) || strings.Contains(out, "[high]") || strings.Contains(out, "\x1b") {
		t.Errorf("findings\n got %q\nwant suffix %q", out, want)
	}
}

// Headings are bold and the severity is a badge on a coloured stream; nothing
// else is styled.
func TestWriteSummary_Coloured(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.TrueColor, palette.Color256, palette.Color16} {
		env := report.Envelope{Data: report.Summary{
			Counts:          []report.CountRow{{Category: "hosts", N: 12}},
			FailedChecks:    []report.StageCount{{Stage: "asn", N: 2}},
			Deferred:        []report.StageCount{{Stage: "shodan", N: 1}},
			Findings:        headlineRows(),
			Candidates:      []report.CandidateRow{candidateRow("x.org", "-d x.org", 1)},
			CandidatesTotal: 1,
			Changes:         &report.Changes{Findings: headlineRows()[:1]},
		}}
		out := writeSummary(d, env)
		for _, w := range []string{
			d.Bold("Summary") + "\n",
			d.Bold("Failed checks (retried on the next run; --debug shows each failure)") + "\n",
			d.Bold("Deferred to the next run") + "\n",
			d.Bold("Findings (high and medium)") + "\n",
			d.Bold("Candidates worth promoting (high confidence)") + "\n",
			d.Bold("Since last run") + "\n",
			d.Bold("New findings (high and medium)") + "\n",
			"  " + d.Value(palette.Severity, "high") + " exposed-admin",
			"  " + d.Value(palette.Severity, "medium") + " banner",
		} {
			if !strings.Contains(out, w) {
				t.Errorf("depth %d: missing %q in\n%q", d, w, out)
			}
		}
		rest := out
		for _, s := range []string{d.Value(palette.Severity, "high"), d.Value(palette.Severity, "medium"), d.Bold("")[:4], "\x1b[0m"} {
			rest = strings.ReplaceAll(rest, s, "")
		}
		if strings.Contains(rest, "\x1b") {
			t.Errorf("depth %d: something besides headings and badges is styled: %q", d, rest)
		}
		// A badge pads its text, so compare the words.
		if got, want := strings.Fields(stripEscapes(out)), strings.Fields(writeSummary(palette.None, env)); !slices.Equal(got, want) {
			t.Errorf("depth %d: the coloured text differs from the plain\n got %q\nwant %q", d, got, want)
		}
	}
}

// At most the rows given are listed, and the overflow line counts the rest of
// the total. A total equal to the list has no overflow line.
func TestWriteSummary_CandidatesOverTheCap(t *testing.T) {
	t.Parallel()
	var rows []report.CandidateRow
	for i := range 20 {
		v := string(rune('a'+i)) + ".org"
		rows = append(rows, candidateRow(v, v, 2))
	}
	rows[0] = report.CandidateRow{Kind: "netblock", Value: "198.51.100.0/24", Sources: []string{"crtsh"}, EvidenceCount: 3, Confidence: "high", Promote: "--cidr 198.51.100.0/24"}
	out := writeSummary(palette.None, withData(report.Summary{Candidates: rows, CandidatesTotal: 22}))
	for _, w := range []string{
		"  198.51.100.0/24  3 evidence (crtsh)  promote: --cidr 198.51.100.0/24\n",
		"  t.org  2 evidence (crtsh;whoisxml)  promote: t.org\n",
		"  and 2 more in candidates.csv\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
	if strings.Contains(out, "u.org") {
		t.Errorf("a row past the list was printed:\n%s", out)
	}
	out = writeSummary(palette.None, withData(report.Summary{Candidates: rows, CandidatesTotal: 20}))
	if strings.Contains(out, "more in candidates.csv") {
		t.Errorf("overflow line with nothing over:\n%s", out)
	}
	// A total below the list (never written by the runner) adds no line either.
	out = writeSummary(palette.None, withData(report.Summary{Candidates: rows, CandidatesTotal: 3}))
	if strings.Contains(out, "more in candidates.csv") {
		t.Errorf("overflow line for a total below the list:\n%s", out)
	}
}

// With no candidates listed there is no block, whatever the total says.
func TestWriteSummary_NoCandidateBlock(t *testing.T) {
	t.Parallel()
	out := writeSummary(palette.None, withData(report.Summary{Counts: []report.CountRow{{Category: "hosts", N: 1}}, CandidatesTotal: 5}))
	if strings.Contains(out, "andidates") {
		t.Errorf("candidate block with no candidates:\n%s", out)
	}
}

// A candidate with no sources has empty parentheses; each source joins with ;.
func TestWriteSummary_CandidateSources(t *testing.T) {
	t.Parallel()
	out := writeSummary(palette.None, withData(report.Summary{Candidates: []report.CandidateRow{
		{Value: "a.org", Sources: []string{"x", "y", "z"}, EvidenceCount: 3, Promote: "-d a.org"},
		{Value: "b.org", EvidenceCount: 1, Promote: "-d b.org"},
	}, CandidatesTotal: 2}))
	for _, w := range []string{"  a.org  3 evidence (x;y;z)  promote: -d a.org\n", "  b.org  1 evidence ()  promote: -d b.org\n"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in\n%s", w, out)
		}
	}
}

// The block ends the summary and has seven lines, zeros included. Returned
// records count with the new ones, and a kind it does not count is left out.
func TestWriteSummary_SinceLastRun(t *testing.T) {
	t.Parallel()
	env := withData(report.Summary{
		Counts:     []report.CountRow{{Category: "hosts", N: 12}},
		Candidates: []report.CandidateRow{candidateRow("x.org", "-d x.org", 1)},
		Deferred:   []report.StageCount{{Stage: "shodan", N: 4}},
		Changes: &report.Changes{
			Counts: []report.ChangeCount{
				{Kind: "finding", Change: "gone", N: 3},
				{Kind: "finding", Change: "new", N: 1},
				{Kind: "hostname", Change: "new", N: 2},
				{Kind: "hostname", Change: "returned", N: 1},
				{Kind: "url", Change: "new", N: 40}, // not one the block counts
				{Kind: "web service", Change: "new", N: 1},
				{Kind: "open port", Change: "returned", N: 5},
				{Kind: "address", Change: "gone", N: 9}, // gone is shown for findings only
			},
			Findings: []report.FindingRow{{Severity: "medium", Category: "certificates", Target: "https://a.example.com", Detail: strPtr("expired certificate")}},
		},
	})
	out := writeSummary(palette.None, env)
	want := "Since last run\n" +
		"  new hostnames    3\n" +
		"  new addresses    0\n" +
		"  new web services 1\n" +
		"  new open ports   5\n" +
		"  new candidates   0\n" +
		"  new findings     1\n" +
		"  gone findings    3\n" +
		"New findings (high and medium)\n" +
		"  medium   certificates https://a.example.com - expired certificate\n"
	if !strings.HasSuffix(out, want) {
		t.Errorf("block\n got %q\nwant suffix %q", out, want)
	}
	if strings.Contains(out, "urls") {
		t.Errorf("an uncounted kind is in the summary:\n%s", out)
	}
	for _, before := range []string{"Candidates worth promoting", "Deferred to the next run"} {
		if i := strings.Index(out, before); i < 0 || i > strings.Index(out, "Since last run") {
			t.Errorf("%q is not before the block:\n%s", before, out)
		}
	}
}

// A first run has no block; a run with changes of none still says so.
func TestWriteSummary_SinceLastRunPresence(t *testing.T) {
	t.Parallel()
	if out := writeSummary(palette.None, withData(report.Summary{})); strings.Contains(out, "Since last run") {
		t.Errorf("a first run has a block:\n%s", out)
	}
	out := writeSummary(palette.None, withData(report.Summary{Changes: &report.Changes{}}))
	if want := "Summary\nSince last run\n  new hostnames    0\n"; !strings.HasPrefix(out, want) || strings.Contains(out, "New findings") {
		t.Errorf("an empty block:\n%s", out)
	}
	if n := strings.Count(out, "\n  "); n != 7 {
		t.Errorf("%d lines in the empty block, want 7:\n%s", n, out)
	}
}

// Target-supplied text is sanitised in every place.
func TestWriteSummary_Sanitises(t *testing.T) {
	t.Parallel()
	evil := "x\x1b[2J\x1b]0;pwn\x07y\u202ez\nnext\r"
	row := report.FindingRow{Severity: "high", Category: evil, Target: evil, Detail: &evil}
	env := report.Envelope{Data: report.Summary{
		Counts:       []report.CountRow{{Category: evil, N: 1}},
		FailedChecks: []report.StageCount{{Stage: evil, N: 1}},
		Deferred:     []report.StageCount{{Stage: evil, N: 1}},
		Findings:     []report.FindingRow{row},
		Candidates:   []report.CandidateRow{{Value: evil, Sources: []string{evil, evil}, Promote: evil}},
		Notes:        []string{evil},
		Changes:      &report.Changes{Findings: []report.FindingRow{row}},
	}}
	for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
		rest := stripEscapes(writeSummary(d, env))
		for _, bad := range []string{"\x1b", "\x07", "\u202e", "\r", "[2J", "]0;pwn"} {
			if strings.Contains(rest, bad) {
				t.Errorf("depth %d: %q reached the output:\n%q", d, bad, rest)
			}
		}
	}
}

// The summary is written in one call, ends in one newline and writes nothing
// but text.
func TestWriteSummary_OneWriteOneNewline(t *testing.T) {
	t.Parallel()
	var c countingWriter
	report.WriteSummary(&c, palette.None, withData(report.Summary{Counts: []report.CountRow{{Category: "hosts", N: 1}}}))
	if c.writes != 1 {
		t.Errorf("%d writes, want 1", c.writes)
	}
	if s := c.buf.String(); !strings.HasSuffix(s, "\n") || strings.HasSuffix(s, "\n\n") {
		t.Errorf("trailing newlines: %q", s)
	}
}

type countingWriter struct {
	buf    bytes.Buffer
	writes int
}

func (c *countingWriter) Write(p []byte) (int, error) { c.writes++; return c.buf.Write(p) }

// The summary does not change the envelope it is given.
func TestWriteSummary_LeavesTheEnvelopeAlone(t *testing.T) {
	t.Parallel()
	env := secretEnvelope()
	writeSummary(palette.None, env)
	if !reflect.DeepEqual(env, secretEnvelope()) {
		t.Error("WriteSummary changed the envelope")
	}
}
