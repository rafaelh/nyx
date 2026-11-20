package report_test

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/testkit"
)

// termSummary is the summary on a terminal of the given depth and width.
func termSummary(d palette.Depth, width int, env report.Envelope) string {
	var buf bytes.Buffer
	report.WriteSummary(&buf, termStream(d, width), env)
	return buf.String()
}

// richEnvelope has something in every block, with text long enough to need wrapping at 60 columns
// but no unbreakable token that is wider than the space it has.
func richEnvelope() report.Envelope {
	long := "the login page of the administration console answers with a form that asks for a username and a password and sets no cookie"
	rows := []report.FindingRow{
		{Severity: "high", Category: "exposed-admin", Target: "https://admin.example.com/login", Detail: &long},
		{Severity: "medium", Category: "banner", Target: "10.0.0.1:21", Detail: new("ftp")},
		{Severity: "high", Category: "takeover", Target: "a dangling record on the shared hosting platform of the supplier", Detail: &long},
	}
	return report.Envelope{
		Data: report.Summary{
			Counts:        []report.CountRow{{Category: "hosts", N: 12}, {Category: "open ports", N: 5}, {Category: "urls", N: 3400}},
			FailedChecks:  []report.StageCount{{Stage: "asn", N: 2}},
			Deferred:      []report.StageCount{{Stage: "shodan", N: 41}},
			NotConfigured: []report.StageReason{{Stage: "ports", Reason: "passive-only"}},
			Findings:      rows,
			Candidates: []report.CandidateRow{
				{Kind: "root", Value: "x.example.org", Sources: []string{"crtsh", "whoisxml", "securitytrails", "certspotter", "hackertarget"}, EvidenceCount: 12, Confidence: "high", Promote: "-d x.example.org"},
				{Kind: "root", Value: "an organisation name with several words in it", Sources: []string{"whoisxml"}, EvidenceCount: 3, Confidence: "high", Promote: "--org an organisation name"},
			},
			CandidatesTotal:       9,
			UnconfirmedRiskyPorts: 3,
			Notes:                 []string{"shodan: the search of 198.51.100.0/24 was truncated at 10 pages, so the open ports of the later pages are not in this summary"},
			Changes: &report.Changes{
				Counts:   []report.ChangeCount{{Kind: "hostname", Change: "new", N: 4}, {Kind: "finding", Change: "gone", N: 12}},
				Findings: rows[:1],
			},
		},
		Meta: report.Meta{DeadlineExceeded: true, ChecksCompleted: 700, ChecksCancelled: 20},
	}
}

func linesOf(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }

// indexOfLine is the index of the first line of lines equal to want, or -1.
func indexOfLine(lines []string, want string) int {
	for i, l := range lines {
		if l == want {
			return i
		}
	}
	return -1
}

// Every heading, the first included, is bold in the info colour on a coloured terminal and plain
// on an uncoloured one, with a rule of the layout width beneath it: ─ in the separator colour, or
// - with no colour.
func TestSummaryTerminalHeadings(t *testing.T) {
	t.Parallel()
	headings := []string{"Summary", "Failed checks (retried on the next run; --debug shows each failure)", "Deferred to the next run",
		"Findings (high and medium)", "Candidates worth promoting (high confidence)", "Since last run", "New findings (high and medium)"}
	for _, d := range []palette.Depth{palette.None, palette.TrueColor, palette.Color256, palette.Color16} {
		lines := linesOf(termSummary(d, 80, richEnvelope()))
		rule := strings.Repeat("-", 80)
		if d != palette.None {
			rule = d.Text(palette.Chrome, "SEPARATOR", strings.Repeat("─", 80))
		}
		for _, h := range headings {
			i := indexOfLine(lines, d.BoldText(palette.Semantic, "info", h))
			if i < 0 || i+1 >= len(lines) || lines[i+1] != rule {
				t.Errorf("depth %d: heading %q has no rule under it (line %d)\n%s", d, h, i, strings.Join(lines, "\n"))
			}
		}
	}
}

// A heading wider than the layout width wraps at spaces; each continuation line is in the heading
// style, at column 0, and the rule follows the last line.
func TestSummaryTerminalHeadingWraps(t *testing.T) {
	t.Parallel()
	d := palette.TrueColor
	lines := linesOf(termSummary(d, 60, richEnvelope()))
	first := d.BoldText(palette.Semantic, "info", "Failed checks (retried on the next run; --debug shows each")
	if i := indexOfLine(lines, first); i < 0 {
		t.Fatalf("the heading did not wrap at 60 columns:\n%s", strings.Join(lines, "\n"))
	} else if lines[i+1] != d.BoldText(palette.Semantic, "info", "failure)") || lines[i+2] != d.Text(palette.Chrome, "SEPARATOR", strings.Repeat("─", 60)) {
		t.Errorf("continuation and rule: %q", lines[i+1:i+3])
	}
	// Uncoloured it is the same words at column 0 with no escape.
	for _, l := range linesOf(termSummary(palette.None, 60, richEnvelope())) {
		if strings.Contains(l, "\x1b") {
			t.Errorf("escape in %q", l)
		}
	}
}

// Count blocks keep their labels and have no header row; the numbers of one block are right-aligned
// in one column, which is as wide as the widest number.
func TestSummaryTerminalCounts(t *testing.T) {
	t.Parallel()
	env := report.Envelope{Data: report.Summary{
		Counts:       []report.CountRow{{Category: "hosts", N: 5}, {Category: "open ports", N: 1234}, {Category: "urls", N: 12}, {Category: "a very long category label", N: 1}},
		FailedChecks: []report.StageCount{{Stage: "asn", N: 7}, {Stage: "dns", N: 20}},
		Deferred:     []report.StageCount{{Stage: "shodan", N: 100}},
		Changes:      &report.Changes{Counts: []report.ChangeCount{{Kind: "hostname", Change: "new", N: 4000}}},
	}}
	out := termSummary(palette.None, 100, env)
	line := func(label string, labelWidth int, n string, numWidth int) string {
		return "  " + label + strings.Repeat(" ", labelWidth-len(label)) + " " + strings.Repeat(" ", numWidth-len(n)) + n + "\n"
	}
	for _, want := range []string{
		line("hosts", 26, "5", 4),
		line("open ports", 26, "1234", 4),
		line("urls", 26, "12", 4),
		line("a very long category label", 26, "1", 4),
		line("asn", 16, "7", 2),
		line("dns", 16, "20", 2),
		line("shodan", 16, "100", 3),
		line("new hostnames", 16, "4000", 4),
		line("gone findings", 16, "0", 4),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "CATEGORY") || strings.Contains(out, "COUNT") {
		t.Errorf("a count block has a header row:\n%s", out)
	}
}

// The findings table has the columns SEVERITY, CATEGORY, TARGET and DETAIL, an indent of 2, a gap
// of 2, no border characters and no trailing spaces; rows keep their order.
func TestSummaryTerminalFindingsTable(t *testing.T) {
	t.Parallel()
	env := withData(report.Summary{Findings: headlineRows()})
	got := termSummary(palette.None, 100, env)
	want := "Summary\n" + strings.Repeat("-", 100) + "\n" +
		"Findings (high and medium)\n" + strings.Repeat("-", 100) + "\n" +
		"  SEVERITY  CATEGORY       TARGET                       DETAIL\n" +
		"  high      exposed-admin  https://a.example.com/admin  login page\n" +
		"  medium    banner         10.0.0.1:21                  ftp\n"
	if got != want {
		t.Errorf("findings table\n got %q\nwant %q", got, want)
	}
	for _, l := range linesOf(got) {
		if strings.HasSuffix(l, " ") || strings.ContainsAny(l, "|+│┌┐└┘├┤┬┴┼") {
			t.Errorf("trailing space or border in %q", l)
		}
	}
}

// The header row is bold in the timestamp colour on a coloured terminal, and the severity is the
// badge; uncoloured, neither has an escape.
func TestSummaryTerminalTableStyle(t *testing.T) {
	t.Parallel()
	for _, d := range depths {
		out := termSummary(d, 100, withData(report.Summary{Findings: headlineRows(), Candidates: []report.CandidateRow{candidateRow("x.org", "-d x.org", 2)}, CandidatesTotal: 1}))
		for _, h := range []string{"SEVERITY", "CATEGORY", "TARGET", "DETAIL", "VALUE", "EVIDENCE", "SOURCES", "PROMOTE"} {
			if !strings.Contains(out, d.BoldText(palette.Chrome, "TIMESTAMP", h)) {
				t.Errorf("depth %d: header %s is not bold in the timestamp colour", d, h)
			}
		}
		for _, sev := range []string{"high", "medium"} {
			if !strings.Contains(out, d.Value(palette.Severity, sev)) {
				t.Errorf("depth %d: no %s badge", d, sev)
			}
		}
		testkit.OnlyPaletteEscapes(t, d, out)
	}
	if out := termSummary(palette.None, 100, richEnvelope()); strings.Contains(out, "\x1b") {
		t.Error("an escape in an uncoloured terminal summary")
	}
}

// DETAIL is left out when no row has one: nil and "" count as none.
func TestSummaryTerminalDetailColumnDropped(t *testing.T) {
	t.Parallel()
	rows := []report.FindingRow{
		{Severity: "high", Category: "a", Target: "t1"},
		{Severity: "medium", Category: "b", Target: "t2", Detail: new("")},
	}
	out := termSummary(palette.None, 80, withData(report.Summary{Findings: rows}))
	if strings.Contains(out, "DETAIL") {
		t.Errorf("DETAIL with no detail:\n%s", out)
	}
	if !strings.Contains(out, "  SEVERITY  CATEGORY  TARGET\n  high      a         t1\n  medium    b         t2\n") {
		t.Errorf("table without DETAIL:\n%s", out)
	}
	rows[1].Detail = new("x")
	if out := termSummary(palette.None, 80, withData(report.Summary{Findings: rows})); !strings.Contains(out, "DETAIL") {
		t.Errorf("DETAIL dropped though a row has one:\n%s", out)
	}
}

// columnOf is the cell index at which the header of the table starts the column, in a plain line.
func columnOf(lines []string, header string) int {
	for _, l := range lines {
		if i := strings.Index(l, header); i >= 0 && strings.HasPrefix(strings.TrimSpace(l), "SEVERITY") {
			return i
		}
	}
	return -1
}

// At 80 columns a long DETAIL wraps within its column before TARGET does, a hostname in TARGET is
// never broken, and DETAIL stays aligned on every row, for both findings tables.
func TestSummaryTerminalFindingsWrapping(t *testing.T) {
	t.Parallel()
	long := strings.TrimSpace(strings.Repeat("a long detail of words ", 10))
	host := "https://" + strings.Repeat("h", 10) + ".example.com"
	rows := []report.FindingRow{
		{Severity: "high", Category: "exposed-admin", Target: "https://a.example.com/admin", Detail: &long},
		{Severity: "medium", Category: "banner", Target: host, Detail: &long},
	}
	env := withData(report.Summary{Findings: rows, Changes: &report.Changes{Findings: rows}})
	lines := linesOf(termSummary(palette.None, 80, env))
	for _, tbl := range []string{"Findings (high and medium)", "New findings (high and medium)"} {
		start := indexOfLine(lines, tbl)
		if start < 0 {
			t.Fatalf("no %q:\n%s", tbl, strings.Join(lines, "\n"))
		}
		block := lines[start+2:]
		col := columnOf(block, "DETAIL")
		if col < 0 {
			t.Fatalf("no DETAIL header after %q", tbl)
		}
		// Every line of the table, up to the next heading, is within 80 cells except one holding the
		// whole long target; DETAIL's cells start at col.
		end := len(block)
		for i, l := range block {
			if strings.HasPrefix(l, "-") {
				end = i - 1
				break
			}
		}
		var detail []string
		for _, l := range block[1:end] {
			if len(l) > col {
				detail = append(detail, strings.TrimSpace(l[col:]))
			}
		}
		if len(detail) < 5 {
			t.Errorf("%s: the detail did not wrap (%d lines):\n%s", tbl, len(detail), strings.Join(block[:end], "\n"))
		}
		joined := strings.Join(block[:end], "\n")
		if !strings.Contains(joined, "https://a.example.com/admin") || !strings.Contains(joined, host) {
			t.Errorf("%s: a target was broken:\n%s", tbl, joined)
		}
		// The first row's target is intact on one line: it fits, so TARGET did not wrap.
		if strings.Count(joined, "https://a.example.com/admin") != 1 {
			t.Errorf("%s: the target wrapped:\n%s", tbl, joined)
		}
		for _, l := range block[:end] {
			if cells(l) > 80 && !strings.Contains(l, host) {
				t.Errorf("%s: %d cells in %q", tbl, cells(l), l)
			}
		}
	}
}

// When DETAIL has shrunk as far as it goes, TARGET wraps, at spaces.
func TestSummaryTerminalTargetWrapsAfterDetail(t *testing.T) {
	t.Parallel()
	target := strings.TrimSpace(strings.Repeat("a target with words ", 8))
	rows := []report.FindingRow{{Severity: "high", Category: "exposed", Target: target, Detail: new("a detail that is quite a bit longer than ten cells")}}
	lines := linesOf(termSummary(palette.None, 70, withData(report.Summary{Findings: rows})))
	var rowLines []string
	for i, l := range lines {
		if strings.HasPrefix(l, "  SEVERITY") {
			rowLines = lines[i+1:]
		}
	}
	if len(rowLines) < 3 {
		t.Fatalf("lines:\n%s", strings.Join(lines, "\n"))
	}
	col := strings.Index(lines[len(lines)-len(rowLines)-1], "DETAIL")
	for _, l := range rowLines {
		if len(l) > col && l[col-2:col] != "  " {
			t.Errorf("DETAIL is not aligned: %q", l)
		}
		if cells(l) > 70 {
			t.Errorf("%d cells in %q", cells(l), l)
		}
	}
	// TARGET wrapped at spaces: its words come back in order down its column.
	header := lines[len(lines)-len(rowLines)-1]
	from := strings.Index(header, "TARGET")
	var words []string
	for _, l := range rowLines {
		words = append(words, strings.Fields(l[from:col-2])...)
	}
	if strings.Join(words, " ") != target {
		t.Errorf("TARGET's words = %q, want %q", strings.Join(words, " "), target)
	}
}

// The candidates table has the columns VALUE, EVIDENCE, SOURCES and PROMOTE; EVIDENCE is the bare
// count, SOURCES are joined with ", " and PROMOTE has no label; the overflow line follows it.
func TestSummaryTerminalCandidatesTable(t *testing.T) {
	t.Parallel()
	env := withData(report.Summary{
		Candidates:      []report.CandidateRow{candidateRow("x.org", "-d x.org", 2), candidateRow("y.org", "-d y.org", 15)},
		CandidatesTotal: 5,
	})
	got := termSummary(palette.None, 100, env)
	want := "Candidates worth promoting (high confidence)\n" + strings.Repeat("-", 100) + "\n" +
		"  VALUE  EVIDENCE  SOURCES          PROMOTE\n" +
		"  x.org  2         crtsh, whoisxml  -d x.org\n" +
		"  y.org  15        crtsh, whoisxml  -d y.org\n" +
		"  and 3 more in candidates.csv\n"
	if !strings.HasSuffix(got, want) {
		t.Errorf("candidates\n got %q\nwant suffix %q", got, want)
	}
	if strings.Contains(got, "promote:") || strings.Contains(got, "evidence (") {
		t.Errorf("today's layout is still there:\n%s", got)
	}
}

// At 60 columns SOURCES wraps first, after commas, and VALUE does not wrap while SOURCES can.
func TestSummaryTerminalCandidatesWrapping(t *testing.T) {
	t.Parallel()
	row := report.CandidateRow{Value: "x.example.org", Sources: []string{"crtsh", "whoisxml", "securitytrails", "certspotter", "hackertarget", "virustotal"},
		EvidenceCount: 9, Promote: "-d x.example.org"}
	lines := linesOf(termSummary(palette.None, 60, withData(report.Summary{Candidates: []report.CandidateRow{row}, CandidatesTotal: 1})))
	i := indexOfLine(lines, "Candidates worth promoting (high confidence)")
	if i < 0 {
		t.Fatalf("no candidates heading:\n%s", strings.Join(lines, "\n"))
	}
	block := lines[i+2:]
	if len(block) < 3 {
		t.Fatalf("the sources did not wrap:\n%s", strings.Join(lines, "\n"))
	}
	col := strings.Index(block[0], "SOURCES")
	for _, l := range block {
		if cells(l) > 60 {
			t.Errorf("%d cells in %q", cells(l), l)
		}
	}
	if !strings.HasPrefix(block[1], "  x.example.org") {
		t.Errorf("VALUE wrapped: %q", block[1])
	}
	if !strings.HasSuffix(strings.TrimRight(block[1][col:], " "), ",") && !strings.Contains(block[1][col:], ",") {
		t.Errorf("SOURCES did not break after a comma: %q", block[1])
	}
}

// The risky-ports line, the notes and the deadline line wrap to the width, with continuation lines
// indented 2 under the text, and keep their words.
func TestSummaryTerminalOtherLinesWrap(t *testing.T) {
	t.Parallel()
	env := richEnvelope()
	lines := linesOf(termSummary(palette.None, 60, env))
	text := strings.Join(lines, "\n")
	note := env.Data.Notes[0]
	i := indexOfLine(lines, "  shodan: the search of 198.51.100.0/24 was truncated at 10")
	if i < 0 {
		t.Fatalf("the note did not wrap at 60 columns:\n%s", text)
	}
	var got []string
	for _, l := range lines[i:] {
		if !strings.HasPrefix(l, "  ") || strings.HasPrefix(l, "   ") {
			break
		}
		got = append(got, strings.TrimPrefix(l, "  "))
		if strings.HasSuffix(l, "summary") {
			break
		}
	}
	if strings.Join(got, " ") != note {
		t.Errorf("the note's words:\n got %q\nwant %q", strings.Join(got, " "), note)
	}
	if wide := termSummary(palette.None, 80, env); !strings.Contains(wide, "  Stopped by the deadline: 700 checks completed, 20 cancelled\n") {
		t.Errorf("deadline line missing:\n%s", wide)
	}
	if !strings.Contains(text, "  Stopped by the deadline: 700 checks completed, 20\n  cancelled\n") {
		t.Errorf("the deadline line did not wrap with its continuation at 2:\n%s", text)
	}
	// A deadline line wider than the space wraps too.
	narrow := report.Envelope{Data: report.Summary{}, Meta: report.Meta{DeadlineExceeded: true, ChecksCompleted: 700000000, ChecksCancelled: 20000000000}}
	for _, l := range linesOf(termSummary(palette.None, 60, narrow)) {
		if cells(l) > 60 {
			t.Errorf("%d cells in %q", cells(l), l)
		}
	}
	for _, l := range got {
		if cells("  "+l) > 60 {
			t.Errorf("%d cells in %q", cells(l), l)
		}
	}
}

// A summary with no findings or candidates shows neither the heading nor a table.
func TestSummaryTerminalEmptyTables(t *testing.T) {
	t.Parallel()
	out := termSummary(palette.None, 80, withData(report.Summary{
		Counts: []report.CountRow{{Category: "hosts", N: 1}}, Findings: []report.FindingRow{}, Candidates: []report.CandidateRow{},
		Changes: &report.Changes{},
	}))
	for _, bad := range []string{"Findings", "New findings", "Candidates", "SEVERITY", "VALUE", "Failed", "Deferred"} {
		if strings.Contains(out, bad) {
			t.Errorf("%q in\n%s", bad, out)
		}
	}
	if want := "Summary\n" + strings.Repeat("-", 80) + "\n  hosts            1\n"; !strings.HasPrefix(out, want) {
		t.Errorf("summary\n got %q\nwant prefix %q", out, want)
	}
	if got := termSummary(palette.None, 80, report.Envelope{}); got != "Summary\n"+strings.Repeat("-", 80)+"\n" {
		t.Errorf("the zero envelope = %q", got)
	}
}

// The summary is one write that ends in one newline, and reads the width once.
func TestSummaryTerminalOneWriteAndOneWidthRead(t *testing.T) {
	t.Parallel()
	var c countingWriter
	var reads atomic.Int32
	s := layout.Stream{Terminal: true, Width: func() int { reads.Add(1); return 80 }}
	report.WriteSummary(&c, s, richEnvelope())
	if c.writes != 1 {
		t.Errorf("%d writes, want 1", c.writes)
	}
	if out := c.buf.String(); !strings.HasSuffix(out, "\n") || strings.HasSuffix(out, "\n\n") {
		t.Errorf("trailing newlines: %q", out[max(0, len(out)-20):])
	}
	if reads.Load() != 1 {
		t.Errorf("the width was read %d times, want once", reads.Load())
	}
}

// Every line of the summary is at most the layout width, at each width, for a fixture with no
// unbreakable token wider than its space.
func TestSummaryTerminalFitsTheWidth(t *testing.T) {
	t.Parallel()
	for _, width := range []int{80, 100, 120} {
		for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
			out := termSummary(d, width, richEnvelope())
			for _, l := range linesOf(out) {
				if cells(l) > width {
					t.Errorf("width %d depth %d: %d cells in %q", width, d, cells(l), l)
				}
			}
		}
	}
}

// Text from a target is sanitised before it is laid out, in the heading-free lines and in each
// table, with the control sequences placed where the text wraps.
func TestSummaryTerminalSanitises(t *testing.T) {
	t.Parallel()
	evil := "x\x1b[2J\x1b]0;pwn\x07y\u202ez\nnext\r"
	for pad := 20; pad < 80; pad += 3 {
		filler := strings.Repeat("a", pad) + " "
		text := filler + evil + " " + filler + evil + filler
		row := report.FindingRow{Severity: "high", Category: evil, Target: text, Detail: &text}
		env := report.Envelope{Data: report.Summary{
			Counts:       []report.CountRow{{Category: evil, N: 1}},
			FailedChecks: []report.StageCount{{Stage: evil, N: 1}},
			Findings:     []report.FindingRow{row},
			Candidates:   []report.CandidateRow{{Value: text, Sources: []string{text, evil}, Promote: evil}},
			Notes:        []string{text},
			Changes:      &report.Changes{Findings: []report.FindingRow{row}},
		}}
		for _, d := range []palette.Depth{palette.None, palette.TrueColor} {
			testkit.OnlyPaletteEscapes(t, d, termSummary(d, 60, env))
		}
	}
}
