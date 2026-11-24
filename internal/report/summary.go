package report

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// Summary supplies human recon output and the JSON envelope's ordered data keys. Adding keys is
// compatible; removing, renaming or changing their types breaks the interface. WriteEnvelope
// normalises lists to non-nil values.
type Summary struct {
	Engagement            string         `json:"engagement"`
	Directory             string         `json:"directory"`
	Counts                []CountRow     `json:"counts"`
	FailedChecks          []StageCount   `json:"failed_checks"`
	Deferred              []StageCount   `json:"deferred"`
	NotConfigured         []StageReason  `json:"not_configured"`
	Findings              []FindingRow   `json:"findings"`
	Candidates            []CandidateRow `json:"candidates"`
	CandidatesTotal       int            `json:"candidates_total"`
	UnconfirmedRiskyPorts int            `json:"unconfirmed_risky_ports"`
	Notes                 []string       `json:"notes"`
	Changes               *Changes       `json:"changes"`
}

// CountRow is how many records a category holds.
type CountRow struct {
	Category string `json:"category"`
	N        int    `json:"n"`
}

// StageCount is a number of checks of one stage.
type StageCount struct {
	Stage string `json:"stage"`
	N     int    `json:"n"`
}

// StageReason is a stage that did not run, and why.
type StageReason struct {
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
}

// FindingRow is a finding of high or medium severity. Detail is nil when it has none.
type FindingRow struct {
	Severity string  `json:"severity"`
	Category string  `json:"category"`
	Target   string  `json:"target"`
	Detail   *string `json:"detail"`
}

// CandidateRow is a high-confidence candidate and the input that promotes it.
type CandidateRow struct {
	Kind          string   `json:"kind"`
	Value         string   `json:"value"`
	Sources       []string `json:"sources"`
	EvidenceCount int      `json:"evidence_count"`
	Confidence    string   `json:"confidence"`
	Promote       string   `json:"promote"`
}

// Changes summarises differences from the previous run; first runs use nil.
type Changes struct {
	Counts   []ChangeCount `json:"counts"`
	Findings []FindingRow  `json:"findings"`
}

// ChangeCount is how many records of a kind changed in one way.
type ChangeCount struct {
	Kind   string `json:"kind"`
	Change string `json:"change"`
	N      int    `json:"n"`
}

// WriteSummary formats counts, stage notes, partial-work details, findings, candidates and
// optional changes in their supplied order. It sanitises target text and writes once with a
// final newline. Plain streams use lines; terminals use aligned counts, tables and wrapped text
// with ruled headings. Width is captured once for consistent alignment.
func WriteSummary(w io.Writer, st layout.Stream, env Envelope) {
	if !st.Terminal {
		writePlainSummary(w, st.Depth, env)
		return
	}
	writeTerminalSummary(w, st, env)
}

// writePlainSummary preserves non-terminal summary formatting.
func writePlainSummary(w io.Writer, d palette.Depth, env Envelope) {
	var b strings.Builder
	s := env.Map(sanitize.Text).Data
	b.WriteString(d.Bold("Summary"))
	rows := make([]labelled, 0, len(s.Counts))
	for _, c := range s.Counts {
		rows = append(rows, labelled{c.Category, c.N})
	}
	writeLabelled(&b, rows)
	if s.UnconfirmedRiskyPorts > 0 {
		fmt.Fprintf(&b, "\n  %d risky ports reported by Shodan, unconfirmed", s.UnconfirmedRiskyPorts)
	}
	for _, n := range s.Notes {
		b.WriteString("\n  " + n)
	}
	if env.Meta.DeadlineExceeded {
		fmt.Fprintf(&b, "\n  Stopped by the deadline: %d checks completed, %d cancelled", env.Meta.ChecksCompleted, env.Meta.ChecksCancelled)
	}
	for _, blk := range []struct {
		heading string
		rows    []StageCount
	}{
		{"Failed checks (retried on the next run; --debug shows each failure)", s.FailedChecks},
		{"Deferred to the next run", s.Deferred},
	} {
		if len(blk.rows) == 0 {
			continue
		}
		b.WriteString("\n" + d.Bold(blk.heading))
		rows = rows[:0]
		for _, r := range blk.rows {
			rows = append(rows, labelled{r.Stage, r.N})
		}
		writeLabelled(&b, rows)
	}
	writeFindingRows(&b, d, "Findings (high and medium)", s.Findings)
	if len(s.Candidates) > 0 {
		b.WriteString("\n" + d.Bold("Candidates worth promoting (high confidence)"))
		for _, c := range s.Candidates {
			fmt.Fprintf(&b, "\n  %s  %d evidence (%s)  promote: %s",
				c.Value, c.EvidenceCount, strings.Join(c.Sources, ";"), c.Promote)
		}
		if more := s.CandidatesTotal - len(s.Candidates); more > 0 {
			fmt.Fprintf(&b, "\n  and %d more in candidates.csv", more)
		}
	}
	if s.Changes != nil {
		writeSinceLastRun(&b, d, *s.Changes)
	}
	fmt.Fprintln(w, b.String())
}

// labelled pairs a count label with its value.
type labelled struct {
	label string
	n     int
}

// writeLabelled aligns values after labels with a minimum label width of 16 cells.
func writeLabelled(b *strings.Builder, rows []labelled) {
	width := 16
	for _, r := range rows {
		width = max(width, utf8.RuneCountInString(r.label))
	}
	for _, r := range rows {
		fmt.Fprintf(b, "\n  %-*s %d", width, r.label, r.n)
	}
}

// writeSinceLastRun reports new/returned entries, gone findings and new high/medium findings.
// Missing kinds or change types count as zero.
func writeSinceLastRun(b *strings.Builder, d palette.Depth, ch Changes) {
	b.WriteString("\n" + d.Bold("Since last run"))
	writeLabelled(b, changeCounts(ch))
	writeFindingRows(b, d, "New findings (high and medium)", ch.Findings)
}

// writeFindingRows writes a heading and one line per finding, or nothing when there are
// none.
func writeFindingRows(b *strings.Builder, d palette.Depth, heading string, rows []FindingRow) {
	if len(rows) == 0 {
		return
	}
	b.WriteString("\n" + d.Bold(heading))
	for _, r := range rows {
		fmt.Fprintf(b, "\n  %s %s %s", d.Value(palette.Severity, r.Severity), r.Category, r.Target)
		if r.Detail != nil && *r.Detail != "" {
			b.WriteString(" - " + *r.Detail)
		}
	}
}

// writeTerminalSummary writes the summary laid out for a terminal.
func writeTerminalSummary(w io.Writer, st layout.Stream, env Envelope) {
	st = st.Fixed() // so the whole summary has one width
	sum := env.Map(sanitize.Text).Data
	var b strings.Builder
	heading := func(text string) {
		for _, l := range layout.Heading(st, text, true) {
			b.WriteString(l + "\n")
		}
	}
	text := func(msg string) {
		for _, l := range layout.Hang("  ", layout.Plain(msg), st.Cols(), layout.Spaces) {
			b.WriteString(l + "\n")
		}
	}
	counts := func(rows []labelled) {
		for _, l := range countLines(rows) {
			b.WriteString(l + "\n")
		}
	}
	heading("Summary")
	rows := make([]labelled, 0, len(sum.Counts))
	for _, c := range sum.Counts {
		rows = append(rows, labelled{c.Category, c.N})
	}
	counts(rows)
	if sum.UnconfirmedRiskyPorts > 0 {
		text(fmt.Sprintf("%d risky ports reported by Shodan, unconfirmed", sum.UnconfirmedRiskyPorts))
	}
	for _, n := range sum.Notes {
		text(n)
	}
	if env.Meta.DeadlineExceeded {
		text(fmt.Sprintf("Stopped by the deadline: %d checks completed, %d cancelled", env.Meta.ChecksCompleted, env.Meta.ChecksCancelled))
	}
	for _, blk := range []struct {
		heading string
		rows    []StageCount
	}{
		{"Failed checks (retried on the next run; --debug shows each failure)", sum.FailedChecks},
		{"Deferred to the next run", sum.Deferred},
	} {
		if len(blk.rows) == 0 {
			continue
		}
		heading(blk.heading)
		rows = rows[:0]
		for _, r := range blk.rows {
			rows = append(rows, labelled{r.Stage, r.N})
		}
		counts(rows)
	}
	findingsTable(&b, st, heading, "Findings (high and medium)", sum.Findings)
	if len(sum.Candidates) > 0 {
		heading("Candidates worth promoting (high confidence)")
		b.WriteString(candidatesTable(st, sum.Candidates))
		if more := sum.CandidatesTotal - len(sum.Candidates); more > 0 {
			text(fmt.Sprintf("and %d more in candidates.csv", more))
		}
	}
	if sum.Changes != nil {
		heading("Since last run")
		counts(changeCounts(*sum.Changes))
		findingsTable(&b, st, heading, "New findings (high and medium)", sum.Changes.Findings)
	}
	_, _ = io.WriteString(w, b.String()) // a failed write of the summary has nowhere to be reported
}

// countLines aligns labels in at least 16 cells and right-aligns counts to the widest number.
func countLines(rows []labelled) []string {
	label, num := 16, 0
	nums := make([]string, len(rows))
	for i, r := range rows {
		label = max(label, layout.Measure(r.label))
		nums[i] = strconv.Itoa(r.n)
		num = max(num, len(nums[i]))
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = "  " + layout.PadRight(r.label, label) + " " + layout.PadLeft(nums[i], num)
	}
	return out
}

// findingsTable omits empty tables and adds DETAIL only when at least one row has details.
func findingsTable(b *strings.Builder, st layout.Stream, heading func(string), title string, rows []FindingRow) {
	if len(rows) == 0 {
		return
	}
	heading(title)
	b.WriteString(findingsTableText(st, rows))
}

// findingsTableText includes DETAIL only when a row needs it.
func findingsTableText(st layout.Stream, rows []FindingRow) string {
	withDetail := slices.ContainsFunc(rows, func(r FindingRow) bool { return r.Detail != nil && *r.Detail != "" })
	t := layout.Table{Indent: 2, Columns: []layout.Column{
		{Header: "SEVERITY"}, {Header: "CATEGORY"}, {Header: "TARGET", Wrap: layout.Spaces, Shrink: 2},
	}}
	if withDetail {
		t.Columns = append(t.Columns, layout.Column{Header: "DETAIL", Wrap: layout.Spaces, Shrink: 1})
	}
	for _, r := range rows {
		row := []layout.Cell{{badgeSpan(st, palette.Severity, r.Severity)}, layout.Plain(r.Category), layout.Plain(r.Target)}
		if withDetail {
			detail := ""
			if r.Detail != nil {
				detail = *r.Detail
			}
			row = append(row, layout.Plain(detail))
		}
		t.Rows = append(t.Rows, row)
	}
	return t.Render(st)
}

// candidatesTable displays value, evidence count, sources and promotion input.
func candidatesTable(st layout.Stream, rows []CandidateRow) string {
	t := layout.Table{Indent: 2, Columns: []layout.Column{
		{Header: "VALUE", Wrap: layout.Spaces, Shrink: 2}, {Header: "EVIDENCE"},
		{Header: "SOURCES", Wrap: layout.Commas, Shrink: 1}, {Header: "PROMOTE"},
	}}
	for _, c := range rows {
		t.Rows = append(t.Rows, []layout.Cell{layout.Plain(c.Value), layout.Plain(strconv.Itoa(c.EvidenceCount)),
			layout.Plain(strings.Join(c.Sources, ", ")), layout.Plain(c.Promote)})
	}
	return t.Render(st)
}

// changeCounts formats new/returned counts and gone findings for the changes block, treating
// absent counts as zero.
func changeCounts(ch Changes) []labelled {
	type key struct{ kind, change string }
	counts := make(map[key]int, len(ch.Counts))
	for _, c := range ch.Counts {
		counts[key{c.Kind, c.Change}] += c.N
	}
	rows := make([]labelled, 0, 7)
	for _, l := range []struct {
		heading, kind, change string
	}{
		{"new hostnames", kinds.LabelHostname, output.ChangeNew}, {"new addresses", kinds.LabelAddress, output.ChangeNew},
		{"new web services", kinds.LabelWebService, output.ChangeNew}, {"new open ports", kinds.LabelOpenPort, output.ChangeNew},
		{"new candidates", kinds.LabelCandidate, output.ChangeNew}, {"new findings", kinds.LabelFinding, output.ChangeNew},
		{"gone findings", kinds.LabelFinding, output.ChangeGone},
	} {
		n := counts[key{l.kind, l.change}]
		if l.change == output.ChangeNew {
			n += counts[key{l.kind, output.ChangeReturned}]
		}
		rows = append(rows, labelled{l.heading, n})
	}
	return rows
}
