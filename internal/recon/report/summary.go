package report

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/output"
	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/palette"
	"github.com/rafaelh/nyx/internal/term/sanitize"
)

// Summary supplies human recon output and the JSON envelope's ordered data keys. Adding keys is
// compatible; removing, renaming or changing their types breaks the interface. WriteEnvelope
// normalises lists to non-nil values.
type Summary struct {
	Engagement            string            `json:"engagement"`
	Directory             string            `json:"directory"`
	Counts                []CountRow        `json:"counts"`
	FailedJobs            []ProcedureCount  `json:"failed_jobs"`
	Deferred              []ProcedureCount  `json:"deferred"`
	NotConfigured         []ProcedureReason `json:"not_configured"`
	Findings              []FindingRow      `json:"findings"`
	Candidates            []CandidateRow    `json:"candidates"`
	CandidatesTotal       int               `json:"candidates_total"`
	UnconfirmedRiskyPorts int               `json:"unconfirmed_risky_ports"`
	HostsInScopeByAddress int               `json:"hosts_in_scope_by_address"`
	Notes                 []string          `json:"notes"`
	Changes               *Changes          `json:"changes"`
}

// CountRow is how many records a category holds.
type CountRow struct {
	Category string `json:"category"`
	N        int    `json:"n"`
}

// ProcedureCount is a number of jobs of one procedure.
type ProcedureCount struct {
	Procedure string `json:"procedure"`
	N         int    `json:"n"`
}

// ProcedureReason is a procedure that did not run, and why.
type ProcedureReason struct {
	Procedure string `json:"procedure"`
	Reason    string `json:"reason"`
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

// WriteSummary formats counts, procedure notes, partial-work details, findings, candidates and
// optional changes in their supplied order. It sanitises target text and writes once with a
// final newline. Plain streams use lines; terminals use aligned counts, tables and wrapped text
// with ruled headings. Width is captured once for consistent alignment.
func WriteSummary(w io.Writer, st layout.Stream, env Envelope) {
	env = env.Map(sanitize.Text)
	var b strings.Builder
	if !st.Terminal {
		writeSummaryBlocks(&plainSummary{b: &b, d: st.Depth}, env)
		fmt.Fprintln(w, b.String())
		return
	}
	writeSummaryBlocks(&terminalSummary{b: &b, st: st.Fixed()}, env) // Fixed: the whole summary has one width
	_, _ = io.WriteString(w, b.String())                             // a failed write of the summary has nowhere to be reported
}

// summaryWriter lays out the summary's blocks for one kind of stream.
type summaryWriter interface {
	heading(text string)
	text(msg string)
	counts(rows []labelled)
	findings(title string, rows []FindingRow) // writes nothing when there are no rows
	candidates(rows []CandidateRow)
}

// writeSummaryBlocks walks the summary's blocks in order, so both layouts show the same ones.
func writeSummaryBlocks(o summaryWriter, env Envelope) {
	s := env.Data
	o.heading("Summary")
	rows := make([]labelled, 0, len(s.Counts))
	for _, c := range s.Counts {
		rows = append(rows, labelled{c.Category, c.N})
	}
	o.counts(rows)
	if s.UnconfirmedRiskyPorts > 0 {
		o.text(fmt.Sprintf("%d risky ports reported by Shodan, unconfirmed", s.UnconfirmedRiskyPorts))
	}
	if s.HostsInScopeByAddress > 0 {
		o.text(layout.Count(s.HostsInScopeByAddress, "host", "hosts") + " in scope by address")
	}
	for _, n := range s.Notes {
		o.text(n)
	}
	if env.Meta.DeadlineExceeded {
		o.text(fmt.Sprintf("Stopped by the deadline: %d jobs completed, %d cancelled", env.Meta.JobsCompleted, env.Meta.JobsCancelled))
	}
	for _, blk := range []struct {
		heading string
		rows    []ProcedureCount
	}{
		{"Failed jobs (retried on the next run; --debug shows each failure)", s.FailedJobs},
		{"Deferred to the next run", s.Deferred},
	} {
		if len(blk.rows) == 0 {
			continue
		}
		o.heading(blk.heading)
		rows = rows[:0]
		for _, r := range blk.rows {
			rows = append(rows, labelled{r.Procedure, r.N})
		}
		o.counts(rows)
	}
	o.findings("Findings (high and medium)", s.Findings)
	if len(s.Candidates) > 0 {
		o.heading("Candidates worth promoting (high confidence)")
		o.candidates(s.Candidates)
		if more := s.CandidatesTotal - len(s.Candidates); more > 0 {
			o.text(fmt.Sprintf("and %d more in candidates.csv", more))
		}
	}
	if s.Changes != nil {
		// New/returned entries and gone findings; missing kinds or change types count as zero.
		o.heading("Since last run")
		o.counts(changeCounts(*s.Changes))
		o.findings("New findings (high and medium)", s.Changes.Findings)
	}
}

// labelled pairs a count label with its value.
type labelled struct {
	label string
	n     int
}

// plainSummary writes one line per item, each starting with a newline; the caller ends the
// summary with one.
type plainSummary struct {
	b *strings.Builder
	d palette.Depth
}

func (p *plainSummary) heading(text string) {
	if p.b.Len() > 0 {
		p.b.WriteString("\n")
	}
	p.b.WriteString(p.d.Bold(text))
}

func (p *plainSummary) text(msg string) { p.b.WriteString("\n  " + msg) }

// counts aligns values after labels with a minimum label width of 16 cells.
func (p *plainSummary) counts(rows []labelled) {
	width := 16
	for _, r := range rows {
		width = max(width, utf8.RuneCountInString(r.label))
	}
	for _, r := range rows {
		fmt.Fprintf(p.b, "\n  %-*s %d", width, r.label, r.n)
	}
}

func (p *plainSummary) findings(title string, rows []FindingRow) {
	if len(rows) == 0 {
		return
	}
	p.heading(title)
	for _, r := range rows {
		fmt.Fprintf(p.b, "\n  %s %s %s", p.d.Value(palette.Severity, r.Severity), r.Category, r.Target)
		if r.Detail != nil && *r.Detail != "" {
			p.b.WriteString(" - " + *r.Detail)
		}
	}
}

func (p *plainSummary) candidates(rows []CandidateRow) {
	for _, c := range rows {
		fmt.Fprintf(p.b, "\n  %s  %d evidence (%s)  promote: %s",
			c.Value, c.EvidenceCount, strings.Join(c.Sources, ";"), c.Promote)
	}
}

// terminalSummary lays the summary out for a terminal: ruled headings, wrapped text, aligned
// counts and tables.
type terminalSummary struct {
	b  *strings.Builder
	st layout.Stream
}

func (t *terminalSummary) lines(ls []string) {
	for _, l := range ls {
		t.b.WriteString(l + "\n")
	}
}

func (t *terminalSummary) heading(text string) { t.lines(layout.Heading(t.st, text, true)) }

func (t *terminalSummary) text(msg string) {
	t.lines(layout.Hang("  ", layout.Plain(msg), t.st.Cols(), layout.Spaces))
}

func (t *terminalSummary) counts(rows []labelled) { t.lines(countLines(rows)) }

// findings omits empty tables.
func (t *terminalSummary) findings(title string, rows []FindingRow) {
	if len(rows) == 0 {
		return
	}
	t.heading(title)
	t.b.WriteString(findingsTableText(t.st, rows))
}

func (t *terminalSummary) candidates(rows []CandidateRow) {
	t.b.WriteString(candidatesTable(t.st, rows))
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
