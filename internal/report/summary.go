package report

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// Summary is what a recon run reports when it ends: the human summary and the
// data of the --json envelope. Its fields, in this order, are the envelope's keys, a
// stable interface: adding a key is compatible, renaming, removing or retyping one is a
// breaking change. A list is never nil once written (see WriteEnvelope).
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

// Changes is what changed since the run before. It is nil in a Summary on a first run.
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

// WriteSummary writes the human summary of env to w: the counts, the stages' notes, a
// line for a run the deadline ended, the failed and deferred checks, the findings, the
// candidates and, when Data.Changes is set, the "Since last run" block. Text that came
// from a target is sanitised. Rows come out in the order they are given. The whole
// summary is one write and ends in one newline.
func WriteSummary(w io.Writer, d palette.Depth, env Envelope) {
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

// labelled is a line of a block of counts.
type labelled struct {
	label string
	n     int
}

// writeLabelled writes one line for each row, with the numbers in one column: at least
// 16 wide, and wide enough for the longest label.
func writeLabelled(b *strings.Builder, rows []labelled) {
	width := 16
	for _, r := range rows {
		width = max(width, utf8.RuneCountInString(r.label))
	}
	for _, r := range rows {
		fmt.Fprintf(b, "\n  %-*s %d", width, r.label, r.n)
	}
}

// writeSinceLastRun writes the block that ends the summary of a run that has an earlier
// one to compare with: what is new (including what returned) and the findings that are
// gone, then the new findings of high and medium severity. A kind or change that is
// missing counts as none.
func writeSinceLastRun(b *strings.Builder, d palette.Depth, ch Changes) {
	type key struct{ kind, change string }
	counts := make(map[key]int, len(ch.Counts))
	for _, c := range ch.Counts {
		counts[key{c.Kind, c.Change}] += c.N
	}
	b.WriteString("\n" + d.Bold("Since last run"))
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
	writeLabelled(b, rows)
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
