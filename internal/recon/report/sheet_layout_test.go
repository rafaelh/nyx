package report_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/lookup/cve"
	"github.com/rafaelh/nyx/internal/recon/report"
	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/palette"
	"github.com/rafaelh/nyx/internal/testkit"
)

func termSheet(s layout.Stream) string {
	var buf bytes.Buffer
	report.Sheet(&buf, s, clk().In(time.UTC))
	return buf.String()
}

// Terminal sheets exercise headings, tables, severity bars, procedure states, found formats and
// over-width logs.
func TestSheetLayoutPart(t *testing.T) {
	t.Parallel()
	for _, d := range []palette.Depth{palette.None, palette.TrueColor, palette.Color256, palette.Color16} {
		s := termStream(d, 80)
		out := termSheet(s)
		lines := strings.Split(out, "\n")
		heading := "layout"
		if d != palette.None {
			heading = d.BoldText(palette.Semantic, "info", "layout")
		}
		head := indexOfLine(lines, heading)
		if head < 0 {
			t.Fatalf("depth %d: no layout heading:\n%s", d, out)
		}
		added := strings.Join(lines[head:], "\n")
		checkSheetTable(t, d, added)
		checkSheetBars(t, s, added)
		checkSheetProcedureLines(t, d, added)
		checkSheetFoundLines(t, d, added)
		checkSheetWrapped(t, d, added)
		for i, l := range lines[head:] {
			if cells(l) > 80 {
				t.Errorf("depth %d: line %d of the layout part is %d cells: %q", d, i, cells(l), l)
			}
		}
		testkit.OnlyPaletteEscapes(t, d, out)
		if d == palette.None && strings.Contains(out, "\x1b") {
			t.Errorf("an escape in an uncoloured terminal sheet")
		}
	}
}

// checkSheetTable checks the header row of the sample table.
func checkSheetTable(t *testing.T, d palette.Depth, added string) {
	t.Helper()
	for _, h := range []string{"SEVERITY", "CATEGORY", "TARGET", "DETAIL"} {
		if !strings.Contains(added, d.BoldText(palette.Semantic, "muted", h)) {
			t.Errorf("depth %d: the sample table lacks the header %s", d, h)
		}
	}
}

// checkSheetBars checks a CVE bar for each severity label, UNKNOWN and NONE.
func checkSheetBars(t *testing.T, s layout.Stream, added string) {
	t.Helper()
	for _, l := range append(palette.Labels(palette.Severity), "", "NONE") {
		if bar := cve.Bar(s, "CVE-2021-44228", l, true); !strings.Contains(added, bar) {
			t.Errorf("depth %d: no CVE bar for %q:\n%q", s.Depth, l, bar)
		}
	}
	if s.Depth == palette.None && (!strings.Contains(added, "[UNKNOWN]") || !strings.Contains(added, "[NONE]")) {
		t.Errorf("the uncoloured bars:\n%s", added)
	}
}

// checkSheetProcedureLines checks a procedure line for each state, with the state's colour.
func checkSheetProcedureLines(t *testing.T, d palette.Depth, added string) {
	t.Helper()
	for _, c := range []struct {
		state string
		group palette.Group
		name  string
	}{
		{"running", palette.Semantic, "info"}, {"done", palette.Semantic, "success"},
		{"done-previously", palette.Semantic, "success"}, {"failed", palette.Semantic, "error"},
		{"not-configured", palette.Semantic, "muted"},
	} {
		if !strings.Contains(added, " "+d.Text(c.group, c.name, c.state)) {
			t.Errorf("depth %d: no procedure line for %s", d, c.state)
		}
	}
}

// checkSheetFoundLines checks a found line with a badge and one of the form category: value.
func checkSheetFoundLines(t *testing.T, d palette.Depth, added string) {
	t.Helper()
	plainAdded := stripEscapes(added)
	if !strings.Contains(added, d.Value(palette.Severity, "high")+" ") || !strings.Contains(plainAdded, "+ ") {
		t.Errorf("depth %d: no found line with a badge:\n%s", d, plainAdded)
	}
	if !strings.Contains(plainAdded, "+ host: ") {
		t.Errorf("depth %d: no found line of the form category: value:\n%s", d, plainAdded)
	}
}

// checkSheetWrapped checks that the long log line wrapped: two or more lines at the message column.
func checkSheetWrapped(t *testing.T, d palette.Depth, added string) {
	t.Helper()
	indent := 19
	if d != palette.None {
		indent = 21
	}
	wrapped := 0
	for l := range strings.SplitSeq(stripEscapes(added), "\n") {
		if strings.HasPrefix(l, strings.Repeat(" ", indent)) && !strings.HasPrefix(l, strings.Repeat(" ", indent+1)) {
			wrapped++
		}
	}
	if wrapped < 2 {
		t.Errorf("depth %d: the long log line did not wrap (%d continuation lines):\n%s", d, wrapped, stripEscapes(added))
	}
}

// Terminal sheet headings gain semantic styles without changing palette entries.
func TestSheetHeadingsOnATerminal(t *testing.T) {
	t.Parallel()
	for _, d := range depths {
		lines := strings.Split(termSheet(termStream(d, 80)), "\n")
		for _, c := range palette.Categories() {
			if indexOfLine(lines, d.BoldText(palette.Semantic, "info", string(c))) < 0 {
				t.Errorf("depth %d: no heading for %s", d, c)
			}
		}
		for _, g := range palette.Groups() {
			if indexOfLine(lines, d.BoldText(palette.Semantic, "info", string(g))) < 0 {
				t.Errorf("depth %d: no heading for %s", d, g)
			}
		}
	}
}

// Repeated sheet writes remeasure stream width, including header bars.
func TestSheetFollowsTheWidth(t *testing.T) {
	t.Parallel()
	narrow := termSheet(termStream(palette.None, 60))
	wide := termSheet(termStream(palette.None, 120))
	if narrow == wide {
		t.Error("the sheet does not depend on the width")
	}
	bar := func(out string) int {
		for l := range strings.SplitSeq(out, "\n") {
			if strings.HasPrefix(l, "CVE-2021-44228") && strings.Contains(l, "[HIGH]") {
				return cells(l)
			}
		}
		return -1
	}
	if bar(narrow) != 60 || bar(wide) != 120 {
		t.Errorf("bar widths = %d and %d, want 60 and 120", bar(narrow), bar(wide))
	}
}
