package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/cve"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
)

// Sheet previews palette entries and real log formatting for checking terminal themes. It uses
// now for sample timestamps. On terminals it also includes headings, tables, CVE bars, procedure
// states, found events and an over-width message to exercise wrapping.
func Sheet(w io.Writer, s layout.Stream, now time.Time) {
	if s.Terminal {
		s = s.Fixed() // so the whole sheet has one width
	}
	d := s.Depth
	var b strings.Builder
	heading := func(text string) { b.WriteString(d.Bold(text) + "\n") }
	if s.Terminal {
		heading = func(text string) {
			for _, l := range layout.Heading(s, text, false) {
				b.WriteString(l + "\n")
			}
		}
	}
	for _, c := range palette.Categories() {
		heading(string(c))
		for _, l := range palette.Labels(c) {
			b.WriteString("  " + d.Badge(c, l) + "\n")
		}
	}
	for _, g := range palette.Groups() {
		heading(string(g))
		for _, n := range palette.Names(g) {
			b.WriteString("  " + d.Text(g, n, n) + "\n")
		}
	}
	heading("log lines")
	for l := Debug; l <= Crit; l++ {
		fmt.Fprintln(&b, Line(s, now, l, "a sample "+l.Label()+" message"))
	}
	fmt.Fprintln(&b, Line(s, now, Info, "a message of two lines\ncontinued under the message column"))
	if s.Terminal {
		heading("layout")
		writeLayoutSamples(&b, s, now)
	}
	_, _ = io.WriteString(w, b.String()) // a failed write of the sheet has nowhere to be reported
}

// sampleLong is a message wider than any layout width the sheet is shown at.
const sampleLong = "a log line whose message is longer than the layout width, so that it wraps and each " +
	"continuation line starts under the message column instead of under the timestamp, with the " +
	"words kept whole and a host such as www.example.com never broken"

// writeLayoutSamples previews terminal-specific formatting.
func writeLayoutSamples(b *strings.Builder, s layout.Stream, now time.Time) {
	b.WriteString(findingsTableText(s, []FindingRow{
		{Severity: "high", Category: "exposed-admin", Target: "https://app.example.com/admin", Detail: new("a login page with no rate limit")},
		{Severity: "medium", Category: "banner", Target: "198.51.100.7:21", Detail: new("an FTP banner that names its version")},
		{Severity: "low", Category: "headers", Target: "www.example.com"},
	}))
	for _, label := range append(palette.Labels(palette.Severity), "", "NONE") {
		b.WriteString(cve.Bar(s, "CVE-2021-44228", label, true) + "\n")
	}
	for _, c := range []struct {
		state, reason string
		level         Level
	}{
		{"running", "", Info}, {"done", "", Info}, {"done-previously", "", Info},
		{"failed", "", Error}, {"not-configured", "no key", Info},
	} {
		b.WriteString(LineSpans(s, now, c.level, procedureSpans(s, "crtsh", c.state, c.reason, "12", "1")) + "\n")
	}
	b.WriteString(LineSpans(s, now, Info, foundSpans(s, "finding", "https://app.example.com/admin", "", "high")) + "\n")
	b.WriteString(LineSpans(s, now, Info, foundSpans(s, "host", "www.example.com", "", "")) + "\n")
	b.WriteString(Line(s, now, Warn, sampleLong) + "\n")
}
