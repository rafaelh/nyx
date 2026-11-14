package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rafaelh/recon/internal/palette"
)

// Sheet writes the palette sheet: every entry of every table of the palette,
// then one sample log line per level and one two-line message, all through the
// formatter a run uses, so a new terminal or theme can be checked by eye. The
// log lines carry the time now, as it is to be shown.
func Sheet(w io.Writer, d palette.Depth, now time.Time) {
	var b strings.Builder
	heading := func(s string) { b.WriteString(d.Bold(s) + "\n") }
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
		fmt.Fprintln(&b, Line(d, now, l, "a sample "+l.Label()+" message"))
	}
	fmt.Fprintln(&b, Line(d, now, Info, "a message of two lines\ncontinued under the message column"))
	_, _ = io.WriteString(w, b.String()) // a failed write of the sheet has nowhere to be reported
}
