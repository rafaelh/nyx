package layout

import "strings"

// Field is a label and its plain value, laid out by Fields and Labelled.
type Field struct{ Label, Value string }

// Fields aligns values in one column: each label bold at indent, each value two cells after
// the longest label and wrapped beneath itself at the stream's width.
func Fields(s Stream, indent int, fields []Field) []string {
	longest := 0
	for _, f := range fields {
		longest = max(longest, Measure(f.Label))
	}
	var out []string
	for _, f := range fields {
		out = append(out, Labelled(s, indent, longest, f)...)
	}
	return out
}

// Labelled lays out one field of a column that Fields would align: its label bold at indent,
// its value two cells after a label of longest cells and wrapped beneath itself at the
// stream's width.
func Labelled(s Stream, indent, longest int, f Field) []string {
	head := strings.Repeat(" ", indent) + s.Depth.Bold(f.Label) + strings.Repeat(" ", longest-Measure(f.Label)+2)
	return Hang(head, Plain(f.Value), s.Cols(), Spaces)
}
