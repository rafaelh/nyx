// Package palette holds the console colours as data and writes the escape
// codes for them. It is pure: it never looks at a stream or the environment
// except through the getenv function Detect is given.
//
// The tables follow docs/log-colors.md. Nothing outside this package holds a
// colour value. The document's synonym table and its "unknown name is an
// error" lookup are not built: nyx prints only level names it holds as
// constants and record values, and a value the palette does not know takes the
// DEBUG style.
package palette

import (
	"fmt"
	"strconv"
	"strings"
)

// Depth is how many colours a stream can show.
type Depth int

// The depths, from no colour at all to 24-bit.
const (
	None Depth = iota
	Color16
	Color256
	TrueColor
)

// Detect decides a stream's depth. A stream is coloured only when it is a
// terminal, NO_COLOR is unset or empty and TERM is not dumb; FORCE_COLOR,
// CLICOLOR_FORCE and every other variable are ignored. COLORTERM and TERM then
// choose only how many colours: 24-bit for truecolor or 24bit, 256 for a TERM
// containing 256color, else 16.
func Detect(isTerminal bool, getenv func(string) string) Depth {
	if !isTerminal || getenv("NO_COLOR") != "" || getenv("TERM") == "dumb" {
		return None
	}
	switch getenv("COLORTERM") {
	case "truecolor", "24bit":
		return TrueColor
	}
	if strings.Contains(getenv("TERM"), "256color") {
		return Color256
	}
	return Color16
}

// badgeStyle is a base badge style: 24-bit foreground and background, the nearest
// 256-colour entries, and the fixed 16-colour codes. The 16-colour pair is the
// bright colour of the style's hue on black, not the nearest of the 16 (which
// would make most badges grey on black).
type badgeStyle struct {
	fgStyle
	Name  string
	BG    [3]uint8
	Bold  bool
	BG16  int // SGR code: 40 to 47
	BG256 int // xterm index 16 to 255
}

// fgStyle is a foreground-only style: no background, never bold.
type fgStyle struct {
	FG    [3]uint8
	FG16  int // SGR code: 30 to 37 or 90 to 97
	FG256 int // xterm index 16 to 255
}

func base(name string, fg, bg [3]uint8, bold bool, fg16, bg16 int) badgeStyle {
	return badgeStyle{fgStyle: fgOnly(fg, fg16), Name: name, BG: bg, Bold: bold, BG16: bg16, BG256: nearest256(bg)}
}

func fgOnly(fg [3]uint8, fg16 int) fgStyle {
	return fgStyle{FG: fg, FG16: fg16, FG256: nearest256(fg)}
}

// The base badge styles.
var styles = []badgeStyle{
	base("DEBUG", [3]uint8{169, 177, 198}, [3]uint8{42, 47, 58}, false, 37, 40),
	base("INFO", [3]uint8{143, 179, 255}, [3]uint8{31, 44, 77}, false, 94, 40),
	base("WARN", [3]uint8{236, 208, 143}, [3]uint8{61, 52, 32}, false, 93, 40),
	base("ERROR", [3]uint8{240, 138, 146}, [3]uint8{74, 34, 38}, false, 91, 40),
	base("CRIT", [3]uint8{246, 246, 246}, [3]uint8{163, 52, 60}, true, 97, 41),
	base("PASS", [3]uint8{168, 211, 138}, [3]uint8{36, 54, 31}, false, 92, 40),
	base("DRY RUN", [3]uint8{143, 214, 227}, [3]uint8{29, 58, 64}, false, 96, 40),
	base("MEDIUM", [3]uint8{240, 180, 124}, [3]uint8{69, 48, 28}, false, 33, 40),
}

func styleNamed(name string) badgeStyle {
	for _, s := range styles {
		if s.Name == name {
			return s
		}
	}
	return styles[0] // DEBUG
}

// Category names a badge table.
type Category string

// The badge categories.
const (
	Level      Category = "level"
	Outcome    Category = "outcome"
	Severity   Category = "severity"
	HTTPStatus Category = "http_status"
)

// label is a badge label and its style.
type label struct {
	name  string
	style badgeStyle
}

// labels pairs each label with the base style it takes.
func labels(pairs ...string) []label {
	out := make([]label, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, label{pairs[i], styleNamed(pairs[i+1])})
	}
	return out
}

type table struct {
	cat    Category
	labels []label
}

var tables = []table{
	{Level, labels("DEBUG", "DEBUG", "INFO", "INFO", "WARN", "WARN", "ERROR", "ERROR", "CRIT", "CRIT")},
	{Outcome, labels("PASS", "PASS", "FAIL", "ERROR", "SKIP", "WARN", "DRY RUN", "DRY RUN")},
	{Severity, labels("CRITICAL", "CRIT", "HIGH", "ERROR", "MEDIUM", "MEDIUM", "LOW", "WARN", "INFO", "INFO")},
	{HTTPStatus, labels("2xx", "PASS", "3xx", "DEBUG", "4xx", "WARN", "5xx", "ERROR")},
}

func tableOf(c Category) table {
	for _, t := range tables {
		if t.cat == c {
			return t
		}
	}
	return table{cat: c}
}

// Categories lists the badge categories in the order of the palette document.
func Categories() []Category {
	out := make([]Category, len(tables))
	for i, t := range tables {
		out[i] = t.cat
	}
	return out
}

// Labels lists a category's labels in the order of the palette document.
func Labels(c Category) []string {
	var out []string
	for _, l := range tableOf(c).labels {
		out = append(out, l.name)
	}
	return out
}

// Width is the widest label of a category.
func Width(c Category) int {
	w := 0
	for _, l := range tableOf(c).labels {
		w = max(w, len(l.name))
	}
	return w
}

// styleOf finds the style of a label, case-insensitively. A label the category
// does not hold gets the DEBUG style.
func styleOf(c Category, name string) (canonical string, s badgeStyle) {
	for _, l := range tableOf(c).labels {
		if strings.EqualFold(l.name, name) {
			return l.name, l.style
		}
	}
	return name, styles[0] // DEBUG
}

func (d Depth) badge(c Category, text string, s badgeStyle) string {
	padded := fmt.Sprintf("%-*s", Width(c), text)
	if d == None {
		return padded
	}
	return d.wrap(d.badgeParams(s), " "+padded+" ")
}

func (d Depth) badgeParams(s badgeStyle) string {
	p := d.fgParams(s.fgStyle) + ";"
	switch d {
	case TrueColor:
		p += fmt.Sprintf("48;2;%d;%d;%d", s.BG[0], s.BG[1], s.BG[2])
	case Color256:
		p += "48;5;" + strconv.Itoa(s.BG256)
	default:
		p += strconv.Itoa(s.BG16)
	}
	if s.Bold {
		p = "1;" + p
	}
	return p
}

// fgParams are the SGR parameters of a foreground at depth d.
func (d Depth) fgParams(s fgStyle) string {
	switch d {
	case TrueColor:
		return fmt.Sprintf("38;2;%d;%d;%d", s.FG[0], s.FG[1], s.FG[2])
	case Color256:
		return "38;5;" + strconv.Itoa(s.FG256)
	default:
		return strconv.Itoa(s.FG16)
	}
}

func (d Depth) wrap(params, s string) string { return "\x1b[" + params + "m" + s + "\x1b[0m" }

// Badge renders a category label in its canonical upper-case form. A label the
// category does not hold keeps its own text in the DEBUG style.
func (d Depth) Badge(c Category, label string) string {
	canon, s := styleOf(c, label)
	return d.badge(c, canon, s)
}

// Value renders a record value exactly as recorded, in its own case and with
// no truncation, padded to the category's width. Only the style is looked up,
// so a value the palette does not know takes the DEBUG style and never fails.
func (d Depth) Value(c Category, value string) string {
	_, s := styleOf(c, value)
	return d.badge(c, value, s)
}

// Group names a foreground-only table.
type Group string

// The foreground-only groups.
const (
	Method   Group = "http_method"
	Chrome   Group = "chrome"
	Semantic Group = "semantic"
)

type fgEntry struct {
	name string
	fgStyle
}

type fgGroup struct {
	group   Group
	entries []fgEntry
}

var fgGroups = []fgGroup{
	{Method, []fgEntry{
		{"GET", fgOnly([3]uint8{125, 207, 255}, 96)},
		{"POST", fgOnly([3]uint8{192, 153, 240}, 95)},
		{"PATCH", fgOnly([3]uint8{229, 162, 101}, 33)},
		{"PUT", fgOnly([3]uint8{229, 162, 101}, 33)},
		{"DELETE", fgOnly([3]uint8{224, 108, 117}, 91)},
	}},
	{Chrome, []fgEntry{
		{"TIMESTAMP", fgOnly([3]uint8{124, 129, 145}, 90)},
		{"SEPARATOR", fgOnly([3]uint8{74, 79, 92}, 90)},
	}},
	// The semantic text colours are the foregrounds of four base styles.
	{Semantic, []fgEntry{
		{"success", styleNamed("PASS").fgStyle},
		{"error", styleNamed("ERROR").fgStyle},
		{"warning", styleNamed("WARN").fgStyle},
		{"info", styleNamed("INFO").fgStyle},
	}},
}

func entriesOf(g Group) []fgEntry {
	for _, fg := range fgGroups {
		if fg.group == g {
			return fg.entries
		}
	}
	return nil
}

// Groups lists the foreground-only groups in the order of the palette document.
func Groups() []Group {
	out := make([]Group, len(fgGroups))
	for i, fg := range fgGroups {
		out[i] = fg.group
	}
	return out
}

// Names lists the names of a foreground-only group in document order.
func Names(g Group) []string {
	var out []string
	for _, e := range entriesOf(g) {
		out = append(out, e.name)
	}
	return out
}

// Text colours s with the foreground of a named entry of group, with no
// background and no bold. An unknown name leaves s unstyled.
func (d Depth) Text(g Group, name, s string) string {
	if d == None {
		return s
	}
	for _, e := range entriesOf(g) {
		if e.name == name {
			return d.wrap(d.fgParams(e.fgStyle), s)
		}
	}
	return s
}

// Bold makes s bold.
func (d Depth) Bold(s string) string {
	if d == None {
		return s
	}
	return d.wrap("1", s)
}

// BoldText colours s with the foreground of a named entry of group and makes it
// bold: ESC[1;<foreground>m, s, ESC[0m. There is no background. An unknown name
// gives plain bold, as Bold does. At depth None s is returned unchanged.
func (d Depth) BoldText(g Group, name, s string) string {
	if d == None {
		return s
	}
	for _, e := range entriesOf(g) {
		if e.name == name {
			return d.wrap("1;"+d.fgParams(e.fgStyle), s)
		}
	}
	return d.wrap("1", s)
}

// BadgeText writes text in the badge style that label takes in category c, found
// as Value finds it: case-insensitively, and DEBUG for a label the category does
// not hold. Unlike Badge and Value it adds no padding and no space either side:
// it wraps text exactly, so a caller laying out a bar adds its own spaces. At
// depth None text is returned unchanged.
func (d Depth) BadgeText(c Category, label, text string) string {
	if d == None {
		return text
	}
	_, s := styleOf(c, label)
	return d.wrap(d.badgeParams(s), text)
}

// nearest256 is the entry of the xterm 256-colour table, among indices 16 to
// 255, nearest to c by squared RGB distance (the lowest index on a tie).
// Indices 0 to 15 are skipped because their colour depends on the terminal's
// theme.
func nearest256(c [3]uint8) int {
	levels := [6]int{0, 95, 135, 175, 215, 255}
	best, bestD := 16, int(^uint(0)>>1)
	for i := 16; i < 256; i++ {
		var r, g, b int
		if i < 232 {
			n := i - 16
			r, g, b = levels[n/36], levels[n/6%6], levels[n%6]
		} else {
			r = 8 + 10*(i-232)
			g, b = r, r
		}
		dr, dg, db := r-int(c[0]), g-int(c[1]), b-int(c[2])
		if d := dr*dr + dg*dg + db*db; d < bestD {
			best, bestD = i, d
		}
	}
	return best
}
