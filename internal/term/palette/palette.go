// Package palette owns console colours and escape generation. It reads environment values only
// through Detect's supplied callback. Callers use named styles rather than colour values;
// unknown record labels fall back to DEBUG styling.
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

// Detect enables colour only for terminals with NO_COLOR empty and TERM other than dumb.
// COLORTERM=truecolor/24bit selects 24-bit, TERM containing 256color selects 256 colours,
// otherwise 16. Force-colour variables are ignored.
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

// badgeStyle defines 24-bit, 256-colour and fixed 16-colour variants. The 16-colour variant
// uses a bright hue on black to keep badges distinct instead of mapping most to grey.
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

// styleOf matches case-insensitively and falls back to DEBUG for unknown labels.
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

// Badge uses canonical uppercase category labels, preserving unknown text with DEBUG styling.
func (d Depth) Badge(c Category, label string) string {
	canon, s := styleOf(c, label)
	return d.badge(c, canon, s)
}

// Value preserves case and text, padding to the category width. Unknown values use DEBUG
// styling rather than failing.
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
	Setup    Group = "setup"
)

type fgEntry struct {
	name string
	fgStyle
}

type fgGroup struct {
	group   Group
	entries []fgEntry
}

// timestamp and muted share the same grey foreground.
var timestamp = fgOnly([3]uint8{124, 129, 145}, 90)

var fgGroups = []fgGroup{
	{Method, []fgEntry{
		{"GET", fgOnly([3]uint8{125, 207, 255}, 96)},
		{"POST", fgOnly([3]uint8{192, 153, 240}, 95)},
		{"PATCH", fgOnly([3]uint8{229, 162, 101}, 33)},
		{"PUT", fgOnly([3]uint8{229, 162, 101}, 33)},
		{"DELETE", fgOnly([3]uint8{224, 108, 117}, 91)},
	}},
	{Chrome, []fgEntry{
		{"TIMESTAMP", timestamp},
		{"SEPARATOR", fgOnly([3]uint8{74, 79, 92}, 90)},
	}},
	// Semantic text roles use base-style foregrounds. Muted uses timestamp grey; example
	// uses warm amber for help invocations; alert is setup's bad red, for a heading that draws
	// attention; tld, domain and subdomain colour a hostname's last three labels, dot the dots
	// between them, and separator the commas between a list's entries.
	{Semantic, []fgEntry{
		{"success", styleNamed("PASS").fgStyle},
		{"error", styleNamed("ERROR").fgStyle},
		{"warning", styleNamed("WARN").fgStyle},
		{"info", styleNamed("INFO").fgStyle},
		{"muted", timestamp},
		{"example", fgOnly(example, 93)},
		{"alert", bad},
		{"tld", violet},
		{"domain", lavender},
		{"subdomain", fgOnly([3]uint8{159, 112, 169}, 35)},
		{"dot", fgOnly([3]uint8{207, 207, 222}, 37)},
		{"separator", faint},
	}},
	// Setup roles distinguish selected and dim rows. faint de-emphasises unset/skipped
	// content; help styles descriptions; key uses example amber for shortcuts.
	{Setup, []fgEntry{
		{"pointer", fgOnly(green, 92)},
		{"name", fgOnly([3]uint8{128, 255, 234}, 96)},
		{"name-dim", fgOnly([3]uint8{3, 106, 150}, 36)},
		{"value", violet},
		{"value-dim", fgOnly([3]uint8{100, 74, 201}, 35)},
		{"faint", faint},
		{"help", lavender},
		{"key", fgOnly(example, 93)},
		{"good", fgOnly(green, 92)},
		{"bad", bad},
		{"caution", fgOnly([3]uint8{255, 255, 128}, 33)},
	}},
}

// example colours help invocations and setup shortcuts; green marks selections and accepted
// keys; bad marks setup's rejections and alert headings; violet and lavender, setup's values and
// help, also mark a hostname's TLD and domain; faint, setup's unset values, also marks a list's
// commas.
var (
	example  = [3]uint8{255, 202, 128}
	green    = [3]uint8{138, 255, 128}
	bad      = fgOnly([3]uint8{163, 20, 77}, 31)
	violet   = fgOnly([3]uint8{149, 128, 255}, 95)
	lavender = fgOnly([3]uint8{121, 112, 169}, 37)
	faint    = fgOnly([3]uint8{69, 65, 88}, 90)
)

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

// Text applies a named foreground without background or bold. Unknown names leave text
// unchanged.
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

// BoldText applies a named foreground and bold, falling back to plain bold for unknown names.
// None depth leaves text unchanged.
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

// BadgeText applies a case-insensitive badge style without padding so callers can lay out bars
// themselves. Unknown labels use DEBUG; None returns unchanged text.
func (d Depth) BadgeText(c Category, label, text string) string {
	if d == None {
		return text
	}
	_, s := styleOf(c, label)
	return d.wrap(d.badgeParams(s), text)
}

// nearest256 chooses the closest fixed xterm colour by squared RGB distance, preferring the
// lower index on ties. Theme-dependent indexes 0–15 are excluded.
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
