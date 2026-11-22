package palette_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/palette"
)

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

// The colour decision: a terminal, NO_COLOR unset or empty and TERM not dumb;
// nothing else turns colour on, and the depth variables only choose the depth.
func TestDetect(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		tty  bool
		env  map[string]string
		want palette.Depth
	}{
		{"not a terminal", false, map[string]string{"TERM": "xterm-256color", "COLORTERM": "truecolor"}, palette.None},
		{"terminal, plain xterm", true, map[string]string{"TERM": "xterm"}, palette.Color16},
		{"terminal, no TERM", true, nil, palette.Color16},
		{"256 colour", true, map[string]string{"TERM": "xterm-256color"}, palette.Color256},
		{"screen 256", true, map[string]string{"TERM": "screen-256color"}, palette.Color256},
		{"truecolor", true, map[string]string{"TERM": "xterm", "COLORTERM": "truecolor"}, palette.TrueColor},
		{"24bit", true, map[string]string{"TERM": "xterm", "COLORTERM": "24bit"}, palette.TrueColor},
		{"truecolor beats 256", true, map[string]string{"TERM": "xterm-256color", "COLORTERM": "truecolor"}, palette.TrueColor},
		{"other COLORTERM is not truecolor", true, map[string]string{"TERM": "xterm", "COLORTERM": "yes"}, palette.Color16},
		{"NO_COLOR set", true, map[string]string{"TERM": "xterm", "NO_COLOR": "1"}, palette.None},
		{"NO_COLOR empty", true, map[string]string{"TERM": "xterm", "NO_COLOR": ""}, palette.Color16},
		{"TERM dumb", true, map[string]string{"TERM": "dumb"}, palette.None},
		{"FORCE_COLOR forces nothing", false, map[string]string{"TERM": "xterm", "FORCE_COLOR": "1"}, palette.None},
		{"CLICOLOR_FORCE forces nothing", false, map[string]string{"TERM": "xterm", "CLICOLOR_FORCE": "1"}, palette.None},
		{"COLORTERM does not turn colour on", false, map[string]string{"COLORTERM": "truecolor"}, palette.None},
		{"TERM 256color does not turn colour on", false, map[string]string{"TERM": "xterm-256color"}, palette.None},
		{"NO_COLOR beats truecolor", true, map[string]string{"COLORTERM": "truecolor", "NO_COLOR": "x"}, palette.None},
	}
	for _, c := range cases {
		if got := palette.Detect(c.tty, env(c.env)); got != c.want {
			t.Errorf("%s: depth %v, want %v", c.name, got, c.want)
		}
	}
}

// The exact sequences of one badge at each depth, and the unstyled form.
func TestBadgeSequences(t *testing.T) {
	t.Parallel()
	cases := []struct {
		d    palette.Depth
		want string
	}{
		{palette.TrueColor, "\x1b[38;2;236;208;143;48;2;61;52;32m WARN  \x1b[0m"},
		{palette.Color256, "\x1b[38;5;222;48;5;236m WARN  \x1b[0m"},
		{palette.Color16, "\x1b[93;40m WARN  \x1b[0m"},
		{palette.None, "WARN "},
	}
	for _, c := range cases {
		if got := c.d.Badge(palette.Level, "WARN"); got != c.want {
			t.Errorf("depth %v: %q, want %q", c.d, got, c.want)
		}
	}
	// A bold badge carries 1 first.
	if got, want := palette.TrueColor.Badge(palette.Level, "CRIT"), "\x1b[1;38;2;246;246;246;48;2;163;52;60m CRIT  \x1b[0m"; got != want {
		t.Errorf("CRIT: %q, want %q", got, want)
	}
	if got, want := palette.Color16.Badge(palette.Level, "CRIT"), "\x1b[1;97;41m CRIT  \x1b[0m"; got != want {
		t.Errorf("CRIT at 16 colours: %q, want %q", got, want)
	}
}

// Every badge of every category is as wide as its category plus the side spaces.
func TestBadgeWidths(t *testing.T) {
	t.Parallel()
	want := map[palette.Category]int{palette.Level: 5, palette.Outcome: 7, palette.Severity: 8, palette.HTTPStatus: 3}
	for _, c := range palette.Categories() {
		if palette.Width(c) != want[c] {
			t.Errorf("%s: width %d, want %d", c, palette.Width(c), want[c])
		}
		for _, l := range palette.Labels(c) {
			plain := palette.None.Badge(c, l)
			if len(plain) != want[c] {
				t.Errorf("%s %s: plain badge %q is %d wide, want %d", c, l, plain, len(plain), want[c])
			}
			coloured := palette.TrueColor.Badge(c, l)
			if inner := stripEscapes(coloured); len(inner) != want[c]+2 || !strings.HasPrefix(inner, " "+l) {
				t.Errorf("%s %s: coloured badge text %q", c, l, inner)
			}
		}
	}
}

func stripEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// A record value keeps its own text and case, is padded to the category's
// width, and takes the style found case-insensitively; an unknown value takes
// the DEBUG style and never fails.
func TestValueBadge(t *testing.T) {
	t.Parallel()
	if got, want := palette.None.Value(palette.Severity, "high"), "high    "; got != want {
		t.Errorf("plain = %q, want %q", got, want)
	}
	if got, want := palette.TrueColor.Value(palette.Severity, "high"), "\x1b[38;2;240;138;146;48;2;74;34;38m high     \x1b[0m"; got != want {
		t.Errorf("high = %q, want %q", got, want)
	}
	if got, want := palette.TrueColor.Value(palette.Severity, "medium"), "\x1b[38;2;240;180;124;48;2;69;48;28m medium   \x1b[0m"; got != want {
		t.Errorf("medium = %q, want %q", got, want)
	}
	if got, want := palette.TrueColor.Value(palette.Severity, "low"), "\x1b[38;2;236;208;143;48;2;61;52;32m low      \x1b[0m"; got != want {
		t.Errorf("low = %q, want %q", got, want)
	}
	if got, want := palette.TrueColor.Value(palette.Severity, "High"), "\x1b[38;2;240;138;146;48;2;74;34;38m High     \x1b[0m"; got != want {
		t.Errorf("a recorded value keeps its case: %q, want %q", got, want)
	}
	if got, want := palette.TrueColor.Value(palette.Severity, "bogus"), "\x1b[38;2;169;177;198;48;2;42;47;58m bogus    \x1b[0m"; got != want {
		t.Errorf("unknown severity takes the DEBUG style: %q, want %q", got, want)
	}
	if got := palette.None.Value(palette.Severity, "informational-extra"); got != "informational-extra" {
		t.Errorf("a longer value is not truncated: %q", got)
	}
}

// The foreground-only entries at each depth.
func TestTextColours(t *testing.T) {
	t.Parallel()
	cases := []struct {
		d         palette.Depth
		group     palette.Group
		name, out string
	}{
		{palette.TrueColor, palette.Chrome, "TIMESTAMP", "\x1b[38;2;124;129;145mx\x1b[0m"},
		{palette.Color256, palette.Chrome, "TIMESTAMP", "\x1b[38;5;102mx\x1b[0m"},
		{palette.Color16, palette.Chrome, "TIMESTAMP", "\x1b[90mx\x1b[0m"},
		{palette.Color256, palette.Chrome, "SEPARATOR", "\x1b[38;5;239mx\x1b[0m"},
		{palette.Color16, palette.Chrome, "SEPARATOR", "\x1b[90mx\x1b[0m"},
		{palette.Color256, palette.Method, "GET", "\x1b[38;5;117mx\x1b[0m"},
		{palette.Color256, palette.Method, "POST", "\x1b[38;5;141mx\x1b[0m"},
		{palette.Color256, palette.Method, "PATCH", "\x1b[38;5;179mx\x1b[0m"},
		{palette.Color256, palette.Method, "PUT", "\x1b[38;5;179mx\x1b[0m"},
		{palette.Color256, palette.Method, "DELETE", "\x1b[38;5;168mx\x1b[0m"},
		{palette.Color16, palette.Method, "GET", "\x1b[96mx\x1b[0m"},
		{palette.Color16, palette.Method, "POST", "\x1b[95mx\x1b[0m"},
		{palette.Color16, palette.Method, "PUT", "\x1b[33mx\x1b[0m"},
		{palette.Color16, palette.Method, "DELETE", "\x1b[91mx\x1b[0m"},
		{palette.TrueColor, palette.Semantic, "error", "\x1b[38;2;240;138;146mx\x1b[0m"},
		{palette.Color16, palette.Semantic, "success", "\x1b[92mx\x1b[0m"},
		{palette.Color16, palette.Semantic, "error", "\x1b[91mx\x1b[0m"},
		{palette.Color16, palette.Semantic, "warning", "\x1b[93mx\x1b[0m"},
		{palette.Color16, palette.Semantic, "info", "\x1b[94mx\x1b[0m"},
		{palette.None, palette.Chrome, "TIMESTAMP", "x"},
	}
	for _, c := range cases {
		if got := c.d.Text(c.group, c.name, "x"); got != c.out {
			t.Errorf("depth %v %s %s = %q, want %q", c.d, c.group, c.name, got, c.out)
		}
	}
}

func TestBold(t *testing.T) {
	t.Parallel()
	if got := palette.TrueColor.Bold("Summary"); got != "\x1b[1mSummary\x1b[0m" {
		t.Errorf("bold = %q", got)
	}
	if got := palette.None.Bold("Summary"); got != "Summary" {
		t.Errorf("plain bold = %q", got)
	}
}

// BoldText is bold plus the entry's foreground, with no background; an unknown
// name is bold only, and None leaves the text alone.
func TestBoldText(t *testing.T) {
	t.Parallel()
	cases := []struct {
		d         palette.Depth
		group     palette.Group
		name, out string
	}{
		{palette.TrueColor, palette.Semantic, "info", "\x1b[1;38;2;143;179;255mx\x1b[0m"},
		{palette.Color256, palette.Semantic, "info", "\x1b[1;38;5;111mx\x1b[0m"},
		{palette.Color16, palette.Semantic, "info", "\x1b[1;94mx\x1b[0m"},
		{palette.TrueColor, palette.Chrome, "TIMESTAMP", "\x1b[1;38;2;124;129;145mx\x1b[0m"},
		{palette.Color256, palette.Chrome, "TIMESTAMP", "\x1b[1;38;5;102mx\x1b[0m"},
		{palette.Color16, palette.Chrome, "TIMESTAMP", "\x1b[1;90mx\x1b[0m"},
		{palette.Color16, palette.Semantic, "error", "\x1b[1;91mx\x1b[0m"},
		{palette.TrueColor, palette.Semantic, "nope", "\x1b[1mx\x1b[0m"},
		{palette.Color16, palette.Group("nope"), "info", "\x1b[1mx\x1b[0m"},
		{palette.None, palette.Semantic, "info", "x"},
		{palette.None, palette.Semantic, "nope", "x"},
	}
	for _, c := range cases {
		if got := c.d.BoldText(c.group, c.name, "x"); got != c.out {
			t.Errorf("depth %v %s %s = %q, want %q", c.d, c.group, c.name, got, c.out)
		}
	}
}

// BadgeText is the badge of the label's style around the text exactly as given:
// no padding and no added spaces. An unknown label takes DEBUG and None is plain.
func TestBadgeText(t *testing.T) {
	t.Parallel()
	cases := []struct {
		d            palette.Depth
		cat          palette.Category
		label, which string
		out          string
	}{
		{palette.TrueColor, palette.Severity, "HIGH", "T", "\x1b[38;2;240;138;146;48;2;74;34;38mT\x1b[0m"},
		{palette.TrueColor, palette.Severity, "high", "T", "\x1b[38;2;240;138;146;48;2;74;34;38mT\x1b[0m"},
		{palette.TrueColor, palette.Severity, "CRITICAL", "T", "\x1b[1;38;2;246;246;246;48;2;163;52;60mT\x1b[0m"},
		{palette.Color256, palette.Severity, "CRITICAL", "T", "\x1b[1;38;5;255;48;5;131mT\x1b[0m"},
		{palette.Color16, palette.Severity, "CRITICAL", "T", "\x1b[1;97;41mT\x1b[0m"},
		{palette.Color16, palette.Severity, "MEDIUM", "T", "\x1b[33;40mT\x1b[0m"},
		{palette.Color16, palette.Severity, "LOW", "T", "\x1b[93;40mT\x1b[0m"},
		{palette.Color16, palette.Severity, "INFO", "T", "\x1b[94;40mT\x1b[0m"},
		{palette.TrueColor, palette.Severity, "NONE", "T", "\x1b[38;2;169;177;198;48;2;42;47;58mT\x1b[0m"},
		{palette.Color256, palette.Severity, "UNKNOWN", "T", "\x1b[38;5;146;48;5;236mT\x1b[0m"},
		{palette.Color16, palette.Severity, "UNKNOWN", "T", "\x1b[37;40mT\x1b[0m"},
		{palette.None, palette.Severity, "HIGH", "T", "T"},
		{palette.None, palette.Severity, "NONE", "T", "T"},
	}
	for _, c := range cases {
		if got := c.d.BadgeText(c.cat, c.label, c.which); got != c.out {
			t.Errorf("depth %v %s %s = %q, want %q", c.d, c.cat, c.label, got, c.out)
		}
	}
	// The text is not padded: a text longer or shorter than the category's width
	// comes back as given between the escapes.
	got := palette.TrueColor.BadgeText(palette.Severity, "LOW", " a bar ")
	if want := "\x1b[38;2;236;208;143;48;2;61;52;32m a bar \x1b[0m"; got != want {
		t.Errorf("exact text = %q, want %q", got, want)
	}
}

// Lookup is case-insensitive, and the category tables follow the palette document.
func TestCategoryTables(t *testing.T) {
	t.Parallel()
	if palette.TrueColor.Badge(palette.Outcome, "dry run") != palette.TrueColor.Badge(palette.Outcome, "DRY RUN") {
		t.Error("lookup is not case-insensitive")
	}
	if got := palette.None.Badge(palette.Outcome, "dry run"); got != "DRY RUN" {
		t.Errorf("a label renders in its canonical form: %q", got)
	}
	// 4xx is the WARN style and 5xx the ERROR style.
	if palette.TrueColor.Badge(palette.HTTPStatus, "4xx") != strings.Replace(palette.TrueColor.Badge(palette.Level, "WARN"), " WARN  ", " 4xx ", 1) {
		t.Error("4xx is not in the WARN style")
	}
	if palette.TrueColor.Badge(palette.Severity, "CRITICAL") == palette.TrueColor.Badge(palette.Severity, "HIGH") {
		t.Error("CRITICAL and HIGH must differ")
	}
	if got := len(palette.Labels(palette.Severity)); got != 5 {
		t.Errorf("%d severity labels, want 5", got)
	}
	if got := palette.Names(palette.Semantic); len(got) != 6 {
		t.Errorf("semantic names = %v", got)
	}
	for _, d := range []palette.Depth{palette.TrueColor, palette.Color256, palette.Color16} {
		if d.Text(palette.Semantic, "muted", "x") != d.Text(palette.Chrome, "TIMESTAMP", "x") {
			t.Errorf("depth %d: muted is not the timestamp grey", d)
		}
	}
	if got := palette.Names(palette.Method); len(got) != 5 {
		t.Errorf("method names = %v", got)
	}
}

// The setup roles are the colours its screen was specified in, and each selected and unselected
// pair stays apart at every depth.
func TestSetupRoles(t *testing.T) {
	t.Parallel()
	for name, hex := range map[string]string{
		"pointer": "8AFF80", "name": "80FFEA", "name-dim": "036A96", "value": "9580FF", "value-dim": "644AC9",
		"faint": "454158", "help": "7970A9", "key": "FFCA80", "good": "8AFF80", "bad": "A3144D", "caution": "FFFF80",
	} {
		var r, g, b int
		if _, err := fmt.Sscanf(hex, "%02X%02X%02X", &r, &g, &b); err != nil {
			t.Fatal(err)
		}
		if got, want := palette.TrueColor.Text(palette.Setup, name, "x"), fmt.Sprintf("\x1b[38;2;%d;%d;%dmx\x1b[0m", r, g, b); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if got := len(palette.Names(palette.Setup)); got != 11 {
		t.Errorf("%d setup roles, want 11", got)
	}
	for _, d := range []palette.Depth{palette.TrueColor, palette.Color256, palette.Color16} {
		for _, pair := range [][2]string{{"name", "name-dim"}, {"value", "value-dim"}, {"faint", "help"}, {"good", "bad"}} {
			if d.Text(palette.Setup, pair[0], "x") == d.Text(palette.Setup, pair[1], "x") {
				t.Errorf("depth %d: %s and %s are the same", d, pair[0], pair[1])
			}
		}
	}
	if palette.None.Text(palette.Setup, "name", "x") != "x" {
		t.Error("no colour still styles")
	}
}
