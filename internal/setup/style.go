package setup

import (
	"strings"

	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
)

// The roles the screen is drawn in, as palette.Setup names them. Where a role comes in a pair the
// first is the selected row's and the second every other row's.
const (
	rolePointer  = "pointer"   // the selection arrow
	roleName     = "name"      // a key's, setting's or stage's name; the active tab
	roleNameDim  = "name-dim"  //
	roleValue    = "value"     // a key or a setting's value
	roleValueDim = "value-dim" //
	roleFaint    = "faint"     // an unset key, the rule under the tabs, a skipped stage
	roleHelp     = "help"      // explanatory text and what a key does
	roleKey      = "key"       // a key to press
	roleGood     = "good"      // an accepted key, a save
	roleBad      = "bad"       // a rejected key, an invalid value
	roleCaution  = "caution"   // an unsaved change, a test that could not check
)

// pick is on for the selected row and off for any other.
func pick(selected bool, on, off string) string {
	if selected {
		return on
	}
	return off
}

// line is one line of the screen as spans: plain text, each styled once the line is cut to the width.
type line []layout.Span

// plain is an unstyled span.
func plain(s string) layout.Span { return layout.Span{Text: s} }

// paint is s in role.
func (m *model) paint(role, s string) layout.Span {
	d := m.o.Depth
	return layout.Span{Text: s, Style: func(t string) string { return d.Text(palette.Setup, role, t) }}
}

// strong is s in role and bold.
func (m *model) strong(role, s string) layout.Span {
	d := m.o.Depth
	return layout.Span{Text: s, Style: func(t string) string { return d.BoldText(palette.Setup, role, t) }}
}

// width is the cells l takes.
func (l line) width() int {
	n := 0
	for _, s := range l {
		n += layout.Measure(s.Text)
	}
	return n
}

// fit cuts l to w cells, ending in an ellipsis when it was cut, and styles each span's part. No
// escape sequence is ever cut.
func fit(l line, w int) string {
	if w <= 0 {
		return ""
	}
	var sb strings.Builder
	if l.width() <= w {
		for _, s := range l {
			sb.WriteString(styled(s, s.Text))
		}
		return sb.String()
	}
	room := w - 1
	for _, s := range l {
		cut, used := take(s.Text, room)
		room -= used
		sb.WriteString(styled(s, cut))
		if cut != s.Text {
			break
		}
	}
	return sb.String() + "…"
}

// take is the longest start of s at most room cells wide, and its width.
func take(s string, room int) (string, int) {
	used := 0
	for i, r := range s {
		rw := layout.Measure(string(r))
		if used+rw > room {
			return s[:i], used
		}
		used += rw
	}
	return s, used
}

func styled(s layout.Span, text string) string {
	if text == "" || s.Style == nil {
		return text
	}
	return s.Style(text)
}

// hint is a key to press and what it does, as the footer lists it.
type hint struct{ keys, does string }

// hints are a line of the footer: each key in the key role, with the "/" between alternatives and
// the "+" of a chord in the help role, as is what it does.
func (m *model) hints(hs []hint) line {
	var l line
	for i, h := range hs {
		if i > 0 {
			l = append(l, plain("  "))
		}
		start := 0
		for j, r := range h.keys {
			if (r == '/' || r == '+') && j > start {
				l = append(l, m.paint(roleKey, h.keys[start:j]), m.paint(roleHelp, string(r)))
				start = j + 1
			}
		}
		l = append(l, m.paint(roleKey, h.keys[start:]), plain(" "), m.paint(roleHelp, h.does))
	}
	return l
}
