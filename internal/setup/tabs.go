package setup

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// Column widths: the row marks, then the name.
const (
	markW = 2
	nameW = 16
	bodyX = markW + nameW // where a row's value starts
)

// item holds one selectable tab row and an optional editing cursor position.
type item struct {
	lines  []line
	cursor *cursorAt
}

type cursorAt struct{ line, x int }

// marks combines selection and unsaved-change indicators.
func (m *model) marks(selected, changed bool) line {
	l := line{plain(" "), plain(" ")}
	if selected {
		l[0] = m.paint(rolePointer, ">")
	}
	if changed {
		l[1] = m.paint(roleCaution, "*")
	}
	return l
}

// padded styles text and adds plain padding to w cells.
func (m *model) padded(role, s string, w int) line {
	return line{m.paint(role, s), plain(strings.Repeat(" ", max(w-layout.Measure(s), 0)))}
}

// items are the rows of the active tab.
func (m *model) items(t tabID) []item {
	switch t {
	case tabKeys:
		return m.keyItems()
	case tabSettings:
		return m.settingItems()
	case tabSkip:
		return m.skipItems()
	case tabThreat:
		return m.threatItems()
	case tabCount:
	}
	return nil
}

// editing returns the active row's text field, if this row is being edited.
func (m *model) editing(t tabID, i int) *field {
	if m.mode == modeEdit && m.ed != nil && m.ed.tab == t && m.ed.row == i {
		return m.ed.f
	}
	return nil
}

// maskKey shows unset/set or the final four runes when long enough.
func maskKey(k string) string {
	r := []rune(k)
	switch {
	case len(r) == 0:
		return "not set"
	case len(r) < 12:
		return "set"
	}
	return "••••" + sanitize.Line(string(r[len(r)-4:]))
}

// head is a row's marks and its name.
func (m *model) head(selected, changed bool, name string) line {
	return append(m.marks(selected, changed), m.padded(pick(selected, roleName, roleNameDim), name, nameW)...)
}

// note supplies explanatory text beneath a value.
func (m *model) note(text string) line { return line{plain(indent()), m.paint(roleHelp, text)} }

func (m *model) keyItems() []item {
	out := make([]item, 0, len(m.keys))
	for i, r := range m.keys {
		sel := i == m.sel[tabKeys] && m.tab == tabKeys
		head := m.head(sel, r.changed(), r.src.Name)
		var it item
		if f := m.editing(tabKeys, i); f != nil {
			s, x := f.view(max(m.width-bodyX-1, 1))
			it.lines = []line{append(head, m.paint(roleValue, s)), m.note("Type or paste the key; an empty entry clears it")}
			it.cursor = &cursorAt{0, bodyX + x}
		} else {
			value := pick(sel, roleValue, roleValueDim)
			if r.cur == "" {
				value = roleFaint
			}
			status, role := m.keyStatus(r)
			it.lines = []line{
				append(append(head, m.padded(value, maskKey(r.cur.Reveal()), 10)...), m.paint(role, status)),
				m.note(r.src.Turns),
			}
			if r.problem != "" {
				it.lines = append(it.lines, m.noteLines(roleBad, "! "+r.problem)...)
			}
		}
		out = append(out, it)
	}
	return out
}

// keyStatus prefers this session's result, then a visible saved result, then "not tested",
// returning the text and its colour role.
func (m *model) keyStatus(r *keyRow) (string, string) {
	switch {
	case r.testing():
		return "testing…", roleHelp
	case r.result != nil && r.result.Status == TestAccepted:
		return r.result.String(), roleGood
	case r.result != nil && r.result.Status == TestRejected:
		return r.result.String(), roleBad
	case r.result != nil:
		return m.text(r.result.String()), roleCaution
	case r.cur == "":
		return "", roleHelp
	}
	rec, shown := m.fileRecord(r)
	switch {
	case rec == nil:
		return RecordNotTested, roleCaution
	case !shown:
		return "", roleHelp
	case rec.Result == RecordAccepted:
		return RecordAccepted, roleGood
	case rec.Result == RecordRejected:
		return RecordRejected, roleBad
	}
	return RecordNotTested, roleCaution
}

func (m *model) settingItems() []item {
	out := make([]item, 0, len(m.sets))
	for i, r := range m.sets {
		sel := i == m.sel[tabSettings] && m.tab == tabSettings
		head := m.head(sel, r.changed(), r.key)
		var it item
		if f := m.editing(tabSettings, i); f != nil {
			s, x := f.view(max(m.width-bodyX-1, 1))
			it.lines = []line{append(head, m.paint(roleValue, s))}
			it.cursor = &cursorAt{0, bodyX + x}
		} else {
			value := pick(sel, roleValue, roleValueDim)
			if r.set {
				it.lines = []line{append(head, m.paint(value, m.text(r.text)))}
			} else {
				it.lines = []line{append(head, m.paint(value, m.text(r.orig.Default)), m.paint(roleFaint, " (default)"))}
			}
			if rel := r.relative(); rel != "" {
				it.lines = append(it.lines, m.noteLines(roleHelp, rel)...)
			}
			if r.problem != "" {
				it.lines = append(it.lines, m.noteLines(roleBad, "! "+r.problem)...)
			}
		}
		out = append(out, it)
	}
	return out
}

// skipItems marks running stages [x], dims skipped stages and follows them with invalid skip
// entries.
func (m *model) skipItems() []item {
	var out []item
	nameCol := 0
	for _, s := range m.info.Stages {
		nameCol = max(nameCol, layout.Measure(s.Name))
	}
	for i, s := range m.info.Stages {
		sel := i == m.sel[tabSkip] && m.tab == tabSkip
		skipped := slices.Contains(m.skip.on, s.Name)
		changed := skipped != slices.Contains(m.skip.origOn, s.Name)
		box, name, does := "[x] ", pick(sel, roleName, roleNameDim), roleHelp
		if skipped {
			box, name = "[ ] ", pick(sel, roleHelp, roleFaint)
			does = name
		}
		l := append(append(m.marks(sel, changed), m.padded(name, box+s.Name, nameCol+len(box)+2)...), m.paint(does, s.Does))
		out = append(out, item{lines: []line{l}})
	}
	for j, p := range m.skip.problems {
		sel := len(m.info.Stages)+j == m.sel[tabSkip] && m.tab == tabSkip
		out = append(out, item{lines: []line{append(m.marks(sel, false), m.paint(roleBad, "[!] "+m.text(p.Entry)+": "+m.text(p.Message)))}})
	}
	if m.skip.list != "" {
		sel := len(m.info.Stages)+len(m.skip.problems) == m.sel[tabSkip] && m.tab == tabSkip
		out = append(out, item{lines: []line{append(m.marks(sel, false), m.paint(roleBad, "[!] "+m.text(m.skip.list)))}})
	}
	return out
}

// threatItems formats each list's name, source, date, count, active copy, notes and latest
// update result. Source credit and update-unavailable reasons follow the list.
func (m *model) threatItems() []item {
	out := make([]item, 0, len(m.threat))
	for i, r := range m.threat {
		sel := i == m.sel[tabThreat] && m.tab == tabThreat
		l := r.list
		provenance := "built in"
		if l.Downloaded {
			provenance = "downloaded"
		}
		value := pick(sel, roleValue, roleValueDim)
		head := append(m.head(sel, false, m.text(l.List)), m.padded(value, m.text(l.Source), 10)...)
		head = append(head, m.paint(value, m.text(l.Date)))
		lines := []line{
			head,
			{plain(indent()), m.paint(value, fmt.Sprintf("%d entries, %s", l.Entries, provenance))},
		}
		if l.Note != "" {
			lines = append(lines, m.noteLines(roleCaution, l.Note)...)
		}
		switch {
		case m.updating:
			lines = append(lines, m.noteLines(roleHelp, "updating…")...)
		case r.text != "":
			lines = append(lines, m.noteLines(threatRole(r.outcome), r.text)...)
		}
		out = append(out, item{lines: lines})
	}
	foot := m.threatFoot()
	switch {
	case len(foot) == 0:
	case len(out) == 0:
		out = append(out, item{lines: foot})
	default:
		last := &out[len(out)-1]
		last.lines = append(last.lines, foot...)
	}
	return out
}

// threatRole styles each list's update status.
func threatRole(o ThreatOutcome) string {
	switch o {
	case ThreatUpdated:
		return roleGood
	case ThreatSkipped:
		return roleCaution
	case ThreatFailed:
		return roleBad
	case ThreatCurrent:
	}
	return roleHelp
}

// threatFoot shows the first available copyright/terms credit, then any reason updates are
// unavailable.
func (m *model) threatFoot() []line {
	var out []line
	if i := slices.IndexFunc(m.threat, func(r threatEntry) bool { return r.list.Copyright != "" || r.list.Terms != "" }); i >= 0 {
		for _, s := range []string{m.threat[i].list.Copyright, m.threat[i].list.Terms} {
			if s != "" {
				out = append(out, m.noteLines(roleHelp, s)...)
			}
		}
	}
	if why := m.info.ThreatUnavailable; why != "" {
		out = append(out, m.noteLines(roleCaution, why)...)
	}
	if len(out) > 0 {
		out = append([]line{{plain("")}}, out...)
	}
	return out
}

// noteLines wraps notes into at most two lines beyond row indicators.
func (m *model) noteLines(role, text string) []line {
	lines := wrap(m.text(text), m.width-markW, 0)
	if len(lines) > 2 {
		lines = []string{lines[0], lines[1] + "…"}
	}
	out := make([]line, len(lines))
	for i, l := range lines {
		out[i] = line{plain(strings.Repeat(" ", markW)), m.paint(role, l)}
	}
	return out
}

func indent() string { return strings.Repeat(" ", bodyX) }

// bodyHeight reserves an extra row for two-line notices.
func (m *model) bodyHeight() int { return max(m.height-chromeLines-max(len(m.notice)-1, 0), 1) }

// fixScroll moves only enough to keep selection visible.
func (m *model) fixScroll() {
	n := m.rows(m.tab)
	m.sel[m.tab] = max(0, min(m.sel[m.tab], max(n-1, 0)))
	items := m.items(m.tab)
	sel, top, room := m.sel[m.tab], m.top[m.tab], m.bodyHeight()
	top = max(0, min(top, sel))
	for top < sel && heights(items[top:sel+1]) > room {
		top++
	}
	m.top[m.tab] = top
}

func heights(items []item) int {
	n := 0
	for _, it := range items {
		n += len(it.lines)
	}
	return n
}

// position is "3/37" when the tab does not fit.
func (m *model) position() string {
	items := m.items(m.tab)
	if heights(items) <= m.bodyHeight() {
		return ""
	}
	return fmt.Sprintf("%d/%d", m.sel[m.tab]+1, len(items))
}
