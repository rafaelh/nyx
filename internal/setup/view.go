package setup

import (
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/rafaelh/nyx/internal/layout"
)

// The lines the frame always spends besides the body: the header, the tabs, the rule under them, one
// for the notice and two for the keys.
const chromeLines = 6

// bodyTop is the line the body starts on: after the header, the tabs and the rule.
const bodyTop = 3

// sizeMessage is all the view shows in a terminal below the minimum size.
const sizeMessage = "Make the terminal at least 60×16"

// fitTail cuts s to w cells from its start, so the end of a path stays.
func fitTail(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if layout.Measure(s) <= w {
		return s
	}
	r := []rune(s)
	used, i := 1, len(r)
	for i > 0 {
		rw := layout.Measure(string(r[i-1]))
		if used+rw > w {
			break
		}
		used += rw
		i--
	}
	return "…" + string(r[i:])
}

// view is the frame as text.
func (m *model) view() string {
	s, _ := m.viewCursor()
	return s
}

// viewCursor is the frame and, while a field is being edited, where its cursor is.
func (m *model) viewCursor() (string, *tea.Cursor) {
	if m.width < minWidth || m.height < minHeight {
		return m.tooSmall(), nil
	}
	lines := []string{m.header(), m.tabLine(), m.rule()}
	body, cur := m.body()
	lines = append(lines, body...)
	for i := range max(len(m.notice), 1) {
		l := ""
		if i < len(m.notice) {
			l = fit(line{m.paint(m.noticeRole, m.notice[i])}, m.width)
		}
		lines = append(lines, l)
	}
	lines = append(lines, m.footer()...)
	var cursor *tea.Cursor
	if cur != nil {
		cursor = tea.NewCursor(cur.x, bodyTop+cur.line)
	}
	return strings.Join(lines, "\n"), cursor
}

func (m *model) tooSmall() string {
	if m.width < 1 {
		return ""
	}
	return strings.Join(wrap(sizeMessage, m.width, 0), "\n")
}

func (m *model) header() string {
	count, role := "no unsaved changes", roleHelp
	if n := m.changes(); n > 0 {
		count, role = plural(n, "unsaved change", "unsaved changes"), roleCaution
	}
	const title, gap = "nyx setup", "  "
	room := m.width - layout.Measure(title+gap) - layout.Measure(gap+count)
	return fit(line{m.strong(roleName, title), plain(gap), m.paint(roleHelp, fitTail(m.info.Path, room)), plain(gap), m.paint(role, count)}, m.width)
}

func (m *model) tabLine() string {
	names := [tabCount]string{"Keys", "Settings", "Skip", "Threat data"}
	var l line
	for t := range tabCount {
		if t > 0 {
			l = append(l, plain(" "))
		}
		open, end, name := " ", " ", m.paint(roleNameDim, names[t])
		if t == m.tab {
			open, end, name = "[", "]", m.strong(roleName, names[t])
		}
		l = append(l, m.paint(roleFaint, open), name)
		if m.tabChanged(t) {
			l = append(l, m.paint(roleCaution, "*"))
		}
		if _, bad := m.invalid(t); bad {
			l = append(l, m.paint(roleBad, "!"))
		}
		l = append(l, m.paint(roleFaint, end))
	}
	if pos := m.position(); pos != "" {
		if gap := m.width - l.width() - layout.Measure(pos); gap > 0 {
			l = append(l, plain(strings.Repeat(" ", gap)), m.paint(roleHelp, pos))
		}
	}
	return fit(l, m.width)
}

// rule is the line between the tabs and the body.
func (m *model) rule() string {
	return fit(line{m.paint(roleFaint, strings.Repeat("─", m.width))}, m.width)
}

// body is the lines of the active tab, or of the open dialog, exactly the body height.
func (m *model) body() ([]string, *cursorAt) {
	room := m.bodyHeight()
	var lines []string
	var cur *cursorAt
	switch m.mode {
	case modeQuit, modeConflict:
		lines = m.dialogLines(room)
	case modeBrowse, modeEdit:
		items := m.items(m.tab)
		for i := m.top[m.tab]; i < len(items) && len(lines) < room; i++ {
			it := items[i]
			if it.cursor != nil && len(lines)+it.cursor.line < room {
				cur = &cursorAt{line: len(lines) + it.cursor.line, x: it.cursor.x}
			}
			for _, l := range it.lines {
				if len(lines) == room {
					break
				}
				lines = append(lines, fit(l, m.width))
			}
		}
	}
	for len(lines) < room {
		lines = append(lines, "")
	}
	return lines[:room], cur
}

// keymap is the keys the active mode offers, as lines of hints. The tab key also moves to the next
// tab, and is left out to keep the line short.
func (m *model) keymap() [][]hint {
	move := []hint{{"↑/↓", "Move"}, {"←/→", "Switch tab"}, {"q/esc", "Quit"}}
	switch m.mode {
	case modeEdit:
		return [][]hint{
			{{"enter", "Accept"}, {"esc", "Cancel"}},
			{{"←/→", "Move"}, {"home/end", "Ends"}, {"ctrl+u", "Clear"}},
		}
	case modeQuit:
		return [][]hint{{{"s", "Save"}, {"d", "Discard"}, {"esc", "Back"}}}
	case modeConflict:
		return [][]hint{{{"r", "Reload"}, {"o", "Overwrite"}, {"esc", "Back"}}}
	case modeBrowse:
	}
	save := hint{"ctrl+s", "Save"}
	switch m.tab {
	case tabKeys:
		return [][]hint{move, {{"enter", "Edit"}, {"t", "Test"}, {"x", "Clear"}, save}}
	case tabSettings:
		return [][]hint{move, {{"enter", "Edit"}, {"x", "Clear"}, save}}
	case tabSkip:
		return [][]hint{move, {{"enter", "Toggle"}, {"x", "Remove entry"}, save}}
	case tabThreat:
		return [][]hint{move, {{"u", "Update"}, save}}
	case tabCount:
	}
	return nil
}

// footer is two lines of keys.
func (m *model) footer() []string {
	out := make([]string, 2)
	for i, hs := range m.keymap() {
		if i < len(out) {
			out[i] = fit(m.hints(hs), m.width)
		}
	}
	return out
}
