package setup

import (
	"strings"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"

	"github.com/rafaelh/nyx/internal/layout"
)

// The lines the frame spends besides the body: the header, the tabs, two for the notice and two for
// the keys.
const chromeLines = 6

// sizeMessage is all the view shows in a terminal below the minimum size.
const sizeMessage = "make the terminal at least 60×16"

func newHelp() help.Model {
	h := help.New()
	h.Styles = help.Styles{}
	h.ShortSeparator = "  "
	return h
}

// fitTo cuts s to w cells, ending in an ellipsis when it was cut.
func fitTo(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if layout.Measure(s) <= w {
		return s
	}
	var sb strings.Builder
	used := 0
	for _, r := range s {
		rw := layout.Measure(string(r))
		if used+rw > w-1 {
			break
		}
		sb.WriteRune(r)
		used += rw
	}
	return sb.String() + "…"
}

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
	lines := []string{m.header(), m.tabLine()}
	body, cur := m.body()
	lines = append(lines, body...)
	for i := range 2 {
		l := ""
		if i < len(m.notice) {
			l = fitTo(m.notice[i], m.width)
		}
		lines = append(lines, l)
	}
	lines = append(lines, m.footer()...)
	var cursor *tea.Cursor
	if cur != nil {
		cursor = tea.NewCursor(cur.x, 2+cur.line)
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
	count := "no unsaved changes"
	if n := m.changes(); n > 0 {
		count = plural(n, "unsaved change", "unsaved changes")
	}
	left, right := "nyx setup  ", "  "+count
	room := m.width - layout.Measure(left) - layout.Measure(right)
	return fitTo(left+fitTail(m.info.Path, room)+right, m.width)
}

func (m *model) tabLine() string {
	names := [tabCount]string{"Keys", "Settings", "Skip"}
	var parts []string
	for t := range tabCount {
		label := names[t]
		if m.tabChanged(t) {
			label += "*"
		}
		if _, bad := m.invalid(t); bad {
			label += "!"
		}
		if t == m.tab {
			label = "[" + label + "]"
		} else {
			label = " " + label + " "
		}
		parts = append(parts, label)
	}
	line := strings.Join(parts, " ")
	if pos := m.position(); pos != "" {
		gap := m.width - layout.Measure(line) - layout.Measure(pos)
		if gap > 0 {
			line += strings.Repeat(" ", gap) + pos
		}
	}
	return fitTo(line, m.width)
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
			selected := i == m.sel[m.tab]
			if it.cursor != nil && len(lines)+it.cursor.line < room {
				cur = &cursorAt{line: len(lines) + it.cursor.line, x: it.cursor.x}
			}
			for _, l := range it.lines {
				if len(lines) == room {
					break
				}
				if selected && m.mode == modeBrowse {
					l = m.o.Depth.Bold(l)
				}
				lines = append(lines, l)
			}
		}
	}
	for len(lines) < room {
		lines = append(lines, "")
	}
	return lines[:room], cur
}

func bind(keys, desc string) key.Binding {
	return key.NewBinding(key.WithKeys(keys), key.WithHelp(keys, desc))
}

// keymap is the keys the active mode offers, as lines of bindings.
func (m *model) keymap() [][]key.Binding {
	move := []key.Binding{bind("↑/↓", "move"), bind("tab", "switch tab"), bind("q", "quit")}
	switch m.mode {
	case modeEdit:
		return [][]key.Binding{
			{bind("enter", "accept"), bind("esc", "cancel")},
			{bind("←/→", "move"), bind("home/end", "ends"), bind("ctrl+u", "clear")},
		}
	case modeQuit:
		return [][]key.Binding{{bind("s", "save"), bind("d", "discard"), bind("esc", "back")}}
	case modeConflict:
		return [][]key.Binding{{bind("r", "reload"), bind("o", "overwrite"), bind("esc", "back")}}
	case modeBrowse:
	}
	save := bind("ctrl+s", "save")
	switch m.tab {
	case tabKeys:
		return [][]key.Binding{move, {bind("enter", "edit"), bind("t", "test"), bind("x", "clear"), save}}
	case tabSettings:
		return [][]key.Binding{move, {bind("enter", "edit"), bind("x", "clear"), save}}
	case tabSkip:
		return [][]key.Binding{move, {bind("enter", "toggle"), bind("x", "remove entry"), save}}
	case tabCount:
	}
	return nil
}

// footer is two lines of keys.
func (m *model) footer() []string {
	m.help.SetWidth(m.width)
	out := make([]string, 2)
	for i, g := range m.keymap() {
		if i < len(out) {
			out[i] = fitTo(m.help.ShortHelpView(g), m.width)
		}
	}
	return out
}
