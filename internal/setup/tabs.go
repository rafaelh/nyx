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

// item is one selectable row of a tab as lines of text. cursor is where the field's cursor is, when
// the row is being edited.
type item struct {
	lines  []string
	cursor *cursorAt
}

type cursorAt struct{ line, x int }

// marks is the two characters before a row: the selection and whether it holds a change.
func marks(selected, changed bool) string {
	m := []byte("  ")
	if selected {
		m[0] = '>'
	}
	if changed {
		m[1] = '*'
	}
	return string(m)
}

// items are the rows of the active tab, each already cut to the width.
func (m *model) items(t tabID) []item {
	switch t {
	case tabKeys:
		return m.keyItems()
	case tabSettings:
		return m.settingItems()
	case tabSkip:
		return m.skipItems()
	case tabCount:
	}
	return nil
}

// editing is the field of the row being edited, if row i of tab t is it.
func (m *model) editing(t tabID, i int) *field {
	if m.mode == modeEdit && m.ed != nil && m.ed.tab == t && m.ed.row == i {
		return m.ed.f
	}
	return nil
}

// maskKey is how a key shows: not set, set (under twelve runes) or its last four runes.
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

func (m *model) keyItems() []item {
	out := make([]item, 0, len(m.keys))
	for i, r := range m.keys {
		sel := i == m.sel[tabKeys] && m.tab == tabKeys
		name := layout.PadRight(r.src.Name, nameW)
		var it item
		if f := m.editing(tabKeys, i); f != nil {
			s, x := f.view(max(m.width-bodyX-1, 1))
			it.lines = []string{marks(sel, r.changed()) + name + s, indent() + "type or paste the key; an empty entry clears it"}
			it.cursor = &cursorAt{0, bodyX + x}
		} else {
			value := layout.PadRight(maskKey(r.cur.Reveal()), 10)
			status := ""
			switch {
			case r.testing():
				status = "testing…"
			case r.result != nil:
				status = r.result.String()
			}
			line := marks(sel, r.changed()) + name + value + fitTo(m.text(status), m.width-bodyX-10)
			it.lines = []string{line, indent() + r.src.Turns}
			if r.problem != "" {
				it.lines = append(it.lines, m.noteLines("! "+r.problem)...)
			}
		}
		out = append(out, it)
	}
	return cutItems(out, m.width)
}

func (m *model) settingItems() []item {
	out := make([]item, 0, len(m.sets))
	for i, r := range m.sets {
		sel := i == m.sel[tabSettings] && m.tab == tabSettings
		name := layout.PadRight(r.key, nameW)
		var it item
		if f := m.editing(tabSettings, i); f != nil {
			s, x := f.view(max(m.width-bodyX-1, 1))
			it.lines = []string{marks(sel, r.changed()) + name + s}
			it.cursor = &cursorAt{0, bodyX + x}
		} else {
			shown := m.text(r.text)
			if !r.set {
				shown = m.text(r.orig.Default) + " (default)"
			}
			it.lines = []string{marks(sel, r.changed()) + name + shown}
			if rel := r.relative(); rel != "" {
				it.lines = append(it.lines, m.noteLines(rel)...)
			}
			if r.problem != "" {
				it.lines = append(it.lines, m.noteLines("! "+r.problem)...)
			}
		}
		out = append(out, it)
	}
	return cutItems(out, m.width)
}

func (m *model) skipItems() []item {
	var out []item
	nameCol := 0
	for _, s := range m.info.Stages {
		nameCol = max(nameCol, layout.Measure(s.Name))
	}
	for i, s := range m.info.Stages {
		sel := i == m.sel[tabSkip] && m.tab == tabSkip
		on := slices.Contains(m.skip.on, s.Name)
		box := "[ ]"
		if on {
			box = "[x]"
		}
		changed := on != slices.Contains(m.skip.origOn, s.Name)
		out = append(out, item{lines: []string{marks(sel, changed) + box + " " + layout.PadRight(s.Name, nameCol) + "  " + s.Does}})
	}
	for j, p := range m.skip.problems {
		sel := len(m.info.Stages)+j == m.sel[tabSkip] && m.tab == tabSkip
		out = append(out, item{lines: []string{marks(sel, false) + "[!] " + m.text(p.Entry) + ": " + m.text(p.Message)}})
	}
	if m.skip.list != "" {
		sel := len(m.info.Stages)+len(m.skip.problems) == m.sel[tabSkip] && m.tab == tabSkip
		out = append(out, item{lines: []string{marks(sel, false) + "[!] " + m.text(m.skip.list)}})
	}
	return cutItems(out, m.width)
}

// noteLines lays a note under a row out in at most two lines, indented past the row marks.
func (m *model) noteLines(text string) []string {
	lines := wrap(m.text(text), m.width-markW, 0)
	if len(lines) > 2 {
		lines = []string{lines[0], lines[1] + "…"}
	}
	for i, l := range lines {
		lines[i] = strings.Repeat(" ", markW) + l
	}
	return lines
}

func indent() string { return strings.Repeat(" ", bodyX) }

// cutItems cuts every line to the width.
func cutItems(items []item, w int) []item {
	for i := range items {
		for j, l := range items[i].lines {
			items[i].lines[j] = fitTo(l, w)
		}
	}
	return items
}

// bodyHeight is the number of lines the active tab's rows may take.
func (m *model) bodyHeight() int { return max(m.height-chromeLines, 1) }

// fixScroll keeps the selection on the screen: the first row shown moves only as far as it must.
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
