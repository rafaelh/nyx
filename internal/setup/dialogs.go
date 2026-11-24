package setup

import (
	"fmt"

	"github.com/rafaelh/nyx/internal/term/layout"
)

// wrap limits text to w cells with rest-cell continuation indentation.
func wrap(text string, w, rest int) []string {
	return layout.Wrap(layout.Plain(text), max(w, 1), 0, rest, layout.Spaces)
}

// plainLines applies one role to text lines; empty role leaves them plain.
func (m *model) plainLines(role string, lines []string) []line {
	out := make([]line, len(lines))
	for i, l := range lines {
		out[i] = line{plain(l)}
		if role != "" {
			out[i] = line{m.paint(role, l)}
		}
	}
	return out
}

// title is a dialog's first line.
func (m *model) title(s string) line { return line{m.strong(roleName, s)} }

// choice formats a dialog shortcut and its description.
func (m *model) choice(key, does string) line {
	return line{plain("  "), m.paint(roleKey, key), plain(layout.PadRight("", 5-layout.Measure(key))), plain(does)}
}

// dialogLines limits an open dialog to available body rows.
func (m *model) dialogLines(room int) []string {
	w := m.width - 2
	var lines []line
	switch m.mode {
	case modeQuit:
		lines = m.quitLines(w)
	case modeConflict:
		lines = m.conflictLines(w, room)
	case modeBrowse, modeEdit:
	}
	if len(lines) > room {
		lines = lines[:room]
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = fit(l, m.width)
	}
	return out
}

func (m *model) quitLines(w int) []line {
	lines := []line{m.title("Unsaved changes"), nil}
	lines = append(lines, m.plainLines("", wrap(fmt.Sprintf("You have %s to %s.", layout.Count(m.changes(), "unsaved change", "unsaved changes"), m.info.Path), w, 0))...)
	return append(lines, nil, line{plain("Save them before quitting?")}, nil,
		m.choice("s", "Save and quit"),
		m.choice("d", "Discard them and quit"),
		m.choice("esc", "Go back"))
}

func (m *model) conflictLines(w, room int) []line {
	n := layout.Count(m.changes(), "unsaved change", "unsaved changes")
	if len(m.dlg.problems) == 0 {
		lines := []line{m.title("The config file changed on disk"), nil}
		lines = append(lines, m.plainLines("", wrap("It changed after setup read it or last saved it: "+m.info.Path, w, 0))...)
		return append(lines, nil,
			m.choice("r", "Reload it, which discards your "+n),
			m.choice("o", "Overwrite it with your changes"),
			m.choice("esc", "Go back"))
	}
	head := []line{m.title("Reloading the config file found problems"), nil}
	head = append(head, m.plainLines("", wrap(m.text(m.dlg.path)+":", w, 0))...)
	tail := []line{nil, line{plain("Your " + n + " are kept.")},
		m.choice("o", "Overwrite the file with them"),
		m.choice("r", "Reload again"),
		m.choice("esc", "Go back")}
	var problems []line
	for _, p := range m.dlg.problems {
		problems = append(problems, m.plainLines(roleBad, wrap("- "+m.text(p), w, 2))...)
	}
	if free := room - len(head) - len(tail); len(problems) > free {
		shown := max(free-1, 0)
		problems = append(problems[:shown], line{m.paint(roleHelp, fmt.Sprintf("… and more (%s in all)", layout.Count(len(m.dlg.problems), "problem", "problems")))})
	}
	return append(append(head, problems...), tail...)
}
