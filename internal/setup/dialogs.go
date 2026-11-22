package setup

import (
	"fmt"

	"github.com/rafaelh/nyx/internal/layout"
)

// wrap lays text out in lines at most w cells wide, with rest cells of indent after the first.
func wrap(text string, w, rest int) []string {
	return layout.Wrap(layout.Plain(text), max(w, 1), 0, rest, layout.Spaces)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// dialogLines is the body while a dialog is open, cut to room lines.
func (m *model) dialogLines(room int) []string {
	w := m.width - 2
	var lines []string
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
	for i, l := range lines {
		lines[i] = fitTo(l, m.width)
	}
	return lines
}

func (m *model) quitLines(w int) []string {
	lines := []string{"Unsaved changes", ""}
	lines = append(lines, wrap(fmt.Sprintf("You have %s to %s.", plural(m.changes(), "unsaved change", "unsaved changes"), m.info.Path), w, 0)...)
	lines = append(lines, "", "Save them before quitting?", "", "  s    save and quit", "  d    discard them and quit", "  esc  go back")
	return lines
}

func (m *model) conflictLines(w, room int) []string {
	n := plural(m.changes(), "unsaved change", "unsaved changes")
	if len(m.dlg.problems) == 0 {
		lines := []string{"The config file changed on disk", ""}
		lines = append(lines, wrap("It changed after setup read it or last saved it: "+m.info.Path, w, 0)...)
		lines = append(lines, "",
			"  r    reload it, which discards your "+n,
			"  o    overwrite it with your changes",
			"  esc  go back")
		return lines
	}
	head := []string{"Reloading the config file found problems", ""}
	head = append(head, wrap(m.text(m.dlg.path)+":", w, 0)...)
	tail := []string{"", "Your " + n + " are kept.",
		"  o    overwrite the file with them",
		"  r    reload again",
		"  esc  go back"}
	var problems []string
	for _, p := range m.dlg.problems {
		problems = append(problems, wrap("- "+m.text(p), w, 2)...)
	}
	if free := room - len(head) - len(tail); len(problems) > free {
		shown := max(free-1, 0)
		problems = append(problems[:shown], fmt.Sprintf("… and more (%s in all)", plural(len(m.dlg.problems), "problem", "problems")))
	}
	return append(append(head, problems...), tail...)
}
