package setup

import (
	"fmt"
	"runtime/debug"

	tea "charm.land/bubbletea/v2"

	"github.com/rafaelh/nyx/internal/clierr"
)

// panicMsg carries recovered panic text and a stack. Keeping text rather than the original
// value prevents later formatting from exposing a key differently.
type panicMsg struct {
	text  string
	stack []byte
}

// safe converts Cmd panics into messages. root.Update re-panics inside the wrapper that stops
// the Program and restores the terminal, since Bubble Tea's own catcher is disabled.
func safe(cmd tea.Cmd) tea.Cmd {
	if cmd == nil {
		return nil
	}
	return func() (msg tea.Msg) {
		defer func() {
			if r := recover(); r != nil {
				msg = panicMsg{text: fmt.Sprint(r), stack: debug.Stack()}
			}
		}()
		return cmd()
	}
}

// guard lets model panic handling stop the Program.
type guard struct {
	// kill ends the Program and restores the terminal; nil until the Program exists.
	kill func()
	// panicErr is the first panic the root recovered.
	panicErr *clierr.PanicError
}

// root wraps all model and Cmd entry points so a panic stops the Program, restores the terminal
// and returns through Run.
type root struct {
	m *model
	g *guard
}

// fail redacts panic details and stops the Program.
func (r *root) fail(text string, stack []byte) {
	if r.g.panicErr == nil {
		r.g.panicErr = scrubbedPanic(r.m, text, stack)
	}
	if r.g.kill != nil {
		r.g.kill()
	}
}

// scrubbedPanic converts panic text/stack to an error with all known keys removed, including
// before model creation.
func scrubbedPanic(m *model, text string, stack []byte) *clierr.PanicError {
	if m != nil {
		text, stack = m.scrub(text), []byte(m.scrub(string(stack)))
	}
	return &clierr.PanicError{Value: text, Stack: stack}
}

// caught handles a recovered panic from a deferred wrapper.
func (r *root) caught(v any) {
	if pm, ok := v.(panicMsg); ok {
		r.fail(pm.text, pm.stack)
		return
	}
	r.fail(fmt.Sprint(v), debug.Stack())
}

// Init starts no work; model initialisation happens before Program startup.
func (r *root) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (r *root) Update(msg tea.Msg) (next tea.Model, cmd tea.Cmd) {
	defer func() {
		if v := recover(); v != nil {
			r.caught(v)
			next, cmd = r, tea.Quit
		}
	}()
	if pm, ok := msg.(panicMsg); ok {
		panic(pm)
	}
	return r, safe(r.m.update(msg))
}

// View implements tea.Model.
func (r *root) View() (v tea.View) {
	defer func() {
		if p := recover(); p != nil {
			r.caught(p)
			v = tea.NewView("")
			v.AltScreen = true
		}
	}()
	content, cursor := r.m.viewCursor()
	v = tea.NewView(content)
	v.AltScreen = true
	v.Cursor = cursor
	return v
}
