package setup

import (
	"fmt"
	"runtime/debug"

	tea "charm.land/bubbletea/v2"

	"github.com/rafaelh/nyx/internal/clierr"
)

// panicMsg is a panic a Cmd recovered, as text with the stack where it happened. The text is
// already a string, so the message never carries a value that could print a key some other way.
type panicMsg struct {
	text  string
	stack []byte
}

// safe wraps cmd so that a panic in it, which nothing in Bubble Tea would recover once its own
// catcher is off, becomes a message. root.Update panics again on that message, inside the code that
// kills the Program and restores the terminal.
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

// guard holds what the root model needs to end the Program when the model panics.
type guard struct {
	// kill ends the Program and restores the terminal; nil until the Program exists.
	kill func()
	// panicErr is the first panic the root recovered.
	panicErr *clierr.PanicError
}

// root is the tea.Model the Program runs. It wraps the model so that a panic in Init, Update or
// View, or in a Cmd, kills the Program (which restores the terminal) and is returned by Run.
type root struct {
	m *model
	g *guard
}

// fail records a panic, with every key the model knows removed from its text, and kills the Program.
func (r *root) fail(text string, stack []byte) {
	if r.g.panicErr == nil {
		r.g.panicErr = scrubbedPanic(r.m, text, stack)
	}
	if r.g.kill != nil {
		r.g.kill()
	}
}

// scrubbedPanic is a panic's text and stack as an error, with every key m knows removed (m may be
// nil, before the model exists).
func scrubbedPanic(m *model, text string, stack []byte) *clierr.PanicError {
	if m != nil {
		text, stack = m.scrub(text), []byte(m.scrub(string(stack)))
	}
	return &clierr.PanicError{Value: text, Stack: stack}
}

// caught is called from a deferred function with what recover returned.
func (r *root) caught(v any) {
	if pm, ok := v.(panicMsg); ok {
		r.fail(pm.text, pm.stack)
		return
	}
	r.fail(fmt.Sprint(v), debug.Stack())
}

// Init implements tea.Model. It does nothing, so it cannot panic.
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
