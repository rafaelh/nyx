package setup

import (
	"context"
	"fmt"
	"runtime/debug"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"

	"github.com/rafaelh/nyx/internal/term/palette"
)

// profile maps nyx's colour depth to the Program's.
func profile(d palette.Depth) colorprofile.Profile {
	switch d {
	case palette.None:
		return colorprofile.Ascii
	case palette.Color16:
		return colorprofile.ANSI
	case palette.Color256:
		return colorprofile.ANSI256
	case palette.TrueColor:
		return colorprofile.TrueColor
	}
	return colorprofile.Ascii
}

// Run opens the config through b and runs the editor. Normal quit returns nil; cancellation
// wraps the context error. Panics become clierr.PanicError after restoring the terminal and
// redacting keys. Only explicit saves through b write the file.
func Run(ctx context.Context, b Backend, o Options) (err error) {
	var m *model
	defer func() {
		if v := recover(); v != nil {
			err = scrubbedPanic(m, fmt.Sprint(v), debug.Stack())
		}
	}()
	m, err = newModel(ctx, b, o)
	if err != nil {
		return err
	}
	defer m.stop()
	g := &guard{}
	opts := []tea.ProgramOption{
		tea.WithInput(o.In),
		tea.WithContext(ctx),
		tea.WithoutSignalHandler(),
		tea.WithoutCatchPanics(),
		tea.WithColorProfile(profile(o.Depth)),
	}
	if o.Out != nil {
		opts = append(opts, tea.WithOutput(o.Out))
	}
	if o.Env != nil {
		opts = append(opts, tea.WithEnvironment(o.Env))
	}
	if o.Width > 0 && o.Height > 0 {
		opts = append(opts, tea.WithWindowSize(o.Width, o.Height))
	}
	p := tea.NewProgram(&root{m: m, g: g}, opts...)
	g.kill = p.Kill
	if o.OnProgram != nil {
		o.OnProgram(p.Kill)
	}
	_, err = p.Run()
	if g.panicErr != nil {
		return g.panicErr
	}
	return err
}
