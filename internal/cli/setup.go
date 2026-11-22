package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/configedit"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/setup"
)

// setupOptions are the flags of nyx setup.
type setupOptions struct{ configPath string }

// newSetupCommand builds the setup command: a full-screen editor for the config file.
func newSetupCommand(inv *invocation) *cobra.Command {
	o := &setupOptions{}
	cmd := &cobra.Command{
		Use:   "setup [flags]",
		Short: "Store API keys and common settings in the config file, and test the keys",
		Long: "setup opens a full-screen editor for the config file: your API keys (each can be tested without being\n" +
			"saved), the output directory and the common settings, and the stages to skip. Edits are held until you\n" +
			"save. It needs a terminal, takes no arguments, and edits only the config file, which is where\n" +
			"every setting and key nyx uses is kept.",
		Example: "  nyx setup\n" +
			"  nyx setup --config ./nyx.yaml",
		Args: cobra.ArbitraryArgs,
		Annotations: map[string]string{
			annotationEveryday: "config",
		},
		RunE: func(c *cobra.Command, positional []string) error {
			return inv.start(c, runSetup(c.Context(), inv, positional, o))
		},
	}
	f := cmd.Flags()
	f.SortFlags = false
	f.StringVar(&o.configPath, "config", "", configFlagUsage)
	f.BoolP("help", "h", false, "Help for setup")
	return cmd
}

// secrets keeps every key value setup has seen, so that an error cannot carry one: the failure
// writer's redactor is rebuilt as each new one is added.
type secrets struct {
	mu     sync.Mutex
	inv    *invocation
	values []string
}

func (s *secrets) add(vs ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.values)
	for _, v := range vs {
		if !slices.Contains(s.values, v) {
			s.values = append(s.values, v)
		}
	}
	if len(s.values) > n || n == 0 {
		// The longest first: the values include each prefix of a key as it is typed, and a prefix
		// masked first would leave the rest of the key in the text.
		vals := slices.Clone(s.values)
		slices.SortStableFunc(vals, func(a, b string) int { return len(b) - len(a) })
		s.inv.fw.setRedactor(config.NewRedactor(vals...))
	}
}

// setupBackend is the configedit store, with the key test added.
type setupBackend struct {
	*configedit.Store
	egress egress.Options
}

// Save and Overwrite give a failed save's reason alone: the editor shows the file's path beside it.
func (b setupBackend) Save(snap setup.Snapshot, edits setup.Edits) (setup.Snapshot, error) {
	snap, err := b.Store.Save(snap, edits)
	return snap, saveReason(err)
}

func (b setupBackend) Overwrite(edits setup.Edits) (setup.Snapshot, error) {
	snap, err := b.Store.Overwrite(edits)
	return snap, saveReason(err)
}

func saveReason(err error) error {
	if se, ok := errors.AsType[*configedit.SaveError](err); ok {
		return errors.New(se.Reason())
	}
	return err
}

func (b setupBackend) Test(ctx context.Context, source string, key config.Secret) setup.TestResult {
	return testKey(ctx, b.egress, source, key)
}

// runSetup checks what can be checked before the terminal is taken over, each failure a usage
// error and in this order: an argument, no path to the config file, no terminal, a file that
// cannot be edited. It then runs the editor.
func runSetup(ctx context.Context, inv *invocation, positional []string, o *setupOptions) error {
	d := inv.d
	if err := inv.problems().Err(); err != nil {
		return err
	}
	if len(positional) > 0 {
		return &clierr.Error{Code: clierr.InvalidInput, Message: "nyx setup takes no arguments",
			Hint: "nyx setup --help", Input: map[string][]string{"argument": positional}}
	}
	path := o.configPath
	if path == "" {
		path = config.DefaultConfigPath(d.Env)
	}
	if path == "" {
		return &clierr.Error{Code: clierr.InvalidInput, Message: "no config file path: neither XDG_CONFIG_HOME nor HOME is set",
			Hint: "pass --config <file>", Input: map[string][]string{"config": {""}}}
	}
	abs := path
	if !filepath.IsAbs(path) {
		// Against the directory nyx was run from, as the editor resolves relative paths.
		if cwd, err := d.Getwd(); err == nil {
			abs = filepath.Join(cwd, path)
		} else if a, err := filepath.Abs(path); err == nil {
			abs = a
		}
	}
	if !d.StdinIsTTY() || !inv.st.out.Terminal {
		return &clierr.Error{Code: clierr.InvalidInput,
			Message: fmt.Sprintf("nyx setup needs a terminal for stdin and stdout, to edit %s", abs),
			Hint:    fmt.Sprintf("edit %s by hand; see the README's Configuration section", abs),
			Input:   map[string][]string{"config": {abs}}}
	}

	names := stageNames(d.Stages)
	store := configedit.NewStore(configedit.StoreOptions{
		Path: abs, Env: d.Env,
		Sources: setupSources(d.Stages), Stages: setupStages(d.Stages),
		SkipEntry: func(name string) string { msg, _ := skipProblem(name, "", names); return msg },
		Getwd:     d.Getwd, NoFsync: d.NoFsync,
	})
	// Every key the file holds is masked before anything can fail, the keys of sources nyx does
	// not know included, which setup never shows.
	seen := &secrets{inv: inv}
	held, _ := config.Load(nil, abs, d.Env) // the keys it holds are returned even when the file has problems
	seen.add(held.KeyValues()...)
	w, h := 0, 0
	if d.WindowSize != nil {
		w, h = d.WindowSize()
	}
	err := setup.Run(ctx, setupBackend{Store: store, egress: d.Egress}, setup.Options{
		In: d.Stdin, Out: inv.rawOut, Env: d.Env, Depth: inv.st.out.Depth, Width: w, Height: h,
		Now:      func() time.Time { return d.Clock().In(d.Location) },
		OnSecret: func(v string) { seen.add(v) },
		OnProgram: func(kill func()) {
			inv.mu.Lock()
			inv.beforeHardExit = kill
			inv.mu.Unlock()
		},
	})
	if fe, ok := errors.AsType[*setup.FileError](err); ok {
		return &clierr.Error{Code: clierr.InvalidInput,
			Message: fmt.Sprintf("cannot edit %s: %s", fe.Path, strings.Join(fe.Problems, "; ")),
			Hint:    "fix the file by hand, or pass --config <file> to edit another",
			Input:   map[string][]string{"config": {fe.Path}}}
	}
	return err
}
