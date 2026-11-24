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
	"github.com/rafaelh/nyx/internal/setup"
)

// setupOptions are the flags of nyx setup.
type setupOptions struct {
	configPath       string
	updateThreatData bool
}

// newSetupCommand builds the interactive config editor command.
func newSetupCommand(inv *invocation) *cobra.Command {
	o := &setupOptions{}
	cmd := &cobra.Command{
		Use:   "setup [flags]",
		Short: "Store API keys and common settings in the config file, and test the keys",
		Long: "setup opens a full-screen editor for the config file: your API keys (each can be tested without being\n" +
			"saved), the output directory and the common settings, the stages to skip, and a tab for the threat data nyx\n" +
			"checks addresses against. Edits to the config file are held until you save. It needs a terminal and takes no\n" +
			"arguments. The config file is where every setting and key nyx uses is kept.\n" +
			"\n" +
			"setup --update-threat-data is its one use without the editor (u on the Threat data tab runs the same update):\n" +
			"it downloads Spamhaus's DROP lists and ipapi.is's abuse lists, needs no terminal, reads no config file and\n" +
			"exits. It writes the downloaded copy, and nothing else, to the threat-data directory beside the default\n" +
			"config file: spamhaus.jsonl and ipapi.json, each with a state file and a lock file. Its exit codes are 0 when\n" +
			"no source failed, 7 when one did, 1 when both did, 2 when there is nowhere to keep the data, and 130, 143 or\n" +
			"129 on a signal.",
		Example: "  nyx setup\n" +
			"  nyx setup --config ./nyx.yaml\n" +
			"  nyx setup --update-threat-data",
		Args: cobra.ArbitraryArgs,
		Annotations: map[string]string{
			annotationEveryday: "config," + updateThreatDataFlag,
		},
		RunE: func(c *cobra.Command, positional []string) error {
			return inv.start(c, runSetup(c.Context(), inv, positional, o))
		},
	}
	f := cmd.Flags()
	f.SortFlags = false
	f.StringVar(&o.configPath, "config", "", configFlagUsage)
	f.BoolVar(&o.updateThreatData, updateThreatDataFlag, false,
		"Update the threat data (Spamhaus's DROP lists and ipapi.is's abuse lists) and exit, with no editor, no terminal and no config file")
	f.BoolP("help", "h", false, "Help for setup")
	return cmd
}

// secrets tracks every key setup has seen and rebuilds the failure redactor when new values
// arrive.
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
		// Mask longest values first: masking a typed prefix first would expose the rest
		// of the key.
		vals := slices.Clone(s.values)
		slices.SortStableFunc(vals, func(a, b string) int { return len(b) - len(a) })
		s.inv.fw.setRedactor(config.NewRedactor(vals...))
	}
}

// setupBackend adds credential testing to configedit's file backend.
type setupBackend struct {
	*configedit.Store
	threatKeeper // shared client options for credential tests and threat-list updates
}

// Return only save reasons here; the editor displays the path separately.
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

// runSetup validates arguments, config path, terminal and editable file before starting the UI.
// --update-threat-data branches after argument validation and skips editor-specific checks.
func runSetup(ctx context.Context, inv *invocation, positional []string, o *setupOptions) error {
	d := inv.d
	if err := inv.problems().Err(); err != nil {
		return err
	}
	if len(positional) > 0 {
		return &clierr.Error{Code: clierr.InvalidInput, Message: "nyx setup takes no arguments",
			Hint: "nyx setup --help", Input: map[string][]string{"argument": positional}}
	}
	if o.updateThreatData {
		return runThreatUpdate(ctx, inv)
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
		// Resolve paths from the same working directory as the editor.
		if cwd, err := d.Getwd(); err == nil {
			abs = filepath.Join(cwd, path)
		} else if a, err := filepath.Abs(path); err == nil {
			abs = a
		}
	}
	if !d.StdinIsTTY() || !inv.st.out.Terminal {
		return &clierr.Error{Code: clierr.InvalidInput,
			Message: fmt.Sprintf("nyx setup needs a terminal for stdin and stdout, to edit %s", abs),
			Hint:    fmt.Sprintf("edit %s by hand; see docs/configuration.md in nyx's repository", abs),
			Input:   map[string][]string{"config": {abs}}}
	}

	names := stageNames(d.Stages)
	store := configedit.NewStore(configedit.StoreOptions{
		Path: abs, Env: d.Env,
		Sources: setupSources(d.Stages), Stages: setupStages(d.Stages),
		SkipEntry: func(name string) string { msg, _ := skipProblem(name, "", names); return msg },
		Getwd:     d.Getwd, NoFsync: d.NoFsync,
	})
	// Register all stored keys for redaction before any failure, including unknown sources
	// that setup does not display.
	seen := &secrets{inv: inv}
	held, _ := config.Load(nil, abs, d.Env) // include usable keys for redaction even when validation fails
	seen.add(held.KeyValues()...)
	w, h := 0, 0
	if d.WindowSize != nil {
		w, h = d.WindowSize()
	}
	err := setup.Run(ctx, setupBackend{Store: store, threatKeeper: newThreatKeeper(d)}, setup.Options{
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
