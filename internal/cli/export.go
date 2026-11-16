package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/engagement"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/sanitize"
	"github.com/rafaelh/nyx/internal/store"
)

// The kinds of the lines that are not records: the engagement's inputs and exclusions.
const (
	exportInput     = "input"
	exportExclusion = "exclusion"
)

type exportOptions struct {
	engagement, output, configPath string
	current                        bool
	kinds                          []string
}

// newExportCommand builds the export command. Its help is coloured at depth,
// the colour depth of stdout.
func newExportCommand(o *exportOptions, depth palette.Depth, runFn func(*cobra.Command)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export -e <engagement> [flags]",
		Short: "Write everything recorded about an engagement as JSON lines",
		Long: "export writes one JSON object per line to stdout (or --output) for every record in the engagement,\n" +
			"current or not, and for its inputs and exclusions. It reads a snapshot of the state database, takes no\n" +
			"lock, so it works while a run is in progress, writes nothing to the engagement and makes no network\n" +
			"requests. API keys are never in it.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(c *cobra.Command, _ []string) error {
			runFn(c)
			return nil
		},
	}
	f := cmd.Flags()
	f.SortFlags = false
	f.StringVarP(&o.engagement, "engagement", "e", "", "Engagement name (required)")
	f.StringVar(&o.output, "output", "", "Write to this file, replacing it atomically, instead of stdout")
	f.BoolVar(&o.current, "current", false, "Export only records that are current")
	f.StringArrayVar(&o.kinds, "kind", nil, "Export only this kind (repeatable); the kinds are listed below")
	settings := pflag.NewFlagSet("settings", pflag.ContinueOnError)
	config.RegisterFlags(settings)
	f.AddFlag(settings.Lookup("output-dir")) // read by config.Load, as for a run
	f.StringVar(&o.configPath, "config", "", configFlagUsage)
	f.BoolP("help", "h", false, "Help for export") // replaces cobra's, to capitalise it
	_ = cmd.MarkFlagRequired("engagement")         // only fails for an unknown flag
	cmd.SetHelpFunc(func(c *cobra.Command, _ []string) {
		fmt.Fprint(c.OutOrStdout(), colourHelp(depth, c.Long+"\n\n"+c.UsageString()+"\nKinds accepted by --kind: "+strings.Join(exportKinds(), ", ")+"\n"))
	})
	return cmd
}

// exportKinds are the names --kind accepts: every record kind, then the two
// kinds of line that are not records.
func exportKinds() []string {
	var names []string
	for _, k := range kinds.All() {
		names = append(names, k.Name)
	}
	return append(names, exportInput, exportExclusion)
}

// exportLine is one exported record. The fields are written in this order. An
// entity kind has a Scope and any other kind has Shown.
type exportLine struct {
	Kind      string         `json:"kind"`
	Key       string         `json:"key"`
	Attrs     map[string]any `json:"attrs"`
	Current   bool           `json:"current"`
	FirstSeen string         `json:"first_seen"`
	LastSeen  string         `json:"last_seen"`
	Stages    []string       `json:"stages"`
	Scope     string         `json:"scope,omitempty"`
	Shown     *bool          `json:"shown,omitempty"`
}

// exportInputLine is an input (its Type is root, org, asn or cidr) or an
// exclusion (which has no type).
type exportInputLine struct {
	Kind  string `json:"kind"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
	Added string `json:"added"`
}

func runExport(cmd *cobra.Command, o *exportOptions, d Deps, dp depths) int {
	em := newEmitter(d, &options{}, dp)
	bail := func(code int, err error) int { return fail(em, code, err) }

	valid := exportKinds()
	for _, k := range o.kinds {
		if !slices.Contains(valid, k) {
			return bail(run.ExitInvalid, fmt.Errorf("unknown kind %q for --kind (kinds: %s)", k, strings.Join(valid, ", ")))
		}
	}
	settings, err := config.Load(cmd.Flags(), o.configPath)
	if err != nil {
		return bail(run.ExitInvalid, err)
	}
	red := config.NewRedactor(settings.KeyValues()...)
	em = report.WithRedactor(em, red)
	name, err := input.EngagementName(o.engagement)
	if err != nil {
		return bail(run.ExitInvalid, err)
	}

	db, err := engagement.OpenReadOnly(filepath.Join(settings.OutputDir, name))
	if err != nil {
		return bail(run.ExitFatal, err)
	}
	defer db.Close() // nothing to save: it cannot write

	lines, err := exportSnapshot(db, stageNames(d.Stages), o, red)
	if err != nil {
		return bail(run.ExitFatal, err)
	}
	if err := writeExport(o.output, d.Stdout, lines); err != nil {
		return bail(run.ExitFatal, err)
	}
	return run.ExitOK
}

// exportSnapshot reads the engagement in one read transaction and returns the
// lines to write, inputs and exclusions first and then the records in kind and
// key order, each classified as a run would.
func exportSnapshot(db *store.ReadOnly, order []string, o *exportOptions, red *config.Redactor) ([]any, error) {
	want := func(kind string) bool { return len(o.kinds) == 0 || slices.Contains(o.kinds, kind) }
	var lines []any
	err := db.View(func(r store.Reader) error {
		lines = nil // View may call again, for a run that started while it read
		rows, err := r.Inputs()
		if err != nil {
			return err
		}
		// Inputs come first and then exclusions, each in stored order.
		var exclusions []any
		for _, in := range rows {
			value := cleanText(in.Value, red)
			switch {
			case in.Kind == engagement.InputExclusion:
				if want(exportExclusion) {
					exclusions = append(exclusions, exportInputLine{Kind: exportExclusion, Value: value, Added: in.AddedAt})
				}
			case want(exportInput):
				lines = append(lines, exportInputLine{Kind: exportInput, Type: in.Kind, Value: value, Added: in.AddedAt})
			}
		}
		lines = append(lines, exclusions...)

		var wanted []kinds.Kind
		for _, k := range kinds.All() {
			if want(k.Name) {
				wanted = append(wanted, k)
			}
		}
		if len(wanted) == 0 {
			return nil // only inputs and exclusions: no scope to build
		}
		src := &snapshotSource{r: r, order: order, all: map[string][]store.Record{}}
		built, err := run.BuildScope(engagement.ParseInputs(rows), src)
		if err != nil {
			return err
		}
		for _, k := range wanted {
			h, _ := kinds.Lookup(k.Name)
			recs, err := src.records(k.Name)
			if err != nil {
				return err
			}
			delete(src.all, k.Name) // the scope is built, so nothing reads them again
			for _, rec := range recs {
				if o.current && !rec.Current {
					continue
				}
				l := exportLine{
					Kind: k.Name, Key: cleanText(rec.Key, red), Attrs: cleanAttrs(rec.Attrs, red),
					Current: rec.Current, FirstSeen: rec.FirstSeen, LastSeen: rec.LastSeen, Stages: rec.Stages,
				}
				if l.Stages == nil {
					l.Stages = []string{}
				}
				if k.Entity {
					l.Scope = built.Vis.Placement(h, rec).String()
				} else {
					shown := built.Vis.Shown(h, rec)
					l.Shown = &shown
				}
				lines = append(lines, l)
			}
		}
		return nil
	})
	return lines, err
}

// snapshotSource gives run.BuildScope the records of one snapshot, merged in
// the registry's stage order.
type snapshotSource struct {
	r     store.Reader
	order []string
	all   map[string][]store.Record // every record of the kinds read so far
}

func (s *snapshotSource) records(kind string) ([]store.Record, error) {
	if recs, ok := s.all[kind]; ok {
		return recs, nil
	}
	recs, err := s.r.Records(kind, s.order)
	if err != nil {
		return nil, err
	}
	s.all[kind] = recs
	return recs, nil
}

func (s *snapshotSource) CurrentRecords(k kinds.Named) ([]store.Record, error) {
	recs, err := s.records(k.Name())
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(slices.Clone(recs), func(r store.Record) bool { return !r.Current }), nil
}

func (s *snapshotSource) Observations(k kinds.Named, stage string) ([]store.ObsRow, error) {
	return s.r.Observations(k.Name(), stage)
}

// cleanText is target-supplied text as the console shows it, with any API key masked.
func cleanText(s string, red *config.Redactor) string { return red.Redact(sanitize.Text(s)) }

// cleanAttrs sanitises and redacts every string in a record's attributes. A
// record that is not current has none, and is written as {}.
func cleanAttrs(attrs map[string]any, red *config.Redactor) map[string]any {
	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		out[cleanText(k, red)] = cleanValue(v, red)
	}
	return out
}

func cleanValue(v any, red *config.Redactor) any {
	switch x := v.(type) {
	case string:
		return cleanText(x, red)
	case map[string]any:
		return cleanAttrs(x, red)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = cleanValue(e, red)
		}
		return out
	}
	return v
}

// writeExport writes the lines to stdout, or to the file path, which it
// replaces by renaming a complete temporary file beside it into place. A file
// it replaces keeps its permissions; a new one gets the umask's, as any file
// the shell creates would.
func writeExport(path string, stdout io.Writer, lines []any) (err error) {
	if path == "" {
		return encodeLines(stdout, lines)
	}
	tmp, err := createBeside(path)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = encodeLines(tmp, lines); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if fi, serr := os.Stat(path); serr == nil {
		if err = tmp.Chmod(fi.Mode().Perm()); err != nil {
			return err
		}
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// createBeside creates a new temporary file in path's directory. Unlike
// os.CreateTemp, whose files are 0600 whatever the umask, it creates with 0666
// so the umask decides the mode.
func createBeside(path string) (*os.File, error) {
	for range 100 {
		name := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-"+strconv.FormatUint(rand.Uint64(), 36))
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666)
		if !errors.Is(err, fs.ErrExist) {
			return f, err
		}
	}
	return nil, fmt.Errorf("cannot create a temporary file beside %s", path)
}

func encodeLines(w io.Writer, lines []any) error {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false) // a URL's & stays readable
	for _, l := range lines {
		if err := enc.Encode(l); err != nil { // Encode ends the line
			return err
		}
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	return nil
}
