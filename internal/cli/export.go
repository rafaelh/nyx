package cli

import (
	"bytes"
	"context"
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

// newExportCommand builds recon's export command.
func newExportCommand(inv *invocation) *cobra.Command {
	o := &exportOptions{}
	kindsLine := exportKindsLine()
	cmd := &cobra.Command{
		Use:   "export -e <engagement> [flags]",
		Short: "Write everything recorded about an engagement as JSON lines",
		Long: "export writes one JSON object per line to stdout (or --output) for every record in the engagement,\n" +
			"current or not, and for its inputs and exclusions. It reads a snapshot of the state database, takes no\n" +
			"lock, so it works while a run is in progress, writes nothing to the engagement and makes no network\n" +
			"requests. API keys are never in it.",
		Example: "  nyx recon export -e example.com --json\n" +
			"  nyx recon export -e example.com --current --kind finding --output findings.jsonl --json",
		Args: cobra.NoArgs,
		Annotations: map[string]string{
			annotationValues: kindsLine,
			annotationFooter: kindsLine,
		},
		RunE: func(c *cobra.Command, _ []string) error {
			return inv.start(c, runExport(c.Context(), inv, c, o))
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
	f.BoolP("help", "h", false, "Help for export")
	return cmd
}

// exportKindsLine names the values --kind accepts.
func exportKindsLine() string {
	return "Kinds accepted by --kind: " + strings.Join(exportKinds(), ", ")
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

// runExport checks every value, reporting all problems in one usage error,
// then writes the snapshot unless a signal arrived while it was read.
func runExport(ctx context.Context, inv *invocation, cmd *cobra.Command, o *exportOptions) error {
	probs := inv.problems()
	if o.engagement == "" {
		probs.Add("engagement", "", "missing -e: name the engagement to export", "nyx recon export -e <engagement>")
	}
	valid := exportKinds()
	for _, k := range o.kinds {
		if !slices.Contains(valid, k) {
			probs.Add("kind", k, fmt.Sprintf("unknown kind %q for --kind", k), "kinds: "+strings.Join(valid, ", "))
		}
	}
	settings, red := inv.loadSettings(cmd.Flags(), o.configPath, probs)
	var name string
	if o.engagement != "" {
		var err error
		if name, err = input.EngagementName(o.engagement); err != nil {
			probs.Add("engagement", o.engagement, err.Error(), "")
		}
	}
	if o.output != "" {
		if fi, err := os.Stat(filepath.Dir(o.output)); err != nil || !fi.IsDir() {
			probs.Add("output", o.output, "the directory of --output does not exist: "+filepath.Dir(o.output), "")
		}
	}
	// The directory is probed before it is opened, so the error says what is wrong with it: a
	// directory that is not an engagement is a usage problem, reported with any other, and one
	// that does not exist is not found once nothing else is wrong.
	absent, probeErr := probeEngagement(probs, settings.OutputDir, name, o.engagement)
	if err := probs.Err(); err != nil {
		return err
	}
	// A directory the probe could not read is reported only once every usage problem has been.
	if probeErr != nil {
		return probeErr
	}
	if absent {
		return engagementNotFound(settings.OutputDir, name, o.engagement, false)
	}

	db, err := engagement.OpenReadOnly(filepath.Join(settings.OutputDir, name))
	if err != nil {
		return err
	}
	defer db.Close() // nothing to save: it cannot write

	data, err := exportSnapshot(db, stageNames(inv.d.Stages), o, red)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return context.Cause(ctx) // a signal while reading: write nothing
	}
	return writeExport(o.output, inv.d.Stdout, data, !inv.d.NoFsync)
}

// exportSnapshot reads the engagement in one read transaction and returns the
// JSON lines to write, inputs and exclusions first and then the records in
// kind and key order, each classified as a run would. Each line is encoded as
// it is built, so the cleaned copy of a record's attributes is not kept.
//
//nolint:gocognit // TODO: split; predates the complexity ceiling
func exportSnapshot(db *store.ReadOnly, order []string, o *exportOptions, red *config.Redactor) ([]byte, error) {
	want := func(kind string) bool { return len(o.kinds) == 0 || slices.Contains(o.kinds, kind) }
	var out, exclusions bytes.Buffer
	enc, excl := lineEncoder(&out), lineEncoder(&exclusions)
	err := db.View(func(r store.Reader) error {
		out.Reset() // View may call again, for a run that started while it read
		exclusions.Reset()
		rows, err := r.Inputs()
		if err != nil {
			return err
		}
		// Inputs come first and then exclusions, each in stored order.
		for _, in := range rows {
			value := cleanText(in.Value, red)
			switch {
			case in.Kind == engagement.InputExclusion:
				if want(exportExclusion) {
					if err := excl.Encode(exportInputLine{Kind: exportExclusion, Value: value, Added: in.AddedAt}); err != nil {
						return err
					}
				}
			case want(exportInput):
				if err := enc.Encode(exportInputLine{Kind: exportInput, Type: in.Kind, Value: value, Added: in.AddedAt}); err != nil {
					return err
				}
			}
		}
		out.Write(exclusions.Bytes())

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
				if err := enc.Encode(l); err != nil { // Encode ends the line
					return err
				}
			}
		}
		return nil
	})
	return out.Bytes(), err
}

// lineEncoder encodes one JSON value per line to w.
func lineEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // a URL's & stays readable
	return enc
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

// writeExport writes data to stdout, or to the file path, which it
// replaces by renaming a complete temporary file beside it into place. A file
// it replaces keeps its permissions; a new one gets the umask's, as any file
// the shell creates would. With fsync, the file reaches the disk before the rename.
func writeExport(path string, stdout io.Writer, data []byte, fsync bool) (err error) {
	if path == "" {
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("write export: %w", err)
		}
		return nil
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
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if fsync {
		if err = tmp.Sync(); err != nil {
			return err
		}
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
