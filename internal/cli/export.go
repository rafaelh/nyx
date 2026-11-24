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

// exportLine defines ordered export fields. Procedures lists the procedures observing the record
// now, and Analysis names the analysis that produces it now, if any. Entities carry Scope; other
// kinds carry Shown.
type exportLine struct {
	Kind       string         `json:"kind"`
	Key        string         `json:"key"`
	Attrs      map[string]any `json:"attrs"`
	Current    bool           `json:"current"`
	FirstSeen  string         `json:"first_seen"`
	LastSeen   string         `json:"last_seen"`
	Procedures []string       `json:"procedures"`
	Analysis   string         `json:"analysis,omitempty"`
	Scope      string         `json:"scope,omitempty"`
	Shown      *bool          `json:"shown,omitempty"`
}

// exportInputLine is an input (its Type is root, org, asn or cidr) or an
// exclusion (which has no type).
type exportInputLine struct {
	Kind  string `json:"kind"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value"`
	Added string `json:"added"`
}

// runExport validates inputs before reading/writing a snapshot, discarding output on
// interruption.
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
	// Probe before opening: foreign directories join other validation problems; missing
	// engagements become NOT_FOUND once validation passes.
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

	data, err := exportSnapshot(db, inv.d.Procedures, o, red)
	if err != nil {
		return err
	}
	if ctx.Err() != nil {
		return context.Cause(ctx) // a signal while reading: write nothing
	}
	return writeExport(o.output, inv.d.Stdout, data, !inv.d.NoFsync)
}

// exportSnapshot reads one consistent transaction, writing inputs and exclusions before records
// sorted by kind and key. Classification matches a run. Each row is encoded immediately so
// cleaned attribute copies do not accumulate.
func exportSnapshot(db *store.ReadOnly, procedures []run.Procedure, o *exportOptions, red *config.Redactor) ([]byte, error) {
	var out, exclusions bytes.Buffer
	x := &exporter{o: o, procedures: procedures, names: procedureNames(procedures), analyses: run.AnalysisNames(),
		red: red, enc: lineEncoder(&out), excl: lineEncoder(&exclusions)}
	err := db.View(func(r store.Reader) error {
		out.Reset() // View may call again, for a run that started while it read
		exclusions.Reset()
		rows, err := r.Inputs()
		if err != nil {
			return err
		}
		if err := x.inputs(rows); err != nil {
			return err
		}
		out.Write(exclusions.Bytes())
		return x.records(r, rows)
	})
	return out.Bytes(), err
}

// exporter writes ordered inputs/records and buffers exclusions until inputs are complete.
type exporter struct {
	o          *exportOptions
	procedures []run.Procedure // the registry, in order
	names      []string        // the registry's names, in order
	analyses   []string        // run.AnalysisNames
	red        *config.Redactor
	enc, excl  *json.Encoder
}

// want reports whether --kind selects kind (no --kind selects every kind).
func (x *exporter) want(kind string) bool {
	return len(x.o.kinds) == 0 || slices.Contains(x.o.kinds, kind)
}

// inputs encodes the inputs and the exclusions, each in stored order.
func (x *exporter) inputs(rows []store.Input) error {
	for _, in := range rows {
		value := cleanText(in.Value, x.red)
		switch {
		case in.Kind == engagement.InputExclusion:
			if x.want(exportExclusion) {
				if err := x.excl.Encode(exportInputLine{Kind: exportExclusion, Value: value, Added: in.AddedAt}); err != nil {
					return err
				}
			}
		case x.want(exportInput):
			if err := x.enc.Encode(exportInputLine{Kind: exportInput, Type: in.Kind, Value: value, Added: in.AddedAt}); err != nil {
				return err
			}
		}
	}
	return nil
}

// records exports selected kinds in kind/key order with snapshot-derived scope classification.
func (x *exporter) records(r store.Reader, rows []store.Input) error {
	var wanted []kinds.Kind
	for _, k := range kinds.All() {
		if x.want(k.Name) {
			wanted = append(wanted, k)
		}
	}
	if len(wanted) == 0 {
		return nil // only inputs and exclusions: no scope to build
	}
	src := &snapshotSource{r: r, order: x.names, all: map[string][]store.Record{}}
	built, err := run.BuildScope(engagement.ParseInputs(rows), x.procedures, src)
	if err != nil {
		return err
	}
	for _, k := range wanted {
		recs, err := src.records(k.Name)
		if err != nil {
			return err
		}
		delete(src.all, k.Name) // the scope is built, so nothing reads them again
		if err := x.kind(k, recs, built.Vis); err != nil {
			return err
		}
	}
	return nil
}

// kind encodes the records of one kind, skipping any not current under --current.
func (x *exporter) kind(k kinds.Kind, recs []store.Record, vis *kinds.Visibility) error {
	h, _ := kinds.Lookup(k.Name)
	for _, rec := range recs {
		if x.o.current && !rec.Current {
			continue
		}
		l := exportLine{
			Kind: k.Name, Key: cleanText(rec.Key, x.red), Attrs: cleanAttrs(rec.Attrs, x.red),
			Current: rec.Current, FirstSeen: rec.FirstSeen, LastSeen: rec.LastSeen,
		}
		l.Procedures, l.Analysis = x.splitProducers(rec.Producers)
		if class, placed := vis.Placement(h, rec); placed {
			l.Scope = class.String()
		} else {
			// An entity on record but listed in no file is not shown.
			shown := !k.Entity() && vis.Shown(h, rec)
			l.Shown = &shown
		}
		if err := x.enc.Encode(l); err != nil { // Encode ends the line
			return err
		}
	}
	return nil
}

// splitProducers divides a record's producers into the registry's procedures and the analysis
// that produces it (a record has at most one: see the internal/run package doc). A producer that
// is neither, such as a procedure since removed from the registry, is dropped.
func (x *exporter) splitProducers(producers []string) (procedures []string, analysis string) {
	procedures = []string{}
	for _, p := range producers {
		switch {
		case slices.Contains(x.names, p):
			procedures = append(procedures, p)
		case slices.Contains(x.analyses, p):
			analysis = p
		}
	}
	return procedures, analysis
}

// lineEncoder encodes one JSON value per line to w.
func lineEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // a URL's & stays readable
	return enc
}

// snapshotSource supplies snapshot records merged in registry order to BuildScope.
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

func (s *snapshotSource) Observations(k kinds.Named, procedure string) ([]store.ObsRow, error) {
	return s.r.Observations(k.Name(), procedure)
}

// cleanText sanitises display text and masks API keys.
func cleanText(s string, red *config.Redactor) string { return red.Redact(sanitize.Text(s)) }

// cleanAttrs cleans/redacts attribute strings. Non-current records have no attributes and
// encode as {}.
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

// writeExport writes stdout or atomically replaces a file through a neighbouring temporary
// file. Replacements keep permissions; new files use the umask. When enabled, fsync precedes
// rename.
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

// createBeside uses mode 0666 plus umask for new export files; os.CreateTemp would force 0600.
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
