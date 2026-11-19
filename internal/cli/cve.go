package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/cve"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/shellquote"
)

// cveOptions are the flags of nyx cve.
type cveOptions struct {
	fields, timeout, configPath string
}

const (
	// cveConcurrency is how many lookups are in flight at once.
	cveConcurrency = 4
	// maxStdinLine is the longest line nyx cve reads from stdin.
	maxStdinLine = 64 << 10
	// nyxKeysWarning is the warning of a NYX_KEYS_NVD that cve does not read.
	nyxKeysWarning = "NYX_KEYS_NVD is not read; set NVD_API_KEY instead"
)

// newCVECommand builds the cve command: CVE records from the NVD, by CVE ID.
func newCVECommand(inv *invocation) *cobra.Command {
	o := &cveOptions{fields: "all", timeout: "60s"}
	fieldsLine := "Fields accepted by --fields: " + strings.Join(cve.FieldNames(), ", ") + ", all"
	cmd := &cobra.Command{
		Use:   "cve <CVE-ID>... [flags]",
		Short: "Look up CVEs in the NVD by CVE ID",
		Long: "cve looks each CVE ID up in the NVD and returns one record for each ID the NVD holds, in argument\n" +
			"order. A lone - reads the IDs from stdin, one per line. It needs no engagement, writes no files and\n" +
			"contacts only the NVD, paced to its rate limit: 50 requests per 30 seconds with an API key\n" +
			"(NVD_API_KEY, else keys.nvd in the config file), 5 without.",
		Example: "  nyx cve CVE-2021-44228 CVE-2024-3094 --json\n" +
			"  nyx cve - --json < ids.txt\n" +
			"  nyx cve CVE-2021-44228 --fields id,cvss_score,cvss_severity --json",
		Args: cobra.ArbitraryArgs,
		Annotations: map[string]string{
			annotationEveryday: "fields,timeout,config",
			annotationValues:   fieldsLine,
			annotationFooter:   fieldsLine,
		},
		RunE: func(c *cobra.Command, args []string) error {
			return inv.start(c, runCVE(c.Context(), inv, c, args, o))
		},
	}
	f := cmd.Flags()
	f.SortFlags = false
	f.StringVar(&o.fields, "fields", o.fields, "Return only these fields, separated by commas, plus id; all returns every field")
	f.Var(timeoutFlag{&o.timeout}, "timeout", "Deadline for the whole call, e.g. 30s or 2m")
	f.StringVar(&o.configPath, "config", "", configFlagUsage)
	f.BoolP("help", "h", false, "Help for cve")
	return cmd
}

// runCVE checks every flag and argument, reporting all problems in one usage
// error before stdin is read or the NVD is asked, then looks the IDs up and
// writes the records, unless a signal arrived while it did. A warning about
// NYX_KEYS_NVD joins the hint of an error that leaves stdout empty.
func runCVE(ctx context.Context, inv *invocation, cmd *cobra.Command, args []string, o *cveOptions) (err error) {
	started := time.Now() // the deadline counts from here; not d.Clock, which tests fix
	d := inv.d
	warning, wrote := "", false
	defer func() { err = withWarning(err, warning, helpOf(cmd), wrote) }()

	probs := inv.problems()
	fields, unknown := cve.Select(o.fields)
	for _, n := range unknown {
		probs.Add("fields", n, fmt.Sprintf("unknown field %q for --fields", n), cve.ValidFields())
	}
	timeout := parseTimeout(probs, o.timeout, "--timeout 60s")
	// The file's keys.nvd is told apart from NYX_KEYS_NVD, which cve does not read, by loading
	// without it; the error still masks its value.
	env, nyxKeysSet := config.WithoutEnvKey(d.Env, "nvd")
	settings, red := inv.loadSettings(cmd.Flags(), o.configPath, env, probs)
	switch {
	case len(args) == 0:
		probs.Add("", "", "no CVE IDs given: pass one or more, or - to read them from stdin", "nyx --help")
	case slices.Contains(args, "-") && len(args) > 1:
		probs.Add("id", "-", "- reads the IDs from stdin, and is given alone", "pass the IDs as arguments, or - alone")
	}
	key, authHint := cveKey(d.Env, settings, o.configPath)
	if key == "" && nyxKeysSet {
		warning = nyxKeysWarning
	}
	if err := probs.Err(); err != nil {
		return err
	}

	dctx, cancel := context.WithDeadline(ctx, started.Add(timeout))
	defer cancel()
	inputs := args
	if args[0] == "-" {
		if inputs, err = readIDs(dctx, d.Stdin); err != nil {
			return cveEnded(ctx, err)
		}
	}

	em, warnings := newEmitter(inv, red)
	if warning != "" {
		em.Emit(report.Event{Type: "warning", Fields: map[string]any{"message": warning}})
	}
	cfg := cve.Config{HTTP: nvdHTTP(d.Egress, key, red), Keyed: key != "", AuthHint: authHint}
	if inv.sh.debug {
		cfg.Debug = func(msg string) { em.Emit(report.Event{Type: "debug", Fields: map[string]any{"message": msg}}) }
	}
	client := cve.NewClient(cfg)
	results := cveTargets(inputs)
	lookUp(dctx, results, client.Get)
	if ctx.Err() != nil {
		return context.Cause(ctx) // a signal: nothing is written
	}
	records, metaErrs, outErr := cve.Outcome(results, cveRetryCommand(cmd, inv.sh.json, o))
	if outErr != nil && outErr.Code != clierr.Partial {
		return outErr // none succeeded, all with one code: nothing on stdout
	}
	if err := writeCVE(inv, records, metaErrs, fields, warnings, red); err != nil {
		return err
	}
	wrote = inv.sh.json || len(records) > 0 // human mode writes nothing without a record
	if outErr != nil {
		return outErr // not a nil *clierr.Error in a non-nil error
	}
	return nil
}

// withWarning appends the warning to the hint of an error that leaves stdout
// empty: anything but a PARTIAL that wrote to stdout, a usage error included,
// whose default hint is help, as Execute's would be.
func withWarning(err error, warning, help string, wrote bool) error {
	if err == nil || warning == "" {
		return err
	}
	if probs, ok := errors.AsType[clierr.Problems](err); ok {
		err = probs.Usage(help)
	}
	var e *clierr.Error
	if !errors.As(err, &e) || e.Code == clierr.Partial && wrote {
		return err
	}
	if e.Hint == "" {
		e.Hint = warning
	} else {
		e.Hint += "; " + warning
	}
	return e
}

// cveEnded is err, or, when a signal ended ctx, the signal's cause.
func cveEnded(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return err
}

// cveKey is the NVD's API key, "" for none, and the hint of its refusal: the
// trimmed NVD_API_KEY, else keys.nvd from the configuration.
func cveKey(env config.Env, settings config.Settings, configPath string) (key, authHint string) {
	if k := strings.TrimSpace(env.Get("NVD_API_KEY")); k != "" {
		return k, "check NVD_API_KEY"
	}
	if k := strings.TrimSpace(settings.Keys["nvd"].Reveal()); k != "" {
		if configPath == "" {
			configPath = config.DefaultConfigPath(env)
		}
		return k, "check keys.nvd in " + configPath
	}
	return "", ""
}

// readIDs reads the lines of stdin that are not blank, each as given without
// its line ending. The read is abandoned at the deadline or a signal, as a
// stdin that is never closed would otherwise block the call.
func readIDs(ctx context.Context, r io.Reader) ([]string, error) {
	type read struct {
		lines []string
		err   error
	}
	done := make(chan read, 1)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 4096), maxStdinLine)
		var lines []string
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) != "" {
				lines = append(lines, sc.Text())
			}
		}
		done <- read{lines, sc.Err()}
	}()
	select {
	case got := <-done:
		switch {
		case errors.Is(got.err, bufio.ErrTooLong):
			return nil, &clierr.Error{Code: clierr.InvalidInput, Message: "a line on stdin is longer than 64 KiB", Hint: "give one CVE ID per line"}
		case got.err != nil:
			return nil, fmt.Errorf("read stdin: %w", got.err)
		case len(got.lines) == 0:
			return nil, &clierr.Error{Code: clierr.InvalidInput, Message: "no CVE IDs on stdin", Hint: "nyx --help"}
		}
		return got.lines, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &clierr.Error{Code: clierr.Timeout, Message: "stdin was not closed before the deadline",
				Hint: "close stdin, or pass the IDs as arguments"}
		}
		return nil, ctx.Err()
	}
}

// cveTargets are the results to fill, one per argument once normalised and
// deduplicated, in argument order. A malformed argument already holds its
// failure.
func cveTargets(inputs []string) []cve.Result {
	seen := map[string]bool{}
	var out []cve.Result
	for _, in := range inputs {
		id, ok := cve.NormaliseID(in)
		if seen[id] {
			continue
		}
		seen[id] = true
		r := cve.Result{Input: in, ID: id}
		if !ok {
			r.ID = ""
			r.Fail = &cve.Failure{Err: &clierr.Error{Code: clierr.InvalidInput, Message: "not a CVE ID",
				Hint: "expected CVE-YYYY-NNNN, e.g. CVE-2021-44228"}}
		}
		out = append(out, r)
	}
	return out
}

// fetchFunc looks one ID up: a record, or an error that is a *cve.Failure or
// the context's.
type fetchFunc func(context.Context, string) (cve.Record, error)

// lookUp fills each result that has no failure yet with what fetch returns
// for its ID, cveConcurrency at a time.
func lookUp(ctx context.Context, results []cve.Result, fetch fetchFunc) {
	var todo []int
	for i, r := range results {
		if r.Fail == nil {
			todo = append(todo, i)
		}
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(cveConcurrency, len(todo)) {
		wg.Go(func() {
			for {
				j := int(next.Add(1) - 1)
				if j >= len(todo) {
					return
				}
				lookUpOne(ctx, &results[todo[j]], fetch)
			}
		})
	}
	wg.Wait()
}

// lookUpOne fills r with what fetch returns for its ID. A panic is that ID's
// unexpected failure.
func lookUpOne(ctx context.Context, r *cve.Result, fetch fetchFunc) {
	defer func() {
		if v := recover(); v != nil {
			r.Fail = &cve.Failure{Err: &clierr.Error{Code: clierr.Unexpected, Message: (&clierr.PanicError{Value: v}).Error()}}
		}
	}()
	rec, err := fetch(ctx, r.ID)
	var fl *cve.Failure
	switch {
	case err == nil:
		r.Record = &rec
	case errors.As(err, &fl):
		r.Fail = fl
	default: // a context that ended for a signal, which the caller reports
		r.Fail = &cve.Failure{Err: &clierr.Error{Code: clierr.Interrupted, Message: err.Error()}}
	}
}

// nvdHTTP is the client to the NVD: base's options (so tests can redirect it)
// with the key of the "nvd" source, when there is one, and the call's
// redactor. egress's own per-source limit never binds, as the window paces
// every request.
func nvdHTTP(base egress.Options, key string, red *config.Redactor) egress.ThirdPartyHTTP {
	o := base
	o.Keys = nil
	if key != "" {
		o.Keys = map[string]config.Secret{"nvd": config.Secret(key)}
	}
	o.Redactor = red
	o.RatePerSource = math.MaxFloat64 // rate.Inf
	return egress.New(o).Clients(false, []string{cve.Host}).ThirdParty
}

// cveRetryCommand is the command that looks ids up again: nyx cve with the
// flags the caller set, from the parsed flags, shell-quoted.
func cveRetryCommand(cmd *cobra.Command, jsonMode bool, o *cveOptions) cve.HintFunc {
	var flags []string
	if jsonMode {
		flags = append(flags, "--json")
	}
	fs := cmd.Flags()
	for _, f := range []struct{ name, value string }{{"fields", o.fields}, {"timeout", o.timeout}, {"config", o.configPath}} {
		if fs.Changed(f.name) {
			flags = append(flags, "--"+f.name, f.value)
		}
	}
	return func(ids []string) string { return "nyx cve " + shellquote.Join(append(slices.Clone(ids), flags...)) }
}

// cveEnvelope is the --json result of nyx cve.
type cveEnvelope struct {
	Data []cve.Projected `json:"data"`
	Meta cveMeta         `json:"meta"`
}

// cveMeta is the envelope's meta: every key, every time.
type cveMeta struct {
	Count    int         `json:"count"`
	Errors   []errorLine `json:"errors"`
	Warnings []string    `json:"warnings"`
}

// writeCVE writes the records: the envelope under --json, else the cve
// tool's layout, which writes nothing when there is no record.
func writeCVE(inv *invocation, records []cve.Record, metaErrs []*clierr.Error, fields cve.Fields, warnings *report.Warnings, red *config.Redactor) error {
	d := inv.d
	if !inv.sh.json {
		return cve.Render(d.Stdout, records, fields, inv.dp.out, cve.Width(d.Env.Get("COLUMNS")))
	}
	env := cveEnvelope{Data: make([]cve.Projected, len(records)),
		Meta: cveMeta{Count: len(records), Errors: make([]errorLine, len(metaErrs)), Warnings: warnings.List()}}
	for i, r := range records {
		env.Data[i] = fields.Project(r)
	}
	for i, e := range metaErrs {
		env.Meta.Errors[i] = newErrorLine(e, red)
	}
	return lineEncoder(d.Stdout).Encode(env)
}
