package cli

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rafaelh/nyx/internal/batch"
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/cve"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/report"
)

// cveOptions are the flags of nyx cve.
type cveOptions struct {
	fields, timeout, configPath string
	// limit and match are kept as given, with how many times each was set, so that an
	// invalid or repeated one is a usage error and the retry command repeats it as typed.
	limit, match         string
	limitSets, matchSets int
}

const (
	// cveConcurrency is how many lookups are in flight at once.
	cveConcurrency = 4
	// nyxKeysWarning is the warning of a NYX_KEYS_NVD that cve does not read.
	nyxKeysWarning = "NYX_KEYS_NVD is not read; set NVD_API_KEY instead"
)

// newCVECommand builds the cve command: CVE records from the NVD, by CVE ID.
func newCVECommand(inv *invocation) *cobra.Command {
	o := &cveOptions{timeout: "60s"}
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
			"  nyx cve CVE-2021-44228 --fields id,cvss_score,cvss_severity --json\n" +
			"  nyx cve CVE-2021-44228 --fields affected_products --match log4j --limit 10 --json",
		Args: cobra.ArbitraryArgs,
		Annotations: map[string]string{
			annotationEveryday: "fields,limit,match,timeout,config",
			annotationValues:   fieldsLine,
			annotationFooter:   fieldsLine,
		},
		RunE: func(c *cobra.Command, args []string) error {
			return inv.start(c, runCVE(c.Context(), inv, c, args, o))
		},
	}
	f := cmd.Flags()
	f.SortFlags = false
	f.StringVar(&o.fields, "fields", "", "Return only these fields, separated by commas, plus id; all returns every field "+
		"(without it, all but affected_products and references, which are counted instead)")
	f.Var(rawFlag{&o.limit, &o.limitSets, "int"}, "limit", "Show at most this many entries of each of affected_products and references that --fields shows")
	f.Var(rawFlag{&o.match, &o.matchSets, "string"}, "match", "Keep only the entries of affected_products and references that contain this text, ignoring case")
	f.Var(timeoutFlag(&o.timeout), "timeout", "Deadline for the whole call, e.g. 30s or 2m")
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
	fs := cmd.Flags()
	fields, unknown := cve.Select(o.fields)
	if !fs.Changed("fields") {
		fields = cve.DefaultFields()
	}
	for _, n := range unknown {
		probs.Add("fields", n, fmt.Sprintf("unknown field %q for --fields", n), cve.ValidFields())
	}
	view := cveView(probs, o, fields, len(unknown) == 0)
	timeout := parseTimeout(probs, o.timeout, "--timeout 60s")
	// The file's keys.nvd is told apart from NYX_KEYS_NVD, which cve does not read, by loading
	// without it; the error still masks its value.
	env, nyxKeysSet := config.WithoutEnvKey(d.Env, "nvd")
	settings, red := inv.loadSettings(fs, o.configPath, env, probs)
	stdin := lookupArgs(probs, args, cveStdin)
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
	if stdin {
		if inputs, err = readLines(dctx, d.Stdin, cveStdin); err != nil {
			return err
		}
	}

	em, warnings := newEmitter(inv, red)
	if warning != "" {
		report.Say(em, "warning")(warning)
	}
	cfg := cve.Config{HTTP: nvdHTTP(d.Egress, key, red), Keyed: key != "", AuthHint: authHint}
	if inv.sh.debug {
		cfg.Debug = report.Say(em, "debug")
	}
	client := cve.NewClient(cfg)
	results := cveTargets(inputs)
	lookUp(dctx, results, client.Get)
	if ctx.Err() != nil {
		return context.Cause(ctx) // a signal: nothing is written
	}
	retry := retryCommand("cve", inv.sh.json, fs, "fields", "timeout", "config", "limit", "match")
	records, metaErrs, outErr := cve.Outcome(results, retry)
	wrote = inv.sh.json || len(records) > 0 // for a PARTIAL, which writes; human mode writes nothing without a record
	return endLookup(outErr, func() error { return writeCVE(inv, records, metaErrs, view, warnings, red) })
}

// cveView is the cut --fields, --limit and --match ask for, with each problem they have added to
// probs: a --limit that is not a positive whole number, a --match with no text, either given twice,
// and a flag with nothing to act on. The last is left unsaid when --fields has unknown names, as the
// selection is then unknown too.
func cveView(probs *clierr.Problems, o *cveOptions, fields cve.Fields, known bool) cve.View {
	view := cve.View{Fields: fields}
	if o.limitSets > 0 {
		n, err := strconv.Atoi(o.limit)
		switch {
		case o.limitSets > 1:
			probs.Add("limit", o.limit, "--limit was given more than once", "pass --limit once")
		case errors.Is(err, strconv.ErrRange) && !strings.HasPrefix(o.limit, "-"):
			probs.Add("limit", o.limit, fmt.Sprintf("--limit: invalid value %q: too large", o.limit), "e.g. --limit 10")
		case err != nil || n <= 0:
			probs.Add("limit", o.limit, fmt.Sprintf("--limit: invalid value %q: not a positive whole number", o.limit), "e.g. --limit 10")
		default:
			view.Limit = n
		}
		if known && !fields.ShowsList() {
			probs.Add("limit", o.limit, "--limit has no list to cut: --fields shows neither affected_products nor references",
				"add affected_products or references to --fields")
		}
	}
	if o.matchSets > 0 {
		switch {
		case o.matchSets > 1:
			probs.Add("match", o.match, "--match was given more than once", "pass --match once")
		case strings.TrimSpace(o.match) == "":
			probs.Add("match", o.match, "--match has no text to look for", "e.g. --match log4j")
		default:
			view.Match = o.match // View.Project trims it
		}
		if known && !fields.ShowsCount() { // a list brings its count
			probs.Add("match", o.match, "--match has no list or count to match: --fields shows neither",
				"add affected_products, references or their counts to --fields")
		}
	}
	return view
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

// cveStdin is what nyx cve reads from stdin.
var cveStdin = stdinWords{none: "no CVE IDs given: pass one or more", key: "id",
	plural: "CVE IDs", perLine: "one CVE ID per line", asArgs: "IDs"}

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
	batch.Each(len(todo), cveConcurrency, func(j int) { lookUpOne(ctx, &results[todo[j]], fetch) })
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

// writeCVE writes the records cut by view: the envelope, with the note on how to see the lists the
// view leaves out as its hint, under --json, else the cve tool's layout, which writes nothing when
// there is no record and names the flag of each list it leaves out in that list's heading.
func writeCVE(inv *invocation, records []cve.Record, metaErrs []*clierr.Error, view cve.View, warnings *report.Warnings, red *config.Redactor) error {
	projected := make([]cve.Projected, len(records))
	for i, r := range records {
		projected[i] = view.Project(r)
	}
	if !inv.sh.json {
		return cve.Render(inv.d.Stdout, projected, inv.st.out, red, inv.d.Location)
	}
	return writeEnvelope(inv, projected, metaErrs, warnings, cve.ListHint(projected), red)
}
