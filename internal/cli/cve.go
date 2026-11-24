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

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/lookup/batch"
	"github.com/rafaelh/nyx/internal/lookup/cve"
	"github.com/rafaelh/nyx/internal/recon/report"
)

// cveOptions are the flags of nyx cve.
type cveOptions struct {
	fields, timeout, configPath string
	// Keep limit and match text and occurrence counts for validation and exact retry hints.
	limit, match         string
	limitSets, matchSets int
}

// cveConcurrency is how many lookups are in flight at once.
const cveConcurrency = 4

// newCVECommand configures CVE-ID lookup against NVD.
func newCVECommand(inv *invocation) *cobra.Command {
	o := &cveOptions{timeout: "60s"}
	fieldsLine := "Fields accepted by --fields: " + strings.Join(cve.FieldNames(), ", ") + ", all"
	cmd := &cobra.Command{
		Use:   "cve <CVE-ID>... [flags]",
		Short: "Look up CVEs in the NVD by CVE ID",
		Long: "cve looks each CVE ID up in the NVD and returns one record for each ID the NVD holds, in argument\n" +
			"order. A lone - reads the IDs from stdin, one per line. It needs no engagement, writes no files and\n" +
			"contacts only the NVD, paced to its rate limit: 50 requests per 30 seconds with an API key\n" +
			"(keys.nvd in the config file), 5 without.",
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

// runCVE validates all flags and arguments before reading stdin or contacting NVD, then fetches
// and writes records unless interrupted.
func runCVE(ctx context.Context, inv *invocation, cmd *cobra.Command, args []string, o *cveOptions) (err error) {
	started := time.Now() // the deadline counts from here; not d.Clock, which tests fix
	d := inv.d

	inv.noteNoConfig(o.configPath)
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
	settings, red := inv.loadSettings(fs, o.configPath, probs)
	stdin := lookupArgs(probs, args, cveStdin)
	key, authHint := cveKey(d.Env, settings, o.configPath)
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
	return endLookup(outErr, func() error { return writeCVE(inv, records, metaErrs, view, warnings, red) })
}

// cveView validates the requested field selection, limits and matches. It collects invalid or
// repeated values and flags targeting unselected fields. Unknown field names suppress the
// latter check because the selection is unresolved.
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

// cveKey returns the trimmed configured NVD key and rejection guidance.
func cveKey(env config.Env, settings config.Settings, configPath string) (key, authHint string) {
	secret, _ := settings.Key("nvd") // a blank key is checked after trimming
	if k := strings.TrimSpace(secret.Reveal()); k != "" {
		if configPath == "" {
			configPath = config.DefaultConfigPath(env)
		}
		return k, "check keys.nvd in " + configPath
	}
	return "", ""
}

// cveStdin supplies CVE-specific stdin/error wording.
var cveStdin = stdinWords{none: "no CVE IDs given: pass one or more", key: "id",
	plural: "CVE IDs", perLine: "one CVE ID per line", asArgs: "IDs"}

// cveTargets normalises and deduplicates inputs in argument order, pre-filling invalid-input
// failures.
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

// fetchFunc returns one CVE record or a lookup/context failure.
type fetchFunc func(context.Context, string) (cve.Record, error)

// lookUp fills valid pending slots with bounded concurrent fetches.
func lookUp(ctx context.Context, results []cve.Result, fetch fetchFunc) {
	var todo []int
	for i, r := range results {
		if r.Fail == nil {
			todo = append(todo, i)
		}
	}
	batch.Each(len(todo), cveConcurrency, func(j int) { lookUpOne(ctx, &results[todo[j]], fetch) })
}

// lookUpOne isolates panics as failures of the current ID.
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

// nvdHTTP combines the base egress options, configured NVD key and invocation redactor. The NVD
// sliding window handles pacing before egress's per-source limit can bind.
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

// writeCVE applies the selected fields, limits and matches. JSON includes any list-expansion
// hint in the envelope; human output names the flags for omitted lists and writes nothing for
// an empty result.
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
