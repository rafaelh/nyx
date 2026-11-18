package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/engagement"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/run"
)

type reconOptions struct {
	domainsFile, excludeFile, engagement, redo, configPath string
	orgs, asns, cidrs, exclude                             []string
	passive, authorised, allowLarge, palette               bool
	timeout                                                string
}

// configFlagUsage is the help of --config, for recon and for export.
const configFlagUsage = "Config file (default $XDG_CONFIG_HOME/nyx/config.yaml, else ~/.config/nyx/config.yaml)"

// reconEveryday are the recon flags the root help shows; the rest are tuning
// settings, listed by nyx recon --help.
var reconEveryday = []string{"domains-file", "org", "asn", "cidr", "exclude", "exclude-file", "engagement",
	"passive", "authorised", "redo", "skip", "allow-large-netblocks", "timeout", "config", "output-dir"}

// interruptedRecon is what to do after a signal ends a run.
const interruptedRecon = "completed work is saved; run the same command again to continue"

// newReconCommand builds the recon command: everything nyx did before it had
// commands.
func newReconCommand(inv *invocation) *cobra.Command {
	o := &reconOptions{}
	names := stageNames(inv.d.Stages)
	cmd := &cobra.Command{
		Use:   "recon [domain...] [flags]",
		Short: "Passive-first reconnaissance of a target's domains, organisations and netblocks",
		Long: "recon records a target's hosts, IPs, web services, URLs and open ports, plus a severity-ranked\n" +
			"list of obvious exposures, using only third-party sources and the kind of contact any member of\n" +
			"the public could make. Results go to the console and to TXT/CSV files in an engagement directory.\n" +
			"Re-run with the same engagement (nyx recon -e <name>) to resume.",
		Example: "  nyx recon example.com --json --timeout 30m\n" +
			"  nyx recon example.com --org 'Example Pty Ltd' --authorised --json --timeout 30m\n" +
			"  nyx recon -e example.com --redo crtsh --json --timeout 30m",
		Args: cobra.ArbitraryArgs,
		Annotations: map[string]string{
			annotationEveryday: strings.Join(reconEveryday, ","),
			annotationValues: "Stages accepted by --redo and --skip: " + strings.Join(names, ", ") + "\n" +
				"Stages --skip refuses: " + strings.Join(unskippable, ", "),
			annotationNote:   "Tuning settings (rates, limits, ports, lists and the rest) are listed by nyx recon --help.",
			annotationFooter: reconFooter,
		},
		RunE: func(c *cobra.Command, positional []string) error {
			return inv.start(c, runRecon(c.Context(), inv, c, positional, names, o))
		},
	}
	f := cmd.Flags()
	f.SortFlags = false
	f.StringVarP(&o.domainsFile, "domains-file", "d", "", "File of root domains, one per line (# comments allowed)")
	f.StringArrayVar(&o.orgs, "org", nil, "Organisation name (repeatable)")
	f.StringArrayVar(&o.asns, "asn", nil, "ASN, AS123 or 123; its announced netblocks become in scope (repeatable)")
	f.StringArrayVar(&o.cidrs, "cidr", nil, "Netblock in CIDR notation (repeatable)")
	f.StringArrayVarP(&o.exclude, "exclude", "x", nil, "Excluded hostname, *.wildcard or CIDR (repeatable)")
	f.StringVar(&o.excludeFile, "exclude-file", "", "File of exclusions, one per line (# comments allowed)")
	f.StringVarP(&o.engagement, "engagement", "e", "", "Engagement name (default: derived from the first input)")
	f.BoolVar(&o.passive, "passive", false, "Use third-party sources only; never contact target-owned systems")
	f.BoolVar(&o.authorised, "authorised", false, "Confirm you are authorised to test this scope, for this and later runs (alias --authorized)")
	f.BoolVar(&o.allowLarge, "allow-large-netblocks", false, "Proceed even if in-scope IPv4 netblocks exceed --netblock-limit")
	f.StringVar(&o.redo, "redo", "", "Re-perform every check of one stage (see nyx help stages)")
	f.Var(timeoutFlag{&o.timeout}, "timeout", "Stop by this deadline, e.g. 30m or 2h, and exit 7; run again to carry on (default: none)")
	f.BoolVar(&o.palette, "palette", false, "Print the colour palette sheet and exit")
	_ = f.MarkHidden("palette") // only fails for an unknown flag
	f.StringVar(&o.configPath, "config", "", configFlagUsage)
	config.RegisterFlags(f)
	f.BoolP("help", "h", false, "Help for recon")
	f.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if name == "authorized" {
			name = "authorised"
		}
		return pflag.NormalizedName(name)
	})
	return cmd
}

// reconFooter is what recon's own help shows after its flags.
const reconFooter = `Configuration:
  Settings come from a YAML config file, NYX_* environment variables or flags; flags override
  environment variables, which override the file. The default config file is
  $XDG_CONFIG_HOME/nyx/config.yaml (default ~/.config/nyx/config.yaml).
  Environment variables are NYX_<SETTING> with dots as underscores, e.g. NYX_CONCURRENCY and
  NYX_RATE_PER_HOST. API keys are never flags: set keys.<source> in the config file or
  NYX_KEYS_<SOURCE> in the environment.
`

// runRecon checks every value and combination, reporting all problems in one
// usage error before anything is created or contacted, then runs the
// engagement.
func runRecon(ctx context.Context, inv *invocation, cmd *cobra.Command, positional, names []string, o *reconOptions) error {
	started := time.Now() // the deadline counts from here; not d.Clock, which tests fix
	d := inv.d
	if o.palette {
		// First, so that a broken config, a missing scope or stray inputs do not matter, and
		// nothing is created or contacted.
		report.Sheet(d.Stdout, inv.helpDepth(), d.Clock().In(d.Location))
		return nil
	}
	probs := inv.problems()
	settings, red := inv.loadSettings(cmd.Flags(), o.configPath, probs)
	var timeout time.Duration
	if cmd.Flags().Changed("timeout") {
		var err error
		if timeout, err = time.ParseDuration(o.timeout); err != nil || timeout <= 0 {
			probs.Add("timeout", o.timeout, fmt.Sprintf("timeout: invalid value %q: not a positive duration", o.timeout), "--timeout 30m")
		}
	}

	parsed, perr := input.Parse(input.Raw{
		Domains: positional, DomainsFile: o.domainsFile, Orgs: o.orgs, ASNs: o.asns, CIDRs: o.cidrs,
		Exclude: o.exclude, ExcludeFile: o.excludeFile,
	})
	probs.Merge(perr)
	noInputs := len(positional) == 0 && o.domainsFile == "" && len(o.orgs)+len(o.asns)+len(o.cidrs) == 0
	var name string
	switch {
	case o.engagement != "":
		n, err := input.EngagementName(o.engagement)
		if err != nil {
			probs.Add("engagement", o.engagement, err.Error(), "")
			break
		}
		name = n
	case noInputs:
		probs.Add("", "", "no inputs: give domains, --org, --asn or --cidr, or -e <engagement> to resume one", "")
	case perr == nil:
		n, err := input.EngagementName(parsed.First)
		if err != nil {
			probs.Add("engagement", parsed.First, err.Error()+"; name the engagement with -e", "")
		}
		name = n
	}
	// Opening an engagement creates it, so the directory is probed first: one that is not
	// an engagement is refused, and one that does not exist is refused when there is
	// nothing to start it with.
	given := o.engagement
	if given == "" {
		given = parsed.First
	}
	absent, probeErr := probeEngagement(probs, settings.OutputDir, name, given)
	absent = absent && noInputs
	if o.redo != "" && !slices.Contains(names, o.redo) {
		probs.Add("redo", o.redo, fmt.Sprintf("unknown stage %q for --redo", o.redo), "valid stages: "+strings.Join(names, ", "))
	}
	validateSkip(probs, settings.Skip, o.redo, names)
	if err := probs.Err(); err != nil {
		return err
	}
	// A directory the probe could not read is reported only once every usage problem has been.
	if probeErr != nil {
		return probeErr
	}
	if absent {
		return engagementNotFound(settings.OutputDir, name, o.engagement, true)
	}

	eng, err := engagement.Open(filepath.Join(settings.OutputDir, name), engagement.Options{Clock: d.Clock, Redactor: red})
	if err != nil {
		return openError(err, given)
	}
	engOpen := true
	defer func() {
		if engOpen {
			eng.Close() // the error that ended the run is the one reported
		}
	}()
	if err := eng.MergeInputs(parsed); err != nil {
		return err
	}
	stored, err := eng.Inputs()
	if err != nil {
		return err
	}
	if stored.Empty() {
		return &clierr.Error{Code: clierr.InvalidInput,
			Message: fmt.Sprintf("engagement %s has no scope; give domains, --org, --asn or --cidr", name),
			Hint:    "nyx recon --help", Input: map[string][]string{"engagement": {o.engagement}}}
	}
	if o.authorised {
		if err := eng.SetAck(); err != nil {
			return err
		}
	}
	inv.setInterruptHint(interruptedRecon)

	base, warnings := newEmitter(d, inv.sh, inv.dp)
	if d.Events != nil {
		base = report.Tee(base, d.Events)
	}
	em := report.WithRedactor(base, red)
	eopts := d.Egress.WithSettings(settings, red)
	if eopts.Now == nil {
		eopts.Now = d.Clock
	}
	runner := run.New(run.Config{
		Engagement: eng, Settings: settings, Stages: d.Stages, Egress: egress.New(eopts), Emitter: em,
		Files: d.Files, Clock: d.Clock,
		Passive: o.passive, AllowLargeNetblocks: o.allowLarge, Redo: o.redo, NoFsync: d.NoFsync,
	})

	// The deadline is a timer that cancels, not a context deadline: a rate limiter would fail the
	// checks waiting on it before the context ended. Checks stop a reserve before the deadline so
	// the files and the summary are written by it.
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	if timeout > 0 {
		timer := time.AfterFunc(timeout-reserve(timeout)-time.Since(started), func() { cancel(errDeadline) })
		defer timer.Stop()
	}
	res, runErr := runner.Run(runCtx)
	deadline := errors.Is(runErr, errDeadline)

	// The outcome is picked after the engagement has closed, so that a failure to save state is
	// the run's only outcome: a signal, a fatal error, the netblock limit, the deadline, then
	// failed checks.
	engOpen = false
	closeErr := eng.Close()
	var nl *run.NetblockLimitError
	switch {
	case runErr != nil && !deadline:
		if errors.As(runErr, &nl) {
			runErr = &clierr.Error{Code: clierr.InvalidInput, Message: nl.Error(), Hint: invocationHint(inv.args, "--allow-large-netblocks")} // approves the netblocks without repeating a stage
		}
		return runErr
	case closeErr != nil:
		return closeErr
	case deadline && ctx.Err() != nil:
		return context.Cause(ctx) // a signal arrived during the deadline's wrap-up: nothing is written
	}

	env := report.Envelope{Data: res.Summary, Meta: report.Meta{Count: 1, DeadlineExceeded: deadline,
		ChecksCompleted: res.Completed, ChecksCancelled: sumCounts(res.Cancelled)}}
	if warnings != nil {
		env.Meta.Warnings = warnings.List()
	}
	env = env.Map(func(s string) string { return cleanText(s, red) })
	if inv.sh.json {
		if err := report.WriteEnvelope(d.Stdout, env); err != nil {
			return err
		}
	} else {
		report.WriteSummary(d.Stdout, inv.dp.out, env)
	}
	if e := partialError(inv.args, o.timeout, deadline, res); e != nil {
		return e
	}
	return nil
}

// unskippable are the stages other stages' safety depends on: resolve and wildcard decide which
// names are real, ipowner and providerranges decide which addresses are shared infrastructure that
// must not be port-checked.
var unskippable = []string{"resolve", "wildcard", "ipowner", "providerranges"}

// validateSkip records a problem for each --skip (or skip setting) that names an unknown stage, a
// stage that is also being redone, or a stage that cannot be skipped.
func validateSkip(probs *clierr.Problems, skip []string, redo string, names []string) {
	skippable := "stages that can be skipped: " + strings.Join(slices.DeleteFunc(slices.Clone(names), func(s string) bool {
		return slices.Contains(unskippable, s)
	}), ", ")
	for _, n := range skip {
		switch {
		case !slices.Contains(names, n):
			probs.Add("skip", n, fmt.Sprintf("unknown stage %q for --skip or the skip setting", n), "valid stages: "+strings.Join(names, ", "))
		case n == redo:
			probs.Add("skip", n, fmt.Sprintf("stage %q is named in both --redo and --skip", n), skippable)
		case slices.Contains(unskippable, n):
			probs.Add("skip", n, fmt.Sprintf("stage %q cannot be skipped: other stages' safety depends on it", n), skippable)
		}
	}
}
