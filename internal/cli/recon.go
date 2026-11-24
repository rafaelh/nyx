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

// configFlagUsage shares config-path guidance between recon and export.
const configFlagUsage = "Config file (default $XDG_CONFIG_HOME/nyx/config.yaml, else ~/.config/nyx/config.yaml)"

// reconEveryday limits root help to common flags; command help includes tuning settings.
var reconEveryday = []string{"domains-file", "org", "asn", "cidr", "exclude", "exclude-file", "engagement",
	"passive", "authorised", "redo", "skip", "allow-large-netblocks", "timeout", "config", "output-dir"}

// interruptedRecon handles cleanup after a signal ends recon.
const interruptedRecon = "completed work is saved; run the same command again to continue"

// newReconCommand builds engagement discovery and its controls.
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
	f.Var(timeoutFlag(&o.timeout), "timeout", "Stop by this deadline, e.g. 30m or 2h, and exit 7; run again to carry on (default: none)")
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

// reconFooter supplies text after recon's flags.
const reconFooter = `Configuration:
  Settings come from a YAML config file or flags; flags override the file. The default config
  file is $XDG_CONFIG_HOME/nyx/config.yaml (default ~/.config/nyx/config.yaml). No setting is
  read from the environment. API keys are never flags: set keys.<source> in the config file.
`

// runRecon collects validation problems before creating state or making requests, then executes
// the engagement.
func runRecon(ctx context.Context, inv *invocation, cmd *cobra.Command, positional, names []string, o *reconOptions) error {
	started := time.Now() // the deadline counts from here; not d.Clock, which tests fix
	d := inv.d
	if o.palette {
		// Handle this early so config/scope errors cannot cause side effects for a
		// non-running invocation.
		report.Sheet(d.Stdout, inv.helpStream(), d.Clock().In(d.Location))
		return nil
	}
	inv.noteNoConfig(o.configPath)
	probs := inv.problems()
	settings, red := inv.loadSettings(cmd.Flags(), o.configPath, probs)
	timeout := reconTimeout(probs, cmd, o.timeout)

	parsed, perr := input.Parse(input.Raw{
		Domains: positional, DomainsFile: o.domainsFile, Orgs: o.orgs, ASNs: o.asns, CIDRs: o.cidrs,
		Exclude: o.exclude, ExcludeFile: o.excludeFile,
	})
	probs.Merge(perr)
	noInputs := len(positional) == 0 && o.domainsFile == "" && len(o.orgs)+len(o.asns)+len(o.cidrs) == 0
	name := reconEngagementName(probs, o.engagement, parsed.First, noInputs, perr == nil)
	// Probe before Open creates anything: reject foreign directories and require scope
	// inputs to start a missing engagement.
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
	// Defer unreadable-directory errors until all usage problems have been collected.
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
			eng.Close() // preserve the run's terminating error
		}
	}()
	if err := prepareEngagement(eng, parsed, name, o); err != nil {
		return err
	}
	inv.setInterruptHint(interruptedRecon)

	em, warnings := newEmitter(inv, red)
	threat := inv.loadThreat(em, warnings, func(string) bool { return true })
	eopts := d.Egress.WithSettings(settings, red)
	if eopts.Now == nil {
		eopts.Now = d.Clock
	}
	runner := run.New(run.Config{
		Engagement: eng, Settings: settings, Stages: d.Stages, Egress: egress.New(eopts), Emitter: em,
		Files: d.Files, Clock: d.Clock,
		Passive: o.passive, AllowLargeNetblocks: o.allowLarge, Redo: o.redo, NoFsync: d.NoFsync, Abusive: threat.Abusive, Drop: &threat.Drop,
	})

	// Use a cancellation timer rather than a context deadline, which would make rate-limit
	// waits fail early. Stop checks before the deadline to reserve time for output.
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	if timeout > 0 {
		timer := time.AfterFunc(timeout-reserve(timeout)-time.Since(started), func() { cancel(errDeadline) })
		defer timer.Stop()
	}
	res, runErr := runner.Run(runCtx)
	deadline := errors.Is(runErr, errDeadline)

	// Choose the outcome after Close so state-save failures can be reported before
	// interpreting signals, run errors or partial results.
	engOpen = false
	closeErr := eng.Close()
	if err := reconFailure(ctx, inv, runErr, closeErr, deadline); err != nil {
		return err
	}
	return reportRecon(inv, o, red, res, warnings, deadline)
}

// reconTimeout accepts a positive --timeout duration or zero when omitted, collecting invalid
// values as problems.
func reconTimeout(probs *clierr.Problems, cmd *cobra.Command, value string) time.Duration {
	if !cmd.Flags().Changed("timeout") {
		return 0
	}
	return parseTimeout(probs, value, "--timeout 30m")
}

// reconEngagementName uses -e or the first parsed input. Missing both is a validation problem.
func reconEngagementName(probs *clierr.Problems, engagement, first string, noInputs, parsed bool) string {
	switch {
	case engagement != "":
		n, err := input.EngagementName(engagement)
		if err != nil {
			probs.Add("engagement", engagement, err.Error(), "")
			return ""
		}
		return n
	case noInputs:
		probs.Add("", "", "no inputs: give domains, --org, --asn or --cidr, or -e <engagement> to resume one", "")
	case parsed:
		n, err := input.EngagementName(first)
		if err != nil {
			probs.Add("engagement", first, err.Error()+"; name the engagement with -e", "")
		}
		return n
	}
	return ""
}

// prepareEngagement unions stored inputs, requires nonempty scope and persists explicit
// authorisation.
func prepareEngagement(eng *engagement.Engagement, parsed input.Parsed, name string, o *reconOptions) error {
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
		return eng.SetAck()
	}
	return nil
}

// reconFailure resolves errors before summary output: fatal run errors/signals, state-save
// failure, then a signal during deadline cleanup. Netblock limits become usage errors. Nil
// means the summary can be written.
func reconFailure(ctx context.Context, inv *invocation, runErr, closeErr error, deadline bool) error {
	switch {
	case runErr != nil && !deadline:
		if nl, ok := errors.AsType[*run.NetblockLimitError](runErr); ok {
			return &clierr.Error{Code: clierr.InvalidInput, Message: nl.Error(), Hint: invocationHint(inv.args, "--allow-large-netblocks")} // approves the netblocks without repeating a stage
		}
		return runErr
	case closeErr != nil:
		return closeErr
	case deadline && ctx.Err() != nil:
		return context.Cause(ctx) // interruption during deadline cleanup must leave stdout empty
	}
	return nil
}

// reportRecon writes the summary as text or a JSON envelope, then returns any
// deadline/check-failure partial error.
func reportRecon(inv *invocation, o *reconOptions, red *config.Redactor, res run.Result, warnings *report.Warnings, deadline bool) error {
	d := inv.d
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
		report.WriteSummary(d.Stdout, inv.st.out, env)
	}
	if e := partialError(inv.args, o.timeout, deadline, res); e != nil {
		return e
	}
	return nil
}

// unskippable lists stages supplying contact decisions: resolve/wildcard identify real names;
// ipowner/providerranges identify shared addresses that must not be port-checked.
var unskippable = []string{"resolve", "wildcard", "ipowner", "providerranges"}

// validateSkip collects unknown stages, redo conflicts and stages required for contact
// decisions.
func validateSkip(probs *clierr.Problems, skip []string, redo string, names []string) {
	for _, n := range skip {
		if msg, hint := skipProblem(n, redo, names); msg != "" {
			probs.Add("skip", n, msg, hint)
		}
	}
}

// skipProblem returns a reason and hint for an unknown, redone or required stage, otherwise
// empty strings.
func skipProblem(n, redo string, names []string) (msg, hint string) {
	switch {
	case !slices.Contains(names, n):
		return fmt.Sprintf("unknown stage %q for --skip or the skip setting", n), "valid stages: " + strings.Join(names, ", ")
	case n == redo:
		return fmt.Sprintf("stage %q is named in both --redo and --skip", n), skippableHint(names)
	case slices.Contains(unskippable, n):
		return fmt.Sprintf("stage %q cannot be skipped: other stages' safety depends on it", n), skippableHint(names)
	}
	return "", ""
}

// skippableHint lists the stages that can be skipped.
func skippableHint(names []string) string {
	return "stages that can be skipped: " + strings.Join(slices.DeleteFunc(slices.Clone(names), func(s string) bool {
		return slices.Contains(unskippable, s)
	}), ", ")
}
