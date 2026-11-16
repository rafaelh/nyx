// Package cli is the nyx command line: flags, validation, the
// authorisation prompt, signals and exit codes.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/engagement"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/asn"
	"github.com/rafaelh/nyx/internal/stages/dns"
	"github.com/rafaelh/nyx/internal/stages/github"
	"github.com/rafaelh/nyx/internal/stages/orgpivot"
	"github.com/rafaelh/nyx/internal/stages/ports"
	"github.com/rafaelh/nyx/internal/stages/providerranges"
	"github.com/rafaelh/nyx/internal/stages/rdap"
	"github.com/rafaelh/nyx/internal/stages/reverseip"
	"github.com/rafaelh/nyx/internal/stages/risk"
	"github.com/rafaelh/nyx/internal/stages/shodan"
	"github.com/rafaelh/nyx/internal/stages/subdomains"
	"github.com/rafaelh/nyx/internal/stages/web"
)

// Deps are the collaborators of Execute, replaceable in tests.
type Deps struct {
	Stages        []run.Stage // in registry order
	Files         []output.File
	Egress        egress.Options
	Stdin         io.Reader
	Stdout        io.Writer
	Stderr        io.Writer
	StdinIsTTY    func() bool
	StdoutIsTTY   func() bool
	StderrIsTTY   func() bool    // nil means false
	Location      *time.Location // the time zone log lines are shown in; nil means time.Local
	Clock         func() time.Time
	HandleSignals bool   // SIGINT, SIGTERM and SIGHUP cancel the run; a second one exits at once
	Version       string // shown by --version; empty means "devel"
}

// DefaultDeps returns the production dependencies.
func DefaultDeps() Deps {
	return Deps{
		Version: versionString(debug.ReadBuildInfo()),
		Stages:  defaultStages(), Files: output.Default(),
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		StdinIsTTY:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		StdoutIsTTY: func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		StderrIsTTY: func() bool { return term.IsTerminal(int(os.Stderr.Fd())) },
		Clock:       time.Now, HandleSignals: true,
	}
}

// defaultStages is the registry order: sources first, then DNS, then the stages derived from what
// the sources found. Passes repeat, so late discoveries are picked up. The port sweep is last so
// that probing hostnames on 80 and 443 does not wait for a sweep that can take hours; the pass
// after it probes the ports it found. The email stage follows the DNS stages (dnsroot, which
// records a root's own NS, SOA, TXT and CAA, among them); rdap and shodan-host follow ipowner,
// whose owners decide which addresses may be asked about; storage follows the crawl so references
// found in the same pass are checked, identifier-pivot follows the web stages whose identifiers it
// searches, and the Target stages run before the port sweep.
func defaultStages() []run.Stage {
	sub := subdomains.New() // crtsh, wayback, commoncrawl, virustotal, securitytrails, hackertarget, urlscan, certspotter, censys, chaos
	stages := []run.Stage{asn.New(), orgpivot.NewOrgASN(), orgpivot.NewCTOrg(), orgpivot.NewWhoisXML()}
	stages = append(stages, sub...)
	return append(stages,
		github.New(), shodan.New(), shodan.NewDNS(), providerranges.New(),
		dns.NewResolve(), dns.NewWildcard(nil), dns.NewPermutations(), dns.NewRDNS(), dns.NewIPOwner(), dns.NewDNSRoot(), rdap.New(), shodan.NewHost(), reverseip.New(),
		risk.NewEmail(), web.NewProbe(), web.NewCrawl(), web.NewJSParse(), shodan.NewPivot(),
		risk.NewStorage(), risk.NewTakeover(), risk.NewSensitivePaths(), ports.New())
}

type options struct {
	domainsFile, excludeFile, engagement, redo, configPath string
	orgs, asns, cidrs, exclude                             []string
	passive, authorised, allowLarge, json, quiet, debug    bool
	palette                                                bool
}

// depths are the colour depths of the two output streams, each decided once.
type depths struct{ out, err palette.Depth }

// configFlagUsage is the help of --config, for a run and for export.
const configFlagUsage = "Config file (default $XDG_CONFIG_HOME/nyx/config.yaml, else ~/.config/nyx/config.yaml)"

const ackPrompt = "Confirm you are authorised to test this engagement's scope [y/N] "

// Execute runs nyx with args and returns the process exit code.
func Execute(ctx context.Context, args []string, d Deps) int {
	if d.Version == "" {
		d.Version = develVersion // cobra only adds --version when Version is set
	}
	if d.Files == nil {
		d.Files = output.Default()
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.StdinIsTTY == nil {
		d.StdinIsTTY = func() bool { return false }
	}
	if d.StdoutIsTTY == nil {
		d.StdoutIsTTY = func() bool { return false }
	}
	if d.StderrIsTTY == nil {
		d.StderrIsTTY = func() bool { return false }
	}
	if d.Location == nil {
		d.Location = time.Local
	}
	dp := depths{out: palette.Detect(d.StdoutIsTTY(), os.Getenv), err: palette.Detect(d.StderrIsTTY(), os.Getenv)}
	if d.Stdin == nil {
		d.Stdin = strings.NewReader("")
	}
	var o options
	var ex exportOptions
	code := run.ExitOK
	cmd := newCommand(&o, d, dp.out, func(c *cobra.Command, positional []string) {
		code = runCommand(ctx, c, positional, &o, d, dp)
	})
	cmd.AddCommand(newExportCommand(&ex, dp.out, func(c *cobra.Command) { code = runExport(c, &ex, d, dp) }),
		newTopic("findings", "Finding types and their default severities", findingsHelp, dp.out),
		newTopic("stages", "The stages, in run order, and what each one contacts and does",
			func(dep palette.Depth) string { return stagesHelp(dep, d.Stages) }, dp.out))
	cmd.SetArgs(args)
	cmd.SetOut(d.Stdout)
	cmd.SetErr(d.Stderr)
	if err := cmd.ExecuteContext(ctx); err != nil {
		return fail(newEmitter(d, &o, dp), run.ExitInvalid, err)
	}
	return code
}

// fail reports a fatal error and the run's end, and returns code.
func fail(em report.Emitter, code int, err error) int {
	em.Emit(report.Event{Type: "error", Fields: map[string]any{"message": err.Error(), "exit_code": code}})
	em.Emit(report.Event{Type: "run_end", Fields: map[string]any{"exit_code": code}})
	return code
}

func stageNames(stages []run.Stage) []string {
	var names []string
	for _, s := range stages {
		names = append(names, s.Name())
	}
	return names
}

// newEmitter builds the run's event sink. The console writes the log to stderr and the summary to
// stdout. Under --json stdout is the JSON event stream, which never carries a debug event so that
// stdout is the same with or without --debug, and there is no console, except that --debug adds one
// on stderr which passes only the debug events: a level threshold there would also write the
// summary and a second copy of the error.
func newEmitter(d Deps, o *options, dp depths) report.Emitter {
	minLevel := report.Info
	switch {
	case o.debug:
		minLevel = report.Debug
	case o.quiet:
		minLevel = report.Warn
	}
	console := report.ConsoleOptions{Log: d.Stderr, LogDepth: dp.err, Summary: d.Stdout, SummaryDepth: dp.out,
		Min: minLevel, Clock: d.Clock, Location: d.Location}
	if !o.json {
		return report.NewConsole(console)
	}
	js := report.NewJSON(d.Stdout, d.Clock)
	if !o.debug {
		return js
	}
	return report.Tee(js, report.Only("debug", report.NewConsole(console)))
}

// newCommand builds the root command. Its help is coloured at depth, the colour depth of stdout,
// except under --json.
func newCommand(o *options, d Deps, depth palette.Depth, runFn func(*cobra.Command, []string)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nyx [domain...] [flags]",
		Short: "Passive-first reconnaissance of a target's domains, organisations and netblocks",
		Long: "nyx records a target's hosts, IPs, web services, URLs and open ports, plus a severity-ranked\n" +
			"list of obvious exposures, using only third-party sources and the kind of contact any member of\n" +
			"the public could make. Results go to the console and to TXT/CSV files in an engagement directory.\n" +
			"Re-run with the same engagement (nyx -e <name>) to resume.",
		Args:          cobra.ArbitraryArgs,
		Version:       d.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		// A subcommand would otherwise bring cobra's completion command with it.
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
		RunE: func(c *cobra.Command, args []string) error {
			runFn(c, args)
			return nil
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
	f.BoolVar(&o.authorised, "authorised", false, "Confirm you are authorised to test this scope (alias --authorized)")
	f.BoolVar(&o.allowLarge, "allow-large-netblocks", false, "Proceed even if in-scope IPv4 netblocks exceed --netblock-limit")
	f.StringVar(&o.redo, "redo", "", "Re-perform every check of one stage (see nyx help stages)")
	f.BoolVar(&o.json, "json", false, "Emit one JSON event per line on stdout, with no styling or prompts")
	f.BoolVarP(&o.quiet, "quiet", "q", false, "Write only warnings and errors to stderr; the summary is still printed")
	f.BoolVar(&o.debug, "debug", false, "Also write each failed check to stderr")
	f.BoolVar(&o.palette, "palette", false, "Print the colour palette sheet and exit")
	_ = f.MarkHidden("palette") // only fails for an unknown flag
	f.StringVar(&o.configPath, "config", "", configFlagUsage)
	f.Bool("version", false, "Print the version and exit") // long-only: -v is usually read as verbose
	config.RegisterFlags(f)
	f.BoolP("help", "h", false, "Help for nyx") // replaces cobra's, to capitalise it
	f.SetNormalizeFunc(func(_ *pflag.FlagSet, name string) pflag.NormalizedName {
		if name == "authorized" {
			name = "authorised"
		}
		return pflag.NormalizedName(name)
	})

	cmd.MarkFlagsMutuallyExclusive("quiet", "debug")

	cmd.SetVersionTemplate("nyx {{.Version}}\n")
	cmd.SetUsageTemplate(topicsByName(cmd.UsageTemplate()))
	cmd.SetHelpFunc(func(c *cobra.Command, _ []string) {
		if o.json {
			depth = palette.None
		}
		fmt.Fprint(c.OutOrStdout(), colourHelp(depth, c.Long+"\n\n"+c.UsageString()+"\n"+helpFooter()))
	})
	return cmd
}

func helpFooter() string {
	return `
Configuration:
  Settings come from a YAML config file, NYX_* environment variables or flags; flags override
  environment variables, which override the file. The default config file is
  $XDG_CONFIG_HOME/nyx/config.yaml (default ~/.config/nyx/config.yaml).
  Environment variables are NYX_<SETTING> with dots as underscores, e.g. NYX_CONCURRENCY and
  NYX_RATE_PER_HOST. API keys are never flags: set keys.<source> in the config file or
  NYX_KEYS_<SOURCE> in the environment.

`
}

func runCommand(ctx context.Context, cmd *cobra.Command, positional []string, o *options, d Deps, dp depths) (code int) {
	if o.palette {
		// First, so that a broken config, a missing scope or stray inputs do not matter, and
		// nothing is created or contacted.
		sheetDepth := dp.out
		if o.json {
			sheetDepth = palette.None
		}
		report.Sheet(d.Stdout, sheetDepth, d.Clock().In(d.Location))
		return run.ExitOK
	}
	em := newEmitter(d, o, dp)
	bail := func(code int, err error) int { return fail(em, code, err) }

	settings, err := config.Load(cmd.Flags(), o.configPath)
	if err != nil {
		return bail(run.ExitInvalid, err)
	}
	red := config.NewRedactor(settings.KeyValues()...)
	em = report.WithRedactor(em, red)

	parsed, err := input.Parse(input.Raw{
		Domains: positional, DomainsFile: o.domainsFile, Orgs: o.orgs, ASNs: o.asns, CIDRs: o.cidrs,
		Exclude: o.exclude, ExcludeFile: o.excludeFile,
	})
	if err != nil {
		return bail(run.ExitInvalid, err)
	}
	var name string
	switch {
	case o.engagement != "":
		if name, err = input.EngagementName(o.engagement); err != nil {
			return bail(run.ExitInvalid, err)
		}
	case parsed.Empty():
		return bail(run.ExitInvalid, errors.New("no inputs: give domains, --org, --asn or --cidr, or -e <engagement> to resume one"))
	default:
		if name, err = input.EngagementName(parsed.First); err != nil {
			return bail(run.ExitInvalid, fmt.Errorf("%w; name the engagement with -e", err))
		}
	}
	names := stageNames(d.Stages)
	if o.redo != "" && !slices.Contains(names, o.redo) {
		return bail(run.ExitInvalid, fmt.Errorf("unknown stage %q for --redo (stages: %s)", o.redo, strings.Join(names, ", ")))
	}
	if err := validateSkip(settings.Skip, o.redo, names); err != nil {
		return bail(run.ExitInvalid, err)
	}

	eng, err := engagement.Open(filepath.Join(settings.OutputDir, name), engagement.Options{Clock: d.Clock, Redactor: red})
	if err != nil {
		return bail(run.ExitFatal, err)
	}
	engOpen := true
	defer func() {
		if engOpen {
			eng.Close() // an earlier error was already reported
		}
	}()

	if err := eng.MergeInputs(parsed); err != nil {
		return bail(run.ExitFatal, err)
	}
	stored, err := eng.Inputs()
	if err != nil {
		return bail(run.ExitFatal, err)
	}
	if stored.Empty() {
		return bail(run.ExitInvalid, fmt.Errorf("engagement %s has no scope; give domains, --org, --asn or --cidr", name))
	}

	if err := acknowledge(eng, o, d, settings.Skip); err != nil {
		return bail(run.ExitFatal, err)
	}

	if d.HandleSignals {
		var stop context.CancelFunc
		ctx, stop = handleSignals(ctx)
		defer stop()
	}

	eopts := d.Egress.WithSettings(settings, red)
	if eopts.Now == nil {
		eopts.Now = d.Clock
	}
	eg := egress.New(eopts)
	runner := run.New(run.Config{
		Engagement: eng, Settings: settings, Stages: d.Stages, Egress: eg, Emitter: em,
		Files: d.Files, Clock: d.Clock,
		Passive: o.passive, AllowLargeNetblocks: o.allowLarge, Redo: o.redo,
	})
	code, err = runner.Run(ctx)
	if err != nil {
		return bail(code, err)
	}
	// Close before run_end so a failure to save state is the run's only outcome.
	engOpen = false
	if err := eng.Close(); err != nil {
		return bail(run.ExitFatal, err)
	}
	if code == run.ExitInterrupted {
		em.Emit(report.Event{Type: "warning", Fields: map[string]any{"message": "interrupted; completed work is saved, re-run to continue"}})
	}
	em.Emit(report.Event{Type: "run_end", Fields: map[string]any{"exit_code": code}})
	return code
}

// unskippable are the stages other stages' safety depends on: resolve and wildcard decide which
// names are real, ipowner and providerranges decide which addresses are shared infrastructure that
// must not be port-checked.
var unskippable = []string{"resolve", "wildcard", "ipowner", "providerranges"}

// validateSkip rejects a --skip (or skip setting) that names an unknown stage, a stage that is also
// being redone, or a stage that cannot be skipped.
func validateSkip(skip []string, redo string, names []string) error {
	skippable := func() string {
		return strings.Join(slices.DeleteFunc(slices.Clone(names), func(s string) bool { return slices.Contains(unskippable, s) }), ", ")
	}
	for _, n := range skip {
		switch {
		case !slices.Contains(names, n):
			return fmt.Errorf("unknown stage %q for --skip or the skip setting (stages: %s)", n, strings.Join(names, ", "))
		case n == redo:
			return fmt.Errorf("stage %q is named in both --redo and --skip (stages that can be skipped: %s)", n, skippable())
		case slices.Contains(unskippable, n):
			return fmt.Errorf("stage %q cannot be skipped: other stages' safety depends on it (stages that can be skipped: %s)", n, skippable())
		}
	}
	return nil
}

// acknowledge records the operator's authorisation: by flag, or once per engagement by prompt when
// there is a terminal. A skipped stage does not need it, so the prompt is shown only when a stage
// that contacts the target will run.
func acknowledge(eng *engagement.Engagement, o *options, d Deps, skip []string) error {
	if o.authorised {
		return eng.SetAck()
	}
	if eng.Acked() || o.passive || o.json || !d.StdinIsTTY() {
		return nil
	}
	if !slices.ContainsFunc(d.Stages, func(s run.Stage) bool {
		return s.Contact() == run.Target && !slices.Contains(skip, s.Name())
	}) {
		return nil
	}
	fmt.Fprint(d.Stderr, ackPrompt)
	line, _ := bufio.NewReader(d.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a == "y" || a == "yes" {
		return eng.SetAck()
	}
	return nil
}

func handleSignals(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, unix.SIGTERM, unix.SIGHUP)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
			return
		}
		<-ch
		os.Exit(run.ExitInterrupted)
	}()
	return ctx, func() { signal.Stop(ch); cancel() }
}
