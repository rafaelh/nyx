// Package cli is the nyx command line: the command tree (nyx, recon, recon
// export, help and the help topics), flags, validation, help text, signals,
// and the one place that picks the exit code and writes the error.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/asn"
	"github.com/rafaelh/nyx/internal/stages/dns"
	"github.com/rafaelh/nyx/internal/stages/dnshistory"
	"github.com/rafaelh/nyx/internal/stages/github"
	"github.com/rafaelh/nyx/internal/stages/nsreverse"
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
	Stages      []run.Stage // in registry order
	Files       []output.File
	Egress      egress.Options
	Stdout      io.Writer
	Stderr      io.Writer
	StdoutIsTTY func() bool
	StderrIsTTY func() bool    // nil means false
	Location    *time.Location // the time zone log lines are shown in; nil means time.Local
	Clock       func() time.Time
	// Signals delivers SIGINT, SIGTERM and SIGHUP; nil means none arrive. The
	// first cancels the command, a second exits at once (see NotifySignals).
	Signals <-chan os.Signal
	Version string // shown by --version and sent as the User-Agent; empty means "devel"
}

// DefaultDeps returns the production dependencies, except Signals, which only
// main subscribes to (see NotifySignals).
func DefaultDeps() Deps {
	return Deps{
		Version: versionString(debug.ReadBuildInfo()),
		Stages:  defaultStages(), Files: output.Default(),
		Stdout: os.Stdout, Stderr: os.Stderr,
		StdoutIsTTY: func() bool { return term.IsTerminal(int(os.Stdout.Fd())) },
		StderrIsTTY: func() bool { return term.IsTerminal(int(os.Stderr.Fd())) },
		Clock:       time.Now,
	}
}

// NotifySignals subscribes to SIGINT, SIGTERM and SIGHUP, for Deps.Signals.
// The subscription changes what those signals do to the whole process, so
// only main makes it, not DefaultDeps.
func NotifySignals() <-chan os.Signal {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, unix.SIGTERM, unix.SIGHUP)
	return ch
}

// withDefaults fills in what a test leaves out of Deps.
func withDefaults(d Deps) Deps {
	if d.Version == "" {
		d.Version = develVersion
	}
	d.Egress.UserAgent = "nyx/" + d.Version // every command's requests carry it
	if d.Files == nil {
		d.Files = output.Default()
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	if d.Stdout == nil {
		d.Stdout = io.Discard
	}
	if d.Stderr == nil {
		d.Stderr = io.Discard
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
	return d
}

// defaultStages is the registry order: sources first, then DNS, then the stages derived from what
// the sources found. Passes repeat, so late discoveries are picked up. The port sweep is last so
// that probing hostnames on 80 and 443 does not wait for a sweep that can take hours; the pass
// after it probes the ports it found. The email stage follows the DNS stages (dnsroot, which
// records a root's own NS, SOA, TXT and CAA, among them); rdap and shodan-host follow ipowner,
// whose owners decide which addresses may be asked about; storage follows the crawl so references
// found in the same pass are checked, identifier-pivot follows the web stages whose identifiers it
// searches, and the Target stages run before the port sweep. dnshistory follows reverseip, as both ask
// SecurityTrails about addresses and names the earlier stages found; origincheck follows dnshistory
// and the probe, whose historical addresses and web services its candidates come from.
func defaultStages() []run.Stage {
	sub := subdomains.New() // crtsh, wayback, commoncrawl, virustotal, securitytrails, hackertarget, urlscan, certspotter, censys, chaos
	stages := []run.Stage{asn.New(), orgpivot.NewOrgASN(), orgpivot.NewCTOrg(), orgpivot.NewWhoisXML()}
	stages = append(stages, sub...)
	return append(stages,
		github.New(), shodan.New(), shodan.NewDNS(), providerranges.New(),
		dns.NewResolve(), dns.NewWildcard(nil), dns.NewPermutations(), dns.NewRDNS(), dns.NewIPOwner(), dns.NewDNSRoot(), rdap.New(), shodan.NewHost(), reverseip.New(),
		dnshistory.New(), risk.NewEmail(), nsreverse.New(), web.NewProbe(), web.NewCrawl(), web.NewJSParse(), shodan.NewPivot(),
		risk.NewStorage(), risk.NewTakeover(), risk.NewSensitivePaths(), web.NewOriginCheck(), ports.New())
}

// depths are the colour depths of the two output streams, each decided once.
type depths struct{ out, err palette.Depth }

// shared are the flags every command takes, before or after its name. None of
// them is a setting.
type shared struct{ json, quiet, debug bool }

// invocation is one call of nyx: what the commands share, and what they hand
// back to Execute.
type invocation struct {
	d    Deps
	dp   depths
	args []string // as given, for the hints that repeat them
	raw  shared   // the shared flags as a scan of args finds them, before any parse
	sh   shared   // the shared flags as parsed
	fw   *failureWriter

	cmd *cobra.Command // the command that ran, for the default hint
	err error          // what it returned

	mu            sync.Mutex
	interruptHint string // what to do after a signal, set by the command
}

func newInvocation(d Deps, args []string) *invocation {
	inv := &invocation{d: d, args: args, raw: scanShared(args)}
	inv.dp = depths{out: palette.Detect(d.StdoutIsTTY(), os.Getenv), err: palette.Detect(d.StderrIsTTY(), os.Getenv)}
	inv.fw = newFailureWriter(d.Stderr, inv.raw.json, inv.dp.err, config.NewRedactor(config.EnvKeyValues()...))
	return inv
}

// loadSettings loads a command's settings into probs and has the error mask
// every key that loaded, even when some setting did not.
func (inv *invocation) loadSettings(fs *pflag.FlagSet, configPath string, probs *clierr.Problems) (config.Settings, *config.Redactor) {
	settings, err := config.Load(fs, configPath)
	probs.Merge(err)
	red := config.NewRedactor(settings.KeyValues()...)
	inv.fw.setRedactor(red)
	return settings, red
}

// Execute runs nyx with args and returns the process exit code. It alone
// picks the exit code and writes the error: commands return an error and
// print none.
func Execute(ctx context.Context, args []string, d Deps) int {
	inv := newInvocation(withDefaults(d), args)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	sigs := watchSignals(inv.d.Signals, cancel, func(s os.Signal) {
		// A second signal: exit at once, the one exit outside main.
		inv.fw.write(inv.interruptError(s))
		os.Exit(signalCode(s))
	})
	defer sigs.stop()

	err := inv.execute(runCtx)
	if err == nil {
		return 0
	}
	s := sigs.received()
	if s == nil && errors.Is(ctx.Err(), context.Canceled) {
		s = os.Interrupt // the caller cancelled: an interrupt, as Ctrl-C would be
	}
	if s != nil {
		inv.fw.write(inv.interruptError(s))
		return signalCode(s)
	}
	e := inv.toError(err)
	inv.fw.write(e)
	return clierr.ExitCode(e.Code)
}

// execute builds the tree, classifies the arguments and runs the command. A
// panic anywhere on this goroutine ends here, as an unexpected failure.
func (inv *invocation) execute(ctx context.Context) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = &clierr.PanicError{Value: v, Stack: debug.Stack()}
		}
	}()
	root := newRoot(inv)
	sc := classify(inv.args, root)
	if sc.err == nil && (sc.version || sc.help) {
		// Every argument is a shared flag or --version, so the scan is the parse.
		inv.sh = inv.raw
		if err := inv.problems().Err(); err != nil {
			return err
		}
	}
	switch {
	case sc.err != nil:
		return sc.err
	case sc.version:
		fmt.Fprintf(inv.d.Stdout, "nyx %s\n", inv.d.Version)
		return nil
	case sc.help:
		inv.printHelp(root, root)
		return nil
	}
	root.SetArgs(inv.args)
	root.SetOut(inv.d.Stdout)
	root.SetErr(inv.d.Stderr)
	cmd, perr := root.ExecuteContextC(ctx)
	if perr != nil {
		// A command's run never returns an error through cobra, so this is the
		// parser's own: a usage error.
		return parseError(cmd, perr)
	}
	return inv.err
}

// toError turns what a command returned into the error to write.
func (inv *invocation) toError(err error) *clierr.Error {
	var e *clierr.Error
	var probs clierr.Problems
	var pe *clierr.PanicError
	switch {
	case errors.As(err, &pe):
		e = &clierr.Error{Code: clierr.Unexpected, Message: pe.Error()}
		if inv.raw.debug {
			_, _ = inv.d.Stderr.Write(pe.Stack) // before the error, which stays the last line
		} else {
			e.Hint = "add --debug for the stack trace"
		}
	case errors.As(err, &e):
	case errors.As(err, &probs):
		e = probs.Usage(inv.helpHint())
	default:
		e = &clierr.Error{Code: clierr.Unexpected, Message: err.Error()}
	}
	return e
}

// helpHint is the help of the command that ran.
func (inv *invocation) helpHint() string { return helpOf(inv.cmd) }

// helpOf is the --help call of cmd, or of nyx when there is none.
func helpOf(cmd *cobra.Command) string {
	if cmd == nil {
		return "nyx --help"
	}
	return cmd.CommandPath() + " --help"
}

// interruptError is the error of a command a signal ended.
func (inv *invocation) interruptError(s os.Signal) *clierr.Error {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	return &clierr.Error{Code: clierr.Interrupted, Message: "interrupted by " + signalName(s), Hint: inv.interruptHint}
}

func (inv *invocation) setInterruptHint(h string) {
	inv.mu.Lock()
	inv.interruptHint = h
	inv.mu.Unlock()
}

// problems starts a command's checks with those of the shared flags.
func (inv *invocation) problems() *clierr.Problems {
	var p clierr.Problems
	if inv.sh.quiet && inv.sh.debug {
		p.Add("quiet", "true", "--quiet and --debug cannot be used together", "drop one of --quiet and --debug")
	}
	return &p
}

// start records the command that runs and returns its run function's error
// slot, so a command never returns an error through cobra.
func (inv *invocation) start(cmd *cobra.Command, err error) error {
	inv.cmd, inv.err = cmd, err
	return nil
}

// parseError is the usage error of an argument the parser refused.
func parseError(cmd *cobra.Command, err error) *clierr.Error {
	e := &clierr.Error{Code: clierr.InvalidInput, Message: err.Error(), Hint: helpOf(cmd)}
	if flag := flagOf(err); flag != "" {
		e.Input = map[string][]string{"flag": {flag}}
	}
	return e
}

// flagOf is the flag a parser error names, as it was written, or "".
func flagOf(err error) string {
	// NotExistError and ValueRequiredError both name the flag as written.
	var named interface {
		GetSpecifiedName() string
		GetSpecifiedShortnames() string
	}
	var iv *pflag.InvalidValueError
	switch {
	case errors.As(err, &named):
		if named.GetSpecifiedShortnames() != "" {
			return "-" + named.GetSpecifiedName()
		}
		return "--" + named.GetSpecifiedName()
	case errors.As(err, &iv):
		return "--" + iv.GetFlag().Name
	}
	return ""
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
// summary.
func newEmitter(d Deps, sh shared, dp depths) report.Emitter {
	minLevel := report.Info
	switch {
	case sh.debug:
		minLevel = report.Debug
	case sh.quiet:
		minLevel = report.Warn
	}
	console := report.ConsoleOptions{Log: d.Stderr, LogDepth: dp.err, Summary: d.Stdout, SummaryDepth: dp.out,
		Min: minLevel, Clock: d.Clock, Location: d.Location}
	if !sh.json {
		return report.NewConsole(console)
	}
	js := report.NewJSON(d.Stdout, d.Clock)
	if !sh.debug {
		return js
	}
	return report.Tee(js, report.Only("debug", report.NewConsole(console)))
}
