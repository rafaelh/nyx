// Package cli is the nyx command line: the command tree (nyx, recon, recon
// export, cve, ip, help and the help topics), flags, validation, help text,
// signals, and the one place that picks the exit code and writes the error.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/sanitize"
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
	StderrIsTTY func() bool // nil means false
	// StdoutWidth and StderrWidth report the width in cells of a terminal stream, or 0 when it has
	// none; nil means 0. They are consulted only for a stream that is a terminal.
	StdoutWidth func() int
	StderrWidth func() int
	Location    *time.Location // the time zone human output shows times in; nil means time.Local
	Clock       func() time.Time
	// Signals delivers SIGINT, SIGTERM and SIGHUP; nil means none arrive. The
	// first cancels the command, a second exits at once (see NotifySignals).
	Signals <-chan os.Signal
	Version string // shown by --version and sent as the User-Agent; empty means "devel"
	// Env is the environment settings and colours are read from, as os.Environ gives it; nil
	// means an empty one.
	Env config.Env
	// NoFsync writes output files without syncing them to disk first, which on macOS costs a full
	// flush of the drive's cache per file. Only tests set it.
	NoFsync bool
	// Events, when set, also receives every event of a recon run, as the console would see it
	// (redacted). Only tests set it, to read the events that --json no longer writes.
	Events report.Emitter
	// Stdin is read by a lookup command given a lone "-" (nyx cve, nyx ip), and is the terminal's
	// input for nyx setup; nil means an empty one.
	Stdin io.Reader
	// StdinIsTTY reports whether Stdin is a terminal, which nyx setup needs; nil means false.
	StdinIsTTY func() bool
	// WindowSize is the size in cells of the terminal nyx setup draws in, for a Stdout that the
	// terminal library cannot size itself (a test's buffer); nil means the library asks Stdout.
	WindowSize func() (width, height int)
	// Getwd is the directory nyx was run from, which nyx setup resolves relative paths against;
	// nil means os.Getwd.
	Getwd func() (string, error)
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
		StdoutWidth: func() int { return termWidth(os.Stdout.Fd()) },
		StderrWidth: func() int { return termWidth(os.Stderr.Fd()) },
		Clock:       time.Now,
		Env:         os.Environ(), //nolint:forbidigo // main reads the process environment once, into Deps.Env
		Stdin:       os.Stdin,
		StdinIsTTY:  func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		Getwd:       os.Getwd,
	}
}

// termWidth is the width in cells of the terminal on fd, or 0 when fd is not one.
func termWidth(fd uintptr) int {
	w, _, err := term.GetSize(int(fd))
	if err != nil {
		return 0
	}
	return w
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
	if d.StdoutWidth == nil {
		d.StdoutWidth = func() int { return 0 }
	}
	if d.StderrWidth == nil {
		d.StderrWidth = func() int { return 0 }
	}
	if d.Location == nil {
		d.Location = time.Local
	}
	if d.Stdin == nil {
		d.Stdin = strings.NewReader("")
	}
	if d.StdinIsTTY == nil {
		d.StdinIsTTY = func() bool { return false }
	}
	if d.Getwd == nil {
		d.Getwd = os.Getwd
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

// streams are the two output streams as the layout sees them: whether each is a terminal, its
// colour depth and its width. The depth is decided once; the width is read each time a layout is
// made, so a resize applies from the next one.
type streams struct{ out, err layout.Stream }

// newStream is one output's stream. Its width is COLUMNS when that is a positive number, else the
// terminal's own width (asked of width only when the stream is a terminal), else 100, and never
// less than 60.
func newStream(isTTY func() bool, env config.Env, width func() int) layout.Stream {
	tty := isTTY()
	columns := env.Get("COLUMNS") // the environment is fixed for the process
	return layout.Stream{
		Terminal: tty,
		Depth:    palette.Detect(tty, env.Get),
		Width: func() int {
			term := 0
			if tty { // only a terminal has a width of its own
				term = width()
			}
			return layout.Width(columns, term)
		},
	}
}

// shared are the flags every command takes, before or after its name. None of
// them is a setting.
type shared struct{ json, quiet, debug bool }

// invocation is one call of nyx: what the commands share, and what they hand
// back to Execute.
type invocation struct {
	d    Deps
	st   streams
	args []string // as given, for the hints that repeat them
	raw  shared   // the shared flags as a scan of args finds them, before any parse
	sh   shared   // the shared flags as parsed
	fw   *failureWriter
	mg   *margin // the blank lines around the output on a terminal; Execute closes it

	cmd *cobra.Command // the command that ran, for the default hint
	err error          // what it returned

	// rawOut is Deps.Stdout as the caller gave it, before the margin wraps it. A full-screen
	// command needs the terminal itself, not the wrapped writer.
	rawOut io.Writer
	// hintNoConfig is the default config path to suggest nyx setup for, set by a command that read
	// no config file because there is none ("" for no hint).
	hintNoConfig string

	mu            sync.Mutex
	interruptHint string // what to do after a signal, set by the command
	// beforeHardExit, when set, runs before the process exits on a second signal, so a command
	// that has taken over the terminal can give it back.
	beforeHardExit func()
}

func newInvocation(d Deps, args []string) *invocation {
	inv := &invocation{d: d, args: args, raw: scanShared(args), mg: &margin{}, rawOut: d.Stdout}
	inv.st = streams{out: newStream(d.StdoutIsTTY, d.Env, d.StdoutWidth), err: newStream(d.StderrIsTTY, d.Env, d.StderrWidth)}
	// The pre-scan decides --json: a value refused later still leaves the streams as they were.
	inv.d.Stdout = inv.mg.wrap(d.Stdout, inv.st.out.Terminal && !inv.raw.json)
	inv.d.Stderr = inv.mg.wrap(d.Stderr, inv.st.err.Terminal && !inv.raw.json)
	inv.fw = newFailureWriter(inv.d.Stderr, inv.raw.json, inv.st.err.Depth, config.NewRedactor(config.EnvKeyValues(d.Env)...))
	return inv
}

// loadSettings loads a command's settings from env into probs, and has the
// error mask every key that loaded, even when some setting did not, and every
// key set in the whole environment, whatever env leaves out.
func (inv *invocation) loadSettings(fs *pflag.FlagSet, configPath string, env config.Env, probs *clierr.Problems) (config.Settings, *config.Redactor) {
	settings, err := config.Load(fs, configPath, env)
	probs.Merge(err)
	red := config.NewRedactor(append(settings.KeyValues(), config.EnvKeyValues(inv.d.Env)...)...)
	inv.fw.setRedactor(red)
	return settings, red
}

// Execute runs nyx with args and returns the process exit code. It alone
// picks the exit code and writes the error: commands return an error and
// print none.
func Execute(ctx context.Context, args []string, d Deps) int {
	inv := newInvocation(withDefaults(d), args)
	defer inv.mg.close() // after the error, which Execute writes before it returns
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	sigs := watchSignals(inv.d.Signals, cancel, func(s os.Signal) {
		// A second signal: exit at once, the one exit outside main.
		inv.mu.Lock()
		before := inv.beforeHardExit
		inv.mu.Unlock()
		if before != nil {
			before() // the terminal is given back before any error is written
		}
		inv.fw.write(inv.interruptError(s))
		inv.mg.close()
		os.Exit(signalOf(s).code)
	})
	defer sigs.stop()

	err := inv.execute(runCtx)
	inv.writeNoConfigHint(err)
	if err == nil {
		return 0
	}
	s := sigs.received()
	if s == nil && errors.Is(ctx.Err(), context.Canceled) {
		s = os.Interrupt // the caller cancelled: an interrupt, as Ctrl-C would be
	}
	// A command returns PARTIAL only after it has written its result, so a signal that lands
	// after that leaves it standing: INTERRUPTED never comes with a non-empty stdout.
	var partial *clierr.Error
	isPartial := errors.As(err, &partial) && partial.Code == clierr.Partial
	if s != nil && !isPartial {
		inv.fw.write(inv.interruptError(s))
		return signalOf(s).code
	}
	e := inv.toError(err)
	inv.fw.write(e)
	return clierr.ExitCode(e.Code)
}

// noConfigHint is the line that suggests nyx setup, for the path of the config file that is absent.
func noConfigHint(path string) string {
	return "hint: no config file at " + sanitize.Line(path) + "; run nyx setup to store API keys and settings\n"
}

// noteNoConfig records the default config path for the hint when no --config was given, the
// default path is known and there is no file at it.
func (inv *invocation) noteNoConfig(configPath string) {
	if configPath != "" {
		return
	}
	path := config.DefaultConfigPath(inv.d.Env)
	if path == "" {
		return
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		inv.hintNoConfig = path
	}
}

// writeNoConfigHint writes the hint, once the command has returned and before any error line. It
// stays out of a usage error, which the user is already fixing, and out of --json and --quiet. It
// is not an event, so the events and stdout are as they would be without it.
func (inv *invocation) writeNoConfigHint(err error) {
	if inv.hintNoConfig == "" || inv.sh.json || inv.sh.quiet {
		return
	}
	// A panic is never a usage error, and toError would write its stack under --debug, which
	// Execute then writes again.
	var pe *clierr.PanicError
	if err != nil && !errors.As(err, &pe) && inv.toError(err).Code == clierr.InvalidInput {
		return
	}
	_, _ = io.WriteString(inv.d.Stderr, noConfigHint(inv.hintNoConfig))
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
	root.SetArgs(helpWord(inv.args, root))
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
		e = probs.Usage(helpOf(inv.cmd))
	default:
		e = &clierr.Error{Code: clierr.Unexpected, Message: err.Error()}
	}
	return e
}

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
	return &clierr.Error{Code: clierr.Interrupted, Message: "interrupted by " + signalOf(s).name, Hint: inv.interruptHint}
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

// newEmitter builds a command's event sink, teed to Deps.Events when set and redacting API keys
// with red. The console writes the log to stderr. Under --json nothing is written while the
// command goes on: the warnings are kept (the second result) for the envelope, and --debug adds a
// console on stderr which passes only the debug events, so that stdout is the same with or without
// --debug. The summary is not an event: recon writes it.
func newEmitter(inv *invocation, red *config.Redactor) (report.Emitter, *report.Warnings) {
	d, sh := inv.d, inv.sh
	minLevel := report.Info
	switch {
	case sh.debug:
		minLevel = report.Debug
	case sh.quiet:
		minLevel = report.Warn
	}
	console := report.NewConsole(report.ConsoleOptions{Log: d.Stderr, LogStream: inv.st.err,
		Min: minLevel, Clock: d.Clock, Location: d.Location, Redactor: red})
	var em report.Emitter = console
	var warnings *report.Warnings
	if sh.json {
		warnings = &report.Warnings{}
		em = warnings
		if sh.debug {
			em = report.Tee(warnings, report.Only("debug", console))
		}
	}
	if d.Events != nil {
		em = report.Tee(em, d.Events)
	}
	return report.WithRedactor(em, red), warnings
}
