// Package cli builds nyx's command tree, validates input and handles help, signals and output.
// Execute chooses exit codes and prints command errors.
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
	"github.com/rafaelh/nyx/internal/threatdata"
)

// Deps supplies Execute's replaceable dependencies for production and tests.
type Deps struct {
	Stages      []run.Stage // in registry order
	Files       []output.File
	Egress      egress.Options
	Stdout      io.Writer
	Stderr      io.Writer
	StdoutIsTTY func() bool
	StderrIsTTY func() bool // nil means false
	// StdoutWidth and StderrWidth return terminal widths in cells. They are called only for
	// terminal streams; nil or zero means unknown.
	StdoutWidth func() int
	StderrWidth func() int
	Location    *time.Location // the time zone human output shows times in; nil means time.Local
	Clock       func() time.Time
	// Signals cancels on the first signal and exits on the second. Nil disables signal
	// delivery.
	Signals <-chan os.Signal
	Version string // shown by --version and sent as the User-Agent; empty means "devel"
	// Env supplies process-style environment entries for config paths and colours. Nil is
	// empty.
	Env config.Env
	// NoFsync skips per-file disk flushes in tests, avoiding macOS's costly drive-cache
	// flush.
	NoFsync bool
	// Events receives redacted recon events in tests, including events suppressed from
	// stdout by --json.
	Events report.Emitter
	// Stdin supplies lookup input for a lone "-" and terminal input for setup. Nil means
	// empty input.
	Stdin io.Reader
	// StdinIsTTY gates the interactive editor; nil means false.
	StdinIsTTY func() bool
	// WindowSize supplies dimensions for setup terminals the library cannot measure, such
	// as test buffers. Nil uses Stdout's size.
	WindowSize func() (width, height int)
	// Getwd resolves setup's relative paths. Nil uses os.Getwd.
	Getwd func() (string, error)
	// ThreatBuiltIn supplies fixed threat-data snapshots for tests. Nil uses embedded
	// copies.
	ThreatBuiltIn *threatdata.BuiltIn
}

// DefaultDeps supplies production dependencies without subscribing to signals; main does that
// separately.
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

// NotifySignals changes process-wide SIGINT/SIGTERM/SIGHUP handling. Only main subscribes;
// DefaultDeps leaves handlers alone.
func NotifySignals() <-chan os.Signal {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, unix.SIGTERM, unix.SIGHUP)
	return ch
}

// withDefaults fills omitted test dependencies.
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

// defaultStages orders sources before DNS and stages that consume their discoveries. Repeated
// passes pick up results found late. The port sweep runs last because it can take hours;
// hostname probing runs first, and the next pass probes newly found ports.
//
// Email follows DNS. RDAP and shodan-host follow ipowner so ownership can guide lookups;
// netblockowner follows to supply abuse-check evidence. Storage follows crawling,
// identifier-pivot follows web identifier collection, and origincheck follows DNS history and
// web probing. dnshistory follows reverseip so both can use earlier address/name discoveries.
func defaultStages() []run.Stage {
	sub := subdomains.New() // crtsh, wayback, commoncrawl, virustotal, securitytrails, hackertarget, urlscan, certspotter, censys, chaos
	stages := []run.Stage{asn.New(), orgpivot.NewOrgASN(), orgpivot.NewCTOrg(), orgpivot.NewWhoisXML()}
	stages = append(stages, sub...)
	return append(stages,
		github.New(), shodan.New(), shodan.NewDNS(), providerranges.New(),
		dns.NewResolve(), dns.NewWildcard(nil), dns.NewPermutations(), dns.NewRDNS(), dns.NewIPOwner(), dns.NewNetblockOwner(), dns.NewDNSRoot(), rdap.New(), shodan.NewHost(), reverseip.New(),
		dnshistory.New(), risk.NewEmail(), nsreverse.New(), web.NewProbe(), web.NewCrawl(), web.NewJSParse(), shodan.NewPivot(),
		risk.NewStorage(), risk.NewTakeover(), risk.NewSensitivePaths(), web.NewOriginCheck(), ports.New())
}

// streams holds terminal capabilities for stdout and stderr. Colour depth is fixed per
// invocation; width is read for each layout so resizing takes effect.
type streams struct{ out, err layout.Stream }

// newStream chooses width from positive COLUMNS, then terminal measurement, then 100 columns.
// Width is at least 60; non-terminal streams are never measured.
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

// shared holds invocation flags accepted around every command, separate from config settings.
type shared struct{ json, quiet, debug bool }

// invocation shares parsed state and command results with Execute.
type invocation struct {
	d    Deps
	st   streams
	args []string // as given, for the hints that repeat them
	raw  shared   // the shared flags as a scan of args finds them, before any parse
	sh   shared   // the shared flags as parsed
	fw   *failureWriter
	mg   *margin // terminal output margins, closed by Execute

	cmd *cobra.Command // the command that ran, for the default hint
	err error          // what it returned

	// rawOut preserves the original terminal writer for full-screen commands before margin
	// wrapping.
	rawOut io.Writer
	// hintNoConfig stores a missing default config path for the setup hint; empty
	// suppresses it.
	hintNoConfig string
	// staleHints collects human update notices. JSON reports them as warnings instead.
	staleHints []string

	mu            sync.Mutex
	interruptHint string // command-specific interruption handler
	// beforeHardExit restores command-owned terminal state before a second signal
	// terminates the process.
	beforeHardExit func()
}

func newInvocation(d Deps, args []string) *invocation {
	inv := &invocation{d: d, args: args, raw: scanShared(args), mg: &margin{}, rawOut: d.Stdout}
	inv.st = streams{out: newStream(d.StdoutIsTTY, d.Env, d.StdoutWidth), err: newStream(d.StderrIsTTY, d.Env, d.StderrWidth)}
	// Pre-scan chooses output mode even when later validation rejects a flag value.
	inv.d.Stdout = inv.mg.wrap(d.Stdout, inv.st.out.Terminal && !inv.raw.json)
	inv.d.Stderr = inv.mg.wrap(d.Stderr, inv.st.err.Terminal && !inv.raw.json)
	inv.fw = newFailureWriter(inv.d.Stderr, inv.raw.json, inv.st.err.Depth, config.NewRedactor())
	return inv
}

// loadSettings collects config problems and registers every loaded key for redaction, including
// on invalid config.
func (inv *invocation) loadSettings(fs *pflag.FlagSet, configPath string, probs *clierr.Problems) (config.Settings, *config.Redactor) {
	settings, err := config.Load(fs, configPath, inv.d.Env)
	probs.Merge(err)
	red := config.NewRedactor(settings.KeyValues()...)
	inv.fw.setRedactor(red)
	return settings, red
}

// Execute runs the invocation and owns error printing and exit-code selection. Commands return
// errors for it to report.
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
	inv.writeHints(err)
	if err == nil {
		return 0
	}
	s := sigs.received()
	if s == nil && errors.Is(ctx.Err(), context.Canceled) {
		s = os.Interrupt // the caller cancelled: an interrupt, as Ctrl-C would be
	}
	// PARTIAL means output was already written. A later signal must preserve that outcome
	// so INTERRUPTED never accompanies partial stdout.
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

// noConfigHint suggests setup for a missing default config path.
func noConfigHint(path string) string {
	return "hint: no config file at " + sanitize.Line(path) + "; run nyx setup to store API keys and settings\n"
}

// noteNoConfig records a hint only for a missing, known default path when --config was not
// explicit.
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

// writeHints prints config and stale-data hints after command execution and before errors.
// Usage errors, --json and --quiet suppress these lines. They are not events; JSON receives
// stale notices as warnings instead.
func (inv *invocation) writeHints(err error) {
	if (inv.hintNoConfig == "" && len(inv.staleHints) == 0) || inv.sh.json || inv.sh.quiet {
		return
	}
	// Recover panics as unexpected errors without passing through toError, which would
	// duplicate the debug stack.
	var pe *clierr.PanicError
	if err != nil && !errors.As(err, &pe) && inv.toError(err).Code == clierr.InvalidInput {
		return
	}
	if inv.hintNoConfig != "" {
		_, _ = io.WriteString(inv.d.Stderr, noConfigHint(inv.hintNoConfig))
	}
	for _, h := range inv.staleHints {
		_, _ = io.WriteString(inv.d.Stderr, "hint: "+h+"\n")
	}
}

// execute builds and runs the command tree, recovering main-goroutine panics as unexpected
// failures.
func (inv *invocation) execute(ctx context.Context) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = &clierr.PanicError{Value: v, Stack: debug.Stack()}
		}
	}()
	root := newRoot(inv)
	sc := classify(inv.args, root)
	if sc.err == nil && (sc.version || sc.help) {
		// Only shared flags/version remain, so pre-scan has already resolved the
		// invocation.
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
		// Command errors bypass Cobra; errors returned here come from parsing and are
		// usage failures.
		return parseError(cmd, perr)
	}
	return inv.err
}

// toError normalises command errors for reporting.
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

// helpOf builds the command's --help hint, falling back to root help.
func helpOf(cmd *cobra.Command) string {
	if cmd == nil {
		return "nyx --help"
	}
	return cmd.CommandPath() + " --help"
}

// interruptError maps a received signal to its command error.
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

// problems begins validation with shared-flag conflicts.
func (inv *invocation) problems() *clierr.Problems {
	var p clierr.Problems
	if inv.sh.quiet && inv.sh.debug {
		p.Add("quiet", "true", "--quiet and --debug cannot be used together", "drop one of --quiet and --debug")
	}
	return &p
}

// start captures command errors separately so Cobra does not print or handle them.
func (inv *invocation) start(cmd *cobra.Command, err error) error {
	inv.cmd, inv.err = cmd, err
	return nil
}

// parseError translates parser failures into usage errors.
func parseError(cmd *cobra.Command, err error) *clierr.Error {
	e := &clierr.Error{Code: clierr.InvalidInput, Message: err.Error(), Hint: helpOf(cmd)}
	if flag := flagOf(err); flag != "" {
		e.Input = map[string][]string{"flag": {flag}}
	}
	return e
}

// flagOf extracts the original flag spelling from parser errors, or "".
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

// newEmitter redacts API keys and optionally copies events to Deps.Events. Human logs go to
// stderr. In JSON mode it collects warnings for the envelope; --debug additionally prints only
// debug events to stderr. Recon writes its summary separately.
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
