// Package run executes stages over an engagement: repeated passes in registry
// order, a worker pool per stage, gating, the netblock guard, redo and the
// stage states shown on the console.
package run

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/engagement"
	"github.com/rafaelh/nyx/internal/eol"
	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

// NetblockLimitError is returned when in-scope IPv4 netblocks exceed the limit.
// The caller says how to proceed (--allow-large-netblocks).
type NetblockLimitError struct{ Count, Limit uint64 }

func (e *NetblockLimitError) Error() string {
	return fmt.Sprintf("in-scope IPv4 netblocks cover %d addresses, over the limit of %d; nothing in them was contacted", e.Count, e.Limit)
}

// interrupted is the error of a run its context ended. It wraps the context's
// cause, so a caller can tell a cancel from a deadline.
func interrupted(ctx context.Context) error {
	return fmt.Errorf("run interrupted: %w", context.Cause(ctx))
}

// Config is everything a Runner needs.
type Config struct {
	Engagement          *engagement.Engagement
	Settings            config.Settings
	Stages              []Stage
	Egress              *egress.Egress
	Emitter             report.Emitter
	Files               []output.File
	Clock               func() time.Time
	Passive             bool
	AllowLargeNetblocks bool
	Redo                string
	NoFsync             bool // write output files without syncing them to disk (see output.Render); for tests
}

// Runner runs the stages.
type Runner struct {
	cfg   Config
	st    *store.Store
	order []string

	inputs input.Parsed
	acked  bool // the engagement holds the authorisation; read once, as Run fixes it for the run
	sc     atomic.Pointer[scope.Scope]
	inv    atomic.Pointer[inventory.Inventory]
	vis    atomic.Pointer[kinds.Visibility] // of sc and inv, for the found lines

	// ranges caches the indexed provider_range records (thousands of rows) as
	// of store KindVersion rangesVer; buildScope runs after every stage.
	ranges    *provider.Ranges
	rangesVer uint64
	scopeSig  string // what the Scope was last built from (see buildScope)
	// baseBuilt is the build loadBaseline made, from the records baseSig says,
	// for the first buildScope to reuse when nothing has changed since.
	baseBuilt *Built
	baseSig   string
	// policy is the egress Policy last set, and scriptsVer the script KindVersion
	// its Scripts were read at: new scripts only replace Policy.Scripts.
	policy     *egress.Policy
	scriptsVer uint64

	recMu     sync.Mutex
	recs      map[string]recordsCache   // the records of each kind read so far (see records)
	observing map[string]observersCache // the observers of each kind read so far (see observers)

	mu      sync.Mutex
	failed  map[string]map[string]bool // stage -> check key, failed this run
	stats   map[string]*stageStats
	last    map[string]string // last printed state signature
	counts  map[string]int    // last emitted category counts
	lastTot map[string]int    // category counts computed by the last emitCounts
	aborted map[string]error  // stage -> the error that aborted it this run

	guarded sync.Map // value+"\x00"+reason already sent to the guard pseudo-stage
	warned  sync.Map // warning texts already emitted this run (see warn)

	derivedSig     string                          // what the findings were last derived from (see deriveFindings)
	attribution    map[string]findings.StorageAttr // the storage attribution of that derivation
	storedFindings [sha256.Size]byte               // the date and findings last stored (see storeDerived)

	derivers   []*deriver           // the derived records other than findings (see deriveRecords)
	findingIn  []kinds.Named        // the kinds the findings are derived from (see derivationSignature)
	evidencers map[string]Evidencer // the stages that account for their own candidate evidence

	base       *baseline        // the state the run started from, nil on a first run (see loadBaseline)
	changes    []output.Change  // what the last render found changed since then
	target     map[string]bool  // the stages that make contact with the target
	lastShown  []store.ShownRow // the baseline last saved, and whether one was (see saveShown)
	shownSaved bool
}

// recordsCache holds the records of a kind, and the current ones among them,
// as of store KindVersion ver.
type recordsCache struct {
	ver       uint64
	all, curr []store.Record
}

// observersCache holds the observers of the records of a kind as of store
// KindVersion ver. Completing, redoing or retiring a check bumps the version of
// every kind it observes, so the version also tracks the checks that count.
type observersCache struct {
	ver uint64
	m   map[string][]store.Observer
}

// stageStats are a stage's counters. spent is the budget the checks sent this
// run have used (see Budgeted) and deferred the cost of the checks its last
// pass deferred.
//
// completed, succeeded, cancelled and rejected feed the Result: the checks Stage.Run returned from
// (succeeded when without error), the ones the context ended, and the failures a refused key caused.
type stageStats struct{ attempted, failed, spent, deferred, completed, succeeded, cancelled, rejected int }

// New creates a Runner.
func New(cfg Config) *Runner {
	r := &Runner{
		cfg: cfg, st: cfg.Engagement.Store(),
		failed: map[string]map[string]bool{}, stats: map[string]*stageStats{},
		last: map[string]string{}, counts: map[string]int{}, aborted: map[string]error{},
		recs: map[string]recordsCache{}, observing: map[string]observersCache{},
	}
	r.evidencers = map[string]Evidencer{}
	for _, s := range cfg.Stages {
		r.order = append(r.order, s.Name())
		if e, ok := s.(Evidencer); ok {
			r.evidencers[s.Name()] = e
		}
	}
	r.derivers = r.newDerivers()
	r.findingIn = r.findingInputs()
	r.target = targetStages(cfg.Stages)
	if cfg.Clock == nil {
		r.cfg.Clock = time.Now
	}
	return r
}

func (r *Runner) emit(typ string, fields map[string]any) {
	r.cfg.Emitter.Emit(report.Event{Type: typ, Fields: fields})
}

// warn emits a warning event, a WARN line on the console. A text already
// emitted in this run is not emitted again: View.Warn is called from Checks,
// which runs on every pass, so the same warning would otherwise repeat. A
// message whose text differs is a different warning.
func (r *Runner) warn(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if _, seen := r.warned.LoadOrStore(msg, struct{}{}); seen {
		return
	}
	r.emit("warning", map[string]any{"message": msg})
}

func (r *Runner) today() string { return r.cfg.Clock().UTC().Format(time.DateOnly) }

// Run executes the engagement. It returns a nil error when every pass has finished; the Result
// then holds the summary. When the context ends the run the error wraps context.Cause(ctx), and
// the Result is still filled in from what was done: the work is flushed, the scope rebuilt and
// the files rendered first. A *NetblockLimitError, or any other error, leaves the Result zero;
// the files are still rendered first. An error from that render or flush replaces them.
func (r *Runner) Run(ctx context.Context) (Result, error) {
	eng := r.cfg.Engagement
	if r.cfg.Redo != "" {
		if err := r.st.Redo(r.cfg.Redo); err != nil {
			return Result{}, err
		}
	}
	if err := output.Sweep(eng.Dir()); err != nil {
		return Result{}, err
	}
	r.st.OnNew(r.onNewRecord)

	// The inputs are merged before the run starts and are fixed for its life.
	var err error
	if r.inputs, err = eng.Inputs(); err != nil {
		return Result{}, err
	}
	r.acked = eng.Acked()
	r.emit("run_start", map[string]any{
		"engagement": filepath.Base(eng.Dir()),
		"scope": fmt.Sprintf("%d roots, %d orgs, %d asns, %d cidrs, %d exclusions",
			len(r.inputs.Roots), len(r.inputs.Orgs), len(r.inputs.ASNs), len(r.inputs.CIDRs), len(r.inputs.Exclusions)),
		"passive": r.cfg.Passive, "authorised": r.acked,
	})
	r.warnUnauthorised()
	r.warnStaleEOLData()

	// The baseline is read before anything is derived, from what the last render
	// saved, so that a run that is resumed compares against where the run it
	// resumes stopped.
	if r.base, err = r.loadBaseline(); err != nil {
		return Result{}, err
	}
	if err = r.passes(ctx); err == nil {
		// The final pass has just rendered and counted; nothing has changed since.
		return r.result(), nil
	}
	return r.wrapUp(ctx, err)
}

// wrapUp renders what a run that ended in err has done. When the context ended the run, the
// work of the stage it cut short is flushed, the scope is rebuilt (which can meet the netblock
// limit, and then that is the error), the files are rendered and the counts emitted, so the
// summary and the findings include that work.
func (r *Runner) wrapUp(ctx context.Context, err error) (Result, error) {
	cut := ctx.Err() != nil && errors.Is(err, context.Cause(ctx))
	if cut {
		if ferr := r.st.Flush(); ferr != nil {
			err, cut = ferr, false
		} else if berr := r.buildScope(); berr != nil {
			err, cut = berr, false
		}
	}
	snap, rerr := r.render()
	if rerr != nil {
		return Result{}, rerr
	}
	if !cut {
		return Result{}, err
	}
	r.emitCounts(snap)
	return r.result(), err
}

// passes runs passes over every stage until one does no work, rendering the
// files and emitting the counts after each.
func (r *Runner) passes(ctx context.Context) error {
	ctx = withRunState(ctx)
	for pass := 1; ; pass++ {
		worked, err := r.pass(ctx, pass == 1)
		if err != nil {
			return err
		}
		rendered, err := r.render()
		if err != nil {
			return err
		}
		r.emitCounts(rendered)
		// A pass that did no work has nothing left to cut short, so a deadline or a
		// signal that lands during its render changes nothing.
		if !worked {
			return nil
		}
		if ctx.Err() != nil {
			return interrupted(ctx)
		}
	}
}

// pass runs every stage once, in registry order, and reports whether any of
// them did work.
func (r *Runner) pass(ctx context.Context, first bool) (bool, error) {
	if err := r.buildScope(); err != nil {
		return false, err
	}
	worked := false
	for _, s := range r.cfg.Stages {
		if ctx.Err() != nil {
			return false, interrupted(ctx)
		}
		did, err := r.runStage(ctx, s, first)
		if err != nil {
			return false, err
		}
		worked = worked || did
		if ctx.Err() != nil {
			return false, interrupted(ctx)
		}
		if did {
			if err := r.afterWork(); err != nil {
				return false, err
			}
		}
	}
	return worked, nil
}

// afterWork follows a stage that did work: it flushes the store, rebuilds the
// scope and derives again. Findings follow every stage that did work, so a
// finding's found line is printed as soon as its evidence is stored.
func (r *Runner) afterWork() error {
	if err := r.st.Flush(); err != nil {
		return err
	}
	if err := r.buildScope(); err != nil {
		return err
	}
	return r.derive()
}

// buildScope builds the Scope and the egress Policy from stored inputs and
// observations (see BuildScope), then applies the netblock guard. It does
// nothing when none of them has changed since the last build, and only renews
// Policy.Scripts when just the script records have.
func (r *Runner) buildScope() error {
	eng := r.cfg.Engagement
	// The inputs and the authorisation are fixed for the run (see Run), so
	// only the records the scope is built from can change it.
	sig := r.kindSig(scopeKinds)
	if sig == r.scopeSig {
		if r.st.KindVersion(kinds.Script.Name()) == r.scriptsVer {
			return nil
		}
		p := *r.policy
		if err := r.setScripts(&p); err != nil {
			return err
		}
		r.cfg.Egress.SetPolicy(&p)
		r.policy = &p
		return nil
	}
	built := r.baseBuilt
	r.baseBuilt = nil
	if built == nil || sig != r.baseSig {
		var err error
		if built, err = BuildScope(r.inputs, runnerSource{r}); err != nil {
			return err
		}
	}
	sc, inv := built.Scope, built.Inv
	r.sc.Store(sc)
	r.inv.Store(inv)
	r.vis.Store(built.Vis)

	var sensitivePaths []string // egress addresses an entry by its index
	for _, e := range r.cfg.Settings.SensitivePathEntries {
		sensitivePaths = append(sensitivePaths, e.Path)
	}
	p := &egress.Policy{
		Scope: sc, Ack: r.acked, Passive: r.cfg.Passive,
		Ports: r.cfg.Settings.Ports, SensitivePaths: sensitivePaths,
		Resolutions: inv.Addrs(), Candidates: built.Candidates,
		Shared:       inv.Shared,
		OwnerUnknown: func(a netip.Addr) bool { return !inv.OwnerKnown(a, sc) },
		Excluded:     r.guard,
	}
	if err := r.setScripts(p); err != nil {
		return err
	}
	r.cfg.Egress.SetPolicy(p)
	r.policy = p

	count := sc.IPv4AddressCount()
	limit := uint64(r.cfg.Settings.NetblockLimit)
	if approved := uint64(eng.NetblockApproved()); approved > limit {
		limit = approved
	}
	if count > limit {
		if !r.cfg.AllowLargeNetblocks {
			return &NetblockLimitError{Count: count, Limit: limit}
		}
		if err := eng.SetNetblockApproved(int(count)); err != nil {
			return err
		}
	}
	r.scopeSig = sig
	return nil
}

// setScripts sets p.Scripts to the URLs of the current script records: the only
// ones egress lets the jsparse stage request.
func (r *Runner) setScripts(p *egress.Policy) error {
	ver := r.st.KindVersion(kinds.Script.Name())
	recs, err := r.currentRecords(kinds.Script)
	if err != nil {
		return err
	}
	p.Scripts = make(map[string]bool, len(recs))
	for _, rec := range recs {
		p.Scripts[rec.Key] = true
	}
	r.scriptsVer = ver
	return nil
}

// guard records an address that triggered an exclusion at dial time, once per
// distinct value and reason per run.
func (r *Runner) guard(value, reason string) {
	if _, seen := r.guarded.LoadOrStore(value+"\x00"+reason, struct{}{}); seen {
		return
	}
	r.st.Complete("guard", value, []store.Obs{kinds.ExcludedKind.Obs(value, kinds.ExcludedAttrs{Reason: reason})})
}

// hasFailed reports whether the stage's check failed earlier in this run.
func (r *Runner) hasFailed(stage, key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed[stage][key]
}

func (r *Runner) stat(stage string) *stageStats {
	if r.stats[stage] == nil {
		r.stats[stage] = &stageStats{}
	}
	return r.stats[stage]
}

// reasonNoAuthorisation is the reason a Target stage is left out until the
// operator confirms authorisation.
const reasonNoAuthorisation = "no authorisation"

// gateByRun is the part of gate that depends only on the operator's choices:
// --skip, --passive and the authorisation. It never asks the stage.
func (r *Runner) gateByRun(s Stage) (bool, string) {
	// Skipped comes before every other reason: it is the operator's choice, and
	// it must not depend on a key, --passive or the authorisation.
	if slices.Contains(r.cfg.Settings.Skip, s.Name()) {
		return false, "skipped"
	}
	if s.Contact() == Target {
		if r.cfg.Passive {
			return false, "passive-only"
		}
		if !r.acked {
			return false, reasonNoAuthorisation
		}
	}
	return true, ""
}

func (r *Runner) gate(s Stage) (bool, string) {
	if ok, reason := r.gateByRun(s); !ok {
		return false, reason
	}
	return s.Configured(Env{Settings: r.cfg.Settings, Passive: r.cfg.Passive, Authorised: r.acked})
}

// warnStaleEOLData warns, once per run and with no flag, when the run date is more than twelve
// months after the day the embedded end-of-life data was taken: past that, findings of
// end-of-life software may be missing or out of date. Findings are still derived from it.
func (r *Runner) warnStaleEOLData() {
	taken, err := time.Parse(time.DateOnly, eol.DataDate())
	if err != nil || r.today() <= taken.AddDate(1, 0, 0).Format(time.DateOnly) {
		return
	}
	r.warn("the end-of-life software data in this build was taken on %s, over twelve months ago, so end-of-life findings may be missing or out of date; use a newer build", eol.DataDate())
}

// warnUnauthorised warns, once, that stages are left out for lack of
// authorisation. It names exactly the stages whose stage line reads
// not-configured (no authorisation), in registry order, and asks no stage
// whether it is configured. It is written right after the run header so that an
// interrupted run still shows it.
func (r *Runner) warnUnauthorised() {
	var names []string
	for _, s := range r.cfg.Stages {
		if ok, reason := r.gateByRun(s); !ok && reason == reasonNoAuthorisation {
			names = append(names, s.Name())
		}
	}
	if len(names) > 0 {
		r.warn("not authorised, so these stages are left out: %s; --authorised confirms authorisation", strings.Join(names, ", "))
	}
}

func (r *Runner) setState(name, state, reason string, checks, failed int) {
	sig := fmt.Sprintf("%s|%s|%d|%d", state, reason, checks, failed)
	r.mu.Lock()
	if r.last[name] == sig {
		r.mu.Unlock()
		return
	}
	r.last[name] = sig
	r.mu.Unlock()
	f := map[string]any{"name": name, "state": state}
	if reason != "" {
		f["reason"] = reason
	}
	if state == "done" || state == "failed" {
		f["checks"], f["failed"] = checks, failed
	}
	r.emit("stage", f)
}

// runStage performs one pass of one stage and reports whether it did work: it
// attempted a check, or the sweep that finishes a redo or a retire changed a
// record. A sweep's change is work because the stage's own checks, or those of
// another stage, may read the records it changed: after --redo rdap the
// registrations the redo forgot stop being current only at the sweep, and the
// addresses they held are looked up on the next pass.
func (r *Runner) runStage(ctx context.Context, s Stage, first bool) (bool, error) {
	name := s.Name()
	if ok, reason := r.gate(s); !ok {
		r.setState(name, "not-configured", reason, 0, 0)
		return false, nil
	}
	if r.abortErr(name) != nil {
		return false, nil //nolint:nilerr // an aborted stage sits out the rest of the run; its checks are retried next run
	}
	sr, err := r.newStageRun(ctx, s)
	if err != nil {
		return false, err
	}
	sr.execute()
	if ctx.Err() != nil {
		return sr.attempted.Load() > 0, nil //nolint:nilerr // pass sees the cancelled context and reports the interruption
	}
	if n := sr.aborted.Load(); n > 0 {
		r.warn("%s: quota spent or key rejected; %d checks will be retried next run", name, n)
	}

	n := int(sr.attempted.Load())
	r.showOutcome(name, n, sr.spent, sr.deferredCost, first, len(sr.done) > 0)
	swept, err := sr.sweep()
	if err != nil {
		return n > 0, err
	}
	return n > 0 || swept, nil
}

// showOutcome adds a pass's n attempted checks and its budget to the stage's
// counters and shows the stage's state. A first pass that attempted nothing
// shows whether an earlier run did the work (doneBefore).
func (r *Runner) showOutcome(name string, n, spent, deferred int, first, doneBefore bool) {
	r.mu.Lock()
	ss := r.stat(name)
	ss.attempted += n
	ss.spent, ss.deferred = spent, deferred
	total, failed := ss.attempted, ss.failed
	r.mu.Unlock()
	switch {
	case total > 0 && failed == total:
		r.setState(name, "failed", "", total, failed)
	case total > 0:
		r.setState(name, "done", "", total, failed)
	case first && doneBefore:
		r.setState(name, "done-previously", "", 0, 0)
	case first:
		r.setState(name, "done", "", 0, 0)
	}
}

// abortErr is the error that aborted the stage in this run, or nil.
func (r *Runner) abortErr(stage string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aborted[stage]
}

// count updates a stage's counters under the lock.
func (r *Runner) count(stage string, f func(*stageStats)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r.stat(stage))
}

// failCheck records a transient failure and reports it as a debug event: a
// failed check is retried on the next run, so it is not a warning. The stage
// line and the summary count it. A panic's stack follows as debug events, one
// per line.
func (r *Runner) failCheck(stage, key string, err error) {
	r.recordFailure(stage, key, false)
	r.emit("debug", map[string]any{"message": fmt.Sprintf("%s check %s failed: %s", stage, key, err)})
	if p, ok := errors.AsType[*checkPanic](err); ok {
		for line := range strings.SplitSeq(strings.TrimRight(string(p.stack), "\n"), "\n") {
			r.emit("debug", map[string]any{"message": line})
		}
	}
}

// checkPanic is a panic inside a stage's own code: the failure of the check
// (or the enumeration) it happened in, retried on the next run like any other.
type checkPanic struct {
	value any
	stack []byte
}

func (p *checkPanic) Error() string { return fmt.Sprintf("panic: %v", p.value) }

// RecoverInto, deferred, turns a panic into *err, with the stack --debug
// shows. A stage that starts goroutines of its own defers it in each, so a
// panic there fails the check and not the process.
func RecoverInto(err *error) {
	if v := recover(); v != nil {
		*err = &checkPanic{value: v, stack: debug.Stack()}
	}
}

// runCheck runs one check, turning a panic in it into its failure.
func runCheck(ctx context.Context, s Stage, c Check, clients egress.Clients) (_ []Observation, err error) {
	defer RecoverInto(&err)
	return s.Run(ctx, c, clients)
}

// recordFailure records a transient failure: not a completion, not retried
// this run, and retried on the next because it is not completed.
//
// rejected says a refused key caused it (see Result.KeyRejected).
func (r *Runner) recordFailure(stage, key string, rejected bool) {
	r.mu.Lock()
	if r.failed[stage] == nil {
		r.failed[stage] = map[string]bool{}
	}
	r.failed[stage][key] = true
	r.stat(stage).failed++
	if rejected {
		r.stat(stage).rejected++
	}
	r.mu.Unlock()
}

// emitCounts emits the category counts that changed. They are counted from the
// snapshot render wrote the files from, with its Visibility, so the totals match
// the files' rows.
func (r *Runner) emitCounts(snap output.Snapshot) {
	totals := snap.Vis.Totals(snap.Records)
	r.lastTot = totals
	for _, k := range slices.Sorted(maps.Keys(totals)) {
		if r.counts[k] != totals[k] {
			r.counts[k] = totals[k]
			r.emit("count", map[string]any{"category": k, "n": totals[k]})
		}
	}
}

// notes are the lines the stages that run (see Noter) add to the summary, in
// registry order. A stage that is skipped or not configured says nothing.
func (r *Runner) notes() []string {
	notes := []string{}
	sc, inv := r.sc.Load(), r.inv.Load()
	if sc == nil || inv == nil {
		return notes
	}
	view := View{r: r, sc: sc, inv: inv, vis: r.vis.Load(), cache: &recordCache{m: map[string][]store.Record{}}}
	for _, s := range r.cfg.Stages {
		if n, ok := s.(Noter); ok {
			if ok, _ := r.gate(s); ok {
				notes = append(notes, n.Notes(view)...)
			}
		}
	}
	return notes
}

// onNewRecord prints records of Printed kinds the first time the engagement sees them.
func (r *Runner) onNewRecord(kind, key string, attrs map[string]any) {
	if !r.vis.Load().Printed(kind, store.Record{Key: key, Attrs: attrs}) {
		return
	}
	r.emit("found", foundFields(kind, key, attrs))
}

// foundFields are the fields of the found event for a record of the kind.
func foundFields(kind, key string, attrs map[string]any) map[string]any {
	k, _ := kinds.Get(kind)
	f := map[string]any{"category": k.Singular, "value": key}
	if k.Found != nil {
		maps.Copy(f, k.Found(store.Record{Kind: kind, Key: key, Attrs: attrs}))
	}
	return f
}

// render writes the output files from the store and returns the snapshot it
// wrote them from: the records of every kind, which it reads so a new kind's
// file can never render empty, and the scope they were filtered by.
func (r *Runner) render() (output.Snapshot, error) {
	if err := r.st.Flush(); err != nil {
		return output.Snapshot{}, err
	}
	// Findings are derived before the files are written on every path that renders,
	// including an interrupt, so the files and the totals never lag the evidence.
	if err := r.derive(); err != nil {
		return output.Snapshot{}, err
	}
	eng := r.cfg.Engagement
	snap, err := r.snapshot(r.sc.Load(), r.inv.Load(), r.vis.Load())
	if err != nil {
		return output.Snapshot{}, err
	}
	entries := entriesOf(snap)
	var carried []store.ShownRow
	snap.Changes, carried = r.base.compare(entries, r.cfg.Passive, r.target)
	r.changes = snap.Changes
	if err := output.Render(eng.Dir(), r.cfg.Files, snap, !r.cfg.NoFsync); err != nil {
		return output.Snapshot{}, err
	}
	return snap, r.saveShown(entries, carried)
}

// snapshot reads the records of every kind, which it does so that a new kind's
// file can never render empty, with the scope they are shown under (empty ones if
// none has been built yet) and its Visibility vis (built when nil).
func (r *Runner) snapshot(sc *scope.Scope, inv *inventory.Inventory, vis *kinds.Visibility) (output.Snapshot, error) {
	inputs, err := r.st.Inputs()
	if err != nil {
		return output.Snapshot{}, err
	}
	snap := output.Snapshot{Today: r.today(), Inputs: inputs, Records: map[string][]store.Record{}, Scope: sc, Inv: inv}
	for _, k := range kinds.All() {
		recs, err := r.records(k.Name)
		if err != nil {
			return output.Snapshot{}, err
		}
		snap.Records[k.Name] = recs
	}
	snap.Storage = r.attribution // computed with the findings, from the same evidence
	if snap.Scope == nil || snap.Inv == nil {
		snap.Scope = scope.New(scope.Config{})
		snap.Inv = inventory.New(inventory.Data{}, provider.Default())
		vis = nil
	}
	if snap.Vis = vis; vis == nil {
		snap.Vis = kinds.NewVisibility(snap.Scope, snap.Inv)
	}
	if snap.ASNNetblocks, err = asnNetblocks(runnerSource{r}, r.inputs); err != nil {
		return output.Snapshot{}, err
	}
	return snap, nil
}

// deriveFindings derives the findings from the evidence and stores them as
// the "finding" records of the pseudo-stage "findings", its single check key
// "derived", like guard does. A finding no longer derived loses its only
// observation, so it becomes not current and keeps its first_seen; a new one
// is printed once by the store's OnNew callback.
func (r *Runner) deriveFindings() error {
	// Nothing Derive reads has changed since the last derivation (a derivation
	// bumps only "finding"), so the findings are already current.
	sig := r.derivationSignature()
	sc, inv := r.sc.Load(), r.inv.Load()
	if sc == nil || inv == nil || sig == r.derivedSig {
		return nil
	}
	var readErr error
	in := findings.Input{Scope: sc, Inv: inv, Settings: r.cfg.Settings, Today: r.today(),
		Records: keepFirstErr(&readErr, r.records), Roots: r.inputs.Roots, Orgs: r.inputs.Orgs, Vis: r.vis.Load()}
	fs, attribution := findings.DeriveAll(in)
	if readErr != nil {
		return readErr
	}
	obs := make([]store.Obs, len(fs))
	for i, f := range fs {
		obs[i] = kinds.Finding.Obs(f.Key(), f.Attrs)
	}
	// A finding whose severity has risen (an unconfirmed port a handshake then
	// confirmed) is printed again at the new severity; a new one is printed by
	// the store's callback, and a finding that has fallen is not.
	prev, err := r.currentRecords(kinds.Finding)
	if err != nil {
		return err
	}
	stored, err := r.storeDerived("findings", obs, &r.storedFindings)
	if err != nil {
		return err
	}
	if stored {
		was := make(map[string]string, len(prev))
		for _, rec := range prev {
			was[rec.Key] = rec.Str("severity")
		}
		for _, f := range fs {
			if old, ok := was[f.Key()]; ok && findings.Higher(f.Severity, old) {
				r.emit("found", foundFields(kinds.Finding.Name(), f.Key(), f.Attrs))
			}
		}
	}
	r.derivedSig, r.attribution = sig, attribution
	return nil
}

// storeDerived stores obs as the records of the pseudo-stage name, its single
// check key "derived", and reports whether it did: storing the same records
// again on the same day as last (*last) changes nothing, so it is skipped.
func (r *Runner) storeDerived(name string, obs []store.Obs, last *[sha256.Size]byte) (bool, error) {
	sum := sha256.Sum256(fmt.Append(nil, r.today(), obs))
	if sum == *last {
		return false, nil
	}
	r.st.Complete(name, "derived", obs)
	if err := r.st.Flush(); err != nil {
		return false, err
	}
	*last = sum
	return true, nil
}

// keepFirstErr adapts a read by kind name to a derivation's reader, which has
// no error: the first error it meets is kept in *err for the caller to return.
func keepFirstErr[T any](err *error, read func(string) (T, error)) func(kinds.Named) T {
	return func(k kinds.Named) T {
		v, e := read(k.Name())
		if e != nil && *err == nil {
			*err = e
		}
		return v
	}
}

// records returns every record of a kind, current or not, read again only
// when the kind has changed since the last read. The version is read first, so
// a commit racing the read is re-read next time. Callers must not modify the
// returned slice.
func (r *Runner) records(kind string) ([]store.Record, error) {
	c, err := r.cached(kind)
	return c.all, err
}

func (r *Runner) cached(kind string) (recordsCache, error) {
	ver := r.st.KindVersion(kind)
	r.recMu.Lock()
	c, ok := r.recs[kind]
	r.recMu.Unlock()
	if ok && c.ver == ver {
		return c, nil
	}
	all, err := r.st.Records(kind, r.order)
	if err != nil {
		return recordsCache{}, err
	}
	c = recordsCache{ver: ver, all: all}
	for _, rec := range all {
		if rec.Current {
			c.curr = append(c.curr, rec)
		}
	}
	r.recMu.Lock()
	r.recs[kind] = c
	r.recMu.Unlock()
	return c, nil
}

// observers returns, per record key, the completed checks that observe a
// record of the kind (see Store.Observers), read again only when the kind has
// changed since the last read. Callers must not modify the returned map.
func (r *Runner) observers(kind string) (map[string][]store.Observer, error) {
	ver := r.st.KindVersion(kind)
	r.recMu.Lock()
	c, ok := r.observing[kind]
	r.recMu.Unlock()
	if ok && c.ver == ver {
		return c.m, nil
	}
	m, err := r.st.Observers(kind)
	if err != nil {
		return nil, err
	}
	r.recMu.Lock()
	r.observing[kind] = observersCache{ver: ver, m: m}
	r.recMu.Unlock()
	return m, nil
}

// kindSig changes whenever a record of one of the kinds ks does.
func (r *Runner) kindSig(ks []kinds.Named) string {
	var b strings.Builder
	for _, k := range ks {
		fmt.Fprintf(&b, "%s=%d;", k.Name(), r.st.KindVersion(k.Name()))
	}
	return b.String()
}

// derivationSignature changes whenever a record of one of the findings' input
// kinds or the date changes. The Scope and Inventory are built from nothing
// else, and the settings and inputs are fixed for the Runner's life.
func (r *Runner) derivationSignature() string {
	return r.kindSig(r.findingIn) + r.today()
}

// findingInputs is every kind but the derived ones ("finding" and those the
// derivers write). The findings do not read the derived records, so storing
// them must not derive the findings again.
func (r *Runner) findingInputs() []kinds.Named {
	derived := map[string]bool{kinds.Finding.Name(): true}
	for _, d := range r.derivers {
		derived[d.writes.Name()] = true
	}
	var read []kinds.Named
	for _, k := range kinds.All() {
		if !derived[k.Name] {
			named, _ := kinds.Lookup(k.Name)
			read = append(read, named)
		}
	}
	return read
}

// currentRecords returns the current records of a kind. Callers must not
// modify the returned slice.
func (r *Runner) currentRecords(k kinds.Named) ([]store.Record, error) {
	c, err := r.cached(k.Name())
	return c.curr, err
}
