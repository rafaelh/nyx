// Package run executes discovery procedures until no new work remains. It manages worker pools,
// procedure eligibility, netblock limits, redo and console progress.
//
// A procedure is one concrete way of carrying out a technique, such as asking a certificate
// transparency log for names or handshaking with a port. It performs jobs: each job is a resumable
// unit of work with a key that encodes every input and setting that changes it, and its completion
// is stored, so a re-run performs only the jobs that have not completed.
//
// An analysis is a record nyx produces itself rather than one a procedure observes: findings,
// candidate ranks, third parties derived from CNAMEs, and the addresses egress refused to dial
// (the guard). It runs no jobs and stores no completion, only the observations it produces.
// AnalysisNames lists them; each writes a kind of its own, apart from third_party, which a
// procedure may also observe, so a record has at most one analysis.
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
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/eol"
	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/recon/analysis/candidates"
	"github.com/rafaelh/nyx/internal/recon/analysis/findings"
	"github.com/rafaelh/nyx/internal/recon/engagement"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/output"
	"github.com/rafaelh/nyx/internal/recon/report"
	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/threatdata/abusive"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
)

// NetblockLimitError reports that the in-scope IPv4 address count exceeds the limit. The caller
// can suggest --allow-large-netblocks.
type NetblockLimitError struct{ Count, Limit uint64 }

func (e *NetblockLimitError) Error() string {
	return fmt.Sprintf("in-scope IPv4 netblocks cover %d addresses, over the limit of %d; nothing in them was contacted", e.Count, e.Limit)
}

// interrupted wraps the context's cause so callers can distinguish cancellation from a
// deadline.
func interrupted(ctx context.Context) error {
	return fmt.Errorf("run interrupted: %w", context.Cause(ctx))
}

// Config supplies the runner's dependencies and settings.
type Config struct {
	Engagement          *engagement.Engagement
	Settings            config.Settings
	Procedures          []Procedure
	Egress              *egress.Egress
	Emitter             report.Emitter
	Files               []output.File
	Clock               func() time.Time
	Passive             bool
	AllowLargeNetblocks bool
	Redo                string
	NoFsync             bool // skip disk syncs in tests; see output.Render
	// Abusive supplies the network and ASN snapshot used by findings. Nil selects the
	// embedded snapshot.
	Abusive *abusive.Snapshot
	// Drop supplies Spamhaus DROP, DROPv6 and ASN-DROP data for findings. Nil selects the
	// embedded lists.
	Drop *spamhaus.Lists
}

// Runner coordinates procedure execution, stored state and output for an engagement.
type Runner struct {
	cfg   Config
	st    *store.Store
	order []string

	inputs input.Parsed
	acked  bool // engagement authorisation, fixed at the start of Run
	sc     atomic.Pointer[scope.Scope]
	inv    atomic.Pointer[inventory.Inventory]
	vis    atomic.Pointer[kinds.Visibility] // visibility for sc and inv, used by found events

	// ranges caches the provider-range index at rangesVer. Rebuilding it after every procedure
	// would repeatedly index thousands of rows.
	ranges    *provider.Ranges
	rangesVer uint64
	scopeSig  string // signature of the inputs used to build sc
	// baseBuilt lets the first buildScope reuse loadBaseline's scope if the records still
	// match baseSig.
	baseBuilt *Built
	baseSig   string
	// policy is the last installed egress policy. scriptsVer tracks its script records so
	// script-only changes can update Policy.Scripts without rebuilding scope.
	policy     *egress.Policy
	scriptsVer uint64

	recMu     sync.Mutex
	recs      map[string]recordsCache   // cached records by kind; see records
	observing map[string]observersCache // cached record observers by kind; see observers

	mu      sync.Mutex
	failed  map[string]map[string]bool // procedure -> job key, failed this run
	stats   map[string]*procedureStats
	last    map[string]string // last printed state signature
	counts  map[string]int    // last emitted category counts
	lastTot map[string]int    // category counts computed by the last emitCounts
	aborted map[string]error  // procedure -> the error that aborted it this run

	guarded sync.Map // deduplicates guard records by value and reason
	warned  sync.Map // warning texts already emitted this run (see warn)

	analyses    []*analysis                     // derivations in execution order, starting with findings
	attribution map[string]findings.StorageAttr // storage attribution from the last findings calculation
	evidencers  map[string]Evidencer            // procedures that describe their candidate evidence
	historical  map[string]bool                 // the procedures whose addresses come from DNS history
	families    candidates.Families             // candidate source families supplied by procedures

	base       *baseline        // starting baseline; nil for a first run
	changes    []output.Change  // changes from the starting baseline at the last render
	target     map[string]bool  // the procedures that make contact with the target
	lastShown  []store.ShownRow // last saved baseline and whether a baseline exists
	shownSaved bool
	out        *output.Writer // renderer that skips unchanged files
	// renderSig identifies the inputs used for the cached rendered snapshot.
	renderSig string
	rendered  output.Snapshot
}

// recordsCache holds all records and the current subset for one kind at store version ver.
type recordsCache struct {
	ver       uint64
	all, curr []store.Record
}

// observersCache holds a kind's supporting jobs at version ver. Completing, redoing or
// retiring a job updates every affected kind's version, so record versions also invalidate
// this cache.
type observersCache struct {
	ver uint64
	m   map[string][]store.Observer
}

// procedureStats tracks work and outcomes for one procedure. spent accumulates the cost sent this
// run; deferred records the cost left pending in the last pass. Completed, succeeded, cancelled and
// rejected counters feed Result.
type procedureStats struct{ attempted, failed, spent, deferred, completed, succeeded, cancelled, rejected int }

func New(cfg Config) *Runner {
	r := &Runner{
		cfg: cfg, st: cfg.Engagement.Store(),
		failed: map[string]map[string]bool{}, stats: map[string]*procedureStats{},
		last: map[string]string{}, counts: map[string]int{}, aborted: map[string]error{},
		recs: map[string]recordsCache{}, observing: map[string]observersCache{},
	}
	r.evidencers = map[string]Evidencer{}
	r.historical = map[string]bool{}
	if r.cfg.Abusive == nil {
		r.cfg.Abusive = abusive.Default()
	}
	if r.cfg.Drop == nil {
		r.cfg.Drop = spamhaus.Default()
	}
	for _, s := range cfg.Procedures {
		r.order = append(r.order, s.Name())
		if e, ok := s.(Evidencer); ok {
			r.evidencers[s.Name()] = e
		}
		if _, ok := s.(Historical); ok {
			r.historical[s.Name()] = true
		}
	}
	r.families = CandidateFamilies(cfg.Procedures)
	r.analyses = r.newAnalyses()
	r.target = targetProcedures(cfg.Procedures)
	r.out = output.NewWriter(cfg.Engagement.Dir(), !cfg.NoFsync)
	if cfg.Clock == nil {
		r.cfg.Clock = time.Now
	}
	return r
}

func (r *Runner) emit(typ string, fields map[string]any) {
	r.cfg.Emitter.Emit(report.Event{Type: typ, Fields: fields})
}

// warn emits each distinct warning text once per run. Jobs can report the same warning on
// successive passes without repeating console output.
func (r *Runner) warn(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if _, seen := r.warned.LoadOrStore(msg, struct{}{}); seen {
		return
	}
	r.emit("warning", map[string]any{"message": msg})
}

func (r *Runner) today() string { return r.cfg.Clock().UTC().Format(time.DateOnly) }

// Run executes all passes and returns the rendered summary. On cancellation or deadline, it
// flushes work, rebuilds scope and renders files before returning a populated Result and an
// error wrapping context.Cause(ctx). Other errors return a zero Result after attempting to
// render. Flush or render failures take precedence over the original error.
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

	// Inputs have already been merged and stay fixed throughout this run.
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

	// Read the last saved output before derivation so a resumed run compares against where
	// the previous run stopped.
	if r.base, err = r.loadBaseline(); err != nil {
		return Result{}, err
	}
	if err = r.passes(ctx); err == nil {
		// The final pass already rendered and counted this state.
		return r.result(), nil
	}
	return r.wrapUp(ctx, err)
}

// wrapUp saves and renders work after an error. For cancellation, it also rebuilds scope and
// emits counts so partial results include the interrupted procedure's work. A netblock-limit error
// found during that rebuild takes precedence.
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

// passes repeats the procedure registry until no procedure does work, rendering output after each
// pass.
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
		// Once a pass finds no work, a signal or deadline during rendering does not
		// interrupt any pending jobs.
		if !worked {
			return nil
		}
		if ctx.Err() != nil {
			return interrupted(ctx)
		}
	}
}

func (r *Runner) pass(ctx context.Context, first bool) (bool, error) {
	if err := r.buildScope(); err != nil {
		return false, err
	}
	worked := false
	for _, s := range r.cfg.Procedures {
		if ctx.Err() != nil {
			return false, interrupted(ctx)
		}
		did, err := r.runProcedure(ctx, s, first)
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

// afterWork flushes observations, rebuilds scope and recalculates derived records. This lets
// findings appear as soon as their evidence is stored.
func (r *Runner) afterWork() error {
	if err := r.st.Flush(); err != nil {
		return err
	}
	if err := r.buildScope(); err != nil {
		return err
	}
	return r.derive()
}

// buildScope updates scope, egress policy and the netblock guard from stored state. It reuses
// unchanged builds and updates only Policy.Scripts when scripts are the only changed input.
func (r *Runner) buildScope() error {
	eng := r.cfg.Engagement
	// Inputs and authorisation are fixed, so only changes to the scope's source records can
	// invalidate this build.
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
		if built, err = BuildScope(r.inputs, r.cfg.Procedures, runnerSource{r}); err != nil {
			return err
		}
	}
	sc, inv := built.Scope, built.Inv
	r.sc.Store(sc)
	r.inv.Store(inv)
	r.vis.Store(built.Vis)

	var sensitivePaths []string // egress refers to exclusions by index
	for _, e := range r.cfg.Settings.SensitivePathEntries {
		sensitivePaths = append(sensitivePaths, e.Path)
	}
	p := &egress.Policy{
		Scope: sc, Ack: r.acked, Passive: r.cfg.Passive,
		Ports: r.cfg.Settings.Ports, SensitivePaths: sensitivePaths,
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

// setScripts installs the current script URLs that egress allows jsparse to request.
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

// guard records each address and exclusion reason once per run when egress blocks a dial.
func (r *Runner) guard(value, reason string) {
	if _, seen := r.guarded.LoadOrStore(value+"\x00"+reason, struct{}{}); seen {
		return
	}
	r.st.Put(AnalysisGuard, value, []store.Obs{kinds.ExcludedKind.Obs(value, kinds.ExcludedAttrs{Reason: reason})})
}

func (r *Runner) hasFailed(procedure, key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failed[procedure][key]
}

func (r *Runner) stat(procedure string) *procedureStats {
	if r.stats[procedure] == nil {
		r.stats[procedure] = &procedureStats{}
	}
	return r.stats[procedure]
}

const reasonNoAuthorisation = "no authorisation"

// gateByRun checks --skip, --passive and authorisation without calling procedure code.
func (r *Runner) gateByRun(s Procedure) (bool, string) {
	// An explicit --skip takes precedence over configuration and authorisation checks.
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

func (r *Runner) gate(s Procedure) (bool, string) {
	if ok, reason := r.gateByRun(s); !ok {
		return false, reason
	}
	return s.Configured(Env{Settings: r.cfg.Settings, Passive: r.cfg.Passive, Authorised: r.acked})
}

// warnStaleEOLData warns once when embedded end-of-life data is over twelve months old.
// Findings still use that data, but may miss recent support changes.
func (r *Runner) warnStaleEOLData() {
	taken, err := time.Parse(time.DateOnly, eol.DataDate())
	if err != nil || r.today() <= taken.AddDate(1, 0, 0).Format(time.DateOnly) {
		return
	}
	r.warn("the end-of-life software data in this build was taken on %s, over twelve months ago, so end-of-life findings may be missing or out of date; use a newer build", eol.DataDate())
}

// warnUnauthorised lists procedures blocked by missing authorisation in registry order. It runs
// just after the header so even an interrupted run shows the warning, without calling procedure
// configuration checks.
func (r *Runner) warnUnauthorised() {
	var names []string
	for _, s := range r.cfg.Procedures {
		if ok, reason := r.gateByRun(s); !ok && reason == reasonNoAuthorisation {
			names = append(names, s.Name())
		}
	}
	if len(names) > 0 {
		r.warn("not authorised, so these procedures are left out: %s; --authorised confirms authorisation", strings.Join(names, ", "))
	}
}

func (r *Runner) setState(name, state, reason string, jobs, failed int) {
	sig := fmt.Sprintf("%s|%s|%d|%d", state, reason, jobs, failed)
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
		f["jobs"], f["failed"] = jobs, failed
	}
	r.emit("procedure", f)
}

// runProcedure reports work when a job was attempted or a redo/retirement sweep changed records.
// Sweep changes can create work for later passes: removing an old RDAP registration, for
// example, makes its addresses eligible for another lookup.
func (r *Runner) runProcedure(ctx context.Context, s Procedure, first bool) (bool, error) {
	name := s.Name()
	if ok, reason := r.gate(s); !ok {
		if !unlisted(s, ok, reason) {
			r.setState(name, "not-configured", reason, 0, 0)
		}
		return false, nil
	}
	if r.abortErr(name) != nil {
		return false, nil //nolint:nilerr // an aborted procedure sits out the rest of the run; its jobs are retried next run
	}
	sr, err := r.newProcedureRun(ctx, s)
	if err != nil {
		return false, err
	}
	sr.execute()
	if ctx.Err() != nil {
		return sr.attempted.Load() > 0, nil //nolint:nilerr // pass sees the cancelled context and reports the interruption
	}
	if n := sr.aborted.Load(); n > 0 {
		r.warn("%s: quota spent or key rejected; %d jobs will be retried next run", name, n)
	}

	n := int(sr.attempted.Load())
	r.showOutcome(name, n, sr.spent, sr.deferredCost, first, len(sr.done) > 0)
	swept, err := sr.sweep()
	if err != nil {
		return n > 0, err
	}
	return n > 0 || swept, nil
}

// showOutcome updates attempt and budget counters, then displays the procedure state. If the first
// pass attempts nothing, doneBefore distinguishes previously completed work.
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

func (r *Runner) abortErr(procedure string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.aborted[procedure]
}

func (r *Runner) count(procedure string, f func(*procedureStats)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f(r.stat(procedure))
}

// failJob counts a failure and logs details at debug level. Failed jobs are retried next
// run; the procedure summary reports their count. Panics also log their stack, one line per debug
// event.
func (r *Runner) failJob(procedure, key string, err error) {
	r.recordFailure(procedure, key, false)
	r.emit("debug", map[string]any{"message": fmt.Sprintf("%s job %s failed: %s", procedure, key, err)})
	if p, ok := errors.AsType[*jobPanic](err); ok {
		for line := range strings.SplitSeq(strings.TrimRight(string(p.stack), "\n"), "\n") {
			r.emit("debug", map[string]any{"message": line})
		}
	}
}

// jobPanic carries a procedure panic and stack as a retryable job or enumeration failure.
type jobPanic struct {
	value any
	stack []byte
}

func (p *jobPanic) Error() string { return fmt.Sprintf("panic: %v", p.value) }

// RecoverInto converts a panic to an error with a stack for --debug. Defer it in each
// procedure-owned goroutine to keep that goroutine's panic from terminating the process.
func RecoverInto(err *error) {
	if v := recover(); v != nil {
		*err = &jobPanic{value: v, stack: debug.Stack()}
	}
}

// runJob turns a procedure panic into a job failure.
func runJob(ctx context.Context, s Procedure, c Job, clients egress.Clients) (_ []Observation, err error) {
	defer RecoverInto(&err)
	return s.Run(ctx, c, clients)
}

// recordFailure counts a job as failed for this run without marking it complete, allowing
// retry next run. rejected identifies failures caused by an API-key rejection.
func (r *Runner) recordFailure(procedure, key string, rejected bool) {
	r.mu.Lock()
	if r.failed[procedure] == nil {
		r.failed[procedure] = map[string]bool{}
	}
	r.failed[procedure][key] = true
	r.stat(procedure).failed++
	if rejected {
		r.stat(procedure).rejected++
	}
	r.mu.Unlock()
}

// emitCounts uses the rendered snapshot's visibility rules so emitted totals match the output
// rows. Only changed counts produce events.
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

// notes collects summary notes in registry order from procedures eligible to run.
func (r *Runner) notes() []string {
	notes := []string{}
	sc, inv := r.sc.Load(), r.inv.Load()
	if sc == nil || inv == nil {
		return notes
	}
	view := View{r: r, sc: sc, inv: inv, vis: r.vis.Load(), cache: &recordCache{m: map[string][]store.Record{}}}
	for _, s := range r.cfg.Procedures {
		if n, ok := s.(Noter); ok {
			if ok, _ := r.gate(s); ok {
				notes = append(notes, n.Notes(view)...)
			}
		}
	}
	return notes
}

// onNewRecord announces newly discovered records whose kinds allow console output.
func (r *Runner) onNewRecord(kind, key string, attrs map[string]any) {
	if !r.vis.Load().Printed(kind, store.Record{Key: key, Attrs: attrs}) {
		return
	}
	r.emit("found", foundFields(kind, key, attrs))
}

func foundFields(kind, key string, attrs map[string]any) map[string]any {
	k, _ := kinds.Get(kind)
	f := map[string]any{"category": k.Singular, "value": key}
	if k.Found != nil {
		maps.Copy(f, k.Found(store.Record{Kind: kind, Key: key, Attrs: attrs}))
	}
	return f
}

// render writes output and returns the snapshot used to produce it. It reads every registered
// kind so newly added kinds are included automatically.
func (r *Runner) render() (output.Snapshot, error) {
	if err := r.st.Flush(); err != nil {
		return output.Snapshot{}, err
	}
	// Recalculate findings even on interruption so files and totals include all stored
	// evidence.
	if err := r.derive(); err != nil {
		return output.Snapshot{}, err
	}
	// Inputs and baseline are fixed for the run. If records, visibility and date are
	// unchanged, reuse the previous render.
	sig := r.renderInputs()
	if sig == r.renderSig {
		return r.rendered, nil
	}
	snap, err := r.snapshot(r.sc.Load(), r.inv.Load(), r.vis.Load())
	if err != nil {
		return output.Snapshot{}, err
	}
	entries := entriesOf(snap)
	var carried []store.ShownRow
	snap.Changes, carried = r.base.compare(entries, r.cfg.Passive, r.target)
	r.changes = snap.Changes
	if err := r.out.Render(r.cfg.Files, snap); err != nil {
		return output.Snapshot{}, err
	}
	if err := r.saveShown(entries, carried); err != nil {
		return output.Snapshot{}, err
	}
	r.renderSig, r.rendered = sig, snap
	return snap, nil
}

// renderInputs fingerprints records, scope and date to detect when output may change.
func (r *Runner) renderInputs() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s|%p|%p|%p|", r.today(), r.sc.Load(), r.inv.Load(), r.vis.Load())
	for _, k := range kinds.All() {
		fmt.Fprintf(&b, "%s=%d;", k.Name, r.st.KindVersion(k.Name))
	}
	return b.String()
}

// snapshot reads every registered kind for output. Before the first scope build it supplies
// empty scope and inventory values. A nil vis is rebuilt from those values.
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
	if snap.ASNNetblocks, err = asnNetblocks(runnerSource{r}, r.cfg.Procedures, r.inputs); err != nil {
		return output.Snapshot{}, err
	}
	return snap, nil
}

// storeAnalysis writes an analysis's observations under its own name, with no job. It skips
// writes when both the date and records match *last, and reports whether it wrote anything.
func (r *Runner) storeAnalysis(name string, obs []store.Obs, last *[sha256.Size]byte) (bool, error) {
	sum := sha256.Sum256(fmt.Append(nil, r.today(), obs))
	if sum == *last {
		return false, nil
	}
	r.st.Put(name, "", obs)
	if err := r.st.Flush(); err != nil {
		return false, err
	}
	*last = sum
	return true, nil
}

// keepFirstErr adapts an error-returning reader for derivations. It saves the first read error
// for the caller because the derivation's reader signature cannot return errors.
func keepFirstErr[T any](err *error, read func(string) (T, error)) func(kinds.Named) T {
	return func(k kinds.Named) T {
		v, e := read(k.Name())
		if e != nil && *err == nil {
			*err = e
		}
		return v
	}
}

// records caches all records, including non-current ones, until the kind's version changes.
// Reading the version first ensures a concurrent commit triggers another read next time. Treat
// the returned slice as read-only.
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

// observers caches completed jobs supporting each record until the kind's version changes.
// Treat the returned map as read-only.
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

// kindSig fingerprints the versions of the supplied record kinds.
func (r *Runner) kindSig(ks []kinds.Named) string {
	var b strings.Builder
	for _, k := range ks {
		fmt.Fprintf(&b, "%s=%d;", k.Name(), r.st.KindVersion(k.Name()))
	}
	return b.String()
}

// currentRecords returns cached current records. Treat the returned slice as read-only.
func (r *Runner) currentRecords(k kinds.Named) ([]store.Record, error) {
	c, err := r.cached(k.Name())
	return c.curr, err
}
