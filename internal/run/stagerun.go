package run

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/fault"
	"github.com/rafaelh/nyx/internal/store"
)

// stageRun is one pass of one stage: a producer, on the calling goroutine,
// that lists the stage's checks and decides which to send, and a pool of
// workers that run them. The fields below the workers' are the producer's own,
// read by runStage only once the workers have finished.
type stageRun struct {
	r    *Runner
	ctx  context.Context // the run's context, with the warner that Checks and Run use
	s    Stage
	name string

	done        map[string]struct{} // the stored keys of the stage's completed checks
	redoPending bool
	retiring    bool
	clients     egress.Clients
	view        View
	workers     int

	work      chan Check
	attempted atomic.Int64
	aborted   atomic.Int64 // checks failed by the stage's abort

	// all holds the keys yielded, in stored (redacted) form like done, to skip a
	// key a stage yields more than once. Only a redo or a retire needs every
	// key; otherwise a completed key is skipped by done and is not kept.
	all     map[string]struct{}
	keepAll bool
	// A budgeted stage spends its budget on the pending checks in the order it
	// yields them. The first one that would pass it, and every pending one after
	// it, is deferred: not sent, not failed, not attempted. The check is already
	// in all, so a redo or a retire still counts it as valid and its earlier
	// evidence stays current. The first pending check of the run is always taken.
	budget       int // 0: the stage is not budgeted
	spent        int
	deferredCost int
	enumFailed   bool
	running      bool // whether the stage has been shown as running
}

// newStageRun reads what a pass of the stage starts from: its completed
// checks, whether a redo of it is pending, the checks failed this run, its
// clients and its budget.
func (r *Runner) newStageRun(ctx context.Context, s Stage) (*stageRun, error) {
	name := s.Name()
	done, err := r.st.Completed(name)
	if err != nil {
		return nil, err
	}
	pend, _ := r.st.PendingRedo()
	sr := &stageRun{r: r, ctx: withWarner(ctx, r.warn), s: s, name: name, done: done,
		redoPending: slices.Contains(pend, name)}
	var exempt []string
	if ce, ok := s.(CandidateExempt); ok {
		exempt = ce.CandidateExemptSources()
	}
	sr.clients = r.cfg.Egress.ClientsWith(s.Contact() == Target, s.Sources(), exempt)
	sr.view = View{r: r, sc: r.sc.Load(), inv: r.inv.Load(), vis: r.vis.Load(), cache: &recordCache{m: map[string][]store.Record{}}, done: done}

	sr.workers = r.cfg.Settings.Concurrency
	if wc, ok := s.(WorkerCounter); ok {
		sr.workers = wc.Workers(r.cfg.Settings)
	}
	// With no workers the first send on work would block forever.
	sr.workers = max(sr.workers, 1)

	_, sr.retiring = s.(Retiring)
	sr.keepAll = sr.redoPending || sr.retiring
	sr.all = map[string]struct{}{}
	if b, ok := s.(Budgeted); ok {
		sr.budget = max(b.Budget(r.cfg.Settings), 1)
	}
	r.mu.Lock()
	sr.spent = r.stat(name).spent
	r.mu.Unlock()
	return sr, nil
}

// execute starts the workers, sends them the pending checks and waits for
// them to finish.
func (sr *stageRun) execute() {
	sr.work = make(chan Check)
	var wg sync.WaitGroup
	for range sr.workers {
		wg.Go(func() {
			for c := range sr.work {
				sr.runOne(c)
			}
		})
	}
	sr.produce()
	close(sr.work)
	wg.Wait()
}

// abortFail fails a check because its stage aborted with cause. The stage warns
// once for all of them (see runStage), not once per check.
func (sr *stageRun) abortFail(key string, cause error) {
	sr.r.recordFailure(sr.name, key, errors.Is(cause, ErrKeyRejected))
	sr.aborted.Add(1)
}

// abortedEarlier fails, as attempted, a check of a stage that aborted earlier
// in this run, and reports whether it did.
func (sr *stageRun) abortedEarlier(key string) bool {
	cause := sr.r.abortErr(sr.name)
	if cause == nil {
		return false
	}
	sr.attempted.Add(1)
	sr.abortFail(key, cause)
	return true
}

// runOne runs a check on a worker and records its result. A check the
// context ended is abandoned, and redone next run.
func (sr *stageRun) runOne(c Check) {
	r, name := sr.r, sr.name
	if sr.ctx.Err() != nil {
		return
	}
	if sr.abortedEarlier(c.Key) {
		return
	}
	fault.PointDetail("in-flight", c.Key)
	obs, err := runCheck(sr.ctx, sr.s, c, sr.clients)
	if sr.ctx.Err() != nil {
		r.count(name, func(s *stageStats) { s.cancelled++ })
		return
	}
	r.count(name, func(s *stageStats) {
		s.completed++
		if err == nil {
			s.succeeded++
		}
	})
	sr.attempted.Add(1)
	if errors.Is(err, ErrAbortStage) {
		r.mu.Lock()
		if r.aborted[name] == nil {
			r.aborted[name] = err
		}
		r.mu.Unlock()
		sr.abortFail(c.Key, err)
		return
	}
	if err != nil {
		r.failCheck(name, c.Key, err)
		return
	}
	r.st.Complete(name, c.Key, obs)
}

// enumFail fails the stage's enumeration, counted once per run like any
// failed check, so passes still terminate.
func (sr *stageRun) enumFail(err error) {
	sr.enumFailed = true
	const enumKey = "(enumeration)"
	r := sr.r
	// An enumeration the cancel cut short is not a failure: the stage is listed again next run.
	if !r.hasFailed(sr.name, enumKey) && sr.ctx.Err() == nil {
		r.failCheck(sr.name, enumKey, err)
		r.count(sr.name, func(s *stageStats) { s.completed++ })
		sr.attempted.Add(1)
	}
}

// produce sends the pending checks to the workers. A panic in the stage's
// own Checks is an enumeration failure: the work channel is still closed
// and the workers waited for.
func (sr *stageRun) produce() {
	var panicked error
	defer func() {
		if panicked != nil {
			sr.enumFail(panicked)
		}
	}()
	defer RecoverInto(&panicked)
	for c, cerr := range sr.s.Checks(sr.ctx, sr.view) {
		if sr.ctx.Err() != nil {
			return // stop producing: the checks that follow would only be cancelled
		}
		if cerr != nil {
			sr.enumFail(cerr)
			continue
		}
		if !sr.admit(c) {
			continue
		}
		if !sr.running {
			sr.r.setState(sr.name, "running", "", 0, 0)
			sr.running = true
		}
		select {
		case sr.work <- c:
		case <-sr.ctx.Done():
			return
		}
	}
}

// admit reports whether a check the stage yielded is sent to the workers. A
// key already yielded, completed or failed this run is skipped; once the
// stage has aborted the check fails at once; and a check past the budget is
// deferred.
func (sr *stageRun) admit(c Check) bool {
	r := sr.r
	stored := r.st.CheckKey(c.Key)
	if _, dup := sr.all[stored]; dup { // a stage may yield a key more than once
		return false
	}
	if _, ok := sr.done[stored]; ok {
		if sr.keepAll {
			sr.all[stored] = struct{}{}
		}
		return false
	}
	sr.all[stored] = struct{}{}
	if r.hasFailed(sr.name, c.Key) {
		return false
	}
	if sr.abortedEarlier(c.Key) {
		sr.running = true
		return false
	}
	return sr.withinBudget(c)
}

// withinBudget spends the check's cost from the budget, or defers it (see
// stageRun.budget).
func (sr *stageRun) withinBudget(c Check) bool {
	if sr.budget == 0 {
		return true
	}
	cost := max(c.Cost, 1)
	if sr.deferredCost > 0 || (sr.spent > 0 && sr.spent+cost > sr.budget) {
		sr.deferredCost += cost
		return false
	}
	sr.spent += cost
	return true
}

// sweep finishes a pending redo and retires the completed checks the stage
// no longer yields, and reports whether either changed a record. The sweep
// needs every valid check; after an enumeration error it would delete the
// observations of checks that were never listed, so the redo stays pending
// until a pass enumerates cleanly.
func (sr *stageRun) sweep() (bool, error) {
	if sr.enumFailed {
		return false, nil
	}
	r := sr.r
	swept := false
	if sr.redoPending {
		if err := r.st.Flush(); err != nil {
			return false, err
		}
		var err error
		if swept, err = r.st.FinishRedo(sr.name, sr.all); err != nil {
			return false, err
		}
	}
	// Only completed checks have observations, so there is nothing to retire
	// unless one of them was not yielded this pass.
	if sr.retiring && sr.unlisted() {
		retired, err := r.st.Retire(sr.name, sr.all)
		if err != nil {
			return false, err
		}
		swept = swept || retired
	}
	return swept, nil
}

// unlisted reports whether a completed check was not yielded this pass.
func (sr *stageRun) unlisted() bool {
	for k := range sr.done {
		if _, ok := sr.all[k]; !ok {
			return true
		}
	}
	return false
}
