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

// stageRun manages one stage pass. The calling goroutine enumerates checks and sends them to a
// worker pool. Fields below the worker counters belong to the producer; runStage reads them
// after workers finish.
type stageRun struct {
	r    *Runner
	ctx  context.Context // run context carrying the warning handler for Checks and Run
	s    Stage
	name string

	done        map[string]struct{} // completed keys in stored form
	redoPending bool
	retiring    bool
	clients     egress.Clients
	view        View
	workers     int

	work      chan Check
	attempted atomic.Int64
	aborted   atomic.Int64 // checks failed because the stage aborted

	// all deduplicates yielded keys in their stored, redacted form. Redo and retirement
	// need all valid keys, including completed ones; other passes can skip completed keys
	// without keeping them here.
	all     map[string]struct{}
	keepAll bool
	// Checks consume the budget in enumeration order. Once a check exceeds the remaining
	// budget, it and later pending checks are deferred. They stay in all so their existing
	// evidence survives redo and retirement. The first pending check is always admitted,
	// even if its cost exceeds the budget.
	budget       int // zero disables budgeting
	spent        int
	deferredCost int
	enumFailed   bool
	running      bool // whether the running state has been displayed
}

// newStageRun loads the pass's completed checks, pending redo, clients and remaining budget.
func (r *Runner) newStageRun(ctx context.Context, s Stage) (*stageRun, error) {
	name := s.Name()
	done, err := r.st.Completed(name)
	if err != nil {
		return nil, err
	}
	pend, _ := r.st.PendingRedo()
	sr := &stageRun{r: r, ctx: withWarner(ctx, r.warn), s: s, name: name, done: done,
		redoPending: slices.Contains(pend, name)}
	sr.clients = r.cfg.Egress.Clients(s.Contact() == Target, s.Sources())
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

// abortFail counts a failure caused by a stage abort. runStage emits one warning for the abort
// rather than one per check.
func (sr *stageRun) abortFail(key string, cause error) {
	sr.r.recordFailure(sr.name, key, errors.Is(cause, ErrKeyRejected))
	sr.aborted.Add(1)
}

// abortedEarlier counts the check as attempted and failed if its stage already aborted this
// run.
func (sr *stageRun) abortedEarlier(key string) bool {
	cause := sr.r.abortErr(sr.name)
	if cause == nil {
		return false
	}
	sr.attempted.Add(1)
	sr.abortFail(key, cause)
	return true
}

// runOne executes a worker's check and stores its result. Cancellation leaves the check
// incomplete for retry next run.
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

// enumFail records one enumeration failure per run so repeated passes can terminate.
func (sr *stageRun) enumFail(err error) {
	sr.enumFailed = true
	const enumKey = "(enumeration)"
	r := sr.r
	// Cancellation leaves enumeration for the next run and does not count as a failure.
	if !r.hasFailed(sr.name, enumKey) && sr.ctx.Err() == nil {
		r.failCheck(sr.name, enumKey, err)
		r.count(sr.name, func(s *stageStats) { s.completed++ })
		sr.attempted.Add(1)
	}
}

// produce sends pending checks to workers. A panic in Checks becomes an enumeration failure;
// execute still closes the channel and waits for workers.
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
			return
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

// admit rejects duplicate, completed or previously failed checks. After a stage abort it counts
// pending checks as failed; after the budget is spent it defers them.
func (sr *stageRun) admit(c Check) bool {
	r := sr.r
	stored := r.st.CheckKey(c.Key)
	if _, dup := sr.all[stored]; dup {
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

// withinBudget charges the check's cost or defers it when the budget is exhausted.
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

// sweep finishes redo and retires obsolete checks, returning whether records changed. It waits
// for successful enumeration: otherwise it could remove evidence for checks that were never
// listed because of the error.
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
	// Only completed checks have observations that may need retirement.
	if sr.retiring && sr.unlisted() {
		retired, err := r.st.Retire(sr.name, sr.all)
		if err != nil {
			return false, err
		}
		swept = swept || retired
	}
	return swept, nil
}

func (sr *stageRun) unlisted() bool {
	for k := range sr.done {
		if _, ok := sr.all[k]; !ok {
			return true
		}
	}
	return false
}
