package run

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/fault"
)

// procedureRun manages one procedure pass. The calling goroutine enumerates jobs and sends them to
// a worker pool. Fields below the worker counters belong to the producer; runProcedure reads them
// after workers finish.
type procedureRun struct {
	r    *Runner
	ctx  context.Context // run context carrying the warning handler for Jobs and Run
	s    Procedure
	name string

	done        map[string]struct{} // completed keys in stored form
	redoPending bool
	retiring    bool
	clients     egress.Clients
	view        View
	workers     int

	work      chan Job
	attempted atomic.Int64
	aborted   atomic.Int64 // jobs failed because the procedure aborted

	// all deduplicates yielded keys in their stored, redacted form. Redo and retirement
	// need all valid keys, including completed ones; other passes can skip completed keys
	// without keeping them here.
	all     map[string]struct{}
	keepAll bool
	// Jobs consume the budget in enumeration order. Once a job exceeds the remaining
	// budget, it and later pending jobs are deferred. They stay in all so their existing
	// evidence survives redo and retirement. The first pending job is always admitted,
	// even if its cost exceeds the budget.
	budget       int // zero disables budgeting
	spent        int
	deferredCost int
	enumFailed   bool
	running      bool // whether the running state has been displayed
}

// newProcedureRun loads the pass's completed jobs, pending redo, clients and remaining budget.
func (r *Runner) newProcedureRun(ctx context.Context, s Procedure) (*procedureRun, error) {
	name := s.Name()
	done, err := r.st.Completed(name)
	if err != nil {
		return nil, err
	}
	pend, _ := r.st.PendingRedo()
	sr := &procedureRun{r: r, ctx: withWarner(ctx, r.warn), s: s, name: name, done: done,
		redoPending: slices.Contains(pend, name)}
	sr.clients = r.cfg.Egress.Clients(s.Contact() == Target, s.Sources())
	sr.view = r.built.Load().view(r)
	sr.view.done = done

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

func (sr *procedureRun) execute() {
	sr.work = make(chan Job)
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

// abortFail counts a failure caused by a procedure abort. runProcedure emits one warning for the
// abort rather than one per job.
func (sr *procedureRun) abortFail(key string, cause error) {
	sr.r.recordFailure(sr.name, key, errors.Is(cause, ErrKeyRejected))
	sr.aborted.Add(1)
}

// abortedEarlier counts the job as attempted and failed if its procedure already aborted this
// run.
func (sr *procedureRun) abortedEarlier(key string) bool {
	cause := sr.r.abortErr(sr.name)
	if cause == nil {
		return false
	}
	sr.attempted.Add(1)
	sr.abortFail(key, cause)
	return true
}

// runOne executes a worker's job and stores its result. Cancellation leaves the job
// incomplete for retry next run.
func (sr *procedureRun) runOne(c Job) {
	r, name := sr.r, sr.name
	if sr.ctx.Err() != nil {
		return
	}
	if sr.abortedEarlier(c.Key) {
		return
	}
	fault.PointDetail("in-flight", c.Key)
	obs, err := runJob(sr.ctx, sr.s, c, sr.clients)
	if sr.ctx.Err() != nil {
		r.count(name, func(s *procedureStats) { s.cancelled++ })
		return
	}
	r.count(name, func(s *procedureStats) {
		s.completed++
		if err == nil {
			s.succeeded++
		}
	})
	sr.attempted.Add(1)
	if errors.Is(err, ErrAbortProcedure) {
		r.mu.Lock()
		if r.aborted[name] == nil {
			r.aborted[name] = err
		}
		r.mu.Unlock()
		sr.abortFail(c.Key, err)
		return
	}
	if err != nil {
		r.failJob(name, c.Key, err)
		return
	}
	r.st.Complete(name, c.Key, obs)
}

// enumFail records one enumeration failure per run so repeated passes can terminate.
func (sr *procedureRun) enumFail(err error) {
	sr.enumFailed = true
	const enumKey = "(enumeration)"
	r := sr.r
	// Cancellation leaves enumeration for the next run and does not count as a failure.
	if !r.hasFailed(sr.name, enumKey) && sr.ctx.Err() == nil {
		r.failJob(sr.name, enumKey, err)
		r.count(sr.name, func(s *procedureStats) { s.completed++ })
		sr.attempted.Add(1)
	}
}

// produce sends pending jobs to workers. A panic in Jobs becomes an enumeration failure;
// execute still closes the channel and waits for workers.
func (sr *procedureRun) produce() {
	var panicked error
	defer func() {
		if panicked != nil {
			sr.enumFail(panicked)
		}
	}()
	defer RecoverInto(&panicked)
	for c, cerr := range sr.s.Jobs(sr.ctx, sr.view) {
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

// admit rejects duplicate, completed or previously failed jobs. After a procedure abort it counts
// pending jobs as failed; after the budget is spent it defers them.
func (sr *procedureRun) admit(c Job) bool {
	r := sr.r
	stored := r.st.JobKey(c.Key)
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

// withinBudget charges the job's cost or defers it when the budget is exhausted. An unbudgeted job
// is admitted without a charge.
func (sr *procedureRun) withinBudget(c Job) bool {
	if sr.budget == 0 || c.Unbudgeted {
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

// sweep finishes redo and retires obsolete jobs, returning whether records changed. It waits
// for successful enumeration: otherwise it could remove evidence for jobs that were never
// listed because of the error.
func (sr *procedureRun) sweep() (bool, error) {
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
	// Only completed jobs have observations that may need retirement.
	if sr.retiring && sr.unlisted() {
		retired, err := r.st.Retire(sr.name, sr.all)
		if err != nil {
			return false, err
		}
		swept = swept || retired
	}
	return swept, nil
}

func (sr *procedureRun) unlisted() bool {
	for k := range sr.done {
		if _, ok := sr.all[k]; !ok {
			return true
		}
	}
	return false
}
