// Package testkit supplies configurable procedure fakes for runner tests.
package testkit

import (
	"context"
	"fmt"
	"iter"
	"sync"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// Procedure implements run.Procedure while recording jobs and concurrency.
type Procedure struct {
	ProcedureName string
	Kind          run.Contact
	Src           []string

	ConfiguredFn func(run.Env) (bool, string)
	JobsFn       func(v run.View) []run.Job
	JobsErr      error // simulate enumeration failure after all supplied jobs
	RunFn        func(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error)

	mu        sync.Mutex
	executed  []string
	active    int
	maxActive int
}

func (s *Procedure) Name() string         { return s.ProcedureName }
func (s *Procedure) Contact() run.Contact { return s.Kind }
func (s *Procedure) Sources() []string    { return s.Src }

func (s *Procedure) Configured(e run.Env) (bool, string) {
	if s.ConfiguredFn != nil {
		return s.ConfiguredFn(e)
	}
	return true, ""
}

func (s *Procedure) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		if s.JobsFn != nil {
			for _, c := range s.JobsFn(v) {
				if !yield(c, nil) {
					return
				}
			}
		}
		if s.JobsErr != nil {
			yield(run.Job{}, s.JobsErr)
		}
	}
}

func (s *Procedure) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	s.mu.Lock()
	s.executed = append(s.executed, c.Key)
	s.active++
	if s.active > s.maxActive {
		s.maxActive = s.active
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
	}()
	if s.RunFn == nil {
		return nil, nil
	}
	return s.RunFn(ctx, c, e)
}

// Executed returns the keys of the jobs run so far, in order.
func (s *Procedure) Executed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.executed...)
}

// MaxActive reports peak concurrent jobs.
func (s *Procedure) MaxActive() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxActive
}

// Reset clears execution history.
func (s *Procedure) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.executed, s.maxActive = nil, 0
}

// Keys creates stable, zero-padded job IDs.
func Keys(prefix string, n int) []run.Job {
	out := make([]run.Job, n)
	for i := range out {
		out[i] = run.Job{Key: fmt.Sprintf("%s%03d", prefix, i)}
	}
	return out
}

// Budgeted adds a Limit-sized per-run budget to the fake procedure.
type Budgeted struct {
	*Procedure
	Limit int
}

// Budget supplies the configured Limit to the runner.
func (b Budgeted) Budget(config.Settings) int { return b.Limit }
