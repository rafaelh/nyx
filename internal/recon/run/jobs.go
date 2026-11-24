package run

import "iter"

// JobsOf yields one job for each item, in order, for a procedure whose Jobs maps a slice to jobs.
func JobsOf[T any](items []T, job func(T) Job) iter.Seq2[Job, error] {
	return func(yield func(Job, error) bool) {
		for _, it := range items {
			if !yield(job(it), nil) {
				return
			}
		}
	}
}
