package iplookup

import "time"

// Deadline allows 6s plus 1.25s per extra address, or 30s plus 2s with --active. Counts below
// one use one. These defaults accommodate InternetDB and registry pacing; --timeout overrides
// them.
func Deadline(active bool, addresses int) time.Duration {
	// Saturate well beyond useful batch sizes to avoid overflow in deadline arithmetic.
	more := time.Duration(min(max(addresses, 1), 1<<20) - 1)
	if active {
		return 30*time.Second + more*2*time.Second
	}
	return 6*time.Second + more*1250*time.Millisecond
}
