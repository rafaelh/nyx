package iplookup

import "time"

// Deadline is the call's default deadline for addresses distinct addresses: 6s for the first and
// 1.25s for each more in the default mode, and 30s and 2s under --active. InternetDB's pace (one
// request a second) dominates a batch, and the registries' pace fits inside it. A count under one
// counts as one. --timeout replaces the whole rule.
func Deadline(active bool, addresses int) time.Duration {
	// Past a million addresses the answer is far beyond any caller's patience, and capping the
	// count keeps the product from overflowing.
	more := time.Duration(min(max(addresses, 1), 1<<20) - 1)
	if active {
		return 30*time.Second + more*2*time.Second
	}
	return 6*time.Second + more*1250*time.Millisecond
}
