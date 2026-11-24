// Package ipsource shares Cymru, RDAP and HackerTarget request/parsing rules between recon and
// nyx ip. It has no engagement state; callers provide paced egress clients. Sources are third
// parties, never the queried address.
//
// ErrQuota lets recon abort a stage and IP lookups stop later calls to the affected host.
package ipsource

import "errors"

// ErrQuota identifies spent source allowances, including 429 and HackerTarget text replies.
// Wrapping preserves errors.Is matching.
var ErrQuota = errors.New("quota spent")

// RateLimitedError names the host returning 429 and matches ErrQuota, allowing per-registry
// rather than global suppression.
type RateLimitedError struct {
	Host string
}

func (e *RateLimitedError) Error() string { return "HTTP 429" }

// Unwrap makes errors.Is(err, ErrQuota) hold.
func (e *RateLimitedError) Unwrap() error { return ErrQuota }
