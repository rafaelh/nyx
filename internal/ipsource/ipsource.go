// Package ipsource asks the third-party sources that say who runs an IP
// address and what else points at it: Team Cymru's DNS service for the origin
// AS and its holder, the regional internet registries' RDAP service for the
// registered netblock and its registrant, and HackerTarget's reverse IP lookup.
//
// It has no engagement state and does not import internal/run, so a command
// that has no engagement (nyx ip) and the recon stages that do share one copy
// of each source's request and reply rules. Every request goes through the
// egress clients its caller passes in; the package does no network I/O of its
// own, and its sources are third parties, never the address asked about.
//
// A spent allowance is ErrQuota. The recon stages wrap it into run.ErrQuota so
// that a stage stops; a command that asks each address in turn latches the
// source instead. Callers pace their requests: egress does, per source host.
package ipsource

import "errors"

// ErrQuota says a source refused the request because its allowance is spent: a
// 429, or HackerTarget's "API count exceeded" reply. Errors that wrap it can
// be told apart with errors.Is.
var ErrQuota = errors.New("quota spent")

// RateLimitedError is a 429 from one host. It matches ErrQuota with errors.Is,
// and names the host so a caller can stop asking that host only (the registries
// each have their own allowance).
type RateLimitedError struct {
	Host string
}

func (e *RateLimitedError) Error() string { return "HTTP 429" }

// Unwrap makes errors.Is(err, ErrQuota) hold.
func (e *RateLimitedError) Unwrap() error { return ErrQuota }
