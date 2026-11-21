// Package httpsrc has what every third-party HTTP source stage shares.
package httpsrc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/ipsource"
	"github.com/rafaelh/nyx/internal/run"
)

// Configured is the Configured result for a source: a keyed source needs keys.<name>.
func Configured(e run.Env, name string, keyed bool) (bool, string) {
	if keyed {
		if _, ok := e.Key(name); !ok {
			return false, "no key"
		}
	}
	return true, ""
}

// Crtsh queries crt.sh's JSON API for unexpired, deduplicated certificates
// matching q. crt.sh is slow on large result sets, hence the long timeout.
func Crtsh(ctx context.Context, c egress.Clients, q url.Values) ([]byte, error) {
	q.Set("output", "json")
	q.Set("exclude", "expired")
	q.Set("deduplicate", "Y")
	return Get(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: "https://crt.sh/?" + q.Encode(), Timeout: 90 * time.Second})
}

// ErrNotFound is a 404. Sources that answer 404 for "no data" treat it as an
// empty result; for the rest it is a transient error like any other status.
var ErrNotFound = errors.New("HTTP 404")

// Get performs a request and maps the failures every source shares. For a
// keyed request a 401, 403 or 429 aborts the stage: the key is bad or the
// quota is spent, so nothing may be recorded as done. A 404 is ErrNotFound.
// A truncated body or any other non-200 status is a transient error.
func Get(ctx context.Context, c egress.Clients, req egress.ThirdPartyRequest) ([]byte, error) {
	return get(ctx, c, req, 0)
}

// GetQuota is Get for a source that answers 429 when its free quota is spent:
// the 429 of an unkeyed request, which Get treats as a failed check, returns
// run.ErrQuota, so the stage stops instead of sending the checks that remain.
// Get is left alone because most sources' 429 is no reason to stop the stage
// (one range publisher refusing must not stop the others).
func GetQuota(ctx context.Context, c egress.Clients, req egress.ThirdPartyRequest) ([]byte, error) {
	return get(ctx, c, req, 429)
}

// GetCredits is Get for a keyed source that answers 402 when the key has no query
// credits left (Shodan's search): the 402 returns run.ErrQuota, so the stage stops
// and the checks that remain are retried on a later run. Get treats a 402 as a
// failed check, which the stages that spend one credit per page accept.
func GetCredits(ctx context.Context, c egress.Clients, req egress.ThirdPartyRequest) ([]byte, error) {
	return get(ctx, c, req, 402)
}

// get is Get, with spent (if not 0) the status that means the source's allowance
// is spent: it returns run.ErrQuota.
func get(ctx context.Context, c egress.Clients, req egress.ThirdPartyRequest, spent int) ([]byte, error) {
	resp, err := c.ThirdParty.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	return body(req, resp, spent)
}

// Body is Get's mapping of a response to req, for a stage that sends the
// request itself in order to act on some statuses first.
func Body(req egress.ThirdPartyRequest, resp egress.ThirdPartyResponse) ([]byte, error) {
	return body(req, resp, 0)
}

func body(req egress.ThirdPartyRequest, resp egress.ThirdPartyResponse, spent int) ([]byte, error) {
	switch {
	case req.KeySource != "" && (resp.Status == 401 || resp.Status == 403):
		return nil, fmt.Errorf("HTTP %d (key rejected or not entitled to this endpoint): %w", resp.Status, run.ErrKeyRejected)
	case req.KeySource != "" && resp.Status == 429:
		return nil, fmt.Errorf("HTTP %d (rate limited or quota exhausted): %w", resp.Status, run.ErrAbortStage)
	case spent != 0 && resp.Status == spent:
		return nil, fmt.Errorf("HTTP %d: %w", resp.Status, run.ErrQuota)
	case resp.Status == 404:
		return nil, ErrNotFound
	case resp.Status != 200:
		return nil, fmt.Errorf("HTTP %d", resp.Status)
	case resp.Truncated:
		return nil, errors.New("response was larger than the 10 MiB limit")
	}
	return resp.Body, nil
}

// JoinLabels turns labels relative to root ("www", "*.cfe") into names. An empty
// label and the bare wildcard "*" are the root itself, which is not a new name.
func JoinLabels(root string, labels []string) []string {
	var names []string
	for _, l := range labels {
		if l = strings.TrimSuffix(strings.TrimSpace(l), "."); l == "" || l == "*" {
			continue
		}
		names = append(names, l+"."+root)
	}
	return names
}

// GetNames GETs u from a source with a free quota (GetQuota) and turns the body
// into names with parse; a 404 is no names.
func GetNames(ctx context.Context, c egress.Clients, u string, parse func([]byte) ([]string, error)) ([]string, error) {
	body, err := GetQuota(ctx, c, egress.ThirdPartyRequest{Method: "GET", URL: u})
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parse(body)
}

// HackerTargetLines returns the lines of a HackerTarget reply, trimmed and
// without the empty ones. An empty body and its "nothing found" replies give no
// lines. Its spent quota is a 200 reply with a text body, which is run.ErrQuota,
// the same as its 429 (GetQuota). The reply rules are written once, for every
// stage that asks HackerTarget.
func HackerTargetLines(body []byte) ([]string, error) {
	lines, quota := ipsource.HackerTargetLines(body)
	if quota {
		return nil, fmt.Errorf("HackerTarget API count exceeded: %w", run.ErrQuota)
	}
	return lines, nil
}

// QuotaError makes an error that wraps ipsource.ErrQuota also wrap run.ErrQuota,
// so the stage stops, and reads as it always has: the text of the error, then
// run.ErrQuota's. Any other error is returned as it is.
func QuotaError(err error) error {
	if err == nil || !errors.Is(err, ipsource.ErrQuota) || errors.Is(err, run.ErrQuota) {
		return err
	}
	return &quotaError{err}
}

type quotaError struct{ err error }

func (e *quotaError) Error() string { return e.err.Error() + ": " + run.ErrQuota.Error() }

func (e *quotaError) Unwrap() []error { return []error{e.err, run.ErrQuota} }

// Sleep waits for d or the context, whichever ends first.
func Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
