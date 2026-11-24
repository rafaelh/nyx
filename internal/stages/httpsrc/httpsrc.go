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

// ErrNotFound lets sources distinguish a meaningful empty 404 from a retryable status failure.
var ErrNotFound = errors.New("HTTP 404")

// Get shares source error handling. Keyed 401/403/429 responses abort the stage; 404 returns
// ErrNotFound. Truncated bodies and other non-200 responses fail the check for later retry.
func Get(ctx context.Context, c egress.Clients, req egress.ThirdPartyRequest) ([]byte, error) {
	return get(ctx, c, req, 0)
}

// GetQuota additionally aborts on unkeyed 429 quota exhaustion. Plain Get keeps those as
// individual failures so one refusing range publisher does not stop unrelated publishers.
func GetQuota(ctx context.Context, c egress.Clients, req egress.ThirdPartyRequest) ([]byte, error) {
	return get(ctx, c, req, 429)
}

// GetCredits additionally maps keyed 402 responses to run.ErrQuota, stopping credit-exhausted
// searches until a later run.
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

// Body applies Get's common response handling after a caller handles source-specific statuses.
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

// JoinLabels expands relative subdomain labels. Empty and bare-wildcard labels denote the root
// and add no new name.
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

// GetNames fetches through GetQuota and parses names, treating 404 as an empty result.
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

// HackerTargetLines normalises response lines, treats "nothing found" as empty and converts
// text quota replies to run.ErrQuota, matching GetQuota's 429 handling.
func HackerTargetLines(body []byte) ([]string, error) {
	lines, quota := ipsource.HackerTargetLines(body)
	if quota {
		return nil, fmt.Errorf("HackerTarget API count exceeded: %w", run.ErrQuota)
	}
	return lines, nil
}

// QuotaError adds run.ErrQuota to ipsource.ErrQuota errors while preserving their message.
// Other errors pass through unchanged.
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
