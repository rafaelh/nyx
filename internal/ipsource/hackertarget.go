package ipsource

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
)

// HackerTargetHost is the host HackerTarget's API is at.
const HackerTargetHost = "api.hackertarget.com"

// HackerTargetLines trims and filters response lines, treating empty/not-found replies as no
// results. Text quota replies with status 200 return quota, matching 429 handling.
func HackerTargetLines(body []byte) (lines []string, quota bool) {
	text := strings.TrimSpace(string(body))
	// Lowercase only the short comparison prefix to avoid copying large hostname lists.
	switch lower := strings.ToLower(text[:min(len(text), 40)]); {
	case lower == "", lower == "no records found", lower == "error check your search parameter",
		strings.HasPrefix(lower, "no dns a records found"):
		return nil, false
	case strings.HasPrefix(lower, "api count exceeded"):
		return nil, true
	}
	for line := range strings.SplitSeq(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, false
}

// errUnreadable reports a response that cannot be interpreted as a hostname list.
var errUnreadable = errors.New("unreadable HackerTarget response")

// ReverseLines validates a one-name-per-line reply while preserving source lines. Whitespace,
// commas or markup indicate an error rather than empty results. quota supplies the exhaustion
// error.
func ReverseLines(body []byte) (lines []string, quota bool, err error) {
	lines, quota = HackerTargetLines(body)
	if quota {
		return nil, true, nil
	}
	for _, l := range lines {
		if strings.ContainsAny(l, " \t,<>") {
			return nil, false, errUnreadable
		}
	}
	return lines, false, nil
}

// ReverseNames cleans, deduplicates and sorts validated reverse lookup names, dropping invalid
// hostnames.
func ReverseNames(body []byte) (names []string, quota bool, err error) {
	lines, quota, err := ReverseLines(body)
	if err != nil || quota {
		return nil, quota, err
	}
	seen := map[string]bool{}
	for _, l := range lines {
		if n := input.CleanName(l); n != "" && !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return names, false, nil
}

// HackerTargetReverse fetches sorted, unique IPv4 reverse names. Empty/404 replies succeed
// without names. Text quota replies and 429 match ErrQuota; other statuses, truncation and
// invalid lists are errors.
func HackerTargetReverse(ctx context.Context, c egress.ThirdPartyHTTP, addr netip.Addr) ([]string, error) {
	u := "https://" + HackerTargetHost + "/reverseiplookup/?" + url.Values{"q": {addr.String()}}.Encode()
	resp, err := c.Do(ctx, egress.ThirdPartyRequest{Method: "GET", URL: u})
	switch {
	case err != nil:
		return nil, err
	case resp.Status == 429:
		return nil, &RateLimitedError{Host: HackerTargetHost}
	case resp.Status == 404:
		return nil, nil
	case resp.Status != 200:
		return nil, fmt.Errorf("HTTP %d", resp.Status)
	case resp.Truncated:
		return nil, errTruncated
	}
	names, quota, err := ReverseNames(resp.Body)
	switch {
	case err != nil:
		return nil, err
	case quota:
		return nil, fmt.Errorf("HackerTarget API count exceeded: %w", ErrQuota)
	}
	return names, nil
}
