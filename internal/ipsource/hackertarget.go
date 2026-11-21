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

// HackerTargetLines returns the lines of a HackerTarget reply, trimmed and
// without the empty ones. An empty body and its "nothing found" replies give no
// lines. Its spent quota is a 200 reply with a text body, which is quota, the
// same as its 429. The reply rules are written once, for every stage and
// command that asks HackerTarget.
func HackerTargetLines(body []byte) (lines []string, quota bool) {
	text := strings.TrimSpace(string(body))
	// Only the start is lowered: every reply compared here is shorter than 40
	// bytes, and a lookup can be thousands of lines.
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

// errUnreadable is the error of a reverse lookup reply that is not a list of names.
var errUnreadable = errors.New("unreadable HackerTarget response")

// ReverseLines reads HackerTarget's reverse lookup reply, one name per line, and
// returns the lines as sent. A line that is not a name (it has a space, tab,
// comma, "<" or ">") means the reply is not a list, which is an error and not
// "no names". quota is HackerTarget's spent quota.
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

// ReverseNames reads a reverse lookup reply (ReverseLines) and returns its
// names cleaned (input.CleanName), without repeats and sorted. Lines that are not
// valid hostnames are dropped.
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

// HackerTargetReverse asks HackerTarget for the names that point at an IPv4
// address, cleaned, without repeats and sorted. A 404 and the "nothing found"
// replies are no names. A 429 and a spent quota in a 200 reply are errors that
// wrap ErrQuota (a *RateLimitedError for the 429); any other status, a
// truncated body or a reply that is not a list is an error.
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
