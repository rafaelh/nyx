package layout

import (
	"net/netip"
	"strings"

	"github.com/rafaelh/nyx/internal/dnsname"
)

const (
	leadingPunct  = "([{<\"'"
	trailingPunct = ")]}>\"',.;:"
)

// Protected reports whether a word must never be broken: a URL with a scheme, an
// email address, an IP address or CIDR netblock, or a hostname. The word is
// first stripped of surrounding punctuation: any of ([{<"' at the start and any
// of )]}>"',.;: at the end. A word is a run of characters with no space in it.
//
//   - A URL is scheme:// followed by at least one character, the scheme being a
//     letter and then letters, digits, + . or -.
//   - An email address has one @, a non-empty local part and a hostname after it.
//   - An IP address or netblock is what net/netip parses.
//   - A hostname has at least one dot and every label passes dnsname.ValidLabel,
//     with an optional leading "*.". Labels are compared in lower case.
//   - An address or a hostname may carry a port, as a risky port's target does:
//     192.0.2.1:3389, [2001:db8::1]:3389 or www.example.com:8443.
//
// CVSS:3.1/AV:N/… is none of these. "e.g" and a version number such as "2.4.41"
// do count as hostnames: they are short, so protecting them does no harm.
func Protected(token string) bool {
	t := strings.TrimLeft(token, leadingPunct)
	t = strings.TrimRight(t, trailingPunct)
	if t == "" {
		return false
	}
	if isURL(t) || isEmail(t) || isHostname(t) || isHostPort(t) || isAddrPort(token) {
		return true
	}
	if _, err := netip.ParseAddr(t); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(t)
	return err == nil
}

// isAddrPort reports whether token, less its trailing punctuation and any of its
// leading punctuation, is an address and port. The bracket that opens an IPv6
// address and port is leading punctuation too, so each amount of it is tried.
func isAddrPort(token string) bool {
	t := strings.TrimRight(token, trailingPunct)
	for t != "" {
		if _, err := netip.ParseAddrPort(t); err == nil {
			return true
		}
		if !strings.ContainsRune(leadingPunct, rune(t[0])) {
			return false
		}
		t = t[1:]
	}
	return false
}

// isHostPort reports whether t is a hostname, a colon and a port number.
func isHostPort(t string) bool {
	i := strings.LastIndexByte(t, ':')
	if i < 0 || i == len(t)-1 {
		return false
	}
	for _, c := range []byte(t[i+1:]) {
		if c < '0' || c > '9' {
			return false
		}
	}
	return isHostname(t[:i])
}

func isURL(t string) bool {
	scheme, rest, ok := strings.Cut(t, "://")
	if !ok || rest == "" || scheme == "" {
		return false
	}
	for i, c := range []byte(scheme) {
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if i == 0 && !letter {
			return false
		}
		if !letter && (c < '0' || c > '9') && c != '+' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

func isEmail(t string) bool {
	local, host, ok := strings.Cut(t, "@")
	return ok && local != "" && !strings.Contains(host, "@") && isHostname(host)
}

func isHostname(t string) bool {
	t = strings.ToLower(strings.TrimPrefix(t, "*."))
	if !strings.Contains(t, ".") {
		return false
	}
	for label := range strings.SplitSeq(t, ".") {
		if !dnsname.ValidLabel(label) {
			return false
		}
	}
	return true
}
