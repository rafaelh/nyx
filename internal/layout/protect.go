package layout

import (
	"net/netip"
	"strings"

	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
)

const (
	leadingPunct  = "([{<\"'"
	trailingPunct = ")]}>\"',.;:"
)

// Protected recognises tokens that wrapping should keep whole: URLs, email addresses, IPs,
// CIDRs and dotted hostnames, including optional ports and wildcard prefixes. Surrounding
// punctuation is ignored. Schemes follow URL syntax; hostname labels use dnsname.ValidLabel.
// Short values such as versions or "e.g" may qualify harmlessly; CVSS vectors do not.
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

// isAddrPort tries punctuation trimming lengths so the opening bracket of an IPv6 address is
// preserved when needed for parsing.
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
