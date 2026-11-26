// Package spf reads Sender Policy Framework records (RFC 7208) without I/O: which TXT string is a
// name's SPF record, its terms, the networks its ip4 and ip6 mechanisms authorise and the domains
// its other mechanisms and modifiers name.
package spf

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
)

// version opens every SPF record.
const version = "v=spf1"

// Record returns a name's SPF record: the one TXT string that starts with v=spf1 (in any case)
// followed by a space or nothing. A name with none, or with more than one, has no usable record
// (RFC 7208 section 4.5).
func Record(txts []string) (string, bool) {
	var found []string
	for _, r := range txts {
		t := strings.TrimSpace(r)
		if len(t) >= len(version) && strings.EqualFold(t[:len(version)], version) &&
			(len(t) == len(version) || t[len(version)] == ' ') {
			found = append(found, t)
		}
	}
	if len(found) != 1 {
		return "", false
	}
	return found[0], true
}

// Policy is a parsed SPF record.
type Policy struct {
	Terms  []Term
	HasAll bool // an all mechanism, which makes a redirect modifier ignored (section 6.1)
}

// Term is one mechanism or modifier of a record.
type Term struct {
	Qualifier byte   // '+', '-', '~' or '?'; a term written without one is '+'
	Name      string // the mechanism or modifier name, lower-cased: ip4, include, redirect, all…
	Value     string // what follows the first ':' or '=', as written; empty when there is none

	afterAll bool // a mechanism after the first all, which is never evaluated
}

// Applies reports whether a term takes effect: a mechanism after an all mechanism is never
// evaluated (RFC 7208 section 5.1), and a redirect modifier beside one is ignored (section 6.1);
// every other term applies.
func (p Policy) Applies(t Term) bool { return !t.afterAll && (t.Name != "redirect" || !p.HasAll) }

// Parse splits a record into its terms, leaving out the version.
func Parse(record string) Policy {
	var p Policy
	fields := strings.Fields(record)
	if len(fields) == 0 {
		return p
	}
	for _, term := range fields[1:] {
		q := byte('+')
		if strings.ContainsRune("+-~?", rune(term[0])) {
			q, term = term[0], term[1:]
		}
		name, value, modifier := term, "", false
		if i := strings.IndexAny(term, ":="); i >= 0 {
			name, value, modifier = term[:i], term[i+1:], term[i] == '='
		}
		name = strings.ToLower(name)
		p.Terms = append(p.Terms, Term{Qualifier: q, Name: name, Value: value, afterAll: p.HasAll && !modifier})
		p.HasAll = p.HasAll || name == "all"
	}
	return p
}

// Network returns the network an ip4 or ip6 term authorises, with its host bits masked; a single
// address is a /32 or /128. It is false for any other term, and for a malformed value or one of
// the other family.
func (t Term) Network() (netip.Prefix, bool) {
	if t.Name != "ip4" && t.Name != "ip6" {
		return netip.Prefix{}, false
	}
	var p netip.Prefix
	if strings.Contains(t.Value, "/") {
		v, err := netip.ParsePrefix(t.Value)
		if err != nil {
			return netip.Prefix{}, false
		}
		p = v.Masked()
	} else {
		a, err := netip.ParseAddr(t.Value)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4() != (t.Name == "ip4") {
		return netip.Prefix{}, false
	}
	return p, true
}

// lookupable matches a domain that can be looked up: dot-separated labels of letters, digits, "-"
// and "_".
var lookupable = regexp.MustCompile(`^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$`)

// Domain returns the domain an include, redirect, a, mx or exists term names, normalised and
// without a /bits suffix. It is false for any other term, and for a macro, an address literal or
// a name that cannot be looked up.
func (t Term) Domain() (string, bool) {
	switch t.Name {
	case "include", "redirect", "a", "mx", "exists":
	default:
		return "", false
	}
	host, _, _ := strings.Cut(t.Value, "/")
	host = dnsname.Normalise(host)
	if _, err := netip.ParseAddr(host); err == nil || len(host) > 253 || !lookupable.MatchString(host) {
		return "", false // a macro's % fails the pattern too
	}
	return host, true
}
