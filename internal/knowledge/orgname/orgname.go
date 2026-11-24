// Package orgname matches organisation inputs by requiring every meaningful word, ignoring
// case, punctuation and legal suffixes. Registry procedures share this rule for consistent matches.
package orgname

import (
	"regexp"
	"strings"
)

var legalSuffix = map[string]bool{
	"inc": true, "llc": true, "ltd": true, "limited": true, "corp": true, "corporation": true, "co": true,
	"company": true, "plc": true, "gmbh": true, "sa": true, "ag": true, "pty": true, "pte": true, "bv": true, "nv": true,
}

var nonAlnum = regexp.MustCompile(`[^a-z0-9]+`)

// Tokens are the lower-case words of an organisation name without legal suffixes.
func Tokens(org string) []string {
	var out []string
	for _, t := range nonAlnum.Split(strings.ToLower(org), -1) {
		if t != "" && !legalSuffix[t] {
			out = append(out, t)
		}
	}
	return out
}

// Matches requires every meaningful organisation word; empty/legal-suffix-only inputs never
// match.
func Matches(org, name string) bool { return New(org).Matches(name) }

// Org caches tokenised input for repeated name comparisons.
type Org struct{ words []string }

// New returns org ready to match names against.
func New(org string) Org { return Org{Tokens(org)} }

// Matches reports whether name contains every word of the organisation (see
// the package function Matches).
func (o Org) Matches(name string) bool {
	if len(o.words) == 0 {
		return false
	}
	name = strings.ToLower(name)
	for _, t := range o.words {
		if !strings.Contains(name, t) {
			return false
		}
	}
	return true
}
