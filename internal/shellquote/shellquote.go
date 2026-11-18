// Package shellquote quotes text for a POSIX shell, for the commands nyx
// suggests the user type (hints, a candidate's promote flag). It does no I/O.
package shellquote

import "strings"

// Quote quotes s for a POSIX shell: as it is when it holds only safe
// characters, else in single quotes, with each single quote inside it closed,
// escaped and reopened.
func Quote(s string) string {
	safe := func(r rune) bool {
		return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("@%+=:,./_-", r)
	}
	if s != "" && strings.IndexFunc(s, func(r rune) bool { return !safe(r) }) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Join quotes each argument with Quote and joins them with spaces.
func Join(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = Quote(a)
	}
	return strings.Join(q, " ")
}
