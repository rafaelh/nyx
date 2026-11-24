// Package shellquote quotes suggested commands and scope-promotion arguments for POSIX shells
// without I/O.
package shellquote

import "strings"

// Quote leaves safe text unchanged; otherwise it single-quotes and escapes embedded quotes by
// closing and reopening the quoted string.
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
