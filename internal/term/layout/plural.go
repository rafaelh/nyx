package layout

import "strconv"

// Plural returns one when n is 1, otherwise many.
func Plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Count returns n and the word for it, such as "1 problem" or "3 problems".
func Count(n int, one, many string) string { return strconv.Itoa(n) + " " + Plural(n, one, many) }
