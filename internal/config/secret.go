package config

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

const mask = "****"

// Secret hides credentials during formatting; Reveal provides explicit value access.
type Secret string

func (Secret) String() string   { return mask }
func (Secret) GoString() string { return `"` + mask + `"` }
func (Secret) Format(f fmt.State, verb rune) {
	fmt.Fprint(f, mask)
}
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + mask + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(mask), nil }

// Reveal returns the secret value.
func (s Secret) Reveal() string { return string(s) }

// Redactor masks configured key values in strings.
type Redactor struct{ values []string }

// NewRedactor masks key values and their URL-encoded forms, including keys in HTTP error URLs.
// Blank values are ignored to avoid corrupting every output line.
func NewRedactor(values ...string) *Redactor {
	r := &Redactor{}
	for _, v := range values {
		if strings.TrimSpace(v) == "" || slices.Contains(r.values, v) {
			continue
		}
		r.values = append(r.values, v)
		for _, enc := range []string{url.QueryEscape(v), url.PathEscape(v)} {
			if enc != v && !slices.Contains(r.values, enc) {
				r.values = append(r.values, enc)
			}
		}
	}
	return r
}

// Redact masks known keys. A nil redactor leaves text unchanged.
func (r *Redactor) Redact(s string) string {
	if r == nil {
		return s
	}
	for _, v := range r.values {
		s = strings.ReplaceAll(s, v, mask)
	}
	return s
}

// Any recursively redacts strings in map/slice/string values.
func (r *Redactor) Any(v any) any {
	if r == nil || len(r.values) == 0 {
		return v
	}
	switch x := v.(type) {
	case string:
		return r.Redact(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[r.Redact(k)] = r.Any(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = r.Any(e)
		}
		return out
	case []string:
		out := make([]string, len(x))
		for i, e := range x {
			out[i] = r.Redact(e)
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(x))
		for i, e := range x {
			out[i] = r.Any(e).(map[string]any)
		}
		return out
	case map[string]string:
		out := make(map[string]string, len(x))
		for k, e := range x {
			out[r.Redact(k)] = r.Redact(e)
		}
		return out
	case map[string][]string:
		out := make(map[string][]string, len(x))
		for k, e := range x {
			out[r.Redact(k)] = r.Any(e).([]string)
		}
		return out
	case map[string]int:
		out := make(map[string]int, len(x))
		for k, e := range x {
			out[r.Redact(k)] = e
		}
		return out
	}
	return v
}
