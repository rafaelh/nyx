package web

import (
	"regexp"
	"strings"

	"github.com/rafaelh/nyx/internal/knowledge/weburl"
)

// endpointPattern finds absolute HTTP(S) URLs anywhere and complete quoted slash-prefixed
// paths. Matching each literal's own quotes avoids stray quotes hiding later endpoints.
// Whitespace/backslashes are excluded except escaped URL slashes, which are decoded later.
var endpointPattern = regexp.MustCompile(
	`(?i:https?)://[^\s"'\x60\\<>()]+` +
		`|(?i:https?):\\/\\/(?:\\/|[^\s"'\x60\\<>()])+` +
		`|"/[^\s"'\x60\\]*"|'/[^\s"'\x60\\]*'|\x60/[^\s"'\x60\\]*\x60`)

// ExtractEndpoints normalises and deduplicates script URLs in appearance order without scope
// checks or requests. It accepts absolute HTTP(S), scheme-relative URLs and quoted paths
// resolved against the script origin.
//
// Paths need a meaningful first segment and cannot contain whitespace, backslashes or template
// placeholders. Absolute URLs stop before a placeholder and are rejected if it affects the
// host. Hosts need a dot unless they are IP literals.
func ExtractEndpoints(body []byte, origin string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range endpointPattern.FindAll(body, -1) {
		lit := string(m)
		var abs string
		var ok bool
		switch lit[0] {
		case '"', '\'', '`':
			if hasPlaceholder(lit) {
				continue
			}
			abs, ok = quotedURL(lit[1:len(lit)-1], origin)
		default:
			abs, ok = absoluteURL(lit)
		}
		if !ok || !namesService(weburl.HostOfURL(abs)) || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, abs)
	}
	return out
}

func hasPlaceholder(s string) bool { return strings.Contains(s, "${") || strings.Contains(s, "{{") }

// absoluteURL unescapes URL slashes, trims sentence punctuation and stops before post-host
// template placeholders, then normalises the result.
func absoluteURL(lit string) (string, bool) {
	lit = strings.ReplaceAll(lit, `\/`, "/")
	cut := -1
	for _, p := range []string{"${", "{{"} {
		if i := strings.Index(lit, p); i >= 0 && (cut < 0 || i < cut) {
			cut = i
		}
	}
	if cut >= 0 {
		_, rest, _ := strings.Cut(lit[:cut], "://")
		if !strings.ContainsAny(rest, "/?#") { // the placeholder is in the host
			return "", false
		}
		lit = lit[:cut]
	}
	return weburl.NormaliseURL(strings.TrimRight(lit, ".,;:!"))
}

// quotedURL resolves slash-prefixed literals against origin, inheriting the scheme for //
// references.
func quotedURL(lit, origin string) (string, bool) {
	if len(lit) < 2 {
		return "", false
	}
	if rest, ok := strings.CutPrefix(lit, "//"); ok { // protocol-relative: the host follows
		if host, _, _ := strings.Cut(rest, "/"); host == "" || strings.ContainsAny(host, "?#") {
			return "", false
		}
	} else if first, _, _ := strings.Cut(strings.TrimPrefix(lit, "/"), "/"); first == "" || strings.HasPrefix(first, "?") || strings.HasPrefix(first, "#") || isExtension(first) {
		return "", false
	}
	return resolve(origin, lit)
}

var extensionOnly = regexp.MustCompile(`^\.[A-Za-z0-9]+$`)

// isExtension rejects extension-only segments such as .js while retaining directories such as
// .well-known.
func isExtension(seg string) bool {
	seg, _, _ = strings.Cut(seg, "?")
	seg, _, _ = strings.Cut(seg, "#")
	return extensionOnly.MatchString(seg)
}

// namesService requires a dotted hostname or IP literal.
func namesService(host string) bool {
	return strings.ContainsAny(host, ".:")
}
