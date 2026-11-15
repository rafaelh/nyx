package web

import (
	"regexp"
	"strings"
)

// endpointPattern finds, in a script's text, the strings ExtractEndpoints looks
// at, in order of appearance: an absolute http(s) URL (anywhere in the text, so
// one inside a longer string is found), or a whole quoted literal that starts
// with "/". A literal is matched by its own quotes, so a stray quote in a
// comment or a regular expression cannot hide what follows. The class that ends
// a URL, or a quoted path, rules out whitespace, quotes and backslashes: a
// regular expression such as /\d+/g or a path with a space is not matched. An
// absolute URL written with escaped slashes ("https:\/\/api.example.com\/v1", as
// JSON inside a script has it) is matched too, and unescaped.
var endpointPattern = regexp.MustCompile(
	`(?i:https?)://[^\s"'\x60\\<>()]+` +
		`|(?i:https?):\\/\\/(?:\\/|[^\s"'\x60\\<>()])+` +
		`|"/[^\s"'\x60\\]*"|'/[^\s"'\x60\\]*'|\x60/[^\s"'\x60\\]*\x60`)

// ExtractEndpoints returns the URLs a script's text names, normalised, each
// once, in order of appearance: absolute http(s) URLs, "//host/path"
// references (which take the scheme of origin) and quoted paths that start with
// "/", joined to origin. It is pure: it judges nothing about scope, and it never
// requests anything. origin is the script's own origin ("https://a.example.com").
//
// A quoted path is at least two characters, has no whitespace or backslash, and
// has a first segment that is neither empty nor just an extension (".js"). A
// quoted path with a template placeholder ("${" or "{{") is left out. An
// absolute URL is cut at its first placeholder, as a literal joined to a value
// with "+" is ("https://api.example.com/v1/${id}" gives
// "https://api.example.com/v1/"), and left out when the placeholder is in its
// host. A candidate whose host has no dot (and is not an address) cannot name a
// service and is left out.
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
		if !ok || !namesService(HostOfURL(abs)) || seen[abs] {
			continue
		}
		seen[abs] = true
		out = append(out, abs)
	}
	return out
}

func hasPlaceholder(s string) bool { return strings.Contains(s, "${") || strings.Contains(s, "{{") }

// absoluteURL is the normalised form of an absolute URL the pattern matched:
// escaped slashes unescaped, cut at a template placeholder that follows the
// host, and without the punctuation that ended a sentence.
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
	return NormaliseURL(strings.TrimRight(lit, ".,;:!"))
}

// quotedURL is the normalised URL a quoted literal that starts with "/" stands
// for, resolved against origin: a "//host/path" reference takes its scheme.
func quotedURL(lit, origin string) (string, bool) {
	if len(lit) < 2 {
		return "", false
	}
	if strings.HasPrefix(lit, "//") { // protocol-relative: the host follows
		if host, _, _ := strings.Cut(strings.TrimPrefix(lit, "//"), "/"); host == "" || strings.ContainsAny(host, "?#") {
			return "", false
		}
	} else if first, _, _ := strings.Cut(strings.TrimPrefix(lit, "/"), "/"); first == "" || strings.HasPrefix(first, "?") || strings.HasPrefix(first, "#") || isExtension(first) {
		return "", false
	}
	return resolve(origin, lit)
}

var extensionOnly = regexp.MustCompile(`^\.[A-Za-z0-9]+$`)

// isExtension reports whether a path segment is a file extension alone: ".js".
// A directory such as ".well-known" is not.
func isExtension(seg string) bool {
	seg, _, _ = strings.Cut(seg, "?")
	seg, _, _ = strings.Cut(seg, "#")
	return extensionOnly.MatchString(seg)
}

// namesService reports whether a host could name a service: a name with a dot,
// or an IP literal.
func namesService(host string) bool {
	return strings.ContainsAny(host, ".:")
}
