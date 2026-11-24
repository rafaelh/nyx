// Package web implements service probing, crawling and script/endpoint discovery. All network
// requests go through egress.
package web

import (
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
)

// NormaliseURL accepts absolute HTTP(S), lowercases scheme/host, canonicalises IPs/ports,
// removes credentials/fragments and default ports, preserves query and supplies "/" for empty
// paths.
func NormaliseURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if (scheme != "http" && scheme != "https") || host == "" {
		return "", false
	}
	if a, ok := input.IPLiteral(host); ok {
		host = a.String()
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		port = strconv.Itoa(n)
	}
	out := url.URL{Scheme: scheme, Host: egress.HostPort(scheme, host, port), Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery}
	if out.Path == "" {
		out.Path = "/"
	}
	if u.ForceQuery && out.RawQuery == "" {
		out.ForceQuery = true
	}
	return out.String(), true
}

// Origin formats a canonical service key without default ports, including brackets for IPv6.
func Origin(scheme, host string, port int) string {
	return scheme + "://" + egress.HostPort(scheme, host, strconv.Itoa(port))
}

// HostOfURL is the lower-case host (no brackets, no port) of a URL.
func HostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

var staticExt = map[string]bool{}

func init() {
	for e := range strings.FieldsSeq(`
		png jpg jpeg gif svg ico webp bmp tif tiff avif apng heic
		css
		woff woff2 ttf otf eot
		mp3 mp4 m4a m4v webm ogg ogv oga wav avi mov mkv flac aac wmv mpg mpeg
		pdf
		zip gz tgz tar bz2 xz 7z rar iso dmg exe msi apk`) {
		staticExt[e] = true
	}
}

// IsStaticAsset identifies images, styles, fonts, media, PDFs and archives by path extension.
// Crawling records these links without fetching; archive selection drops them.
func IsStaticAsset(p string) bool {
	ext := strings.ToLower(strings.TrimPrefix(path.Ext(p), "."))
	return ext != "" && staticExt[ext]
}
