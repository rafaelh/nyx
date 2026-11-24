package web

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"math/bits"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"github.com/rafaelh/nyx/internal/egress"
)

// murmur3 is MurmurHash3 (x86, 32 bit).
func murmur3(data []byte, seed uint32) uint32 {
	const c1, c2 = 0xcc9e2d51, 0x1b873593
	h := seed
	n := len(data) &^ 3
	for i := 0; i < n; i += 4 {
		k := binary.LittleEndian.Uint32(data[i:])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	switch len(data) & 3 {
	case 3:
		k ^= uint32(data[n+2]) << 16
		fallthrough
	case 2:
		k ^= uint32(data[n+1]) << 8
		fallthrough
	case 1:
		k ^= uint32(data[n])
		k *= c1
		k = bits.RotateLeft32(k, 15)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return h
}

// FaviconHash matches Shodan's signed 32-bit MurmurHash3 of base64.encodebytes-style text:
// 76-character lines plus a final newline. Empty files hash to zero.
func FaviconHash(body []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(body)
	var b strings.Builder
	for len(enc) > 0 {
		n := min(len(enc), 76)
		b.WriteString(enc[:n])
		b.WriteByte('\n')
		enc = enc[n:]
	}
	return int32(murmur3([]byte(b.String()), 0))
}

// iconHref selects icon/shortcut-icon links, excluding apple-touch-icon.
func (p page) iconHref() string {
	for n := range p.doc.Descendants() {
		if n.Type == html.ElementNode && n.Data == "link" && slices.Contains(strings.Fields(strings.ToLower(attr(n, "rel"))), "icon") {
			if href := attr(n, "href"); href != "" {
				return href
			}
		}
	}
	return ""
}

// lastOnHost ignores scheme/port while selecting the final response on the initial host.
func lastOnHost(chain []*hop) *hop {
	host := HostOfURL(chain[0].origin)
	return lastWhere(chain, func(h *hop) bool { return HostOfURL(h.origin) == host })
}

// iconRequest prefers a same-host icon link on the final same-host page, otherwise the first
// response's /favicon.ico. egress.Link rejects other hosts.
func iconRequest(chain []*hop) (egress.Request, bool) {
	last := lastOnHost(chain)
	if pg, ok := last.page(); ok {
		if href := pg.iconHref(); href != "" {
			// A relative href resolves against the page's <base href>, as the crawl's links do.
			if u, err := url.Parse(last.resp.URL()); err == nil {
				if t, err := withBase(u, pg.links().base).Parse(href); err == nil {
					href = t.String()
				}
			}
			if req, err := egress.Link(last.resp, href); err == nil {
				return req, true
			}
		}
	}
	req, err := egress.Link(chain[0].resp, "/favicon.ico")
	return req, err == nil
}

// fetchFavicon follows at most one same-host redirect and hashes complete 2xx image responses.
// Missing content type is accepted; markup is rejected. Icon failures do not discard an
// otherwise valid service. Only run cancellation returns an error.
func fetchFavicon(ctx context.Context, chain []*hop, e egress.Clients) (string, error) {
	req, ok := iconRequest(chain)
	if !ok {
		return "", nil
	}
	for redirected := false; ; redirected = true {
		res, err := e.HTTP.Get(ctx, req)
		if err != nil {
			return "", ctx.Err()
		}
		r, live := res.(egress.Response)
		if !live {
			return "", nil
		}
		if isRedirect(r.Status) && r.Location != "" && !redirected {
			if req, err = egress.Link(r, r.Location); err != nil { // another host
				return "", nil //nolint:nilerr // a redirect to another host is not followed, so there is no favicon to fetch
			}
			continue
		}
		if r.Status < 200 || r.Status > 299 || r.Truncated {
			return "", nil
		}
		if ct := r.ContentType(); ct != "" && !strings.HasPrefix(ct, "image/") {
			return "", nil
		}
		if isMarkup(r) {
			return "", nil
		}
		return strconv.Itoa(int(FaviconHash(r.Body))), nil
	}
}
