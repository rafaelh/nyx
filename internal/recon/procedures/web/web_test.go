package web

import (
	"testing"

	"github.com/rafaelh/nyx/internal/knowledge/weburl"
)

// Crawl limits version work but cannot inflate candidate evidence beyond the service identity.
func TestCrawlEvidenceDropsTheLimits(t *testing.T) {
	t.Parallel()
	var s *Crawl
	for _, key := range []string{"https://a.example.com|depth=2|pages=100", "https://a.example.com|depth=3|pages=50"} {
		if src, item := s.Evidence(key); src != "crawl" || item != "https://a.example.com" {
			t.Errorf("Evidence(%q) = %q, %q", key, src, item)
		}
	}
}

// A normalised URL's origin is the service key weburl.Origin builds.
func TestOriginOfMatchesTheServiceKey(t *testing.T) {
	t.Parallel()
	if u, _ := weburl.NormaliseURL("http://[2001:db8:0::1]:8080/x"); originOf(u) != weburl.Origin("http", "2001:db8::1", 8080) {
		t.Errorf("originOf(%q) = %q", u, originOf(u))
	}
}

func TestLinksReadsTheFirstBaseHref(t *testing.T) {
	t.Parallel()
	pg, ok := parsePage([]byte(`<html><head><base href="/static/app/"><base href="/other/"></head><body><a href="login">x</a></body></html>`))
	if !ok {
		t.Fatal("unparsable page")
	}
	if l := pg.links(); l.base != "/static/app/" || len(l.follow) != 1 || l.follow[0] != "login" {
		t.Errorf("links = %+v", l)
	}
}

// The fingerprints are embedded; a dependency upgrade that breaks them must
// fail here rather than silently empty the technologies column.
func TestFingerprintsLoad(t *testing.T) {
	t.Parallel()
	if _, err := fingerprints(); err != nil {
		t.Fatal(err)
	}
	if got := technologies(map[string][]string{"Server": {"nginx/1.25.3"}}, nil); got == "" {
		t.Error("no technology detected from Server: nginx/1.25.3")
	}
}
