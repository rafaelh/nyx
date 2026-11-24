package cli_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// ccAsked lists what the Common Crawl fake was asked, in order: "collinfo" or
// "page=N", and "count" for a page-count query.
func ccAsked(w *world) []string {
	var out []string
	for _, r := range w.requests("index.commoncrawl.org") {
		switch q, _ := url.ParseQuery(r.query()); {
		case strings.HasSuffix(r.path(), "collinfo.json"):
			out = append(out, "collinfo")
		case q.Has("showNumPages"):
			out = append(out, "count")
		default:
			out = append(out, "page="+q.Get("page"))
		}
	}
	return out
}

// ccOverloaded fails each distinct request n times before delegating to next.
func ccOverloaded(n, status int, retryAfter string, next http.HandlerFunc) http.HandlerFunc {
	var mu sync.Mutex
	seen := map[string]int{}
	return func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.RequestURI()]++
		k := seen[r.URL.RequestURI()]
		mu.Unlock()
		if k <= n {
			if retryAfter != "" {
				rw.Header().Set("Retry-After", retryAfter)
			}
			http.Error(rw, "<html>Gateway Time-out</html>", status)
			return
		}
		next(rw, r)
	}
}

// ccIndex serves the collection list and pages of URLs, then the index's 400 for
// a page past the last.
func ccIndex(pages ...[]string) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "collinfo.json") {
			_, _ = rw.Write([]byte(`[{"id":"CC-MAIN-2026-01"}]`))
			return
		}
		var p int
		_, _ = fmt.Sscan(r.URL.Query().Get("page"), &p)
		if p >= len(pages) {
			ccPastLastPage(rw, r, len(pages)-1)
			return
		}
		for _, u := range pages[p] {
			fmt.Fprintf(rw, "{\"url\":%q}\n", u)
		}
	}
}

// Pages are read from 0 until the index answers that the page is past the last;
// the page count is not asked for.
func TestCommonCrawl_PagesAreReadUntilThePastTheLastAnswer(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.handle("index.commoncrawl.org", ccIndex([]string{"https://p0.example.com/"}, []string{"https://p1.example.com/"}))
	w.dns.A("p0.example.com", "203.0.113.5")
	w.dns.A("p1.example.com", "203.0.113.6")
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
	}
	if got := ccAsked(w); !slices.Equal(got, []string{"collinfo", "page=0", "page=1", "page=2"}) {
		t.Errorf("asked = %v, want the collection list then pages 0 to 2", got)
	}
	subs := w.lines(eng, "subdomains.txt")
	for _, n := range []string{"p0.example.com", "p1.example.com"} {
		if !slices.Contains(subs, n) {
			t.Errorf("subdomains.txt = %v, want %s", subs, n)
		}
	}
	if done := w.h.completed(eng, "commoncrawl"); len(done) != 1 {
		t.Errorf("completed = %v, want the root's check", done)
	}
}

// Retry gateway overload responses and complete the check when the index recovers.
func TestCommonCrawl_AnOverloadedAnswerIsSentAgain(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		status     int
		retryAfter string
	}{
		"504 without Retry-After": {504, ""},
		"503 with Retry-After":    {503, "0"},
		"502 with Retry-After":    {502, "0"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.handle("index.commoncrawl.org", ccOverloaded(1, tc.status, tc.retryAfter, ccIndex([]string{"https://cc.example.com/"})))
			w.dns.A("cc.example.com", "203.0.113.5")
			if code := w.run("--passive", "example.com"); code != 0 {
				t.Fatalf("exit %d\n%s", code, w.h.stderr.String())
			}
			want := []string{"collinfo", "collinfo", "page=0", "page=0", "page=1", "page=1"}
			if got := ccAsked(w); !slices.Equal(got, want) {
				t.Errorf("asked = %v, want %v", got, want)
			}
			if !slices.Contains(w.lines(eng, "subdomains.txt"), "cc.example.com") {
				t.Errorf("subdomains.txt = %v", w.lines(eng, "subdomains.txt"))
			}
		})
	}
}

// After three retries the request fails the check, which the next run retries.
func TestCommonCrawl_GivesUpAfterThreeRetries(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.handle("index.commoncrawl.org", ccOverloaded(1000, 504, "0", nil))
	w.h.partial(w.run("--passive", "example.com"), true)
	if got := ccAsked(w); !slices.Equal(got, []string{"collinfo", "collinfo", "collinfo", "collinfo"}) {
		t.Errorf("asked = %v, want the collection list four times", got)
	}
	if st, _ := stateOf(w, "commoncrawl"); st != "failed" {
		t.Errorf("commoncrawl = %s, want failed", st)
	}
	f := w.h.failedChecks("commoncrawl")
	if len(f) != 1 || !strings.Contains(f[0].err, "HTTP 504") || !strings.Contains(f[0].err, "3 retries") {
		t.Errorf("failures = %q, want the 504 and the retries", f)
	}

	w.handle("index.commoncrawl.org", ccIndex([]string{"https://cc.example.com/"}))
	if code := w.run("--passive", "example.com"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if done := w.h.completed(eng, "commoncrawl"); len(done) != 1 {
		t.Errorf("completed = %v, want the root's check", done)
	}
}

// Only the recognised out-of-range 400 ends pagination; other 400s remain failures.
func TestCommonCrawl_AnyOther400IsAFailure(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.handle("index.commoncrawl.org", func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "collinfo.json") {
			_, _ = rw.Write([]byte(`[{"id":"CC-MAIN-2026-01"}]`))
			return
		}
		rw.WriteHeader(http.StatusBadRequest)
		_, _ = rw.Write([]byte(`{"message": "Invalid query"}`))
	})
	w.h.partial(w.run("--passive", "example.com"), true)
	if done := w.h.completed(eng, "commoncrawl"); len(done) != 0 {
		t.Errorf("completed = %v, want none", done)
	}
}

// An interrupt during a wait ends the run at once.
func TestCommonCrawl_InterruptDuringTheWait(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := newWorld(t)
	w.handle("index.commoncrawl.org", ccOverloaded(1000, 503, "30", nil))
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	start := time.Now()
	if code := w.h.execCtx(ctx, "--json", "--rate-per-source", "1000", "--rate-dns", "100000", "--passive", "example.com"); code != 130 {
		t.Fatalf("exit %d, want 130", code)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("exit took %v: the wait must end at the interrupt", took)
	}
}
