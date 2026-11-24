package egress_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/egress/egresstest"
	"github.com/rafaelh/nyx/internal/scope"
)

// recorder is an HTTP server that logs "METHOD host path" for each request.
type recorder struct {
	mu  sync.Mutex
	log []string
	srv *httptest.Server
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.log = append(r.log, req.Method+" "+req.URL.RequestURI())
		r.mu.Unlock()
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.log...)
}

// ThirdPartyHTTP allows HEAD, and still nothing but GET, HEAD and POST.
func TestThirdPartyAllowsHead(t *testing.T) {
	t.Parallel()
	rec := newRecorder(t)
	eg := thirdPartyEgress(t, map[string]string{"storage.googleapis.com": rec.srv.URL}, egress.Options{})
	c := eg.Clients(false, []string{"storage.googleapis.com"}).ThirdParty
	resp, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "HEAD", URL: "https://storage.googleapis.com/b/k"})
	if err != nil || resp.Status != 200 || len(resp.Body) != 0 {
		t.Fatalf("HEAD: %+v %v", resp, err)
	}
	if got := rec.requests(); len(got) != 1 || got[0] != "HEAD /b/k" {
		t.Errorf("requests = %v", got)
	}
	for _, m := range []string{"PUT", "DELETE", "PATCH", "OPTIONS"} {
		if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: m, URL: "https://storage.googleapis.com/b"}); err == nil {
			t.Errorf("%s must still be refused", m)
		}
	}
}

// A source pattern may have one wildcard label in the middle.
func TestSourceMiddleWildcard(t *testing.T) {
	t.Parallel()
	rec := newRecorder(t)
	eg := thirdPartyEgress(t, map[string]string{"s3.*.amazonaws.com": rec.srv.URL, "s3.amazonaws.com": rec.srv.URL}, egress.Options{})
	c := eg.Clients(false, []string{"s3.amazonaws.com", "s3.*.amazonaws.com"}).ThirdParty
	for _, ok := range []string{"https://s3.eu-west-1.amazonaws.com/b", "https://s3.us-gov-west-1.amazonaws.com/b", "https://s3.amazonaws.com/b"} {
		if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: ok}); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	before := len(rec.requests())
	for _, bad := range []string{
		"https://s3.a.b.amazonaws.com/x",        // two labels
		"https://s3.EU_WEST.amazonaws.com/x",    // outside [a-z0-9-]
		"https://ec2.eu-west-1.amazonaws.com/x", // other service
		"https://s3.eu-west-1.amazonaws.com.evil.example/x",
		"https://xs3.eu-west-1.amazonaws.com/x",
		"https://mybucket.s3.amazonaws.com/x", // not a listed source
	} {
		if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: bad}); err == nil {
			t.Errorf("%s should be refused", bad)
		}
	}
	if len(rec.requests()) != before {
		t.Error("refused requests were sent")
	}
}

// Declared sources may be candidates, but in-scope/excluded source hosts remain refused.
func TestCandidateSourceIsContacted(t *testing.T) {
	t.Parallel()
	rec := newRecorder(t)
	eg := thirdPartyEgress(t, map[string]string{"*.blob.core.windows.net": rec.srv.URL}, egress.Options{})
	c := eg.Clients(false, []string{"*.blob.core.windows.net"}).ThirdParty
	if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://cand.blob.core.windows.net/c"}); err != nil {
		t.Errorf("candidate source host: %v", err)
	}
	if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://bad.blob.core.windows.net/c"}); err == nil {
		t.Error("an excluded host is still refused")
	}
	eg.SetPolicy(&egress.Policy{Scope: scope.New(scope.Config{Roots: []string{"blob.core.windows.net"}})})
	if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://mine.blob.core.windows.net/c"}); err == nil {
		t.Error("an in-scope host is still refused")
	}
	if len(rec.requests()) != 1 {
		t.Errorf("requests = %v, want only the candidate's", rec.requests())
	}
}

// SourceBaseURLs accepts exact hosts, checked before patterns.
func TestSourceBaseURLExactHost(t *testing.T) {
	t.Parallel()
	one, two := newRecorder(t), newRecorder(t)
	eg := thirdPartyEgress(t, map[string]string{"*.blob.core.windows.net": one.srv.URL, "acct2.blob.core.windows.net": two.srv.URL}, egress.Options{})
	c := eg.Clients(false, []string{"*.blob.core.windows.net"}).ThirdParty
	for _, h := range []string{"acct1", "acct2"} {
		if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://" + h + ".blob.core.windows.net/x"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(one.requests()) != 1 || len(two.requests()) != 1 {
		t.Errorf("pattern server %v, exact server %v", one.requests(), two.requests())
	}
}

// MX queries and rdata.
func TestResolverMX(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	d.MX("example.com", 10, "Mail.Example.com")
	d.MX("example.com", 20, "mail2.example.com")
	d.MX("null.example.com", 0, ".")
	dnsc := resolver(d.Addr, 300*time.Millisecond)
	res, err := dnsc.Query(context.Background(), "example.com", egress.TypeMX)
	if err != nil || len(res.Answers) != 2 || res.Answers[0].Type != "MX" || res.Answers[0].Value != "10 mail.example.com" || res.Answers[1].Value != "20 mail2.example.com" {
		t.Errorf("MX = %+v %v", res, err)
	}
	res, err = dnsc.Query(context.Background(), "null.example.com", egress.TypeMX)
	if err != nil || len(res.Answers) != 1 || res.Answers[0].Value != "0 ." {
		t.Errorf("null MX = %+v %v", res, err)
	}
}
