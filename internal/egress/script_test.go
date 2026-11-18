package egress_test

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/scope"
)

func scriptURL(host string, port int, path string) string {
	return "http://" + host + ":" + strconv.Itoa(port) + path
}

// Script requests only a URL the policy lists, and the request goes out as a plain GET.
func TestScript_AllowedOnlyForAListedURL(t *testing.T) {
	t.Parallel()
	var methods, uris []string
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) {
		methods, uris = append(methods, r.Method), append(uris, r.URL.RequestURI())
		_, _ = w.Write([]byte("var a=1"))
	})
	listed := scriptURL("www.example.com", f.port, "/static/app.js?v=3")
	f.pol.Scripts = map[string]bool{listed: true}

	res, err := f.client().Get(context.Background(), egress.Script(listed))
	if r, ok := res.(egress.Response); err != nil || !ok || r.Status != 200 || string(r.Body) != "var a=1" {
		t.Fatalf("listed script: %#v %v", res, err)
	}
	if len(uris) != 1 || uris[0] != "/static/app.js?v=3" || methods[0] != "GET" {
		t.Errorf("request = %v %v, want one GET of /static/app.js?v=3", methods, uris)
	}

	for name, u := range map[string]string{
		"another path of the same host": scriptURL("www.example.com", f.port, "/static/other.js"),
		"the same path, another query":  scriptURL("www.example.com", f.port, "/static/app.js?v=4"),
		"the same path on another host": scriptURL("a.example.com", f.port, "/static/app.js?v=3"),
		"an unparsable URL":             "http://www.example.com:" + strconv.Itoa(f.port) + "/%zz",
		"not a URL":                     "app.js",
	} {
		before := f.hits.Load()
		res, err := f.client().Get(context.Background(), egress.Script(u))
		if err != nil || !isRefused(res) {
			t.Errorf("%s: %#v %v, want Refused", name, res, err)
		}
		if f.hits.Load() != before {
			t.Errorf("%s: a refused script request reached the server", name)
		}
	}
	// Without a Scripts set no script may be requested at all.
	f.pol.Scripts = nil
	if res, _ := f.client().Get(context.Background(), egress.Script(listed)); !isRefused(res) {
		t.Errorf("no script set: %#v", res)
	}
}

// Host scope, exclusion and passive mode apply to a listed script as to any target request.
func TestScript_StillSubjectToHostPolicy(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) })
	res := map[string][]netip.Addr{
		"www.example.com":  {addr("127.0.0.1")},
		"cand.example.org": {addr("127.0.0.1")},
		"bad.example.com":  {addr("127.0.0.2")}, // its own address: an excluded name excludes the addresses it resolves to
	}
	build := func(passive bool) *egress.Policy {
		return &egress.Policy{
			Scope:       scope.New(scope.Config{Roots: []string{"example.com"}, Exclusions: mustExcl(t, "bad.example.com"), Resolutions: res}),
			Ack:         true,
			Passive:     passive,
			Ports:       []int{f.port},
			Resolutions: res,
			Candidates:  map[string]bool{"cand.example.org": true},
			Scripts: map[string]bool{
				scriptURL("www.example.com", f.port, "/a.js"):  true,
				scriptURL("cand.example.org", f.port, "/a.js"): true,
				scriptURL("bad.example.com", f.port, "/a.js"):  true,
			},
		}
	}
	for name, tc := range map[string]struct {
		host    string
		passive bool
		refused bool
	}{
		"in scope":       {"www.example.com", false, false},
		"candidate host": {"cand.example.org", false, true},
		"excluded host":  {"bad.example.com", false, true},
		"passive run":    {"www.example.com", true, true},
	} {
		f.eg.SetPolicy(build(tc.passive))
		before := f.hits.Load()
		r, err := f.client().Get(context.Background(), egress.Script(scriptURL(tc.host, f.port, "/a.js")))
		if err != nil || isRefused(r) != tc.refused {
			t.Errorf("%s: %#v %v, want refused=%v", name, r, err, tc.refused)
		}
		if tc.refused && f.hits.Load() != before {
			t.Errorf("%s: reached the server", name)
		}
	}
	// No authorisation yet.
	p := build(false)
	p.Ack = false
	f.eg.SetPolicy(p)
	if r, _ := f.client().Get(context.Background(), egress.Script(scriptURL("www.example.com", f.port, "/a.js"))); !isRefused(r) {
		t.Errorf("unauthorised: %#v", r)
	}
}

// A script body is read up to 4 MiB, and Truncated says when the cap cut it. The
// ordinary 1 MiB cap is unchanged.
func TestScript_BodyCapAndTruncated(t *testing.T) {
	t.Parallel()
	const mib = 1 << 20
	size := 0
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", size)))
	})
	u := scriptURL("www.example.com", f.port, "/bundle.js")
	f.pol.Scripts = map[string]bool{u: true}
	get := func(req egress.Request) egress.Response {
		t.Helper()
		res, err := f.client().Get(context.Background(), req)
		r, ok := res.(egress.Response)
		if err != nil || !ok {
			t.Fatalf("%#v %v", res, err)
		}
		return r
	}

	if egress.MaxScriptBody != 4*mib {
		t.Errorf("MaxScriptBody = %d, want 4 MiB", egress.MaxScriptBody)
	}
	for name, tc := range map[string]struct {
		size      int
		wantLen   int
		truncated bool
	}{
		"just under the cap": {4*mib - 1, 4*mib - 1, false},
		"exactly the cap":    {4 * mib, 4 * mib, false},
		"one byte over":      {4*mib + 1, 4 * mib, true},
		"far over":           {6 * mib, 4 * mib, true},
	} {
		size = tc.size
		r := get(egress.Script(u))
		if len(r.Body) != tc.wantLen || r.Truncated != tc.truncated {
			t.Errorf("%s: len=%d truncated=%v, want len=%d truncated=%v", name, len(r.Body), r.Truncated, tc.wantLen, tc.truncated)
		}
	}

	size = 2 * mib
	if r := get(egress.Root("www.example.com", "http", f.port)); len(r.Body) != mib || !r.Truncated {
		t.Errorf("an ordinary request: len=%d truncated=%v, want the 1 MiB cap and Truncated", len(r.Body), r.Truncated)
	}
	size = mib
	if r := get(egress.Root("www.example.com", "http", f.port)); len(r.Body) != mib || r.Truncated {
		t.Errorf("an ordinary body of exactly 1 MiB: len=%d truncated=%v", len(r.Body), r.Truncated)
	}
}

// A redirect from a script is requested with egress.Redirect, keeps the script cap,
// and is still checked against the host policy.
func TestScript_RedirectKeepsTheCap(t *testing.T) {
	t.Parallel()
	f := newHTTPFixture(t, egress.Options{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/old.js" {
			http.Redirect(w, r, "/new.js", http.StatusMovedPermanently)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("a", 2<<20)))
	})
	u := scriptURL("www.example.com", f.port, "/old.js")
	f.pol.Scripts = map[string]bool{u: true}
	res, _ := f.client().Get(context.Background(), egress.Script(u))
	r, ok := res.(egress.Response)
	if !ok {
		t.Fatalf("listed script: %#v", res)
	}
	req, err := egress.Redirect(r)
	if err != nil {
		t.Fatal(err)
	}
	res, _ = f.client().Get(context.Background(), req)
	if r2, ok := res.(egress.Response); !ok || len(r2.Body) != 2<<20 || r2.Truncated {
		t.Errorf("redirect target of a script: %d bytes, truncated=%v; want the whole 2 MiB", len(r2.Body), r2.Truncated)
	}
}
