package keycheck

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
)

const testKey = config.Secret("k_abcdefghijklmnopqrstuv")

// seen is one request a fake received.
type seen struct {
	method, path, query string
	header              http.Header
	body                string
}

// reply is what a fake answers.
type reply struct {
	status int
	header map[string]string
	body   string
	hold   bool // no answer until the request ends
	drop   bool // the connection is closed with no answer: a network failure
}

// fake is one source's server: it records its requests and answers with reply.
type fake struct {
	srv   *httptest.Server
	mu    sync.Mutex
	reqs  []seen
	reply reply
	done  chan struct{}
}

func (f *fake) set(r reply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reply = r
}

func (f *fake) hits() []seen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reqs)
}

func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{reply: reply{status: 200, body: `{}`}, done: make(chan struct{})}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(b)})
		rp := f.reply
		f.mu.Unlock()
		if rp.drop {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				conn.Close()
			}
			return
		}
		if rp.hold {
			select {
			case <-r.Context().Done():
			case <-f.done:
			}
			return
		}
		for k, v := range rp.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(rp.status)
		_, _ = io.WriteString(w, rp.body)
	}))
	t.Cleanup(func() {
		close(f.done)
		f.srv.Close()
	})
	return f
}

// world is a fake for every source's host, so a request to any host but the right one shows.
type world struct {
	fakes map[string]*fake // by source
	opts  egress.Options
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{fakes: map[string]*fake{}, opts: egress.Options{SourceBaseURLs: map[string]string{}, ResolverAddrs: []string{"127.0.0.1:1"}}}
	for _, s := range Sources() {
		f := newFake(t)
		w.fakes[s] = f
		w.opts.SourceBaseURLs[src(s).host] = f.srv.URL
	}
	return w
}

func (w *world) run(ctx context.Context, source string, key config.Secret) Result {
	return Run(ctx, w.opts, source, key)
}

// only fails the test unless exactly one request arrived, at source's fake.
func (w *world) only(t *testing.T, source string) seen {
	t.Helper()
	var got seen
	for s, f := range w.fakes {
		n := len(f.hits())
		switch {
		case s == source && n != 1:
			t.Errorf("%s: its host saw %d requests, want 1", source, n)
		case s != source && n != 0:
			t.Errorf("%s: the host of %s saw %d requests, want 0", source, s, n)
		}
	}
	if h := w.fakes[source].hits(); len(h) > 0 {
		got = h[0]
	}
	return got
}

func bg() context.Context { return context.Background() }

func TestSources_AreTheNineInOrder(t *testing.T) {
	t.Parallel()
	want := []string{"securitytrails", "shodan", "virustotal", "whoisxml", "censys", "chaos", "github", "certspotter", "nvd"}
	if got := Sources(); !slices.Equal(got, want) {
		t.Errorf("Sources() = %v, want %v", got, want)
	}
}

func TestHost(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"securitytrails": "api.securitytrails.com", "shodan": "api.shodan.io", "virustotal": "www.virustotal.com",
		"whoisxml": "user.whoisxmlapi.com", "censys": "api.platform.censys.io", "chaos": "dns.projectdiscovery.io",
		"github": "api.github.com", "certspotter": "api.certspotter.com", "nvd": "services.nvd.nist.gov",
	}
	for s, h := range want {
		if got := src(s).host; got != h {
			t.Errorf("src(%q).host = %q, want %q", s, got, h)
		}
	}
	if got := src("nosuch").host; got != "" {
		t.Errorf("Host of an unknown source = %q, want empty", got)
	}
}

// TestRequest_ShapePerSource pins each source's method, path, key placement and body on the wire.
func TestRequest_ShapePerSource(t *testing.T) {
	t.Parallel()
	key := string(testKey)
	tests := []struct {
		source, method, path string
		query                string            // the whole query, with the key in it when it travels there
		header               map[string]string // headers that must be exactly these
		body                 string            // JSON, or "" for none
	}{
		{"securitytrails", "GET", "/v1/ping", "", map[string]string{"APIKEY": key}, ""},
		{"shodan", "GET", "/api-info", "key=" + key, nil, ""},
		{"virustotal", "GET", "/api/v3/domains/example.com", "", map[string]string{"x-apikey": key}, ""},
		{"whoisxml", "GET", "/user-service/account-balance", "apiKey=" + key, nil, ""},
		{"censys", "POST", "/v3/global/search/query", "", map[string]string{"Authorization": "Bearer " + key, "Content-Type": "application/json"},
			`{"query":"cert.names: \"example.com\"","page_size":1}`},
		{"chaos", "GET", "/dns/example.com", "", map[string]string{"Authorization": key}, ""},
		{"github", "GET", "/rate_limit", "", map[string]string{"Authorization": "Bearer " + key}, ""},
		{"certspotter", "GET", "/v1/issuances", "domain=example.com", map[string]string{"Authorization": "Bearer " + key}, ""},
		{"nvd", "GET", "/rest/json/cves/2.0", "cveId=CVE-2021-44228", map[string]string{"apiKey": key}, ""},
	}
	if len(tests) != len(Sources()) {
		t.Fatalf("table has %d sources, Sources() has %d", len(tests), len(Sources()))
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			if r := w.run(bg(), tt.source, testKey); r.Status != Accepted {
				t.Fatalf("result = %+v, want accepted", r)
			}
			got := w.only(t, tt.source)
			if got.method != tt.method || got.path != tt.path {
				t.Errorf("request = %s %s, want %s %s", got.method, got.path, tt.method, tt.path)
			}
			if got.query != tt.query {
				t.Errorf("query = %q, want %q", got.query, tt.query)
			}
			for h, v := range tt.header {
				if g := got.header.Get(h); g != v {
					t.Errorf("header %s = %q, want %q", h, g, v)
				}
			}
			if tt.body == "" {
				if got.body != "" {
					t.Errorf("body = %q, want none", got.body)
				}
			} else if !jsonEqual(t, got.body, tt.body) {
				t.Errorf("body = %s, want %s", got.body, tt.body)
			}
			checkKeyPlace(t, got, key, strings.Contains(tt.query, key))
		})
	}
}

// checkKeyPlace fails the test when the key is in the request anywhere but where it belongs: the
// query when inQuery, else a header.
func checkKeyPlace(t *testing.T, got seen, key string, inQuery bool) {
	t.Helper()
	if !inQuery {
		if strings.Contains(got.query, key) || strings.Contains(got.path, key) {
			t.Errorf("the key is in the URL: %s?%s", got.path, got.query)
		}
		return
	}
	for h := range got.header {
		if strings.Contains(strings.Join(got.header.Values(h), ","), key) {
			t.Errorf("the key is also in header %s", h)
		}
	}
}

func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		t.Fatal(err)
	}
	ab, _ := json.Marshal(x)
	bb, _ := json.Marshal(y)
	return string(ab) == string(bb)
}

// recorder is an egress.ThirdPartyHTTP that records each request and answers with one reply.
type recorder struct {
	mu   sync.Mutex
	reqs []egress.ThirdPartyRequest
	resp egress.ThirdPartyResponse
	err  error
}

func (r *recorder) Do(_ context.Context, req egress.ThirdPartyRequest) (egress.ThirdPartyResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	return r.resp, r.err
}

// TestCheck_NeverPutsTheKeyInTheRequest: the request names the key's source and egress attaches it.
func TestCheck_NeverPutsTheKeyInTheRequest(t *testing.T) {
	t.Parallel()
	for _, s := range Sources() {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			rec := &recorder{resp: egress.ThirdPartyResponse{Status: 200}}
			if r := check(bg(), rec, src(s), testKey); r.Status != Accepted {
				t.Fatalf("result = %+v", r)
			}
			if len(rec.reqs) != 1 {
				t.Fatalf("%d requests, want 1", len(rec.reqs))
			}
			req := rec.reqs[0]
			if req.KeySource != s {
				t.Errorf("KeySource = %q, want %q", req.KeySource, s)
			}
			if req.KeyHeader == "" && req.KeyParam == "" {
				t.Error("the request asks for no key placement")
			}
			if strings.Contains(req.URL, string(testKey)) || strings.Contains(string(req.Body), string(testKey)) {
				t.Error("the key is in the URL or body the stage built")
			}
			if !strings.HasPrefix(req.URL, "https://"+src(s).host+"/") {
				t.Errorf("URL %q is not on host %s", req.URL, src(s).host)
			}
			if req.Timeout != 20*time.Second {
				t.Errorf("Timeout = %v, want 20s so the context decides", req.Timeout)
			}
		})
	}
}

func TestCheck_Accepted(t *testing.T) {
	t.Parallel()
	for _, s := range Sources() {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.fakes[s].set(reply{status: 200, body: `{"ok":true}`})
			if r := w.run(bg(), s, testKey); r != (Result{Status: Accepted}) {
				t.Errorf("result = %+v, want accepted", r)
			}
		})
	}
}

func TestCheck_Rejected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		source string
		reply  reply
	}{
		{"securitytrails", reply{status: 401, body: `{"message":"Please check user credentials"}`}},
		{"shodan", reply{status: 401, body: `{"error":"Invalid API key"}`}},
		{"virustotal", reply{status: 401, body: `{"error":{"code":"WrongCredentialsError","message":"Wrong API key"}}`}},
		{"censys", reply{status: 401, body: `{"message":"Access credentials are invalid"}`}},
		{"chaos", reply{status: 400, body: `{"valid":false,"message":"invalid pdcp_api_token"}`}},
		{"chaos", reply{status: 401, body: `{"message":"unauthorised"}`}},
		{"github", reply{status: 401, body: `{"message":"Bad credentials"}`}},
		{"certspotter", reply{status: 401, body: `{"code":"bad_credentials","message":"bad credentials"}`}},
		{"nvd", reply{status: 404, header: map[string]string{"message": "Invalid apiKey."}}},
		{"nvd", reply{status: 401}},
		{"nvd", reply{status: 403, body: `Invalid apiKey`}},
	}
	for _, tt := range tests {
		t.Run(tt.source+" "+http.StatusText(tt.reply.status), func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.fakes[tt.source].set(tt.reply)
			if r := w.run(bg(), tt.source, testKey); r.Status != Rejected {
				t.Errorf("result = %+v, want rejected", r)
			}
		})
	}
}

func TestCheck_CommonAnswers(t *testing.T) {
	t.Parallel()
	for _, s := range Sources() {
		for _, tt := range []struct {
			name  string
			reply reply
			want  string
		}{
			{"rate limited", reply{status: 429, body: `{"message":"slow down"}`}, "rate limited"},
			{"out of credits", reply{status: 402, body: `{"message":"pay up"}`}, "out of credits"},
			{"another status with a message", reply{status: 500, body: `{"message":"it broke"}`}, "HTTP 500: it broke"},
			{"another status with none", reply{status: 503}, "HTTP 503"},
			{"a body that is not JSON", reply{status: 502, body: "<html>bad gateway</html>"}, "HTTP 502"},
		} {
			t.Run(s+" "+tt.name, func(t *testing.T) {
				t.Parallel()
				w := newWorld(t)
				w.fakes[s].set(tt.reply)
				r := w.run(bg(), s, testKey)
				if r.Status != Unknown || r.Reason != tt.want {
					t.Errorf("result = %+v, want unknown %q", r, tt.want)
				}
				if n := len(w.fakes[s].hits()); n != 1 {
					t.Errorf("%d requests, want 1: a test never retries", n)
				}
			})
		}
	}
}

func TestCheck_ReasonFromTheAnswer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		reply reply
		want  string
	}{
		{"message", reply{status: 500, body: `{"message":"m1"}`}, "HTTP 500: m1"},
		{"messages as a list", reply{status: 500, body: `{"messages":["first","second"]}`}, "HTTP 500: first"},
		{"messages as a string", reply{status: 500, body: `{"messages":"just one"}`}, "HTTP 500: just one"},
		{"error.message", reply{status: 500, body: `{"error":{"code":"X","message":"nested"}}`}, "HTTP 500: nested"},
		{"error as a string", reply{status: 500, body: `{"error":"plain"}`}, "HTTP 500: plain"},
		{"no message", reply{status: 500, body: `{"other":1}`}, "HTTP 500"},
		{"nvd header", reply{status: 500, header: map[string]string{"message": "from the header"}}, "HTTP 500: from the header"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			source := "github"
			if strings.HasPrefix(tt.name, "nvd") {
				source = "nvd"
			}
			w := newWorld(t)
			w.fakes[source].set(tt.reply)
			if r := w.run(bg(), source, testKey); r != (Result{Unknown, tt.want}) {
				t.Errorf("result = %+v, want unknown %q", r, tt.want)
			}
		})
	}
}

func TestCheck_ChaosOtherBadRequestIsUnknown(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.fakes["chaos"].set(reply{status: 400, body: `{"valid":true,"message":"bad domain"}`})
	if r := w.run(bg(), "chaos", testKey); r != (Result{Unknown, "HTTP 400: bad domain"}) {
		t.Errorf("result = %+v", r)
	}
}

func TestCheck_NVDRateLimits(t *testing.T) {
	t.Parallel()
	for _, status := range []int{403, 429} {
		w := newWorld(t)
		w.fakes["nvd"].set(reply{status: status, body: `forbidden`})
		if r := w.run(bg(), "nvd", testKey); r != (Result{Unknown, "rate limited"}) {
			t.Errorf("HTTP %d: result = %+v, want rate limited", status, r)
		}
	}
}

// TestCheck_WhoisXMLNeverSaysTheKeyIsBad: its 401 and 403 mean credits, key or allowlist.
func TestCheck_WhoisXMLNeverSaysTheKeyIsBad(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		status int
		body   string
		want   string
	}{
		{401, `{"code":401,"messages":"Access restricted. Check the credits balance or enter the correct API key"}`,
			"Access restricted. Check the credits balance or enter the correct API key"},
		{403, `{"message":"insufficient credits balance, incorrect API key, or your IP address is not added to the IP allowlist"}`,
			"insufficient credits balance, incorrect API key, or your IP address is not added to the IP allowlist"},
		{401, ``, "HTTP 401"},
	} {
		w := newWorld(t)
		w.fakes["whoisxml"].set(reply{status: tt.status, body: tt.body})
		if r := w.run(bg(), "whoisxml", testKey); r != (Result{Unknown, tt.want}) {
			t.Errorf("HTTP %d: result = %+v, want unknown %q", tt.status, r, tt.want)
		}
	}
}

// TestCheck_Rejected401Only: a 403 is a refusal of the request, not clearly of the key.
func TestCheck_ForbiddenIsNotRejected(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"securitytrails", "shodan", "virustotal", "censys", "chaos", "github", "certspotter"} {
		w := newWorld(t)
		w.fakes[s].set(reply{status: 403, body: `{"message":"forbidden"}`})
		if r := w.run(bg(), s, testKey); r.Status == Accepted {
			t.Errorf("%s: a 403 was accepted", s)
		}
	}
}

func TestCheck_NetworkError(t *testing.T) {
	t.Parallel()
	for _, s := range Sources() {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.fakes[s].set(reply{drop: true}) // not a closed port: another parallel test's server could take it
			r := w.run(bg(), s, testKey)
			if r.Status != Unknown || r.Reason == "" || r.Reason == "timed out" {
				t.Fatalf("result = %+v, want unknown with a network reason", r)
			}
			if strings.Contains(r.Reason, string(testKey)) || strings.Contains(r.Reason, "abcdefghijklm") {
				t.Errorf("reason shows the key: %q", r.Reason)
			}
			if strings.ContainsAny(r.Reason, "\r\n") {
				t.Errorf("reason is not one line: %q", r.Reason)
			}
		})
	}
}

func TestCheck_TimesOutWhenTheSourceNeverAnswers(t *testing.T) {
	t.Parallel()
	for _, s := range Sources() {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.fakes[s].set(reply{hold: true})
			ctx, cancel := context.WithTimeout(bg(), 100*time.Millisecond)
			defer cancel()
			if r := w.run(ctx, s, testKey); r != (Result{Unknown, "timed out"}) {
				t.Errorf("result = %+v, want unknown timed out", r)
			}
		})
	}
}

func TestCheck_Cancelled(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.fakes["shodan"].set(reply{hold: true})
	ctx, cancel := context.WithCancel(bg())
	defer cancel()
	go func() {
		for len(w.fakes["shodan"].hits()) == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	r := w.run(ctx, "shodan", testKey)
	if r.Status != Unknown || r.Reason == "timed out" || r.Reason == "" {
		t.Errorf("result = %+v, want unknown, cancelled", r)
	}
}

func TestCheck_MasksTheEchoedKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		key  config.Secret
		msg  string
		want string
	}{
		{"the leading part", testKey, "invalid token k_abcdefghi... given", "HTTP 500: invalid token ****... given"},
		{"a run of five", testKey, "got k_abc then", "HTTP 500: got **** then"},
		{"a run of four stays", testKey, "got k_ab then", "HTTP 500: got k_ab then"},
		{"the whole key", testKey, "key " + string(testKey) + " bad", "HTTP 500: key **** bad"},
		{"a middle part", testKey, "see hijklmnop here", "HTTP 500: see **** here"},
		{"a short key whole", "abcd", "key abcd bad", "HTTP 500: key **** bad"},
		{"each run on its own", testKey, "a k_abcde b qrstuv c", "HTTP 500: a **** b **** c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			body, _ := json.Marshal(map[string]string{"message": tt.msg})
			w.fakes["certspotter"].set(reply{status: 500, body: string(body)})
			if r := w.run(bg(), "certspotter", tt.key); r != (Result{Unknown, tt.want}) {
				t.Errorf("result = %+v, want unknown %q", r, tt.want)
			}
		})
	}
}

func TestCheck_ReasonIsCleanAndOneLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want string
	}{
		{"escapes", `{"message":"a\u001b[31mred\u001b[0m\u0007 b"}`, "HTTP 500: ared b"},
		{"first line only", `{"message":"first\nsecond\r\nthird"}`, "HTTP 500: first"},
		{"a leading blank line", `{"message":"\n\nreal"}`, "HTTP 500: real"},
		{"bidi override", `{"message":"x\u202ey"}`, "HTTP 500: xy"},
		{"only controls", `{"message":"\u001b[2J\u0007"}`, "HTTP 500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.fakes["github"].set(reply{status: 500, body: tt.body})
			if r := w.run(bg(), "github", testKey); r != (Result{Unknown, tt.want}) {
				t.Errorf("result = %+v, want unknown %q", r, tt.want)
			}
		})
	}
	t.Run("a long message is cut", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t)
		body, _ := json.Marshal(map[string]string{"message": strings.Repeat("x", 5000)})
		w.fakes["github"].set(reply{status: 500, body: string(body)})
		r := w.run(bg(), "github", testKey)
		if n := len([]rune(r.Reason)); n > 400 || !strings.HasSuffix(r.Reason, "…") {
			t.Errorf("reason of %d runes %q: want it cut with an ellipsis", n, r.Reason)
		}
	})
	t.Run("the NVD header", func(t *testing.T) {
		t.Parallel()
		// A real server cannot send a control character in a header, so the answer is given directly.
		rec := &recorder{resp: egress.ThirdPartyResponse{Status: 500, Header: map[string][]string{"Message": {"a \x1b[31mred\x1b[0m\u0007 b"}}}}
		if r := check(bg(), rec, src("nvd"), testKey); r != (Result{Unknown, "HTTP 500: a red b"}) {
			t.Errorf("result = %+v", r)
		}
	})
}

// TestRun_OneRequestToItsHostOnly: a test sends exactly one request, to that source's host, and
// every other source's host sees nothing, whatever the answer.
func TestRun_OneRequestToItsHostOnly(t *testing.T) {
	t.Parallel()
	answers := map[string]reply{
		"accepted": {status: 200},
		"rejected": {status: 401},
		"limited":  {status: 429},
		"credits":  {status: 402},
		"broken":   {status: 500},
		"redirect": {status: 302, header: map[string]string{"Location": "https://www.virustotal.com/"}},
	}
	for _, s := range Sources() {
		for name, rp := range answers {
			t.Run(s+" "+name, func(t *testing.T) {
				t.Parallel()
				w := newWorld(t)
				w.fakes[s].set(rp)
				w.run(bg(), s, testKey)
				w.only(t, s)
			})
		}
	}
}

// TestCheck_ClientForAnotherHostRefusesTheRequest: the egress client allows only the one host.
func TestCheck_ClientForAnotherHostRefusesTheRequest(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	opts := w.opts
	opts.Keys = map[string]config.Secret{"shodan": testKey}
	c := egress.New(opts).Clients(false, []string{src("virustotal").host}).ThirdParty
	r := check(bg(), c, src("shodan"), testKey)
	if r.Status != Unknown || r.Reason == "" {
		t.Errorf("result = %+v, want unknown with a reason", r)
	}
	for s, f := range w.fakes {
		if n := len(f.hits()); n != 0 {
			t.Errorf("%s saw %d requests, want none", s, n)
		}
	}
}

func TestRun_UnknownSource(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	r := w.run(bg(), "nosuch", testKey)
	if r.Status != Unknown || r.Reason == "" {
		t.Errorf("result = %+v, want unknown with a reason", r)
	}
	for s, f := range w.fakes {
		if n := len(f.hits()); n != 0 {
			t.Errorf("%s saw %d requests, want none", s, n)
		}
	}
}

// src is the source named name, or the zero source for a name with no test.
func src(name string) source {
	s, _ := lookup(name)
	return s
}
