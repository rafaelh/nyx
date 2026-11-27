package cli_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
)

// Reverse-IP tests run real procedures against loopback HackerTarget/SecurityTrails responses.

const securityTrailsKey = "st-key-SECRET-0004"

// htReverse serves address results, treating unspecified addresses as empty and unrelated paths
// as 404.
type htReverse struct {
	mu      sync.Mutex
	replies map[string]string
	fixed   func(rw http.ResponseWriter) // when set, answers every reverse lookup
}

func (f *htReverse) serve(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/reverseiplookup/" {
		http.NotFound(rw, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fixed != nil {
		f.fixed(rw)
		return
	}
	body, ok := f.replies[r.URL.Query().Get("q")]
	if !ok {
		body = "No records found"
	}
	_, _ = rw.Write([]byte(body))
}

func (f *htReverse) set(addr string, names ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[addr] = strings.Join(names, "\n")
}

func (f *htReverse) answerAll(h func(rw http.ResponseWriter)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fixed = h
}

func (x *web) hackerTarget() *htReverse {
	x.t.Helper()
	f := &htReverse{replies: map[string]string{}}
	x.handle("api.hackertarget.com", f.serve)
	return f
}

// stQuery is the body of a SecurityTrails domain search.
type stQuery struct {
	Filter map[string]string `json:"filter"`
}

func (q stQuery) addr() string { return q.Filter["ipv4"] + q.Filter["ipv6"] }

// server is the name server or mail host searched for, as "ns|<host>" or
// "mx|<host>", or "" for a search by address.
func (q stQuery) server() string {
	switch {
	case q.Filter["ns"] != "":
		return "ns|" + q.Filter["ns"]
	case q.Filter["mx"] != "":
		return "mx|" + q.Filter["mx"]
	}
	return ""
}

// stReverse validates keyed domain searches and supplies empty subdomain responses to isolate
// the tested procedure.
type stReverse struct {
	mu                 sync.Mutex
	byAddr, byNS, byMX map[string][]string
	total              map[string]int // the record_count to report for a server search, where it is not the list's length
	status             int
	pageSize           int // records per page; 0 puts them all on one page
}

func (f *stReverse) serve(rw http.ResponseWriter, r *http.Request) {
	// Return empty subdomains so unrelated source failures cannot make these runs partial.
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/domain/") && strings.HasSuffix(r.URL.Path, "/subdomains") {
		_, _ = rw.Write([]byte(`{"subdomains":[]}`))
		return
	}
	if r.URL.Path != "/v1/domains/list" || r.Method != http.MethodPost {
		http.NotFound(rw, r)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("APIKEY") != securityTrailsKey {
		http.Error(rw, "bad key", http.StatusForbidden)
		return
	}
	if f.status != 0 {
		http.Error(rw, "no", f.status)
		return
	}
	var q stQuery
	_ = json.NewDecoder(r.Body).Decode(&q)
	names := f.byAddr[q.addr()]
	if q.server() != "" {
		names = slices.Concat(f.byNS[q.Filter["ns"]], f.byMX[q.Filter["mx"]])
	}
	total := len(names)
	if t, ok := f.total[q.server()]; ok {
		total = t
	}
	pages := 1
	if f.pageSize > 0 {
		pages = max(1, (len(names)+f.pageSize-1)/f.pageSize)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		lo := min(len(names), max(0, page-1)*f.pageSize)
		names = names[lo:min(len(names), lo+f.pageSize)]
	}
	records := []map[string]string{}
	for _, n := range names {
		records = append(records, map[string]string{"hostname": n})
	}
	_ = json.NewEncoder(rw).Encode(map[string]any{"endpoint": "/v1/domains/list", "pages": pages, "record_count": total, "records": records})
}

func (f *stReverse) setStatus(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = code
}

func (x *web) securityTrails(byAddr map[string][]string) *stReverse {
	x.t.Helper()
	x.h.setKey("securitytrails", securityTrailsKey)
	f := &stReverse{byAddr: byAddr}
	x.handle("api.securitytrails.com", f.serve)
	return f
}

// htAsked are the addresses asked of HackerTarget's reverse lookup, in order.
func (x *web) htAsked() []string {
	var out []string
	for _, r := range x.requests("api.hackertarget.com") {
		if r.path() == "/reverseiplookup/" {
			out = append(out, strings.TrimPrefix(r.query(), "q="))
		}
	}
	return out
}

// stAsked are the addresses of SecurityTrails' domain searches, in order.
func (x *web) stAsked() []string {
	var out []string
	for _, r := range x.requests("api.securitytrails.com") {
		if r.path() != "/v1/domains/list" {
			continue
		}
		var q stQuery
		_ = json.Unmarshal([]byte(r.Body), &q)
		out = append(out, q.addr())
	}
	return out
}

func (x *web) candidates() []map[string]string { return x.table(eng, "candidates.csv") }

func (x *web) candidate(value string) map[string]string { return find(x.candidates(), "value", value) }

func (x *web) hostnameKeys() []string { return slices.Sorted(maps.Keys(x.obsAttrs(eng, "hostname"))) }

// manyDomains lists n names, each under its own registrable domain.
func manyDomains(n int) []string {
	var out []string
	for i := range n {
		out = append(out, fmt.Sprintf("www.site%03d.org", i))
	}
	return out
}

// --- Which addresses are asked ---

// Query only recorded eligible addresses, never expanding netblocks or asking
// shared/excluded/unknown-owner addresses.
func TestReverseIP_AsksOnlyDedicatedKnownOwnerAddresses(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	ht := x.hackerTarget()
	x.names("app.example.com", "cdn.example.com", "ex.example.com", "u.example.com", "nb.example.com")
	x.host("app.example.com", "203.0.113.7") // dedicated
	x.owner("203.0.113.7", 64500, "ACME-NET")
	x.host("cdn.example.com", "104.16.0.5") // shared provider infrastructure
	x.owner("104.16.0.5", 13335, "CLOUDFLARENET")
	x.host("ex.example.com", "203.0.113.70") // inside an excluded CIDR
	x.owner("203.0.113.70", 64500, "ACME-NET")
	x.host("u.example.com", "192.0.2.77") // the owner source is down
	x.dns.Rcode(dnsname.CymruOrigin(mustAddr("192.0.2.77")), int(mdns.RcodeServerFailure))
	x.host("nb.example.com", "198.51.100.1") // one address of an in-scope netblock
	for _, a := range []string{"203.0.113.7", "203.0.113.250", "198.51.100.1", "198.51.100.0", "198.51.100.2", "198.51.100.3", "192.0.2.77"} {
		ht.set(a, "No records found")
	}

	// The owner source is down for one address, which fails the owner job and nothing else.
	if f := x.h.partial(x.passive("--cidr", "198.51.100.0/30", "-x", "203.0.113.64/28"), true); f.msg != "1 jobs failed: ipowner 1" {
		t.Errorf("error = %+v, want the one failed ipowner job", f)
	}

	// The netblock's other addresses, though in scope, were never recorded.
	want := []string{"198.51.100.1", "203.0.113.250", "203.0.113.7"}
	if got := sorted(x.htAsked()); !slices.Equal(got, want) {
		t.Errorf("asked %v, want %v", got, want)
	}
	if st, reason := stateOf(x.world, "reverseip"); st != "done" {
		t.Errorf("reverseip = %s (%s), want done under --passive with no key", st, reason)
	}
	done := x.completedKeys("reverseip")
	// An address inside an in-scope netblock has its own key, since it keeps the names it hosts.
	if !slices.Equal(done, []string{"198.51.100.1|max=100|names", "203.0.113.250|max=100", "203.0.113.7|max=100"}) {
		t.Errorf("completed jobs = %v", done)
	}
}

// Adding SecurityTrails enables IPv6 jobs without repeating completed IPv4 work.
func TestReverseIP_IPv6WaitsForTheKey(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.hackerTarget()
	x.names("v6.example.com")
	x.host("v6.example.com", "2001:db8:1::5")
	x.mustPassive("--cidr", "2001:db8:1::/64")
	if got := sorted(x.htAsked()); !slices.Equal(got, []string{"203.0.113.250"}) {
		t.Errorf("without a key, asked %v, want only the IPv4 address", got)
	}
	if done := x.completedKeys("reverseip"); slices.ContainsFunc(done, func(k string) bool { return strings.HasPrefix(k, "2001:") }) {
		t.Errorf("an IPv6 address has a completed job without a key: %v", done)
	}
	if st, _ := stateOf(x.world, "reverseip"); st != "done" {
		t.Errorf("reverseip = %s, want done", st)
	}

	x.securityTrails(map[string][]string{"2001:db8:1::5": {"six.other.org"}})
	x.mustPassive("--cidr", "2001:db8:1::/64")
	if got := x.stAsked(); !slices.Contains(got, "2001:db8:1::5") {
		t.Errorf("after the key was added, SecurityTrails was asked %v, want the IPv6 address", got)
	}
	if got := x.htAsked(); len(got) != 1 {
		t.Errorf("HackerTarget was asked %v; the address it had answered is not asked again, and IPv6 never is", got)
	}
	if x.candidate("other.org") == nil {
		t.Errorf("the IPv6 address's name was not recorded: %s", x.file(eng, "candidates.csv"))
	}
}

// --- What is recorded ---

// Keep in-scope/excluded hostnames, turn external names into candidate roots and normalise
// wildcard names.
func TestReverseIP_RecordsNamesByScope(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	ht := x.hackerTarget()
	x.names("app.example.com")
	x.host("app.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	x.host("new.example.com", "203.0.113.8")
	x.host("wild.example.com", "203.0.113.9")
	ht.set("203.0.113.7", "new.example.com", "WWW.Other.Org.", "hidden.example.com", "*.wild.example.com", "blocked.banned.net", "app.example.com")
	ht.set("203.0.113.250", "No records found")

	x.mustPassive("-x", "hidden.example.com", "-x", "*.banned.net")

	if got := x.hostnameKeys(); !slices.Contains(got, "new.example.com") || !slices.Contains(got, "wild.example.com") {
		t.Errorf("hostnames = %v, want new.example.com and wild.example.com recorded", got)
	}
	if !slices.Contains(x.lines(eng, "subdomains.txt"), "new.example.com") {
		t.Errorf("subdomains.txt = %v", x.lines(eng, "subdomains.txt"))
	}
	if _, ok := x.obsAttrs(eng, "hostname")["www.other.org"]; ok {
		t.Error("www.other.org, outside every root, was recorded as a hostname")
	}
	if c := x.candidate("other.org"); c == nil || c["sources"] != "reverseip" {
		t.Errorf("other.org = %v, want a candidate root found by reverseip", c)
	}
	for _, r := range x.table(eng, "candidates.csv") {
		if strings.Contains(r["value"], "www.other.org") {
			t.Errorf("candidates.csv lists the hostname: %v", r)
		}
	}
	ex := x.table(eng, "excluded.csv")
	if find(ex, "value", "hidden.example.com") == nil || find(ex, "value", "blocked.banned.net") == nil {
		t.Errorf("excluded.csv = %v, want both excluded names", ex)
	}
	for _, a := range []string{"203.0.113.7|max=100", "203.0.113.250|max=100"} {
		if !slices.Contains(x.completedKeys("reverseip"), a) {
			t.Errorf("%s did not complete: %v", a, x.completedKeys("reverseip"))
		}
	}
}

// Each of HackerTarget's "nothing found" replies completes the job with
// nothing.
func TestReverseIP_NoRecordsCompletesWithNothing(t *testing.T) {
	t.Parallel()
	for _, body := range []string{"No records found", "no dns a records found for 203.0.113.250", "error check your search parameter", ""} {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			x := newWeb(t)
			ht := x.hackerTarget()
			ht.answerAll(func(rw http.ResponseWriter) { _, _ = rw.Write([]byte(body)) })
			x.mustPassive()
			if st, _ := stateOf(x.world, "reverseip"); st != "done" {
				t.Errorf("reverseip = %s, want done", st)
			}
			if got := x.completedKeys("reverseip"); !slices.Equal(got, []string{"203.0.113.250|max=100"}) {
				t.Errorf("completed = %v", got)
			}
			if n := len(x.candidates()); n != 0 {
				t.Errorf("%d candidates from an empty answer", n)
			}
		})
	}
}

// A reply that is not a list of names is an error, retried: it is never recorded
// as "no names".
func TestReverseIP_UnreadableReplyIsAFailedJob(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	ht := x.hackerTarget()
	ht.answerAll(func(rw http.ResponseWriter) { _, _ = rw.Write([]byte("<html>Service unavailable, try later</html>")) })
	if f := x.h.partial(x.passive(), true); f.msg != "1 jobs failed: reverseip 1" || !f.transient {
		t.Errorf("error = %+v, want one transient reverseip failure", f)
	}
	if done := x.completedKeys("reverseip"); len(done) != 0 {
		t.Errorf("an unreadable reply completed %v", done)
	}
	if st, _ := stateOf(x.world, "reverseip"); st != "failed" {
		t.Errorf("reverseip = %s, want failed", st)
	}
}

// --- The shared-hosting guard ---

// Enforce distinct registrable-domain caps inclusively and version jobs when caps change.
func TestReverseIP_SharedHostingGuard(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	ht := x.hackerTarget()
	x.names("app.example.com", "big.example.com")
	x.host("app.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	x.host("big.example.com", "203.0.113.8")
	x.owner("203.0.113.8", 64500, "ACME-NET")
	// 100 registrable domains, one of them with many names: at the default cap.
	atCap := append(manyDomains(99), "a.shared.net", "b.shared.net", "c.shared.net")
	ht.set("203.0.113.7", atCap...)
	// 101 registrable domains, and an in-scope name among them.
	ht.set("203.0.113.8", append(manyDomains(100), "intruder.example.com")...)

	x.mustPassive()

	if x.candidate("site000.org") == nil || x.candidate("shared.net") == nil {
		t.Errorf("100 domains is within the cap and must be recorded: %d candidates", len(x.candidates()))
	}
	if got := len(x.candidates()); got != 100 {
		t.Errorf("%d candidates, want the 100 of the first address and none of the second", got)
	}
	if slices.Contains(x.hostnameKeys(), "intruder.example.com") {
		t.Error("an in-scope name from an address over the cap was recorded")
	}
	warns := x.h.messages("warning", "203.0.113.8")
	if len(warns) != 1 || !strings.Contains(warns[0], "reverseip") || !strings.Contains(warns[0], "max_domains") {
		t.Errorf("want one warning naming the address and the setting, got %q", warns)
	}
	if got := x.h.messages("warning", "203.0.113.7"); len(got) != 0 {
		t.Errorf("an address within the cap was warned about: %q", got)
	}
	if st, _ := stateOf(x.world, "reverseip"); st != "done" {
		t.Errorf("reverseip = %s, want done: an address over the cap is a completed job", st)
	}
	if !slices.Contains(x.completedKeys("reverseip"), "203.0.113.8|max=100") {
		t.Errorf("completed = %v", x.completedKeys("reverseip"))
	}

	// A higher cap is a new job for every address.
	before := len(x.htAsked())
	x.mustPassive("--reverseip-max-domains", "101")
	if got := len(x.htAsked()) - before; got != 3 {
		t.Errorf("changing the cap asked %d addresses again, want all 3", got)
	}
	if x.candidate("site099.org") == nil {
		t.Errorf("with the cap at 101 the second address is recorded: %d candidates", len(x.candidates()))
	}
	if !slices.Contains(x.hostnameKeys(), "intruder.example.com") {
		t.Errorf("hostnames = %v, want intruder.example.com once the address is under the cap", x.hostnameKeys())
	}
}

// --- Quota and keys ---

// Both HTTP and text quota responses abort once, warn once and leave jobs pending.
func TestReverseIP_QuotaStopsTheProcedureAndIsRetried(t *testing.T) {
	t.Parallel()
	variants := map[string]func(rw http.ResponseWriter){
		"HTTP 429": func(rw http.ResponseWriter) { http.Error(rw, "slow down", http.StatusTooManyRequests) },
		"API count exceeded": func(rw http.ResponseWriter) {
			_, _ = rw.Write([]byte("API count exceeded - Increase Quota with Membership"))
		},
	}
	for name, spent := range variants {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			x := newWeb(t)
			ht := x.hackerTarget()
			x.names("app.example.com")
			x.host("app.example.com", "203.0.113.7")
			x.owner("203.0.113.7", 64500, "ACME-NET")
			ht.answerAll(spent)

			// A spent quota clears with time: the error is transient.
			if f := x.h.partial(x.passive("--concurrency", "1"), true); !f.transient || !strings.Contains(f.msg, "reverseip 2") {
				t.Errorf("error = %+v, want a transient failure naming reverseip 2", f)
			}
			if st, _ := stateOf(x.world, "reverseip"); st != "failed" {
				t.Errorf("state = %s, want failed", st)
			}
			if done := x.completedKeys("reverseip"); len(done) != 0 {
				t.Errorf("a spent quota was recorded as done: %v", done)
			}
			if n := len(x.htAsked()); n != 1 {
				t.Errorf("the procedure should stop after the first answer, saw %d lookups", n)
			}
			warns := x.h.messages("warning", "reverseip")
			if len(warns) != 1 || !strings.Contains(warns[0], "quota") || !strings.Contains(warns[0], "retried next run") {
				t.Errorf("want one quota warning naming reverseip, got %q", warns)
			}
			if st, _ := stateOf(x.world, "crtsh"); st != "done" {
				t.Errorf("other procedures must be unaffected: crtsh = %s", st)
			}

			ht.answerAll(nil)
			ht.set("203.0.113.7", "x.other.org")
			x.mustPassive("--concurrency", "1")
			if done := x.completedKeys("reverseip"); !slices.Equal(done, []string{"203.0.113.250|max=100", "203.0.113.7|max=100"}) {
				t.Errorf("the next run completed %v, want both addresses", done)
			}
			if x.candidate("other.org") == nil {
				t.Error("the retried job did not record its name")
			}
		})
	}
}

// Keyed lookups merge both sources and cover IPv6 without exposing credentials.
func TestReverseIP_SecurityTrailsKey(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	ht := x.hackerTarget()
	x.names("app.example.com", "v6.example.com")
	x.host("app.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	x.host("v6.example.com", "2001:db8:1::5")
	ht.set("203.0.113.7", "both.other.org", "ht.other.net")
	x.securityTrails(map[string][]string{
		"203.0.113.7":   {"both.other.org", "st.other.com", "app.example.com"},
		"2001:db8:1::5": {"six.other.io"},
	})

	x.mustPassive("--cidr", "2001:db8:1::/64")

	if got := sorted(x.htAsked()); !slices.Equal(got, []string{"203.0.113.250", "203.0.113.7"}) {
		t.Errorf("HackerTarget asked %v; it cannot answer IPv6", got)
	}
	if got := sorted(x.stAsked()); !slices.Equal(got, []string{"2001:db8:1::5", "203.0.113.250", "203.0.113.7"}) {
		t.Errorf("SecurityTrails asked %v, want every address, IPv6 included", got)
	}
	for _, root := range []string{"other.org", "other.net", "other.com", "other.io"} {
		if x.candidate(root) == nil {
			t.Errorf("%s is not a candidate: %s", root, x.file(eng, "candidates.csv"))
		}
	}
	// One name from both sources is one pair for its root.
	if c := x.candidate("other.org"); c == nil || c["evidence_count"] != "1" {
		t.Errorf("other.org = %v, want one pair of source and address", c)
	}
	if hits := x.anywhere(eng, securityTrailsKey); len(hits) != 0 {
		t.Errorf("the SecurityTrails key appears in %v", hits)
	}
	if st, _ := stateOf(x.world, "reverseip"); st != "done" {
		t.Errorf("reverseip = %s", st)
	}
}

// A rejected SecurityTrails key stops the procedure, HackerTarget lookups included:
// the jobs that remain are not sent, and nothing is completed.
func TestReverseIP_RejectedSecurityTrailsKeyStopsTheProcedure(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	x.hackerTarget()
	x.names("app.example.com")
	x.host("app.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	f := x.securityTrails(nil)
	f.status = 401

	// A refused key is not cured by waiting: the error is not transient.
	if f := x.h.partial(x.passive("--concurrency", "1"), true); f.transient || !strings.Contains(f.msg, "reverseip 2") {
		t.Errorf("error = %+v, want a failure of reverseip 2 that is not transient", f)
	}

	if st, _ := stateOf(x.world, "reverseip"); st != "failed" {
		t.Errorf("reverseip = %s, want failed", st)
	}
	if done := x.completedKeys("reverseip"); len(done) != 0 {
		t.Errorf("completed %v after a rejected key", done)
	}
	if n := len(x.htAsked()); n > 1 {
		t.Errorf("%d HackerTarget lookups: the procedure should stop after the first address", n)
	}
}

// --- Candidates and refresh ---

// Two reverse-IP addresses give medium confidence without duplicate evidence after cap changes
// or candidate contact.
func TestReverseIP_RootOnTwoAddressesIsMedium(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	ht := x.hackerTarget()
	x.names("a.example.com", "b.example.com")
	x.host("a.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	x.host("b.example.com", "203.0.113.8")
	x.owner("203.0.113.8", 64500, "ACME-NET")
	ht.set("203.0.113.7", "www.twice.org", "www.once.org")
	ht.set("203.0.113.8", "mail.twice.org")

	x.mustPassive()

	twice, once := x.candidate("twice.org"), x.candidate("once.org")
	if twice == nil || twice["confidence"] != "medium" || twice["sources"] != "reverseip" || twice["evidence_count"] != "2" {
		t.Errorf("twice.org = %v, want medium, from reverseip, with two pairs", twice)
	}
	if once == nil || once["confidence"] != "low" || once["evidence_count"] != "1" {
		t.Errorf("once.org = %v, want low with one pair", once)
	}

	// Asking again under a new cap is a new key but the same evidence.
	x.mustPassive("--reverseip-max-domains", "50")
	if twice = x.candidate("twice.org"); twice == nil || twice["evidence_count"] != "2" || twice["confidence"] != "medium" {
		t.Errorf("after the cap changed, twice.org = %v, want still two pairs", twice)
	}

	// No candidate root is resolved or contacted.
	for _, qtype := range []string{"A", "AAAA", "NS", "SOA", "TXT", "MX", "CAA"} {
		for _, n := range x.dns.Queried(qtype) {
			if strings.HasSuffix(n, "twice.org") || strings.HasSuffix(n, "once.org") {
				t.Errorf("candidate %s was resolved (%s)", n, qtype)
			}
		}
	}
	if n := x.h.network(); n != 0 {
		t.Errorf("%d requests reached the canaries", n)
	}
}

// Each address is asked once per engagement; --redo reverseip asks again.
func TestReverseIP_OncePerEngagementUntilRedo(t *testing.T) {
	t.Parallel()
	x := newWeb(t)
	ht := x.hackerTarget()
	x.names("a.example.com")
	x.host("a.example.com", "203.0.113.7")
	x.owner("203.0.113.7", 64500, "ACME-NET")
	ht.set("203.0.113.7", "www.first.org")

	x.mustPassive()
	if n := len(x.htAsked()); n != 2 {
		t.Fatalf("first run asked %d addresses, want 2", n)
	}
	x.mustPassive()
	if n := len(x.htAsked()); n != 2 {
		t.Errorf("a re-run asked again: %d lookups in all", n)
	}
	ht.set("203.0.113.7", "www.first.org", "www.second.org")
	x.mustPassive()
	if x.candidate("second.org") != nil {
		t.Error("new results arrived without --redo reverseip")
	}
	x.mustPassive("--redo", "reverseip")
	if n := len(x.htAsked()); n != 4 {
		t.Errorf("--redo reverseip asked %d lookups in all, want 4", n)
	}
	if x.candidate("second.org") == nil {
		t.Errorf("--redo reverseip did not bring the new result: %s", x.file(eng, "candidates.csv"))
	}
}

// --- Registry, help and docs ---

// The registry order is pinned by TestRiskProcedureRegistry.
func TestReverseIP_HelpAndSetting(t *testing.T) {
	t.Parallel()
	h := newHarness(t, defaultProcedureList()...)
	if code := h.exec("--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.stdout.String(), "--reverseip-max-domains") {
		t.Error("help missing --reverseip-max-domains")
	}
	if procedureRow(h.proceduresHelp(), "reverseip") == "" {
		t.Error("help procedures does not list reverseip")
	}
}

func TestReverseIP_DocsSayWhatItDoes(t *testing.T) {
	t.Parallel()
	boundary, docs := docsSection(t, "## Passive boundary")
	for _, want := range []string{
		"reverseip", "--redo reverseip", "reverseip.max_domains", "--reverseip-max-domains", "HackerTarget",
		"reverse IP", "shared hosting",
	} {
		if !strings.Contains(docs, want) {
			t.Errorf("the docs do not mention %q", want)
		}
	}
	// The sentence that lists the reserved names no longer names reverseip.
	if i := strings.Index(docs, "are reserved for procedures that are not built yet"); i >= 0 {
		if sentence := docs[strings.LastIndex(docs[:i], "The names"):i]; strings.Contains(sentence, "`reverseip`") {
			t.Errorf("the docs still list reverseip among the reserved names: %q", sentence)
		}
	}
	// The passive-boundary section names HackerTarget's reverse IP lookup.
	if !strings.Contains(boundary, "reverse") {
		t.Error("the passive-boundary section does not name the reverse IP lookups")
	}
}
