package iplookup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
)

// fakeHTTP answers each request with the reply registered for its URL (404 for any other), and
// records every URL asked.
type fakeHTTP struct {
	mu      sync.Mutex
	replies map[string]fakeReply
	asked   []string
}

type fakeReply struct {
	status    int
	body      string
	header    map[string][]string
	truncated bool
	err       error
	hang      bool // wait for the context
	delay     time.Duration
}

func (f *fakeHTTP) Do(ctx context.Context, r egress.ThirdPartyRequest) (egress.ThirdPartyResponse, error) {
	f.mu.Lock()
	f.asked = append(f.asked, r.URL)
	rep, ok := f.replies[r.URL]
	f.mu.Unlock()
	if !ok {
		return egress.ThirdPartyResponse{Status: 404, Body: []byte(`{"detail":"No information available"}`)}, nil
	}
	if rep.delay > 0 {
		select {
		case <-time.After(rep.delay):
		case <-ctx.Done():
			return egress.ThirdPartyResponse{}, ctx.Err()
		}
	}
	if rep.hang {
		<-ctx.Done()
		return egress.ThirdPartyResponse{}, ctx.Err()
	}
	if rep.err != nil {
		return egress.ThirdPartyResponse{}, rep.err
	}
	return egress.ThirdPartyResponse{Status: rep.status, Body: []byte(rep.body), Header: rep.header, Truncated: rep.truncated}, nil
}

func (f *fakeHTTP) on(u string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[u] = fakeReply{status: status, body: body}
}

func (f *fakeHTTP) set(u string, rep fakeReply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replies[u] = rep
}

// count is how many requests were made for URLs with the prefix.
func (f *fakeHTTP) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.asked {
		if strings.HasPrefix(a, prefix) {
			n++
		}
	}
	return n
}

func (f *fakeHTTP) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

// fakeDNS answers a query by name and type, NXDOMAIN when nothing is set.
type fakeDNS struct {
	mu      sync.Mutex
	results map[string]egress.DNSResult
	errs    map[string]error
	hang    map[string]bool
	asked   []string
	delay   time.Duration
	inside  atomic.Int32
	peak    atomic.Int32
}

func dnsKey(name string, qtype uint16) string { return fmt.Sprintf("%s/%d", name, qtype) }

func (f *fakeDNS) Query(ctx context.Context, name string, qtype uint16) (egress.DNSResult, error) {
	key := dnsKey(name, qtype)
	f.mu.Lock()
	f.asked = append(f.asked, key)
	res, hasRes := f.results[key]
	err := f.errs[key]
	hang := f.hang[key]
	f.mu.Unlock()
	n := f.inside.Add(1)
	defer f.inside.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return egress.DNSResult{}, ctx.Err()
		}
	}
	if hang {
		<-ctx.Done()
		return egress.DNSResult{}, ctx.Err()
	}
	if err != nil {
		return egress.DNSResult{}, err
	}
	if hasRes {
		return res, nil
	}
	return egress.DNSResult{RCode: egress.RCodeNXDomain}, nil
}

func (f *fakeDNS) set(name string, qtype uint16, res egress.DNSResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[dnsKey(name, qtype)] = res
}

func (f *fakeDNS) setErr(name string, qtype uint16, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[dnsKey(name, qtype)] = err
}

func (f *fakeDNS) setHang(name string, qtype uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hang[dnsKey(name, qtype)] = true
}

func (f *fakeDNS) queries() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

func (f *fakeDNS) queried(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, q := range f.asked {
		if strings.HasPrefix(q, name+"/") {
			n++
		}
	}
	return n
}

func txtAnswer(v string) egress.DNSResult {
	return egress.DNSResult{RCode: egress.RCodeSuccess, Answers: []egress.Answer{{Type: "TXT", Value: v}}}
}

func addrAnswer(addrs ...string) egress.DNSResult {
	r := egress.DNSResult{RCode: egress.RCodeSuccess}
	for _, a := range addrs {
		typ := "A"
		if strings.Contains(a, ":") {
			typ = "AAAA"
		}
		r.Answers = append(r.Answers, egress.Answer{Type: typ, Value: a})
	}
	return r
}

func ptrAnswer(names ...string) egress.DNSResult {
	r := egress.DNSResult{RCode: egress.RCodeSuccess}
	for _, n := range names {
		r.Answers = append(r.Answers, egress.Answer{Type: "PTR", Value: n})
	}
	return r
}

// fakeLocal is this machine's resolver.
type fakeLocal struct {
	mu       sync.Mutex
	names    map[string][]netip.Addr
	ptrs     map[string][]string
	errs     map[string]error
	askedFor []string
}

func (f *fakeLocal) Addrs(_ context.Context, name string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.askedFor = append(f.askedFor, "addrs:"+name)
	if err := f.errs["addrs:"+name]; err != nil {
		return nil, err
	}
	return f.names[name], nil
}

func (f *fakeLocal) PTR(_ context.Context, a netip.Addr) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.askedFor = append(f.askedFor, "ptr:"+a.String())
	if err := f.errs["ptr:"+a.String()]; err != nil {
		return nil, err
	}
	return f.ptrs[a.String()], nil
}

func (f *fakeLocal) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.askedFor)
}

// world is the fakes a lookup runs against.
type world struct {
	t     *testing.T
	http  *fakeHTTP
	dns   *fakeDNS
	local *fakeLocal
	mu    sync.Mutex
	warns []string
	cfg   Config
}

// fieldsFor is the selection for a --fields value; "all" is every key.
func fieldsFor(t *testing.T, active bool, spec string) Fields {
	t.Helper()
	if spec == "all" {
		return AllFields(active)
	}
	f, unknown, activeOnly := Select(spec, active)
	if unknown != nil || activeOnly != nil {
		t.Fatalf("Select(%q): unknown %v, active-only %v", spec, unknown, activeOnly)
	}
	return f
}

func newWorld(t *testing.T, active bool, spec string) *world {
	t.Helper()
	w := &world{
		t:     t,
		http:  &fakeHTTP{replies: map[string]fakeReply{}},
		dns:   &fakeDNS{results: map[string]egress.DNSResult{}, errs: map[string]error{}, hang: map[string]bool{}},
		local: &fakeLocal{names: map[string][]netip.Addr{}, ptrs: map[string][]string{}, errs: map[string]error{}},
	}
	w.cfg = Config{
		Fields:     fieldsFor(t, active, spec),
		ThirdParty: w.http, DNS: w.dns, Local: w.local,
		Warn: func(s string) {
			w.mu.Lock()
			defer w.mu.Unlock()
			w.warns = append(w.warns, s)
		},
	}
	return w
}

func (w *world) warnings() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.warns)
}

func (w *world) ctx() context.Context {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	w.t.Cleanup(cancel)
	return ctx
}

// lookup looks up the addresses, each found as a literal.
func (w *world) lookup(addrs ...string) []AddressResult {
	w.t.Helper()
	return w.lookupCtx(w.ctx(), addrs...)
}

func (w *world) lookupCtx(ctx context.Context, addrs ...string) []AddressResult {
	w.t.Helper()
	var r Resolved
	for _, a := range addrs {
		r.Addresses = append(r.Addresses, Address{Addr: netip.MustParseAddr(a), Hostnames: []string{}, Found: FoundLiteral})
	}
	return Lookup(ctx, w.cfg, r)
}

// The addresses of the tests are public, and each source's answer for one is made here.
const (
	pubAddr = "8.8.4.4"
	pub6    = "2001:4860:4860::8844"
)

func originName(a string) string { return dnsname.CymruOrigin(netip.MustParseAddr(a)) }

func ptrName(a string) string { return dnsname.ReverseName(netip.MustParseAddr(a)) }

func ripestatURL(a string) string {
	return "https://stat.ripe.net/data/maxmind-geo-lite/data.json?" + url.Values{"resource": {a}, "sourceapp": {"nyx"}}.Encode()
}

func internetDBURL(a string) string { return "https://internetdb.shodan.io/" + a }

func hackerTargetURL(a string) string {
	return "https://api.hackertarget.com/reverseiplookup/?" + url.Values{"q": {a}}.Encode()
}

const (
	bootstrapURL4 = "https://data.iana.org/rdap/ipv4.json"
	bootstrapURL6 = "https://data.iana.org/rdap/ipv6.json"
	arinBase      = "https://rdap.arin.net/registry/"
	ripeBase      = "https://rdap.db.ripe.net/"
)

// bootstrapFile maps 8.0.0.0/8 to ARIN and 9.0.0.0/8 to RIPE.
const bootstrapFile = `{"services":[
 [["8.0.0.0/8"],["https://rdap.arin.net/registry/"]],
 [["9.0.0.0/8"],["https://rdap.db.ripe.net/"]]]}`

func rdapAnswer(start, end, org string) string {
	return fmt.Sprintf(`{"handle":"NET-%s","startAddress":%q,"endAddress":%q,"entities":[
 {"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text",%q]]]}]}`, start, start, end, org)
}

// ownedBy makes Team Cymru answer that the address is announced by asn, held by name.
func (w *world) ownedBy(a string, asn int, prefix, name string) {
	w.dns.set(originName(a), egress.TypeTXT, txtAnswer(fmt.Sprintf("%d | %s | US | arin | 2000-03-30", asn, prefix)))
	w.dns.set(fmt.Sprintf("AS%d.asn.cymru.com", asn), egress.TypeTXT, txtAnswer(fmt.Sprintf("%d | US | arin | 2000-03-30 | %s, US", asn, name)))
}

// bootstrapped makes the RDAP bootstrap answer for both families.
func (w *world) bootstrapped() {
	w.http.on(bootstrapURL4, 200, bootstrapFile)
	w.http.on(bootstrapURL6, 200, `{"services":[]}`)
}

// populate makes every source answer for the public address a (an address of 8.8.4.0/24).
func (w *world) populate(a string) {
	w.ownedBy(a, 15169, "8.8.4.0/24", "GOOGLE")
	w.dns.set(ptrName(a), egress.TypePTR, ptrAnswer("dns.google.", "Dns.Google"))
	w.http.on(bootstrapURL4, 200, bootstrapFile)
	w.http.on(arinBase+"ip/"+a, 200, rdapAnswer("8.8.4.0", "8.8.4.255", "Google LLC"))
	w.http.on(ripestatURL(a), 200, `{"status":"ok","data":{"located_resources":[{"locations":[
 {"country":"?","city":"","resources":["8.8.4.0/24"],"covered_percentage":10.0},
 {"country":"US","city":"Mountain View","resources":["8.8.4.0/24"],"covered_percentage":90.0}]}]}}`)
	w.http.on(internetDBURL(a), 200, `{"cpes":["cpe:/a:b","cpe:/a:a"],"hostnames":["z.example","a.example"],"ip":"`+a+`","ports":[443,53,53],"tags":["cloud","self-signed"],"vulns":["CVE-2020-2","CVE-2020-1"]}`)
	w.http.on(hackerTargetURL(a), 200, "b.example.com\na.example.com\nA.example.com\n")
}

func deref(p *string) string {
	if p == nil {
		return "<null>"
	}
	return *p
}

// failureOf is the failure of the source in the record, and whether there is one.
func failureOf(r Record, s Source) (Failure, bool) {
	for _, f := range r.Failures {
		if f.Source == s {
			return f, true
		}
	}
	return Failure{}, false
}

func only(t *testing.T, rs []AddressResult) AddressResult {
	t.Helper()
	if len(rs) != 1 {
		t.Fatalf("got %d results, want 1", len(rs))
	}
	return rs[0]
}

// Lookup gives one result per address in the order of the addresses, whole.
func TestLookup_ResultsFollowTheAddresses(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "asn")
	var addrs []string
	for i := 1; i <= 40; i++ {
		a := fmt.Sprintf("8.8.4.%d", i)
		addrs = append(addrs, a)
		w.ownedBy(a, 15169+i, "8.8.4.0/24", "GOOGLE")
	}
	res := w.lookup(addrs...)
	if len(res) != len(addrs) {
		t.Fatalf("%d results for %d addresses", len(res), len(addrs))
	}
	for i, r := range res {
		if r.Record.Address != addrs[i] || r.Record.ASN == nil || *r.Record.ASN != uint32(15169+i+1) {
			t.Errorf("result %d = %s AS %v, want %s AS%d", i, r.Record.Address, r.Record.ASN, addrs[i], 15169+i+1)
		}
	}
}

// Addresses are looked up 32 at a time, and 16 at a time under --active.
func TestLookup_AddressesAtATime(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		active bool
		want   int32
	}{{false, 32}, {true, 16}} {
		t.Run(fmt.Sprintf("active=%v", tc.active), func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, tc.active, "asn")
			w.dns.delay = 30 * time.Millisecond
			var addrs []string
			for i := 1; i <= 100; i++ {
				addrs = append(addrs, fmt.Sprintf("8.8.4.%d", i))
			}
			w.lookup(addrs...)
			if got := w.dns.peak.Load(); got != tc.want {
				t.Errorf("most addresses in flight = %d, want %d", got, tc.want)
			}
		})
	}
}

// A cancelled call returns promptly and leaves nothing running.
func TestLookup_CancelReturnsPromptly(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	var addrs []string
	for i := 1; i <= 50; i++ {
		a := fmt.Sprintf("8.8.4.%d", i)
		addrs = append(addrs, a)
		w.dns.setHang(originName(a), egress.TypeTXT)
		w.http.set(internetDBURL(a), fakeReply{hang: true})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		w.lookupCtx(ctx, addrs...)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Lookup did not return after the context was cancelled")
	}
	if w.dns.inside.Load() != 0 {
		t.Error("a query was still running after Lookup returned")
	}
}

// The deadline is a failure of each source that had not answered, never a missing record.
func TestLookup_DeadlineIsATimeoutFailure(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	w.dns.setHang(originName(pubAddr), egress.TypeTXT)
	w.dns.setHang(ptrName(pubAddr), egress.TypePTR)
	w.http.set(bootstrapURL4, fakeReply{hang: true})
	w.http.set(ripestatURL(pubAddr), fakeReply{hang: true})
	w.http.set(internetDBURL(pubAddr), fakeReply{hang: true})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	r := only(t, w.lookupCtx(ctx, pubAddr))
	for _, s := range []Source{SourceCymru, SourceRDAP, SourcePTR, SourceRIPEstat, SourceInternetDB} {
		f, ok := failureOf(r.Record, s)
		if !ok || f.Code != clierr.Timeout || !f.Transient || f.Quota {
			t.Errorf("%s failure = %+v (present %v), want transient TIMEOUT", s, f, ok)
		}
	}
	// HackerTarget needs the owner, which timed out, so it was not asked.
	if _, ok := failureOf(r.Record, SourceHackerTarget); ok {
		t.Error("hackertarget has a failure although the owner never answered")
	}
	if w.http.count("https://api.hackertarget.com") != 0 {
		t.Error("hackertarget was asked without the owner")
	}
}

func TestResolve_Hostnames(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	w.dns.set("two.example.com", egress.TypeA, addrAnswer("8.8.4.2", "8.8.4.1"))
	w.dns.set("two.example.com", egress.TypeAAAA, addrAnswer("2001:4860::2"))
	w.dns.set("only6.example.com", egress.TypeAAAA, addrAnswer("2001:4860::6"))
	w.dns.set("empty.example.com", egress.TypeA, egress.DNSResult{RCode: egress.RCodeSuccess})
	w.dns.set("empty.example.com", egress.TypeAAAA, egress.DNSResult{RCode: egress.RCodeSuccess})
	plan := ParseInputs([]string{"two.example.com", "only6.example.com", "gone.example.com", "empty.example.com", "8.8.4.9", "bad input", "8.8.4.8/31"}, false)
	r, err := Resolve(w.ctx(), w.cfg, plan)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got, want := strings.Join(list(r.Addresses), " "), "8.8.4.1 8.8.4.2 2001:4860::2 2001:4860::6 8.8.4.9 8.8.4.8"; got != want {
		t.Errorf("addresses = %s, want %s", got, want)
	}
	if len(r.Inputs) != len(plan.Inputs) {
		t.Fatalf("%d input results for %d inputs", len(r.Inputs), len(plan.Inputs))
	}
	wantAddrs := [][]string{{"8.8.4.1", "8.8.4.2", "2001:4860::2"}, {"2001:4860::6"}, nil, nil, {"8.8.4.9"}, nil, {"8.8.4.8", "8.8.4.9"}}
	wantCodes := []clierr.Code{"", "", clierr.NotFound, clierr.NotFound, "", clierr.InvalidInput, ""}
	for i, in := range r.Inputs {
		if in.Input != plan.Inputs[i].Raw {
			t.Errorf("input %d = %q, want %q", i, in.Input, plan.Inputs[i].Raw)
		}
		var code clierr.Code
		if in.Err != nil {
			code = in.Err.Code
		}
		if code != wantCodes[i] || !slices.Equal(in.Addresses, wantAddrs[i]) {
			t.Errorf("input %q: code %q addresses %v, want %q %v", in.Input, code, in.Addresses, wantCodes[i], wantAddrs[i])
		}
	}
	if e := r.Inputs[2].Err; e == nil || e.Transient || e.Hint == "" {
		t.Errorf("NXDOMAIN error = %+v, want a non-transient NOT_FOUND with a hint", e)
	}
	// Hostnames are looked up for A and AAAA, and the recorded address knows how it was found.
	for _, a := range r.Addresses {
		if a.Addr.String() == "8.8.4.1" && (a.Found != FoundPublicDNS || !slices.Equal(a.Hostnames, []string{"two.example.com"})) {
			t.Errorf("8.8.4.1 = %+v", a)
		}
	}
	if w.local.asked() != nil {
		t.Errorf("without --active the local resolver was asked: %v", w.local.asked())
	}
}

func TestResolve_ResolverFailures(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		set   func(w *world)
		ctxTO bool
		code  clierr.Code
	}{
		{"servfail", func(w *world) {
			w.dns.set("a.example.com", egress.TypeA, egress.DNSResult{RCode: egress.RCodeServFail})
			w.dns.set("a.example.com", egress.TypeAAAA, egress.DNSResult{RCode: egress.RCodeServFail})
		}, false, clierr.NetworkError},
		{"no response", func(w *world) {
			w.dns.setErr("a.example.com", egress.TypeA, errors.New("no response from any resolver"))
			w.dns.setErr("a.example.com", egress.TypeAAAA, errors.New("no response from any resolver"))
		}, false, clierr.NetworkError},
		{"deadline", func(w *world) {
			w.dns.setHang("a.example.com", egress.TypeA)
			w.dns.setHang("a.example.com", egress.TypeAAAA)
		}, true, clierr.Timeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, true, "all")
			tc.set(w)
			ctx := w.ctx()
			if tc.ctxTO {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			r, err := Resolve(ctx, w.cfg, ParseInputs([]string{"a.example.com"}, true))
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			e := r.Inputs[0].Err
			if e == nil || e.Code != tc.code || !e.Transient || len(r.Addresses) != 0 {
				t.Errorf("error = %+v, addresses %v; want transient %s and none", e, r.Addresses, tc.code)
			}
			if got := w.local.asked(); got != nil {
				t.Errorf("a resolver failure was retried through the local resolver: %v", got)
			}
		})
	}
}

func TestResolve_OneAnswerIsEnough(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	w.dns.set("a.example.com", egress.TypeA, addrAnswer("8.8.4.1"))
	w.dns.set("a.example.com", egress.TypeAAAA, egress.DNSResult{RCode: egress.RCodeServFail})
	r, err := Resolve(w.ctx(), w.cfg, ParseInputs([]string{"a.example.com"}, false))
	if err != nil || r.Inputs[0].Err != nil || !slices.Equal(r.Inputs[0].Addresses, []string{"8.8.4.1"}) {
		t.Errorf("Resolve = %+v, %v; want the IPv4 address", r.Inputs, err)
	}
}

func localWorld(t *testing.T, active bool) (*world, Resolved) {
	t.Helper()
	w := newWorld(t, active, "all")
	w.local.names["corp.example.com"] = addrs("10.1.2.3", "10.1.2.2")
	w.dns.set("both.example.com", egress.TypeA, addrAnswer("8.8.4.1"))
	r, err := Resolve(w.ctx(), w.cfg, ParseInputs([]string{"corp.example.com", "both.example.com"}, active))
	if err != nil {
		t.Fatal(err)
	}
	return w, r
}

func TestResolve_WithoutActiveNothingIsRetriedLocally(t *testing.T) {
	t.Parallel()
	w, r := localWorld(t, false)
	if e := r.Inputs[0].Err; e == nil || e.Code != clierr.NotFound {
		t.Errorf("without --active the name resolved: %+v", r.Inputs[0])
	}
	if w.local.asked() != nil {
		t.Errorf("the local resolver was asked: %v", w.local.asked())
	}
}

func TestResolve_ActiveRetriesAnUnknownNameLocally(t *testing.T) {
	t.Parallel()
	w, r := localWorld(t, true)
	if r.Inputs[0].Err != nil || !slices.Equal(r.Inputs[0].Addresses, []string{"10.1.2.2", "10.1.2.3"}) {
		t.Errorf("corp.example.com = %+v", r.Inputs[0])
	}
	for _, a := range r.Addresses {
		want := FoundLocalDNS
		if a.Addr.String() == "8.8.4.1" {
			want = FoundPublicDNS
		}
		if a.Found != want {
			t.Errorf("%s found as %d, want %d", a.Addr, a.Found, want)
		}
	}
	if got := w.local.asked(); !slices.Equal(got, []string{"addrs:corp.example.com"}) {
		t.Errorf("local asked %v, want only the name the public resolvers did not know", got)
	}
}

func TestResolve_SingleLabelNamesAreNeverSentPublicly(t *testing.T) {
	t.Parallel()
	w := newWorld(t, true, "all")
	w.local.names["intranet"] = addrs("10.0.0.5")
	r, err := Resolve(w.ctx(), w.cfg, ParseInputs([]string{"intranet", "ghost"}, true))
	if err != nil {
		t.Fatal(err)
	}
	if r.Inputs[0].Err != nil || !slices.Equal(r.Inputs[0].Addresses, []string{"10.0.0.5"}) || r.Addresses[0].Found != FoundLocalDNS {
		t.Errorf("intranet = %+v, %+v", r.Inputs[0], r.Addresses)
	}
	if e := r.Inputs[1].Err; e == nil || e.Code != clierr.NotFound {
		t.Errorf("ghost = %+v, want NOT_FOUND", r.Inputs[1])
	}
	if q := w.dns.queries(); len(q) != 0 {
		t.Errorf("a single-label name reached the public resolvers: %v", q)
	}
}

func TestResolve_LocalFailures(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
		code clierr.Code
	}{
		{"timeout", fmt.Errorf("%w: slow", egress.ErrLocalTimeout), clierr.Timeout},
		{"other", errors.New("server misbehaving"), clierr.NetworkError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, true, "all")
			w.local.errs["addrs:intranet"] = tc.err
			r, err := Resolve(w.ctx(), w.cfg, ParseInputs([]string{"intranet"}, true))
			if err != nil {
				t.Fatal(err)
			}
			if e := r.Inputs[0].Err; e == nil || e.Code != tc.code || !e.Transient {
				t.Errorf("error = %+v, want transient %s", e, tc.code)
			}
		})
	}
}

func TestResolve_CapErrors(t *testing.T) {
	t.Parallel()
	t.Run("literals alone send nothing", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, false, "all")
		_, err := Resolve(w.ctx(), w.cfg, ParseInputs([]string{"8.8.0.0/23", "a.example.com"}, false))
		var ce *clierr.Error
		if !errors.As(err, &ce) || ce.Code != clierr.InvalidInput {
			t.Fatalf("error = %v, want INVALID_INPUT", err)
		}
		if n := len(w.dns.queries()); n != 0 {
			t.Errorf("%d queries were sent before the cap was checked", n)
		}
	})
	t.Run("hostnames pass it", func(t *testing.T) {
		t.Parallel()
		w := newWorld(t, false, "all")
		var as []string
		for i := range 300 {
			as = append(as, fmt.Sprintf("8.%d.%d.1", i/200, i%200))
		}
		w.dns.set("big.example.com", egress.TypeA, addrAnswer(as...))
		_, err := Resolve(w.ctx(), w.cfg, ParseInputs([]string{"big.example.com"}, false))
		var ce *clierr.Error
		if !errors.As(err, &ce) || ce.Code != clierr.InvalidInput {
			t.Fatalf("error = %v, want INVALID_INPUT", err)
		}
		if w.http.total() != 0 {
			t.Error("a third party was asked")
		}
	})
}

func TestResolve_LiteralsAndCIDRsGiveTheirAddresses(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	r, err := Resolve(w.ctx(), w.cfg, ParseInputs([]string{"::ffff:1.2.3.4", "8.8.4.4/30", "2001:db8::1"}, false))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Inputs[1].Addresses) != 4 || r.Inputs[0].Addresses[0] != "1.2.3.4" || r.Inputs[2].Addresses[0] != "2001:db8::1" {
		t.Errorf("inputs = %+v", r.Inputs)
	}
	if len(r.Addresses) != 6 || len(w.dns.queries()) != 0 {
		t.Errorf("addresses %d, queries %v", len(r.Addresses), w.dns.queries())
	}
}

func TestResolve_CancelIsTheContextsError(t *testing.T) {
	t.Parallel()
	w := newWorld(t, false, "all")
	w.dns.setHang("a.example.com", egress.TypeA)
	w.dns.setHang("a.example.com", egress.TypeAAAA)
	ctx, cancel := context.WithCancel(w.ctx())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err := Resolve(ctx, w.cfg, ParseInputs([]string{"a.example.com"}, false))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want the cancellation", err)
	}
}

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
