package iplookup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/ipsource"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/spamhaus"
)

// The hosts of the sources that have one request per address.
const (
	hostInternetDB = "internetdb.shodan.io"
	hostRIPEstat   = "stat.ripe.net"
)

// SourceHosts are the third-party hosts the lookup may ask: Config.ThirdParty must be built for each.
func SourceHosts() []string {
	return append([]string{hostInternetDB, hostRIPEstat, ipsource.HackerTargetHost}, ipsource.RDAPHosts()...)
}

// SourceRates is the pace, in requests a second, of each source host whose pace is not egress's
// default.
func SourceRates() map[string]float64 {
	return map[string]float64{hostInternetDB: 1, ipsource.HackerTargetHost: 1, hostRIPEstat: 4}
}

// maxReverseIP is how many reverse-IP names a record holds.
const maxReverseIP = 100

// latchedMessage is the failure of an address a latched source was not asked for.
const latchedMessage = "not asked: rate-limited earlier in this call"

// latchedError is a request the guard did not send because its host refused earlier in the call.
type latchedError struct{}

func (e *latchedError) Error() string { return latchedMessage }

// transportError is a request that got no response, as opposed to one the source answered badly.
type transportError struct{ err error }

func (e *transportError) Error() string { return e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

// hostState is what the guard knows of one host.
type hostState struct {
	gate    chan struct{} // holds one token: the request in flight to a host that goes one at a time
	latched atomic.Bool
	proven  atomic.Bool // a request has been answered; only matters to a host that is gated until then
}

// guard stands between the sources and egress. It latches a host that answers 429, so the
// addresses that have not asked it yet do not, and it holds back a request until the one before
// it to the same host has been answered (or has taken a second), where the host paces itself at a request a second anyway
// (InternetDB, the registries) or where one answer is wanted before the rest are sent (RIPEstat).
// The latch is checked after the wait, so an address already queued behind a refusal is not sent.
type guard struct {
	inner egress.ThirdPartyHTTP
	warn  func(string)
	mu    sync.Mutex
	hosts map[string]*hostState
}

func newGuard(inner egress.ThirdPartyHTTP, warn func(string)) *guard {
	return &guard{inner: inner, warn: warn, hosts: map[string]*hostState{}}
}

func (g *guard) state(host string) *hostState {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.hosts[host]
	if st == nil {
		st = &hostState{gate: make(chan struct{}, 1)}
		g.hosts[host] = st
	}
	return st
}

func (g *guard) isLatched(host string) bool { return g.state(host).latched.Load() }

// latch stops asking the host for the rest of the call, and warns once.
func (g *guard) latch(host string) {
	if !g.state(host).latched.CompareAndSwap(false, true) {
		return
	}
	switch host {
	case ipsource.HackerTargetHost:
		g.warn("HackerTarget quota is spent (the quota resets daily): reverse IP is not asked again in this call")
	case hostInternetDB:
		g.warn(hostInternetDB + " refused with HTTP 429: InternetDB is not asked again in this call")
	case hostRIPEstat:
		g.warn(hostRIPEstat + " (RIPEstat) refused with HTTP 429: geolocation is not asked again in this call")
	default:
		g.warn("rdap: " + host + " refused with HTTP 429: it is not asked again in this call")
	}
}

// gateHold is the longest a request holds back the ones behind it to the same host.
const gateHold = time.Second

// serialHost reports whether requests to the host go one at a time.
func serialHost(host string) bool {
	_, registry := ipsource.RegistryByHost(host)
	return registry || host == hostInternetDB || host == ipsource.BootstrapHost
}

// Do sends the request unless its host is latched. A 429 latches the host.
func (g *guard) Do(ctx context.Context, r egress.ThirdPartyRequest) (egress.ThirdPartyResponse, error) {
	host := ""
	if u, err := url.Parse(r.URL); err == nil {
		host = strings.ToLower(u.Hostname())
	}
	st := g.state(host)
	if st.latched.Load() {
		return egress.ThirdPartyResponse{}, &latchedError{}
	}
	if serialHost(host) || host == hostRIPEstat && !st.proven.Load() {
		var once sync.Once
		release := func() { once.Do(func() { <-st.gate }) }
		select {
		case st.gate <- struct{}{}:
		case <-ctx.Done():
			return egress.ThirdPartyResponse{}, &transportError{ctx.Err()}
		}
		defer release()
		// A request that has not been answered by now stops holding the queue back: one address
		// whose answer hangs must not leave every address behind it to time out.
		defer time.AfterFunc(gateHold, release).Stop()
		if st.latched.Load() {
			return egress.ThirdPartyResponse{}, &latchedError{}
		}
	}
	if err := ctx.Err(); err != nil {
		return egress.ThirdPartyResponse{}, &transportError{err}
	}
	resp, err := g.inner.Do(ctx, r)
	if err != nil {
		return egress.ThirdPartyResponse{}, &transportError{err}
	}
	switch resp.Status {
	case 429:
		g.latch(host)
	case 200:
		st.proven.Store(true)
	}
	return resp, nil
}

// asnEntry is the cached holder name of one AS.
type asnEntry struct {
	mu   sync.Mutex
	done bool
	name string
}

// state is what the sources of one call share: the guard, the registry bootstrap, the AS names
// asked for already and the warnings given.
type state struct {
	cfg    Config
	guard  *guard
	boot   ipsource.Bootstrap
	htMu   sync.Mutex // HackerTarget is asked one address at a time, so its quota is read before the next
	asnMu  sync.Mutex
	asns   map[int]*asnEntry
	warnMu sync.Mutex
	warned map[string]bool
}

func newState(cfg Config) *state {
	s := &state{cfg: cfg, asns: map[int]*asnEntry{}, warned: map[string]bool{}}
	s.guard = newGuard(cfg.ThirdParty, s.warnOnce)
	return s
}

// warnOnce gives a warning once however many addresses raise it.
func (s *state) warnOnce(msg string) {
	s.warnMu.Lock()
	defer s.warnMu.Unlock()
	if s.warned[msg] || s.cfg.Warn == nil {
		return
	}
	s.warned[msg] = true
	s.cfg.Warn(msg)
}

func (s *state) debugf(format string, args ...any) {
	if s.cfg.Debug != nil {
		s.cfg.Debug(fmt.Sprintf(format, args...))
	}
}

// timedOut reports whether err is the call's deadline or a timeout of a resolver or a request.
func timedOut(ctx context.Context, err error) bool {
	// A rate limiter's wait that would pass the deadline wraps context.DeadlineExceeded too.
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, egress.ErrLocalTimeout) {
		return true
	}
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// transientFailure is a failure of a source worth retrying: the deadline is TIMEOUT, anything
// else is code.
func transientFailure(ctx context.Context, src Source, err error, code clierr.Code) Failure {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return Failure{Source: src, Code: clierr.Timeout, Message: "no answer before the deadline", Transient: true}
	case timedOut(ctx, err):
		return Failure{Source: src, Code: clierr.Timeout, Message: "timed out: " + err.Error(), Transient: true}
	}
	return Failure{Source: src, Code: code, Message: err.Error(), Transient: true}
}

// dnsFailure is the failure of a resolver that did not answer or answered badly.
func dnsFailure(ctx context.Context, src Source, err error) Failure {
	return transientFailure(ctx, src, err, clierr.NetworkError)
}

// httpFailure maps an error of a request to a source to its failure.
func (s *state) httpFailure(ctx context.Context, src Source, err error) Failure {
	var latched *latchedError
	var limited *ipsource.RateLimitedError
	var transport *transportError
	switch {
	case src == SourceHackerTarget && errors.Is(err, ipsource.ErrQuota), src == SourceHackerTarget && errors.As(err, &latched):
		msg := "HackerTarget quota is spent"
		if latched != nil {
			msg = "not asked: quota spent earlier in this call"
		}
		return Failure{Source: src, Code: clierr.RateLimited, Message: msg, Quota: true}
	case errors.As(err, &latched):
		return Failure{Source: src, Code: clierr.RateLimited, Message: latchedMessage, Transient: true}
	case errors.As(err, &limited):
		return Failure{Source: src, Code: clierr.RateLimited, Message: "HTTP 429 from " + limited.Host, Transient: true}
	case timedOut(ctx, err):
		return transientFailure(ctx, src, err, clierr.NetworkError)
	case errors.As(err, &transport):
		return Failure{Source: src, Code: clierr.NetworkError, Message: err.Error(), Transient: true}
	}
	return Failure{Source: src, Code: clierr.UpstreamError, Message: err.Error(), Transient: true}
}

// get asks a source for a JSON answer. A 404 is the source saying it knows nothing: body is nil
// and there is no failure. Any other status than 200, a cut body, or no response is a failure.
func (s *state) get(ctx context.Context, src Source, u string) (body []byte, f *Failure) {
	resp, err := s.guard.Do(ctx, egress.ThirdPartyRequest{Method: "GET", URL: u, Accept: "application/json"})
	var fail Failure
	switch {
	case err != nil:
		fail = s.httpFailure(ctx, src, err)
	case resp.Status == 404:
		return nil, nil
	case resp.Status == 429:
		fail = Failure{Source: src, Code: clierr.RateLimited, Message: "HTTP 429", Transient: true}
	case resp.Status != 200:
		fail = Failure{Source: src, Code: clierr.UpstreamError, Message: fmt.Sprintf("HTTP %d", resp.Status), Transient: true}
	case resp.Truncated:
		fail = Failure{Source: src, Code: clierr.UpstreamError, Message: "the response was cut short", Transient: true}
	default:
		return resp.Body, nil
	}
	return nil, &fail
}

// origin asks Team Cymru for the AS that announces the address. Its failure means the owner is
// unknown; an AS that is not found is an answer, and the owner is unknown but not failed.
func (s *state) origin(ctx context.Context, rec *Record, addr netip.Addr) (provider.Owner, *Failure) {
	o, found, err := ipsource.Origin(ctx, s.cfg.DNS, addr)
	if err != nil {
		f := dnsFailure(ctx, SourceCymru, err)
		return provider.Owner{}, &f
	}
	if !found {
		return provider.Owner{}, nil
	}
	asn := uint32(o.ASN) //nolint:gosec // an AS number is 32 bits
	rec.ASN, rec.ASPrefix = &asn, &o.Prefix
	return provider.Owner{ASN: o.ASN, Known: true}, nil
}

// holder asks Team Cymru for the name of the owner's AS. The provider is decided from the AS
// number alone, so nothing waits for it.
func (s *state) holder(ctx context.Context, rec *Record, owner provider.Owner) *Failure {
	if !owner.Known {
		return nil
	}
	name, err := s.asName(ctx, owner.ASN)
	if err != nil {
		f := dnsFailure(ctx, SourceCymru, err)
		return &f
	}
	if name != "" {
		rec.ASName = &name
	}
	return nil
}

// asName is the holder of the AS, asked once per AS in the call.
func (s *state) asName(ctx context.Context, asn int) (string, error) {
	s.asnMu.Lock()
	e := s.asns[asn]
	if e == nil {
		e = &asnEntry{}
		s.asns[asn] = e
	}
	s.asnMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.done {
		return e.name, nil
	}
	name, err := ipsource.ASName(ctx, s.cfg.DNS, asn)
	if err == nil {
		e.name, e.done = name, true
	}
	return name, err
}

// rdap asks for the registered netblock and its registrant.
func (s *state) rdap(ctx context.Context, rec *Record, addr netip.Addr) *Failure {
	if s.guard.isLatched(ipsource.BootstrapHost) { // the bootstrap remembers the refusal, with a longer message
		f := Failure{Source: SourceRDAP, Code: clierr.RateLimited, Message: latchedMessage, Transient: true}
		return &f
	}
	reg, found, err := ipsource.Lookup(ctx, s.guard, &s.boot, addr, s.warnOnce)
	if err != nil {
		f := s.httpFailure(ctx, SourceRDAP, err)
		return &f
	}
	if !found {
		return nil
	}
	block, registry := input.RangeText(reg.Start, reg.End), reg.Registry
	rec.RDAPNetblock, rec.RDAPRegistry = &block, &registry
	if reg.Registrant != "" {
		rec.RDAPOrg = &reg.Registrant
	}
	return nil
}

// ptr asks the public resolvers for the address's reverse names.
func (s *state) ptr(ctx context.Context, rec *Record, addr netip.Addr) *Failure {
	res, err := s.cfg.DNS.Query(ctx, dnsname.ReverseName(addr), egress.TypePTR)
	if err != nil {
		f := dnsFailure(ctx, SourcePTR, err)
		return &f
	}
	switch res.RCode {
	case egress.RCodeSuccess, egress.RCodeNXDomain:
	default:
		f := dnsFailure(ctx, SourcePTR, fmt.Errorf("resolver answered rcode %d", res.RCode))
		return &f
	}
	names := []string{}
	for _, a := range res.Answers {
		if a.Type != "PTR" {
			continue
		}
		if n, ok := cleanPTRName(dnsname.Normalise(a.Value)); ok && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	rec.PTR = names
	return nil
}

// cleanPTRName is a reverse name as text: a DNS presentation form (\027, \.) is decoded, and a name
// that holds a control character after that is left out, as no host has one and it can only be
// aimed at a terminal.
func cleanPTRName(n string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c == '\\' && i+1 < len(n) {
			if i+3 < len(n) && n[i+1] >= '0' && n[i+1] <= '9' && n[i+2] >= '0' && n[i+2] <= '9' && n[i+3] >= '0' && n[i+3] <= '9' {
				v := int(n[i+1]-'0')*100 + int(n[i+2]-'0')*10 + int(n[i+3]-'0')
				if v > 255 {
					return "", false
				}
				c = byte(v)
				i += 3
			} else {
				c = n[i+1]
				i++
			}
		}
		b.WriteByte(c)
	}
	out := b.String()
	for _, r := range out {
		if r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f {
			return "", false
		}
	}
	return out, out != ""
}

// localPTR asks this machine's resolver, for a non-public address.
func (s *state) localPTR(ctx context.Context, rec *Record, addr netip.Addr) *Failure {
	if s.cfg.Local == nil {
		return nil
	}
	names, err := s.cfg.Local.PTR(ctx, addr)
	if err != nil {
		f := dnsFailure(ctx, SourcePTR, err)
		rec.PTR = nil
		return &f
	}
	out := []string{}
	for _, n := range names {
		if n, ok := cleanPTRName(n); ok {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	rec.PTR = slices.Compact(out)
	return nil
}

// ripestat asks for the address's location.
func (s *state) ripestat(ctx context.Context, rec *Record, addr netip.Addr) *Failure {
	u := "https://" + hostRIPEstat + "/data/maxmind-geo-lite/data.json?" + url.Values{"resource": {addr.String()}, "sourceapp": {"nyx"}}.Encode()
	body, f := s.get(ctx, SourceRIPEstat, u)
	if f != nil {
		return f
	}
	country, city, err := parseGeolocation(body)
	if err != nil {
		return &Failure{Source: SourceRIPEstat, Code: clierr.UpstreamError, Message: err.Error(), Transient: true}
	}
	rec.GeoCountry, rec.GeoCity = country, city
	return nil
}

// parseGeolocation reads RIPEstat's answer: the location that covers most of the address's
// resources (the first, in a tie). An unknown country ("?" or "") and an empty city are null.
func parseGeolocation(body []byte) (country, city *string, err error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil, nil
	}
	var ans struct {
		Data struct {
			Located []struct {
				Locations []struct {
					Country string  `json:"country"`
					City    string  `json:"city"`
					Covered float64 `json:"covered_percentage"`
				} `json:"locations"`
			} `json:"located_resources"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &ans); err != nil {
		return nil, nil, fmt.Errorf("unreadable geolocation: %w", err)
	}
	if len(ans.Data.Located) == 0 {
		return nil, nil, nil
	}
	best := -1
	locs := ans.Data.Located[0].Locations
	for i, l := range locs {
		if best < 0 || l.Covered > locs[best].Covered {
			best = i
		}
	}
	if best < 0 {
		return nil, nil, nil
	}
	if c := strings.TrimSpace(locs[best].Country); c != "" && c != "?" {
		country = &c
	}
	if c := strings.TrimSpace(locs[best].City); c != "" {
		city = &c
	}
	return country, city, nil
}

// internetDB is InternetDB's answer: sorted, without repeats, and never null.
type internetDB struct {
	Ports                        []int
	Hostnames, Tags, CPEs, Vulns []string
}

// parseInternetDB reads InternetDB's answer. An empty body is an answer of nothing.
func parseInternetDB(body []byte) (internetDB, error) {
	out := internetDB{Ports: []int{}, Hostnames: []string{}, Tags: []string{}, CPEs: []string{}, Vulns: []string{}}
	if len(bytes.TrimSpace(body)) == 0 {
		return out, nil
	}
	var ans struct {
		Ports     []int    `json:"ports"`
		Hostnames []string `json:"hostnames"`
		Tags      []string `json:"tags"`
		CPEs      []string `json:"cpes"`
		Vulns     []string `json:"vulns"`
	}
	if err := json.Unmarshal(body, &ans); err != nil {
		return internetDB{}, fmt.Errorf("unreadable InternetDB answer: %w", err)
	}
	out.Ports = sortedUnique(append(out.Ports, ans.Ports...))
	out.Hostnames = sortedUnique(append(out.Hostnames, ans.Hostnames...))
	out.Tags = sortedUnique(append(out.Tags, ans.Tags...))
	out.CPEs = sortedUnique(append(out.CPEs, ans.CPEs...))
	out.Vulns = sortedUnique(append(out.Vulns, ans.Vulns...))
	return out, nil
}

func sortedUnique[T int | string](l []T) []T {
	slices.Sort(l)
	return slices.Compact(l)
}

// internetdb asks for what InternetDB has seen exposed on the address.
func (s *state) internetdb(ctx context.Context, rec *Record, addr netip.Addr) *Failure {
	body, f := s.get(ctx, SourceInternetDB, "https://"+hostInternetDB+"/"+url.PathEscape(addr.String()))
	if f != nil {
		return f
	}
	ans, err := parseInternetDB(body) // a 404 has no body: it is an answer of nothing
	if err != nil {
		return &Failure{Source: SourceInternetDB, Code: clierr.UpstreamError, Message: err.Error(), Transient: true}
	}
	rec.InternetDBPorts, rec.InternetDBHostnames, rec.InternetDBTags = ans.Ports, ans.Hostnames, ans.Tags
	rec.InternetDBCPEs, rec.InternetDBVulns = ans.CPEs, ans.Vulns
	return nil
}

// hackerTargetApplies reports whether HackerTarget is asked about the address: its quota is small,
// it is IPv4 only, and a shared address gives thousands of names that mean nothing.
func hackerTargetApplies(addr netip.Addr, shared bool) bool { return addr.Is4() && !shared }

// hackerTarget asks for the names that point at the address.
func (s *state) hackerTarget(ctx context.Context, rec *Record, addr netip.Addr) *Failure {
	s.htMu.Lock()
	defer s.htMu.Unlock()
	names, err := ipsource.HackerTargetReverse(ctx, s.guard, addr) // a latched host is the guard's error
	if err != nil {
		if errors.Is(err, ipsource.ErrQuota) {
			s.guard.latch(ipsource.HackerTargetHost)
		}
		f := s.httpFailure(ctx, SourceHackerTarget, err)
		return &f
	}
	count := len(names)
	rec.ReverseIP = append([]string{}, names[:min(count, maxReverseIP)]...)
	rec.ReverseIPCount = &count
	return nil
}

// sourceRuns is one address's lookup: the failures by source, and what was asked.
type sourceRuns struct {
	failures [7]*Failure
	asked    [7]bool
}

func (sr *sourceRuns) set(src Source, f *Failure) {
	sr.failures[sourceRank(src)] = f
	sr.asked[sourceRank(src)] = true
}

// lookupAddress asks every source the selection needs for one address, and probes it under
// --active when it is contacted.
func (s *state) lookupAddress(ctx context.Context, a Address) AddressResult {
	rec := NewRecord(a)
	addr := a.Addr.Unmap()
	var runs sourceRuns
	var prov provider.Result
	var ownerFailed *Failure
	if rec.Kind == addrkind.Public {
		prov, ownerFailed = s.publicSources(ctx, &rec, addr, &runs)
		if s.cfg.Fields.Has("abusive_networks") || s.cfg.Fields.Has("abusive_asn") {
			s.abusive(&rec, addr, ownerFailed)
		}
		if s.cfg.Fields.Has("drop_networks") || s.cfg.Fields.Has("drop_asn") {
			s.drop(&rec, addr, ownerFailed)
		}
	} else {
		s.nonPublicSources(ctx, &rec, addr, &runs)
	}
	if s.cfg.Fields.Active() {
		s.contact(ctx, a, &rec, contactInput{Addr: addr, Kind: rec.Kind, Found: a.Found, OwnerFailed: ownerFailed, Provider: prov}, &runs)
	}
	var asked []Source
	for _, src := range s.cfg.Fields.Sources() {
		if runs.asked[sourceRank(src)] {
			asked = append(asked, src)
		}
		if f := runs.failures[sourceRank(src)]; f != nil {
			rec.AddFailure(*f)
		}
	}
	return AddressResult{Record: rec, Asked: asked, Answered: rec.Kind == addrkind.Public && s.cfg.Fields.Sourceless()}
}

// abusive sets the selected abusive keys of a public address from the snapshot, which needs no
// request. The network matches are always set when selected. The ASN match follows the origin AS:
// its entry when the AS is known, [] when Team Cymru knows no owner, and null when the origin lookup
// failed. A failure of the AS name alone leaves the AS known, so the match is set and the failure is
// the name's.
func (s *state) abusive(rec *Record, addr netip.Addr, ownerFailed *Failure) {
	snap := s.cfg.Abusive
	if snap == nil {
		snap = abusive.Default()
	}
	if s.cfg.Fields.Has("abusive_networks") {
		rec.AbusiveNetworks = snap.Networks(addr)
	}
	if !s.cfg.Fields.Has("abusive_asn") || ownerFailed != nil {
		return
	}
	if rec.ASN == nil {
		rec.AbusiveASN = []abusive.ASNMatch{}
		return
	}
	rec.AbusiveASN = snap.ASN(int(*rec.ASN))
}

// drop sets the selected DROP keys of a public address from Spamhaus's lists, which need no
// request, by the rules of the abusive keys: the network entries are always set when selected, and
// the ASN-DROP entry follows the origin AS (its entry when listed, [] when the AS is not listed or
// Team Cymru knows no owner, and null when the origin lookup failed).
func (s *state) drop(rec *Record, addr netip.Addr, ownerFailed *Failure) {
	lists := s.cfg.Drop
	if lists == nil {
		lists = spamhaus.Default()
	}
	if s.cfg.Fields.Has("drop_networks") {
		rec.DropNetworks = lists.Networks(addr)
	}
	if !s.cfg.Fields.Has("drop_asn") || ownerFailed != nil {
		return
	}
	if rec.ASN == nil {
		rec.DropASN = []spamhaus.ASNMatch{}
		return
	}
	rec.DropASN = lists.ASN(int(*rec.ASN))
}

// publicSources asks the sources of a public address concurrently. The provider and HackerTarget
// wait for the owner. It returns what the provider data says of the address, and the failure of
// the owner lookup when the owner is unknown for that reason.
func (s *state) publicSources(ctx context.Context, rec *Record, addr netip.Addr, runs *sourceRuns) (prov provider.Result, ownerFailed *Failure) {
	f := s.cfg.Fields
	var wg sync.WaitGroup
	var mu sync.Mutex
	record := func(src Source, fail *Failure) {
		mu.Lock()
		defer mu.Unlock()
		runs.set(src, fail)
	}
	independent := map[Source]func(context.Context, *Record, netip.Addr) *Failure{
		SourceRDAP: s.rdap, SourcePTR: s.ptr, SourceRIPEstat: s.ripestat, SourceInternetDB: s.internetdb,
	}
	for src, fn := range independent {
		if f.Needs(src) {
			wg.Go(func() { record(src, fn(ctx, rec, addr)) })
		}
	}
	if f.Needs(SourceCymru) {
		wg.Go(func() {
			owner, failed := s.origin(ctx, rec, addr)
			if failed != nil {
				record(SourceCymru, failed)
				ownerFailed = failed
				return // the shared check cannot be made: nothing that depends on it is asked
			}
			prov = provider.Default().Classify(addr, owner, nil)
			if prov.Provider != "" {
				rec.Provider = &prov.Provider
			}
			if prov.Class != "" {
				rec.ProviderClass = &prov.Class
			}
			// HackerTarget needs only the shared check, so it does not wait for the AS name.
			var after sync.WaitGroup
			if f.Needs(SourceHackerTarget) && hackerTargetApplies(addr, prov.SharedInfrastructure()) {
				after.Go(func() { record(SourceHackerTarget, s.hackerTarget(ctx, rec, addr)) })
			}
			record(SourceCymru, s.holder(ctx, rec, owner))
			after.Wait()
		})
	}
	wg.Wait()
	return prov, ownerFailed
}

// nonPublicSources is the sources of a non-public address: no third party and no public resolver
// are asked. Its list keys are empty and its single values null; under --active its PTR is asked
// of this machine's resolver.
func (s *state) nonPublicSources(ctx context.Context, rec *Record, addr netip.Addr, runs *sourceRuns) {
	rec.PTR, rec.InternetDBPorts, rec.InternetDBHostnames = []string{}, []int{}, []string{}
	rec.InternetDBTags, rec.InternetDBCPEs, rec.InternetDBVulns, rec.ReverseIP = []string{}, []string{}, []string{}, []string{}
	if s.cfg.Fields.Active() && s.cfg.Fields.Needs(SourcePTR) {
		runs.set(SourcePTR, s.localPTR(ctx, rec, addr))
	}
}
