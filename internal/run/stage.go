package run

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/rafaelh/nyx/internal/cloudstorage"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/origin"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

// Contact says whom a stage talks to. It is single-valued: a stage with mixed
// behaviour is split into separate stages (egress.Clients only carries Target
// clients to stages whose Contact is Target).
type Contact int

const (
	ThirdParty Contact = iota
	Target
)

// Check is one unit of work. Key must encode every input and setting that
// changes the work done (for example "203.0.113.5:8080", or
// "https://a.example.com|depth=2|pages=100"), so changing such a setting
// creates new checks instead of silently reusing old results.
type Check struct {
	Key   string
	Input any
	// Cost is what the check spends of its stage's per-run budget (see Budgeted):
	// the number of names it queries, requests it sends. 0 means 1.
	Cost int
}

// Observation is a fact a check found, made with a kind's handle (for example
// kinds.Resolution.Obs). Discovered entities are observations of kind
// hostname, root or netblock; scope classifies them (in scope, candidate or
// excluded), so stages never implement candidate or exclusion handling.
type Observation = store.Obs

// ErrAbortStage, wrapped in a check's error, fails that check and every
// remaining check of the stage for this run without sending them.
var ErrAbortStage = errors.New("abort stage")

// ErrQuota, wrapped in a check's error, says the source's quota is spent. It
// aborts the stage like ErrAbortStage, which it wraps: the checks not yet done
// fail and are retried on the next run.
var ErrQuota = fmt.Errorf("quota spent: %w", ErrAbortStage)

// ErrKeyRejected, wrapped in a check's error, says the source refused the API key.
// It aborts the stage like ErrAbortStage, which it wraps, and the run counts the
// failures it causes apart: waiting does not cure a refused key.
var ErrKeyRejected = fmt.Errorf("key rejected: %w", ErrAbortStage)

type runStateKey struct{}

// runState is what PerRun keeps for one run.
type runState struct {
	mu sync.Mutex
	m  map[any]any
}

// withRunState returns a context that PerRun keeps its values in.
func withRunState(ctx context.Context) context.Context {
	return context.WithValue(ctx, runStateKey{}, &runState{m: map[any]any{}})
}

// PerRun returns what init made the first time any check of this run asked for
// key, and the same value to every later ask until the run ends, so a stage
// fetches a file shared by all its checks once per run and not once per process.
// init runs under the lock every PerRun of the run shares, so it must be quick
// and must not call PerRun itself. A context that did not come from the runner
// keeps nothing: init is called every time.
func PerRun[T any](ctx context.Context, key any, init func() T) T {
	st, ok := ctx.Value(runStateKey{}).(*runState)
	if !ok {
		return init()
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if v, ok := st.m[key]; ok {
		return v.(T)
	}
	v := init()
	st.m[key] = v
	return v
}

type warnerKey struct{}

// withWarner returns a context whose Warnf calls go to warn.
func withWarner(ctx context.Context, warn func(format string, a ...any)) context.Context {
	return context.WithValue(ctx, warnerKey{}, warn)
}

// Warnf reports a problem that does not fail the check, such as a truncated
// result. Like View.Warn it is a WARN line, shown by default and written once
// per run for the same text. A context that did not come from the runner has no
// warner, and the call does nothing, so stages stay testable without one.
func Warnf(ctx context.Context, format string, a ...any) {
	if warn, ok := ctx.Value(warnerKey{}).(func(string, ...any)); ok {
		warn(format, a...)
	}
}

// Env is what a stage sees when deciding whether it can run.
type Env struct {
	Settings   config.Settings
	Passive    bool
	Authorised bool
}

// Key returns the configured API key for a source.
func (e Env) Key(source string) (config.Secret, bool) {
	k, ok := e.Settings.Keys[strings.ToLower(source)]
	return k, ok && k.Reveal() != ""
}

// Stage is one discovery stage.
//
// Run reports negative results (closed port, NXDOMAIN, no HTTP service, a
// policy refusal) as observations or as no observations: they are completed
// checks. A returned error means a transient failure (timeout, rate limit,
// source unavailable): the check is not recorded, is not retried in the same
// run, is retried on every later run, and is counted as failed.
type Stage interface {
	Name() string // listed in --help, accepted by --redo
	Contact() Contact
	Sources() []string // third-party host patterns, e.g. "stat.ripe.net", "*.s3.amazonaws.com"
	Configured(Env) (ok bool, reason string)
	Checks(ctx context.Context, v View) iter.Seq2[Check, error]
	Run(ctx context.Context, c Check, e egress.Clients) ([]Observation, error)
}

// WorkerCounter is implemented by a stage that needs a different number of
// workers from Settings.Concurrency (the ports stage, whose checks are slow).
type WorkerCounter interface {
	Workers(config.Settings) int
}

// Budgeted is implemented by a stage that caps the work it does in one run.
type Budgeted interface {
	Budget(config.Settings) int
}

// Noter is implemented by a stage that has something to say in the run summary
// beyond the counts: a search that was cut short, say. Each note is one line,
// asked for once at the end of the run, from the records as they then stand.
type Noter interface {
	Notes(v View) []string
}

// Evidencer is implemented by a stage that says what supports a candidate its
// check found.
type Evidencer interface {
	Evidence(checkKey string) (source, item string)
}

// Retiring is implemented by a stage whose check keys carry a hash of the
// entry a check applies (a fingerprint, a sensitive-path signature, the DKIM
// selector list). After every pass that enumerated cleanly, the runner retires
// its completed checks that it no longer yields (Store.Retire): evidence from a
// superseded check stops being current instead of outliving the edit.
type Retiring interface {
	RetiresUnlistedChecks()
}

// recordCache holds the records a View has read, for one stage pass.
type recordCache struct {
	mu    sync.Mutex
	m     map[string][]store.Record
	hosts map[netip.Addr][]string // address -> probe hostnames, built on first use
}

// View gives a stage read access to the store and the current Scope. It
// caches the records it reads for its lifetime, one stage pass, so callers must
// not modify the returned slices.
type View struct {
	r     *Runner
	sc    *scope.Scope
	inv   *inventory.Inventory
	vis   *kinds.Visibility // of sc and inv
	cache *recordCache
	done  map[string]struct{} // the stage's completed check keys, as the store keeps them
}

// Done reports whether the stage has completed the check with this key, as of
// the start of this pass. A key the stage carries a secret in is looked up in
// its stored (redacted) form.
func (v View) Done(key string) bool {
	_, ok := v.done[v.r.st.CheckKey(key)]
	return ok
}

// Scope is the Scope built at the start of the current pass.
func (v View) Scope() *scope.Scope { return v.sc }

// Warn reports a problem that does not fail a check, such as a stage running
// with reduced capability. It is a WARN line, shown by default; the same text is
// written once per run, however many passes call it.
func (v View) Warn(format string, a ...any) { v.r.warn(format, a...) }

// Settings are the run's settings.
func (v View) Settings() config.Settings { return v.r.cfg.Settings }

// Inputs are the engagement's stored scope inputs and exclusions.
func (v View) Inputs() input.Parsed { return v.r.inputs }

// Records returns the current records of a kind; decode them with its handle.
func (v View) Records(k kinds.Named) []store.Record {
	kind := k.Name()
	v.cache.mu.Lock()
	defer v.cache.mu.Unlock()
	if recs, ok := v.cache.m[kind]; ok {
		return recs
	}
	out, err := v.r.currentRecords(k)
	if err != nil {
		v.r.warn("reading %s records: %v", kind, err)
		return nil
	}
	v.cache.m[kind] = out
	return out
}

// IPs returns the addresses of the current ip records that keep accepts,
// unmapped, without duplicates, and sorted by address. keep sees the unmapped
// address. A record whose key is not an address is skipped.
func (v View) IPs(keep func(netip.Addr) bool) []netip.Addr {
	var out []netip.Addr
	for _, rec := range v.Records(kinds.IP) {
		if a, err := netip.ParseAddr(rec.Key); err == nil && keep(a.Unmap()) {
			out = append(out, a.Unmap())
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return slices.Compact(out)
}

// KnownAddrs returns every address the engagement knows, whether or not it may
// be contacted: the addresses of ips.csv, in address order.
func (v View) KnownAddrs() []netip.Addr { return v.inv.KnownAddrs(v.sc) }

// WebService is a current web_service record whose host is in scope.
type WebService struct {
	Key string
	Svc egress.Service
}

// WebServices returns the current web_service records whose host is in scope,
// in key order. A record whose key is not a service URL is skipped.
func (v View) WebServices() []WebService {
	var out []WebService
	for _, rec := range v.Records(kinds.WebService) {
		if svc, ok := egress.ParseService(rec.Key); ok && v.sc.WebHostInScope(svc.Host) {
			out = append(out, WebService{Key: rec.Key, Svc: svc})
		}
	}
	return out
}

// InScopeRoots returns the in-scope input roots, sorted: the roots the user gave
// that the scope has not excluded.
func (v View) InScopeRoots() []string {
	var out []string
	for _, r := range v.Inputs().Roots {
		if v.sc.HostInScope(r) {
			out = append(out, r)
		}
	}
	slices.Sort(out) // input roots are canonical and unique, but not sorted
	return out
}

// ResolvableHostnames are the names the resolve stage looks up: in-scope and
// excluded hostnames (exclusion by resolved address needs their addresses) and
// the input roots, never candidates. Sorted.
func (v View) ResolvableHostnames() []string {
	set := map[string]bool{}
	add := func(h string) {
		if v.sc.ClassifyHost(h).Class != scope.Candidate {
			set[dnsname.Normalise(h)] = true
		}
	}
	for _, rec := range v.Records(kinds.Hostname) {
		add(rec.Key)
	}
	for _, root := range v.Inputs().Roots {
		add(root)
	}
	return slices.Sorted(maps.Keys(set))
}

// ProbeHostnames are the names later stages may probe over HTTP: resolved,
// in-scope, not excluded, not wildcard-only, plus one representative for each
// wildcard zone. Web stages must use this, not the hostname records, so that
// a wildcard zone is probed once.
func (v View) ProbeHostnames() []string { return v.inv.ProbeHostnames(v.sc) }

// ProviderHosts are the in-scope names on shared provider infrastructure, with
// Resolves=false for chains that dangle. The takeover checks read it.
func (v View) ProviderHosts() []inventory.ProviderHost { return v.inv.ProviderHosts(v.sc) }

// SaaSServed reports whether a host (a name or an IP literal) is served by a
// third-party SaaS platform, by CNAME chain, address ASN or address range.
func (v View) SaaSServed(host string) bool { return v.inv.SaaSServed(host) }

// FrontedHostnames are the probe hostnames that currently resolve to a CDN or WAF, in name order.
func (v View) FrontedHostnames() []string {
	var out []string
	for _, f := range origin.FrontedHosts(v.sc, v.inv) {
		out = append(out, f.Host)
	}
	return out
}

// OriginPairs are the candidate origins of the fronted hostnames, at most
// origincheck.max_candidates for each: the same pairs the findings report.
func (v View) OriginPairs() []origin.Pair {
	return origin.Pairs(v.sc, v.inv, v.vis, v.Records, v.Settings().OriginCheck.MaxCandidates)
}

// StorageRefs are the buckets and containers in-scope names and pages point at,
// sorted. A bucket with a reference is attributed.
func (v View) StorageRefs() []cloudstorage.Reference {
	return findings.References(findings.Input{Scope: v.sc, Inv: v.inv, Records: v.Records, Vis: v.vis})
}

// WildcardZone reports whether the name is a zone known to be a wildcard.
func (v View) WildcardZone(name string) bool { return v.inv.WildcardZone(name) }

// Seeds are the hostnames the generator stage derives names from: never
// names only the generator itself observed, and never one directly under a
// wildcard zone.
func (v View) Seeds(generator string) []string { return v.inv.Seeds(v.sc, generator) }

// OpenPort is a current open_port record: the port stage emits one per
// open port, keyed by netip.AddrPort.String(), with an unprompted banner if any.
type OpenPort struct {
	Addr   netip.AddrPort
	Banner string
}

// OpenPorts returns the current open_port records, sorted by address and port.
// A record whose key is not an address and port is skipped.
func (v View) OpenPorts() []OpenPort {
	var out []OpenPort
	for _, rec := range v.Records(kinds.OpenPort) {
		if ap, ok := kinds.ParsePortKey(rec.Key); ok {
			out = append(out, OpenPort{Addr: ap, Banner: kinds.OpenPort.Attrs(rec).Banner})
		}
	}
	slices.SortFunc(out, func(a, b OpenPort) int { return strings.Compare(a.Addr.String(), b.Addr.String()) })
	return out
}

// PortEligible reports whether the address may be port-checked: the decision
// egress enforces and ips.csv reports.
func (v View) PortEligible(a netip.Addr) bool { return v.inv.PortEligible(a, v.sc) }

// SelfHosted reports whether a name server or mail host is run by the
// organisation (see inventory.SelfHosted).
func (v View) SelfHosted(host string) bool { return v.inv.SelfHosted(host, v.sc) }

// Registered reports whether a current registration record's range holds the address.
func (v View) Registered(a netip.Addr) bool {
	_, ok := v.inv.RegistrationOf(a)
	return ok
}

// OwnerKnown reports whether anything is known about who owns the address.
func (v View) OwnerKnown(a netip.Addr) bool { return v.inv.OwnerKnown(a, v.sc) }

// HostsFor returns the ProbeHostnames that resolve to the address, sorted.
func (v View) HostsFor(a netip.Addr) []string {
	v.cache.mu.Lock()
	defer v.cache.mu.Unlock()
	if v.cache.hosts == nil {
		idx := map[netip.Addr][]string{}
		for _, name := range v.ProbeHostnames() {
			for _, addr := range v.inv.Addrs()[name] {
				if l := idx[addr]; len(l) == 0 || l[len(l)-1] != name {
					idx[addr] = append(l, name)
				}
			}
		}
		v.cache.hosts = idx
	}
	return v.cache.hosts[a.Unmap()]
}
