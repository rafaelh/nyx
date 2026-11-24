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

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/cloudstorage"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/recon/analysis/candidates"
	"github.com/rafaelh/nyx/internal/recon/analysis/findings"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/origin"
	"github.com/rafaelh/nyx/internal/recon/scope"
	"github.com/rafaelh/nyx/internal/recon/store"
)

// Contact identifies whether a procedure contacts third parties or targets. Procedures combining
// both kinds of contact are split so egress can grant target clients only where needed.
type Contact int

const (
	ThirdParty Contact = iota
	Target
)

// Job is a resumable unit of work. Key includes the inputs and settings that affect its
// result, such as an address and port or a URL and crawl depth. This prevents changed settings
// from reusing stale results.
type Job struct {
	Key   string
	Input any
	// Cost counts units of the procedure's per-run budget, such as names queried or requests
	// sent. Zero counts as one.
	Cost int
}

// Observation is a fact found by a job, constructed with a kind handle such as
// kinds.Resolution.Obs. Procedures report discovered entities; scope classification decides whether
// they are in scope, candidates or excluded.
type Observation = store.Obs

// ErrAbortProcedure marks an error that fails the current job and abandons the procedure's
// remaining jobs for this run.
var ErrAbortProcedure = errors.New("abort procedure")

// ErrQuota signals that a source's quota is exhausted. It wraps ErrAbortProcedure, so pending
// jobs fail and can be retried next run.
var ErrQuota = fmt.Errorf("quota spent: %w", ErrAbortProcedure)

// ErrKeyRejected signals a refused API key and aborts the procedure. These failures are counted
// separately because retrying later cannot fix the key.
var ErrKeyRejected = fmt.Errorf("key rejected: %w", ErrAbortProcedure)

type runStateKey struct{}

type runState struct {
	mu sync.Mutex
	m  map[any]any
}

func withRunState(ctx context.Context) context.Context {
	return context.WithValue(ctx, runStateKey{}, &runState{m: map[any]any{}})
}

// PerRun initialises a value once per key and shares it across jobs in this run. This is
// useful for data fetched once per run rather than once per process. init holds the shared
// lock: keep it quick and do not call PerRun from it. Without a runner context, each call
// invokes init again.
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

func withWarner(ctx context.Context, warn func(format string, a ...any)) context.Context {
	return context.WithValue(ctx, warnerKey{}, warn)
}

// Warnf reports a non-fatal problem, such as truncated results. Like View.Warn, it emits each
// warning text once per run. It does nothing without a runner context, so procedures can also run
// in isolated tests.
func Warnf(ctx context.Context, format string, a ...any) {
	if warn, ok := ctx.Value(warnerKey{}).(func(string, ...any)); ok {
		warn(format, a...)
	}
}

// Env supplies the settings and permissions used to decide whether a procedure can run.
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

// Procedure performs discovery as resumable jobs. Negative results such as closed ports, NXDOMAIN
// or policy refusal complete a job with any observations found. Returning an error marks a
// failure: it is counted now and retried on a later run, never in the same run.
type Procedure interface {
	Name() string // listed in --help, accepted by --redo
	Contact() Contact
	Sources() []string // third-party host patterns, e.g. "stat.ripe.net", "*.s3.amazonaws.com"
	Configured(Env) (ok bool, reason string)
	Jobs(ctx context.Context, v View) iter.Seq2[Job, error]
	Run(ctx context.Context, c Job, e egress.Clients) ([]Observation, error)
}

// WorkerCounter overrides Settings.Concurrency for procedures needing a different pool size, such
// as slow port checks.
type WorkerCounter interface {
	Workers(config.Settings) int
}

// Budgeted limits a procedure's total job cost in one run.
type Budgeted interface {
	Budget(config.Settings) int
}

// Noter adds lines to the run summary, such as a warning that a search was cut short. Notes are
// requested once at the end using the final records.
type Noter interface {
	Notes(v View) []string
}

// Evidencer identifies the source and supporting item a job contributes to a candidate.
type Evidencer interface {
	Evidence(jobKey string) (source, item string)
}

// CandidateSourcer groups evidence sources into candidate families. Keys are procedure names or
// Evidence source names before the first colon. Values are known family names or the source's
// own name for an independent family. Undeclared sources each form their own family.
type CandidateSourcer interface {
	CandidateSources() map[string]string
}

// CandidateFamilies combines the source-family mappings declared by procedures.
func CandidateFamilies(procedures []Procedure) candidates.Families {
	named := map[string]string{}
	for _, s := range procedures {
		if c, ok := s.(CandidateSourcer); ok {
			maps.Copy(named, c.CandidateSources())
		}
	}
	return candidates.NewFamilies(named)
}

// ASNExpander marks procedures whose netblocks extend an input ASN's scope. BuildScope includes
// netblocks observed under a job keyed by that ASN.
type ASNExpander interface {
	ExpandsInputASNs()
}

// Retiring marks procedures whose completed jobs can become obsolete, such as jobs keyed by a
// fingerprint hash. After successful enumeration, the runner retires jobs no longer listed so
// their old evidence stops being current.
type Retiring interface {
	RetiresUnlistedJobs()
}

type recordCache struct {
	mu    sync.Mutex
	m     map[string][]store.Record
	hosts map[netip.Addr][]string // probe hostnames by address, indexed lazily
}

// View exposes the store and scope as of one procedure pass. Records are cached for that pass;
// treat returned slices as read-only.
type View struct {
	r     *Runner
	sc    *scope.Scope
	inv   *inventory.Inventory
	vis   *kinds.Visibility // visibility for sc and inv
	cache *recordCache
	done  map[string]struct{} // completed job keys in their stored, redacted form
}

// Done checks completion as of the start of the pass. Keys containing secrets are converted to
// their stored, redacted form before lookup.
func (v View) Done(key string) bool {
	_, ok := v.done[v.r.st.JobKey(key)]
	return ok
}

// Scope returns the scope snapshot for this pass.
func (v View) Scope() *scope.Scope { return v.sc }

// Warn reports a non-fatal procedure problem. Each distinct warning text appears once per run, even
// across repeated passes.
func (v View) Warn(format string, a ...any) { v.r.warn(format, a...) }

func (v View) Settings() config.Settings { return v.r.cfg.Settings }

// Inputs returns the engagement's stored scope inputs and exclusions.
func (v View) Inputs() input.Parsed { return v.r.inputs }

// Records returns cached current records for a kind. Use the kind's handle to decode
// attributes.
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

// IPs filters current IP records after unmapping IPv4-mapped addresses. Invalid keys are
// skipped; results are sorted. keep receives the unmapped address.
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

// KnownAddrs returns the addresses listed in ips.csv, sorted, including those that cannot be
// contacted.
func (v View) KnownAddrs() []netip.Addr { return v.inv.KnownAddrs(v.sc) }

// WebService is a current web_service record whose host is in scope.
type WebService struct {
	Key string
	Svc egress.Service
}

// WebServices returns current in-scope services sorted by key, skipping invalid service URLs.
func (v View) WebServices() []WebService {
	var out []WebService
	for _, rec := range v.Records(kinds.WebService) {
		if svc, ok := egress.ParseService(rec.Key); ok && v.sc.WebHostInScope(svc.Host) {
			out = append(out, WebService{Key: rec.Key, Svc: svc})
		}
	}
	return out
}

// InScopeRoots returns sorted input roots after applying exclusions.
func (v View) InScopeRoots() []string {
	var out []string
	for _, r := range v.Inputs().Roots {
		if v.sc.HostInScope(r) {
			out = append(out, r)
		}
	}
	slices.Sort(out)
	return out
}

// ResolvableHostnames returns sorted input roots and discovered names to resolve. Excluded
// names are included because address-based exclusions need DNS results; candidates are omitted.
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

// ProbeHostnames returns resolved in-scope names eligible for HTTP probing, with one
// representative per wildcard zone. Web procedures use this list to avoid probing every wildcard
// hostname.
func (v View) ProbeHostnames() []string { return v.inv.ProbeHostnames(v.sc) }

// ProviderHosts returns in-scope names on shared infrastructure for takeover checks. Dangling
// CNAME chains have Resolves=false.
func (v View) ProviderHosts() []inventory.ProviderHost { return v.inv.ProviderHosts(v.sc) }

// SaaSServed identifies third-party SaaS hosting from CNAME chains, ASNs or address ranges.
// host can be a name or IP literal.
func (v View) SaaSServed(host string) bool { return v.inv.SaaSServed(host) }

// FrontedHostnames returns sorted probe names resolving to a CDN or WAF.
func (v View) FrontedHostnames() []string {
	var out []string
	for _, f := range origin.FrontedHosts(v.sc, v.inv) {
		out = append(out, f.Host)
	}
	return out
}

// OriginPairs returns the same candidate origins used by findings, capped per host by
// origincheck.max_candidates.
func (v View) OriginPairs() []origin.Pair {
	return origin.Pairs(v.sc, v.inv, v.vis, v.Records, v.Settings().OriginCheck.MaxCandidates)
}

// StorageRefs returns sorted bucket and container references from in-scope names and pages.
// These references establish attribution.
func (v View) StorageRefs() []cloudstorage.Reference {
	return findings.References(findings.Input{Scope: v.sc, Inv: v.inv, Records: v.Records, Vis: v.vis})
}

// WildcardZone identifies known wildcard-answering zones.
func (v View) WildcardZone(name string) bool { return v.inv.WildcardZone(name) }

// Seeds returns hostnames for name generation. It excludes names observed only by this
// generator and direct children of wildcard zones to avoid feeding generated names back into
// discovery.
func (v View) Seeds(generator string) []string { return v.inv.Seeds(v.sc, generator) }

// OpenPort holds an open address/port pair and any banner received without sending application
// data.
type OpenPort struct {
	Addr   netip.AddrPort
	Banner string
}

// OpenPorts returns current open ports sorted by address and port, skipping invalid keys.
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

// PortEligible uses the same port-checking decision as egress and ips.csv.
func (v View) PortEligible(a netip.Addr) bool { return v.inv.PortEligible(a, v.sc) }

// SelfHosted reports whether the organisation runs a mail host or name server; see
// inventory.SelfHosted.
func (v View) SelfHosted(host string) bool { return v.inv.SelfHosted(host, v.sc) }

// Registered checks whether a current registration range contains the address.
func (v View) Registered(a netip.Addr) bool {
	_, ok := v.inv.RegistrationOf(a)
	return ok
}

// OwnerKnown reports whether ownership information is available for the address.
func (v View) OwnerKnown(a netip.Addr) bool { return v.inv.OwnerKnown(a, v.sc) }

// HostsFor returns sorted probe hostnames resolving to the address.
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

// Historical marks procedures that report past DNS addresses. Addresses observed only by these
// procedures may no longer be used by the engagement, so abusive-network findings omit them.
type Historical interface {
	HistoricalAddresses()
}
