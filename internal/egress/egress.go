// Package egress owns nyx's network I/O and enforces target contact policy. It returns its own
// result types so procedure packages do not depend on net, net/http or crypto/tls; the boundary
// test checks this separation.
package egress

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/scope"
)

// Policy contains contact rules rebuilt by the runner when scope changes. Egress does not read
// stored state itself.
type Policy struct {
	Scope          *scope.Scope
	Ack, Passive   bool
	Ports          []int
	SensitivePaths []string
	// Scripts lists normalised script URLs recorded by crawling. Script requests also pass
	// the usual host, exclusion and port checks.
	Scripts map[string]bool
	// Shared reports whether an address is shared provider infrastructure.
	Shared func(netip.Addr) bool
	// OwnerUnknown prevents port checks when ownership is missing. It cannot relax HTTP
	// rules the way known shared hosting can.
	OwnerUnknown func(netip.Addr) bool
	// Excluded receives dial-time exclusion matches for recording.
	Excluded func(value, reason string)
}

func (p *Policy) isShared(a netip.Addr) bool { return p.Shared != nil && p.Shared(a) }

func (p *Policy) ownerUnknown(a netip.Addr) bool { return p.OwnerUnknown != nil && p.OwnerUnknown(a) }

// owner is the Policy's scope.Owner.
func (p *Policy) owner(a netip.Addr) (shared, known bool) { return p.isShared(a), !p.ownerUnknown(a) }

func (p *Policy) reportExcluded(value, reason string) {
	if p.Excluded != nil {
		p.Excluded(value, reason)
	}
}

// portIneligible applies eligibility and reports exclusion-triggered refusals.
func (p *Policy) portIneligible(a netip.Addr) (Refused, bool) {
	ok, why, excluded := p.Scope.PortEligible(a, p.owner)
	if ok {
		return Refused{}, false
	}
	if excluded {
		p.reportExcluded(a.String(), why)
	}
	return Refused{why}, true
}

func (p *Policy) portAllowed(port int, alsoWeb bool) bool {
	return (alsoWeb && (port == 80 || port == 443)) || slices.Contains(p.Ports, port)
}

// targetRefusal requires an installed policy, active mode and acknowledged target contact for
// every target client.
func (p *Policy) targetRefusal() (Refused, bool) {
	switch {
	case p == nil || p.Scope == nil:
		return Refused{"no policy"}, true
	case p.Passive:
		return Refused{"passive-only"}, true
	case !p.Ack:
		return Refused{"no authorisation"}, true
	}
	return Refused{}, false
}

// Options provides rates/timeouts and test routing hooks that preserve policy decisions.
type Options struct {
	ResolverAddrs []string // default: 1.1.1.1, 8.8.8.8, 9.9.9.9 on port 53
	// SourceBaseURLs checks exact hosts before wildcard source patterns when rebasing
	// requests.
	SourceBaseURLs map[string]string
	DialMap        map[string]string // "ip:port" -> "host:port" actually dialled
	// SourceRates overrides default pacing for declared source patterns.
	SourceRates map[string]float64
	// LocalResolverAddr redirects machine DNS to a test host:port.
	LocalResolverAddr string

	DNSTimeout, ConnectTimeout, BannerWait, HTTPTimeout time.Duration

	RateDNS, RatePerHost, RatePerSource float64

	// Now defaults to time.Now for certificate validity checks.
	Now func() time.Time

	// UserAgent identifies source and target HTTP requests, defaulting to DefaultUserAgent.
	UserAgent string

	Keys     map[string]config.Secret
	Redactor *config.Redactor // default: built from Keys
}

// WithSettings overlays configured rates, credentials and redaction.
func (o Options) WithSettings(s config.Settings, r *config.Redactor) Options {
	o.RateDNS, o.RatePerHost, o.RatePerSource = s.Rate.DNS, s.Rate.PerHost, s.Rate.PerSource
	o.Keys, o.Redactor = s.Keys, r
	return o
}

// Clients grants HTTP/TCP target access only to target-contacting procedures.
type Clients struct {
	DNS        Resolver
	ThirdParty ThirdPartyHTTP
	HTTP       TargetHTTP
	TCP        TargetTCP
}

// Egress builds clients and enforces the current Policy.
type Egress struct {
	opts Options
	pol  atomic.Pointer[Policy]

	mu      sync.Mutex
	hostLim map[netip.Addr]*rate.Limiter
	srcLim  map[string]*rate.Limiter
	dnsLim  *rate.Limiter
	rr      atomic.Uint32

	thirdParty *http.Client // shared by every procedure's ThirdPartyHTTP
}

// New creates an Egress.
func New(o Options) *Egress {
	o.DNSTimeout = cmp.Or(o.DNSTimeout, 3*time.Second)
	o.ConnectTimeout = cmp.Or(o.ConnectTimeout, 5*time.Second)
	o.BannerWait = cmp.Or(o.BannerWait, 3*time.Second)
	o.HTTPTimeout = cmp.Or(o.HTTPTimeout, 15*time.Second)
	o.UserAgent = cmp.Or(o.UserAgent, DefaultUserAgent)
	if o.Now == nil {
		o.Now = time.Now
	}
	defr := func(v *float64, d float64) {
		if *v <= 0 {
			*v = d
		}
	}
	defr(&o.RateDNS, 50)
	defr(&o.RatePerHost, 5)
	defr(&o.RatePerSource, 1)
	if len(o.ResolverAddrs) == 0 {
		o.ResolverAddrs = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	}
	if o.Redactor == nil {
		o.Redactor = config.NewRedactor(config.Settings{Keys: o.Keys}.KeyValues()...)
	}
	e := &Egress{
		opts: o, hostLim: map[netip.Addr]*rate.Limiter{}, srcLim: map[string]*rate.Limiter{},
		thirdParty: &http.Client{
			// Allow idle reuse across the CVE command's four concurrent requests.
			Transport:     &http.Transport{Proxy: nil, MaxIdleConnsPerHost: 4},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	e.dnsLim = rate.NewLimiter(rate.Limit(o.RateDNS), max(1, int(o.RateDNS)))
	return e
}

// SetPolicy installs the Policy used by all subsequent requests.
func (e *Egress) SetPolicy(p *Policy) { e.pol.Store(p) }

func (e *Egress) policy() *Policy { return e.pol.Load() }

func (e *Egress) hostLimiter(a netip.Addr) *rate.Limiter {
	return limiterFor(&e.mu, e.hostLim, a, e.opts.RatePerHost)
}

func (e *Egress) sourceLimiter(pattern string) *rate.Limiter {
	r, ok := e.opts.SourceRates[pattern]
	if !ok || r <= 0 {
		r = e.opts.RatePerSource
	}
	return limiterFor(&e.mu, e.srcLim, pattern, r)
}

// limiterFor lazily creates a keyed limiter at rate r.
func limiterFor[K comparable](mu *sync.Mutex, m map[K]*rate.Limiter, k K, r float64) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()
	l, ok := m[k]
	if !ok {
		l = rate.NewLimiter(rate.Limit(r), 1)
		m[k] = l
	}
	return l
}

// wait acquires a rate-limit token. A wait extending beyond ctx's deadline fails immediately
// with a wrapped context.DeadlineExceeded, distinguishable from a network error.
func wait(ctx context.Context, l *rate.Limiter) error {
	err := l.Wait(ctx)
	if err != nil && ctx.Err() == nil {
		if _, ok := ctx.Deadline(); ok {
			return fmt.Errorf("%w: %w", context.DeadlineExceeded, err)
		}
	}
	return err
}

// Clients selects source clients and grants target clients only when authorised by procedure
// contact type.
func (e *Egress) Clients(target bool, sources []string) Clients {
	c := Clients{
		DNS:        &resolver{e: e},
		ThirdParty: &thirdParty{e: e, sources: sources},
	}
	if target {
		c.HTTP = &targetHTTP{e: e}
		c.TCP = &targetTCP{e: e}
	}
	return c
}
