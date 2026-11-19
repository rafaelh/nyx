// Package egress is the only place nyx performs network I/O. Every request
// to a target-owned system passes through the policy checks here, and the
// package returns its own types so that nothing from net, net/http or
// crypto/tls reaches the stages (see the import-boundary test).
package egress

import (
	"cmp"
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

// Policy is what egress enforces. The runner builds a new Policy whenever the
// Scope changes. Egress never reads the store.
type Policy struct {
	Scope          *scope.Scope
	Ack, Passive   bool
	Ports          []int
	SensitivePaths []string
	// Scripts are the script URLs egress.Script may request: the normalised URLs
	// of the script records the crawl made. Host scope, exclusion and port rules
	// apply to each as to any target request.
	Scripts map[string]bool
	// Resolutions maps in-scope and excluded hostnames to their addresses.
	Resolutions map[string][]netip.Addr
	// Candidates are discovered out-of-scope hostnames; ThirdPartyHTTP never contacts them.
	Candidates map[string]bool
	// Shared reports whether an address is shared provider infrastructure.
	Shared func(netip.Addr) bool
	// OwnerUnknown reports whether nothing is known about an address's owner.
	// Port checks fail closed for such addresses, but unlike Shared it never
	// widens what HTTP may do.
	OwnerUnknown func(netip.Addr) bool
	// Excluded is told about each address that triggered an exclusion at dial time.
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

// portIneligible refuses an address that may not be port-checked (excluded, or neither inside an
// in-scope netblock nor dedicated and known), reporting an excluded one.
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

// targetRefusal is the gate shared by every target client: a policy must be
// installed, the run must not be passive, and the operator must have acknowledged.
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

// Options configure an Egress. The test hooks (ResolverAddrs, SourceBaseURLs,
// DialMap) redirect traffic without changing any policy logic.
type Options struct {
	ResolverAddrs []string // default: 1.1.1.1, 8.8.8.8, 9.9.9.9 on port 53
	// SourceBaseURLs maps a source pattern, or an exact host (checked first), to a base URL.
	SourceBaseURLs map[string]string
	DialMap        map[string]string // "ip:port" -> "host:port" actually dialled

	DNSTimeout, ConnectTimeout, BannerWait, HTTPTimeout time.Duration

	RateDNS, RatePerHost, RatePerSource float64

	// RouteLookup decides whether this machine has a route to an address when a
	// connect fails with ENETUNREACH, EHOSTUNREACH or EACCES. Default: a UDP
	// connect, which sends nothing.
	RouteLookup func(netip.Addr) error

	// Now is the clock certificates are checked against. Default: time.Now.
	Now func() time.Time

	// UserAgent is sent with every HTTP request, to a source and to a target
	// alike: nyx/<version>. Default: DefaultUserAgent.
	UserAgent string

	Keys     map[string]config.Secret
	Redactor *config.Redactor // default: built from Keys
}

// WithSettings returns o with rates, keys and redactor taken from the settings.
func (o Options) WithSettings(s config.Settings, r *config.Redactor) Options {
	o.RateDNS, o.RatePerHost, o.RatePerSource = s.Rate.DNS, s.Rate.PerHost, s.Rate.PerSource
	o.Keys, o.Redactor = s.Keys, r
	return o
}

// Clients are the clients handed to a stage. HTTP and TCP are nil for stages
// that do not contact target-owned systems.
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

	thirdParty *http.Client // shared by every stage's ThirdPartyHTTP
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
			// Four idle connections per host: nyx cve has four requests to the NVD in flight.
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
	return limiterFor(&e.mu, e.srcLim, pattern, e.opts.RatePerSource)
}

// limiterFor returns m's limiter for k, creating one at rate r on first use.
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

// Clients returns the clients for a stage. Target clients are only given to
// stages that contact target-owned systems.
func (e *Egress) Clients(target bool, sources []string) Clients {
	return e.ClientsWith(target, sources, nil)
}

// ClientsWith is Clients for a stage with candidate-exempt sources: hosts
// matching one of the exempt patterns skip the refusal of candidate hostnames
// (they are provider endpoints that a redirect may have recorded as candidates).
// An in-scope or excluded host is still refused.
func (e *Egress) ClientsWith(target bool, sources, exempt []string) Clients {
	c := Clients{
		DNS:        &resolver{e: e},
		ThirdParty: &thirdParty{e: e, sources: sources, exempt: exempt},
	}
	if target {
		c.HTTP = &targetHTTP{e: e}
		c.TCP = &targetTCP{e: e}
	}
	return c
}
