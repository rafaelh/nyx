// Package provider identifies shared infrastructure from CNAME suffixes, provider ranges and
// origin ASNs. Classification is pure and recalculated when read.
package provider

import (
	"cmp"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"go.yaml.in/yaml/v3"
)

//go:embed providers.yaml
var embedded []byte

// Match is a provider and service.
type Match struct{ Provider, Service string }

// Owner is the origin AS of an address, from Team Cymru or an in-scope netblock.
type Owner struct {
	ASN    int
	Holder string
	Known  bool
}

// Range is a published provider address range.
type Range struct {
	Prefix                    netip.Prefix
	Provider, Service, Region string
}

// Ranges indexes prefixes by length, avoiding full scans when matching addresses.
type Ranges struct {
	all          []Range
	idx          map[netip.Prefix][]int // masked prefix -> positions in all
	lens4, lens6 []int                  // distinct prefix lengths, per family
}

// NewRanges indexes rs.
func NewRanges(rs []Range) *Ranges {
	x := &Ranges{all: rs, idx: map[netip.Prefix][]int{}}
	for i, r := range rs {
		p := r.Prefix.Masked()
		x.idx[p] = append(x.idx[p], i)
		lens := &x.lens6
		if p.Addr().Is4() {
			lens = &x.lens4
		}
		if !slices.Contains(*lens, p.Bits()) {
			*lens = append(*lens, p.Bits())
		}
	}
	return x
}

// covering returns the ranges that contain a, in their original order.
func (x *Ranges) covering(a netip.Addr) []*Range {
	if x == nil {
		return nil
	}
	lens := x.lens6
	if a.Is4() {
		lens = x.lens4
	}
	var pos []int
	for _, b := range lens {
		p, _ := a.Prefix(b)
		pos = append(pos, x.idx[p]...)
	}
	slices.Sort(pos)
	out := make([]*Range, len(pos))
	for i, j := range pos {
		out[i] = &x.all[j]
	}
	return out
}

// Result describes provider classification, evidence type, service, region and class. Published
// CDN ranges use class cdn; other ranges may leave it blank. Overlapping providers' names,
// services and regions are semicolon-joined.
type Result struct {
	Known, Shared     bool
	Provider, Service string
	Evidence          string
	Class             string
	Region            string
}

// ClassSaaS marks an entry or address served by a third-party SaaS platform.
const ClassSaaS = "saas"

// ClassCDN marks an address served by a content delivery network.
const ClassCDN = "cdn"

// ClassHyperscaler marks customer-dedicated cloud machines. ASN-only recon treats them as
// Shared conservatively, but they are not SharedInfrastructure.
const ClassHyperscaler = "hyperscaler"

// ClassSharedHosting marks an address of a host that serves many customers' sites from one
// address.
const ClassSharedHosting = "shared-hosting"

// ClassWAF identifies fronting firewalls. ASN entries in this class are shared like CDN
// entries.
const ClassWAF = "waf"

// SharedInfrastructure identifies multi-customer CDN/SaaS/WAF/hosting addresses. Hyperscalers
// are excluded: recon's conservative Shared flag alone does not mean a cloud machine serves
// several customers.
func (r Result) SharedInfrastructure() bool { return r.Shared && r.Class != ClassHyperscaler }

// Entry is a provider CNAME match. NXDomain marks claimable dangling chains; Body matches
// unclaimed-resource responses.
type Entry struct {
	Match
	Suffix, Class string
	NXDomain      bool
	Body          string
	re            *regexp.Regexp
}

// BodyMatches checks the unclaimed-resource fingerprint.
func (e Entry) BodyMatches(body []byte) bool { return e.re != nil && e.re.Match(body) }

// Hash identifies job-relevant fingerprint data so changing one entry reruns its jobs
// without invalidating others.
func (e Entry) Hash() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%v|%s", e.Suffix, e.Provider, e.Service, e.Class, e.NXDomain, e.Body)))
	return hex.EncodeToString(sum[:4])
}

// addrRange identifies static provider ranges, including apex-addressed SaaS.
type addrRange struct {
	prefix netip.Prefix
	Match
	class string
}

// txtPrefix is a TXT value prefix (lower case) and the platform it verifies ownership for.
type txtPrefix struct{ prefix, platform string }

// DB is the parsed providers.yaml.
type DB struct {
	cnames  map[string]Entry // by normalised suffix
	asns    map[int]struct{ provider, class string }
	ranges  []addrRange
	txt     []txtPrefix
	domains map[string]string // the provider that operates each normalised suffix
}

var (
	once sync.Once
	def  *DB
)

// Default returns the embedded database.
func Default() *DB {
	once.Do(func() {
		db, err := Parse(embedded)
		if err != nil {
			panic("provider: embedded providers.yaml: " + err.Error())
		}
		def = db
	})
	return def
}

// Parse reads a providers.yaml document.
func Parse(b []byte) (*DB, error) {
	var raw struct {
		CNAME []struct {
			Suffix, Provider, Service, Class, Body string
			NXDomain                               bool `yaml:"nxdomain"`
		}
		ASN []struct {
			ASN             int
			Provider, Class string
		}
		Ranges []struct {
			CIDR, Provider, Service, Class string
		}
		TXT     []struct{ Prefix, Platform string }
		Domains []struct{ Suffix, Provider string }
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	db := &DB{asns: map[int]struct{ provider, class string }{}, cnames: map[string]Entry{}, domains: map[string]string{}}
	for _, c := range raw.CNAME {
		e := Entry{Match: Match{c.Provider, c.Service}, Suffix: dnsname.Normalise(c.Suffix), Class: c.Class, NXDomain: c.NXDomain, Body: c.Body}
		if c.Body != "" {
			re, err := regexp.Compile(c.Body)
			if err != nil {
				return nil, fmt.Errorf("cname %s: body %q: %w", c.Suffix, c.Body, err)
			}
			e.re = re
		}
		if _, dup := db.cnames[e.Suffix]; !dup {
			db.cnames[e.Suffix] = e
		}
	}
	for _, a := range raw.ASN {
		db.asns[a.ASN] = struct{ provider, class string }{a.Provider, a.Class}
	}
	for _, r := range raw.Ranges {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			return nil, fmt.Errorf("range %q: %w", r.CIDR, err)
		}
		db.ranges = append(db.ranges, addrRange{prefix: p.Masked(), Match: Match{r.Provider, r.Service}, class: r.Class})
	}
	for _, t := range raw.TXT {
		if t.Prefix == "" || t.Platform == "" {
			return nil, fmt.Errorf("txt entry %+v needs a prefix and a platform", t)
		}
		db.txt = append(db.txt, txtPrefix{strings.ToLower(t.Prefix), t.Platform})
	}
	for _, d := range raw.Domains {
		if d.Suffix == "" || d.Provider == "" {
			return nil, fmt.Errorf("domains entry %+v needs a suffix and a provider", d)
		}
		if n := dnsname.Normalise(d.Suffix); db.domains[n] == "" {
			db.domains[n] = d.Provider
		}
	}
	return db, nil
}

// CNAMEEntry resolves provider suffixes at DNS label boundaries.
func (db *DB) CNAMEEntry(target string) (Entry, bool) {
	return longestSuffix(db.cnames, dnsname.Normalise(target))
}

// longestSuffix prefers service-specific matches over generic provider domains by trying
// successively shorter name suffixes.
func longestSuffix[V any](m map[string]V, name string) (V, bool) {
	for {
		if v, ok := m[name]; ok {
			return v, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			var zero V
			return zero, false
		}
		name = name[i+1:]
	}
}

func (db *DB) staticRange(a netip.Addr) (addrRange, bool) {
	for _, r := range db.ranges {
		if r.prefix.Contains(a) {
			return r, true
		}
	}
	return addrRange{}, false
}

// rangeRule resolves one provider's nonempty, source-ordered ranges. It fills Shared, Service,
// Region and Class; classifyRanges supplies the rest.
type rangeRule func(rs []*Range) Result

// rangeRules defines the meaning of each supported provider's published ranges. Unlisted
// providers are ignored.
var rangeRules = map[string]rangeRule{
	"aws":          awsRule,
	"gcp":          wholeListRule(true, ""),
	"cloudflare":   wholeListRule(true, ClassCDN),
	"fastly":       wholeListRule(true, ClassCDN),
	"digitalocean": wholeListRule(false, ""),
	"linode":       wholeListRule(false, ""),
	"oracle":       oracleRule,
}

// HasRangeRule checks whether fetched ranges have classification logic; unsupported publishers
// are ignored.
func HasRangeRule(provider string) bool {
	_, ok := rangeRules[provider]
	return ok
}

// wholeListRule classifies all provider ranges alike. It omits service because the list does
// not distinguish services.
func wholeListRule(shared bool, class string) rangeRule {
	return func(rs []*Range) Result { return Result{Shared: shared, Region: rs[0].Region, Class: class} }
}

// awsRule requires EC2 range evidence for dedicated hosting. Other services imply shared
// hosting; AMAZON alone fails closed. CloudFront additionally sets class cdn.
func awsRule(rs []*Range) Result {
	var ec2, amazon *Range
	for _, r := range rs {
		switch r.Service {
		case "EC2":
			ec2 = cmp.Or(ec2, r)
		case "AMAZON":
			amazon = cmp.Or(amazon, r)
		case "CLOUDFRONT":
			return Result{Shared: true, Service: r.Service, Region: r.Region, Class: ClassCDN}
		default:
			return Result{Shared: true, Service: r.Service, Region: r.Region}
		}
	}
	if ec2 != nil {
		return Result{Service: "EC2", Region: ec2.Region}
	}
	return Result{Shared: true, Region: amazon.Region}
}

// oracleRule treats OSN and OBJECT_STORAGE as shared and other ranges as dedicated, preferring
// shared on overlap. Reporting sorts by service then region for stable results.
func oracleRule(rs []*Range) Result {
	slices.SortFunc(rs, func(a, b *Range) int {
		return cmp.Or(cmp.Compare(a.Service, b.Service), cmp.Compare(a.Region, b.Region))
	})
	pick, shared := rs[0], false
	for _, r := range rs {
		if r.Service == "OSN" || r.Service == "OBJECT_STORAGE" {
			pick, shared = r, true
			break
		}
	}
	return Result{Shared: shared, Service: pick.Service, Region: pick.Region}
}

// classifyRanges applies each provider's overlap rules before merging providers in name order.
// Any shared result makes the address shared, failing closed. No recognised covering range
// returns ok=false.
func classifyRanges(covering []*Range) (res Result, ok bool) {
	by := map[string][]*Range{}
	for _, r := range covering {
		if _, known := rangeRules[r.Provider]; known {
			by[r.Provider] = append(by[r.Provider], r)
		}
	}
	if len(by) == 0 {
		return Result{}, false
	}
	var names, services, regions []string
	res = Result{Known: true, Evidence: "range"}
	for _, p := range slices.Sorted(maps.Keys(by)) {
		r := rangeRules[p](by[p])
		names = append(names, p)
		if r.Service != "" {
			services = append(services, r.Service)
		}
		if r.Region != "" {
			regions = append(regions, r.Region)
		}
		res.Shared = res.Shared || r.Shared
		res.Class = cmp.Or(res.Class, r.Class)
	}
	res.Provider = strings.Join(names, ";")
	res.Service = strings.Join(services, ";")
	res.Region = strings.Join(regions, ";")
	return res, true
}

// Classify prefers published ranges over ASN fallback, but a CDN ASN keeps an address shared
// even inside a dedicated provider range. Ownership or a matching range makes the address
// Known. Hyperscaler ASN-only matches, including Azure without ranges, fail closed.
func (db *DB) Classify(a netip.Addr, owner Owner, ranges *Ranges) Result {
	a = a.Unmap()
	if res, ok := classifyRanges(ranges.covering(a)); ok {
		// A dedicated-hosting list can include CDN space, such as Akamai within Linode
		// ranges. CDN origin-AS evidence takes precedence.
		if r, ok := db.asnResult(owner); ok && !res.Shared && r.Class == ClassCDN {
			return r
		}
		return res
	}
	if r, ok := db.staticRange(a); ok {
		return Result{Known: true, Shared: true, Provider: r.Provider, Service: r.Service, Evidence: "range", Class: r.class}
	}
	if r, ok := db.asnResult(owner); ok {
		return r
	}
	return Result{Known: owner.Known}
}

// asnResult classifies known provider ASNs as shared fallback evidence.
func (db *DB) asnResult(owner Owner) (Result, bool) {
	p, ok := db.asns[owner.ASN]
	if !owner.Known || !ok {
		return Result{}, false
	}
	return Result{Known: true, Shared: true, Provider: p.provider, Evidence: "asn", Class: p.class}, true
}

// Verification identifies TXT ownership platforms by case-insensitive prefix.
func (db *DB) Verification(value string) (string, bool) {
	v := strings.ToLower(strings.TrimSpace(value))
	for _, t := range db.txt {
		if strings.HasPrefix(v, t.prefix) {
			return t.platform, true
		}
	}
	return "", false
}

// DomainOwner labels managed dependencies by suffix, respecting DNS label boundaries.
func (db *DB) DomainOwner(name string) (string, bool) {
	return longestSuffix(db.domains, dnsname.Normalise(name))
}
