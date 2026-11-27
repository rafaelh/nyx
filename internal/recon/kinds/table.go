package kinds

import (
	"net/netip"
	"strings"

	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/scope"
)

// Record handles define attributes and visibility rules. Fields always supplied omit omitempty
// so zero values are stored and rendered. Optional fields use omitempty; pointers distinguish
// zero from unknown, such as false for a checked certificate versus nil when TLS was not
// checked. Since observations merge field by field, procedures omit fields they do not know.

// Entities use scope placement; in-scope roots are inputs and are not counted as discoveries.
var (
	Hostname = define[HostnameAttrs](Kind{Name: "hostname", Singular: "host", Category: Hosts, place: placeHost, Printed: true, Change: LabelHostname})
	Root     = defineBare(Kind{Name: "root", Singular: "root", place: placeRoot})
	Netblock = define[NetblockAttrs](Kind{Name: "netblock", Singular: "netblock", Category: Netblocks, place: placeNetblock, Change: LabelNetblock})
	// ExcludedKind records dial-time exclusions; Excluded names their summary category.
	ExcludedKind = define[ExcludedAttrs](Kind{Name: "excluded", Singular: "excluded", place: placeExcluded})
)

// placeHost places a hostname or root as the scope classifies it, leaving a candidate under a
// known provider's domain unlisted (vendorName).
func placeHost(sc *scope.Scope, _ *inventory.Inventory, key string) (scope.Class, bool) {
	class := sc.ClassifyHost(key).Class
	return class, class != scope.Candidate || !vendorName(key)
}

// placeRoot places a root by its name alone: a candidate root in scope by an address of its own
// stays a candidate root, since passing it as a domain is still how its subdomains are found,
// while its hostname record is placed in scope. A candidate under a known provider's domain is
// unlisted, as a hostname is.
func placeRoot(sc *scope.Scope, _ *inventory.Inventory, key string) (scope.Class, bool) {
	class := sc.ClassifyName(key).Class
	return class, class != scope.Candidate || !vendorName(key)
}

// vendorName reports whether a known DNS, mail or SaaS provider operates the name's domain
// (provider.DomainOwner). Such a name is the provider's or one of its tenants', never a domain to
// bring into scope, so it is no candidate; the dependency itself is a third party.
func vendorName(name string) bool {
	_, ok := provider.Default().DomainOwner(name)
	return ok
}

// placeNetblock includes input and input-derived CIDRs in scope, and classifies other valid
// CIDRs as candidates. Invalid CIDR keys remain unlisted, and so does a candidate that an
// in-scope netblock contains: promoting a wider range clears the candidates inside it.
func placeNetblock(sc *scope.Scope, _ *inventory.Inventory, key string) (scope.Class, bool) {
	p, err := netip.ParsePrefix(key)
	if err != nil {
		return 0, false
	}
	if sc.HasNetblock(key) {
		return scope.InScope, true
	}
	if sc.InsideNetblock(p) {
		return 0, false
	}
	return scope.Candidate, true
}

// placeExcluded places a record of what triggered an exclusion as excluded.
func placeExcluded(*scope.Scope, *inventory.Inventory, string) (scope.Class, bool) {
	return scope.Excluded, true
}

// HostnameAttrs: the Common Crawl index a name was found in, if it came from one.
type HostnameAttrs struct {
	Index string `json:"index,omitempty"`
}

// NetblockAttrs identifies the announcing ASN and, for organisation pivots, the searched
// organisation.
type NetblockAttrs struct {
	ASN string `json:"asn,omitempty"`
	Org string `json:"org,omitempty"`
}

// ExcludedAttrs: why it was excluded.
type ExcludedAttrs struct {
	Reason string `json:"reason"`
}

// DNS and address inventory.
var (
	Resolution    = defineJoined(Kind{Name: "resolution", Change: "resolution"}, resolutionFields)
	IP            = defineBare(Kind{Name: "ip", Singular: "ip", Category: "ips", Change: LabelAddress})
	Unresolved    = define[UnresolvedAttrs](Kind{Name: "unresolved", Singular: "unresolved name", Category: "unresolved names", Change: "unresolved name"})
	Wildcard      = define[WildcardAttrs](Kind{Name: "wildcard"})
	IPOwner       = define[IPOwnerAttrs](Kind{Name: "ip_owner"})
	NetblockOwner = define[NetblockOwnerAttrs](Kind{Name: "netblock_owner"})
	IPHostname    = defineJoined(Kind{Name: "ip_hostname"}, ipHostnameFields)
	ProviderRange = defineJoined(Kind{Name: "provider_range"}, providerRangeFields)
)

// ResolutionAttrs describes a DNS answer keyed "<name>|<TYPE>|<value>". Types include host
// A/AAAA/CNAME, root NS/SOA/TXT/CAA and service-name SRV. Only A, AAAA and CNAME establish
// resolution for scope, contact or wildcard decisions.
type ResolutionAttrs struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func resolutionFields(a *ResolutionAttrs) []*string { return []*string{&a.Name, &a.Type, &a.Value} }

// UnresolvedAttrs: why a name has no address (NXDOMAIN, SERVFAIL or NODATA).
type UnresolvedAttrs struct {
	RCode string `json:"rcode"`
}

// WildcardAttrs: what every name in a wildcard zone resolves to.
type WildcardAttrs struct {
	Addrs []string `json:"addrs"`
	CNAME string   `json:"cname"`
}

// IPOwnerAttrs: who announces an address.
type IPOwnerAttrs struct {
	ASN    int    `json:"asn"`
	Prefix string `json:"prefix"`
	Holder string `json:"holder"`
}

// IPHostnameAttrs preserves a source-reported reverse name, keyed "<ip>|<hostname>".
type IPHostnameAttrs struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Source   string `json:"source"`
}

func ipHostnameFields(a *IPHostnameAttrs) []*string { return []*string{&a.IP, &a.Hostname} }

// ProviderRangeAttrs: an address range a cloud or SaaS provider publishes.
type ProviderRangeAttrs struct {
	Provider string `json:"provider"`
	Prefix   string `json:"prefix"`
	Service  string `json:"service"`
	Region   string `json:"region"`
}

// providerRangeFields make the key "<provider>|<prefix>|<service>".
func providerRangeFields(a *ProviderRangeAttrs) []*string {
	return []*string{&a.Provider, &a.Prefix, &a.Service}
}

// Web.
var (
	WebService = define[WebServiceAttrs](Kind{Name: "web_service", Singular: "web service", Category: "web services", Printed: true, HostAttr: "host", Change: LabelWebService})
	HTTPPort   = define[HTTPPortAttrs](Kind{Name: "http_port"})
	URL        = define[URLAttrs](Kind{Name: "url", Singular: "url", Category: "urls", HostAttr: "host", Change: "url"})
)

// WebServiceAttrs holds service evidence from an origin probe.
type WebServiceAttrs struct {
	URL          string `json:"url"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Scheme       string `json:"scheme"`
	Status       int    `json:"status"`
	Server       string `json:"server"`
	Technologies string `json:"technologies"` // ";"-joined
	Redirect     string `json:"redirect,omitempty"`
	FinalURL     string `json:"final_url,omitempty"`
	Title        string `json:"title,omitempty"`
	// TLS, set only when the service presented a certificate.
	TLSSubject    string `json:"tls_subject,omitempty"`
	TLSSANs       string `json:"tls_sans,omitempty"` // ";"-joined
	TLSIssuer     string `json:"tls_issuer,omitempty"`
	TLSExpiry     string `json:"tls_expiry,omitempty"` // YYYY-MM-DD
	TLSError      string `json:"tls_error,omitempty"`
	TLSSelfSigned *bool  `json:"tls_self_signed,omitempty"`
	TLSVersion    string `json:"tls_version,omitempty"`
	TLSCipher     string `json:"tls_cipher,omitempty"`
	TLSTrust      string `json:"tls_trust,omitempty"`
	// BodyLen records bytes read from the first response, subject to the body cap, for
	// origin comparisons. Older service records may omit it.
	BodyLen int `json:"body_len,omitempty"`
}

// Stored trust strings mirror egress certificate classifications, pinned by tests.
const (
	TrustExpired          = "expired" // including not yet valid
	TrustHostnameMismatch = "hostname-mismatch"
	TrustSelfSigned       = "self-signed"
	TrustUntrustedChain   = "untrusted-chain"
	TrustTrusted          = "trusted"
)

// TLSTrust holds a Trust value, or "" when no certificate was seen. Older records infer it from
// tls_error and tls_self_signed for consistent reading.
func TLSTrust(a WebServiceAttrs) string {
	if a.TLSTrust != "" {
		return a.TLSTrust
	}
	if a.TLSError == "" && a.TLSSelfSigned == nil {
		return ""
	}
	switch {
	case strings.Contains(a.TLSError, "certificate has expired or is not yet valid"):
		return TrustExpired
	case strings.Contains(a.TLSError, "certificate is valid for"), strings.Contains(a.TLSError, "is not valid for any names"),
		strings.Contains(a.TLSError, "any IP SANs"), strings.Contains(a.TLSError, "relies on legacy Common Name field"):
		return TrustHostnameMismatch
	case a.TLSSelfSigned != nil && *a.TLSSelfSigned:
		return TrustSelfSigned
	case a.TLSError != "":
		return TrustUntrustedChain
	}
	return TrustTrusted
}

// HTTPPortAttrs: a non-standard port that answered HTTP, for the probe.
type HTTPPortAttrs struct {
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
}

// URLAttrs describes a crawled, redirected or archived URL. Status is present only after
// fetching it.
type URLAttrs struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Status int    `json:"status,omitempty"`
}

// Ports.
var OpenPort = defineKeyed(Kind{Name: "open_port", Singular: "open port", Category: "open ports (confirmed)", Printed: true, PortKey: true, Change: LabelOpenPort},
	func(a OpenPortAttrs) string { return portKey(a.IP, a.Port) },
	func(key string, a *OpenPortAttrs) { rebuildPort(key, &a.IP, &a.Port) })

// OpenPortAttrs holds a TCP port and any unprompted banner, escaped using strconv.Quote rules
// without surrounding quotes. The key is the address/port pair.
type OpenPortAttrs struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner"`
}

// Finding attributes and console text belong to the findings package. It installs a formatter
// through SetFindingFound to avoid an import cycle.
var Finding = define[map[string]any](Kind{Name: "finding", Singular: "finding", Category: "findings", Printed: true, Change: LabelFinding,
	Found: func(r store.Record) map[string]any { return findingFound(r) }})

// findingFound describes a finding's found line; see SetFindingFound.
var findingFound = func(store.Record) map[string]any { return nil }

// SetFindingFound installs the finding event formatter during findings package initialisation,
// before records are read.
func SetFindingFound(found func(store.Record) map[string]any) { findingFound = found }

// Evidence: procedures store these, the findings package derives findings from them.
var (
	TakeoverHTTP   = define[TakeoverHTTPAttrs](Kind{Name: "takeover_http"})
	Storage        = define[StorageAttrs](Kind{Name: "storage"})
	StorageAccount = define[StorageAccountAttrs](Kind{Name: "storage_account"})
	StorageObject  = define[StorageObjectAttrs](Kind{Name: "storage_object"})
	StorageRef     = define[StorageRefAttrs](Kind{Name: "storage_ref", HostAttr: "page_host"})
	SensitiveHit   = define[SensitiveHitAttrs](Kind{Name: "sensitive_hit"})
	EmailPosture   = define[EmailPostureAttrs](Kind{Name: "email_posture", HostKey: true, Change: "email posture"})
)

// TakeoverHTTPAttrs records an unclaimed-resource page on a provider-hosted service.
type TakeoverHTTPAttrs struct {
	Host            string `json:"host"`
	URL             string `json:"url"`
	Status          int    `json:"status"`
	Service         string `json:"service"`
	Provider        string `json:"provider"`
	ProviderService string `json:"provider_service"`
	CNAME           string `json:"cname"`
}

// StorageAttrs records an anonymous listing result. Exists stays unknown for ambiguous
// responses such as Azure private/missing containers. Listable stays unset for nonexistent
// buckets.
type StorageAttrs struct {
	Provider    string   `json:"provider"`
	Name        string   `json:"name"`
	Container   string   `json:"container"`
	Exists      *bool    `json:"exists,omitempty"`
	Listable    *bool    `json:"listable,omitempty"`
	ObjectCount string   `json:"object_count,omitempty"` // "1000+" when the listing was cut
	FirstKeys   []string `json:"first_keys,omitempty"`
	Region      string   `json:"region,omitempty"`
}

// StorageAccountAttrs uses a pointer so missing or unusable Exists data remains unknown rather
// than implying a claimable Azure account.
type StorageAccountAttrs struct {
	Exists *bool `json:"exists"`
}

// StorageObjectAttrs: whether an object of a bucket can be fetched anonymously.
type StorageObjectAttrs struct {
	Bucket    string `json:"bucket"` // the storage record key
	Provider  string `json:"provider"`
	Name      string `json:"name"`
	Container string `json:"container"`
	Object    string `json:"object"`
	Public    bool   `json:"public"`
	URL       string `json:"url"`
}

// StorageRefAttrs: a page that points at a bucket, container or object.
type StorageRefAttrs struct {
	Provider  string `json:"provider"`
	Name      string `json:"name"`
	Container string `json:"container"`
	Object    string `json:"object"`
	URL       string `json:"url"`
	Page      string `json:"page"`
	PageHost  string `json:"page_host"`
	Via       string `json:"via"` // how the page refers to it: asset, link, ...
}

// SensitiveHitAttrs: a sensitive path that answered with its expected signature.
type SensitiveHitAttrs struct {
	Service   string `json:"service"`
	Host      string `json:"host"`
	URL       string `json:"url"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Size      Size   `json:"size"`
	Signature string `json:"signature"`
	Hash      string `json:"hash"` // of the sensitive-path entry
}

// EmailPostureAttrs: the SPF, DMARC, MX and DKIM records of a root domain.
type EmailPostureAttrs struct {
	MX            string `json:"mx"` // ";"-joined
	SPFRecords    int    `json:"spf_records"`
	SPF           string `json:"spf"`
	SPFAll        string `json:"spf_all"`
	SPFLookups    int    `json:"spf_lookups"`
	SPFError      string `json:"spf_error"`
	DMARC         string `json:"dmarc"`
	DMARCPolicy   string `json:"dmarc_policy"`
	DMARCSource   string `json:"dmarc_source"`
	DKIMSelectors string `json:"dkim_selectors"` // ";"-joined
	DKIMErrors    string `json:"dkim_errors"`    // ";"-joined
	MTASTS        string `json:"mta_sts"`        // "present", "absent", or "" for a root with no mail host
}

// NetblockOwnerAttrs: who announces a unit of an in-scope netblock.
type NetblockOwnerAttrs struct {
	ASN    int    `json:"asn"`
	Prefix string `json:"prefix"`
}
