package iplookup

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/input"
)

// Source is where a part of a record comes from.
type Source string

// The sources, in the order a record's keys list them. It is also the order that decides which
// failing source gives an address its error code when none of its sources answered.
const (
	SourceCymru        Source = "cymru"
	SourceRDAP         Source = "rdap"
	SourcePTR          Source = "ptr"
	SourceRIPEstat     Source = "ripestat"
	SourceInternetDB   Source = "internetdb"
	SourceHackerTarget Source = "hackertarget"
	SourceProbe        Source = "probe"
)

// Sources is every source, in the record's order.
func Sources() []Source {
	return []Source{SourceCymru, SourceRDAP, SourcePTR, SourceRIPEstat, SourceInternetDB, SourceHackerTarget, SourceProbe}
}

// sourceRank is the position of s in Sources, or len(Sources()) for one it does not know.
func sourceRank(s Source) int {
	for i, o := range Sources() {
		if o == s {
			return i
		}
	}
	return len(Sources())
}

// Failure is one source that did not answer for an address.
type Failure struct {
	Source    Source      `json:"source"`
	Code      clierr.Code `json:"code"`
	Message   string      `json:"message"`
	Transient bool        `json:"transient"`
	// Quota is true only for a source whose allowance is spent (HackerTarget's). It never counts
	// against the address's success, and it is never worth a retry before the allowance resets.
	Quota bool `json:"quota"`
}

// The state of a port, after the TCP scan.
const (
	PortOpen      = "open"
	PortClosed    = "closed"
	PortNoAnswer  = "no-answer"
	PortNotProbed = "not-probed" // the deadline came first
)

// The outcome of a TLS handshake or a web request.
const (
	OutcomeOK        = "ok"
	OutcomeNoAnswer  = "no-answer"
	OutcomeRefused   = "refused"
	OutcomeNotTLS    = "not-tls"
	OutcomeReset     = "reset"
	OutcomeNotProbed = "not-probed"
)

// Port is what the TCP scan found on one port of an address.
type Port struct {
	Port  int    `json:"port"`
	State string `json:"state"`
	// Banner is the unprompted bytes the port sent, as text (see BannerText); null when none.
	Banner *string `json:"banner"`
}

// TLSEntry is one TLS handshake: on one port, for one server name.
type TLSEntry struct {
	Port int `json:"port"`
	// ServerName is the name the handshake asked for; null when it asked for none.
	ServerName *string `json:"server_name"`
	Outcome    string  `json:"outcome"`
	// Names are the certificate's DNS and IP names; [] when there is no certificate.
	Names  []string `json:"names"`
	Issuer *string  `json:"issuer"`
	// Expiry is the certificate's last day as YYYY-MM-DD in UTC (see Expiry).
	Expiry *string `json:"expiry"`
}

// MarshalJSON encodes the entry with names as [] when there are none.
func (e TLSEntry) MarshalJSON() ([]byte, error) {
	type plain TLSEntry
	if e.Names == nil {
		e.Names = []string{}
	}
	return json.Marshal(plain(e))
}

// WebEntry is one GET /: on one port, with one Host.
type WebEntry struct {
	Port   int    `json:"port"`
	Scheme string `json:"scheme"`
	// Host is the Host the request carried: an input hostname, or the address.
	Host    string  `json:"host"`
	Outcome string  `json:"outcome"`
	Status  *int    `json:"status"`
	Server  *string `json:"server"`
	Title   *string `json:"title"`
	// Location is the redirect's target, which is reported and not followed.
	Location *string `json:"location"`
}

// Record is the answer for one address. A single unknown value is a nil pointer (null) and a list
// that has no entries is empty and not nil ([]); a value from a source that failed is nil, lists
// too, so a nil list is a source that did not answer. Hostnames and Failures encode as [] when
// they are nil. The active-only keys encode only when selected (see Projected). The order of the
// fields is the order of the keys.
type Record struct {
	Address   string        `json:"address"`
	Hostnames []string      `json:"hostnames"`
	Kind      addrkind.Kind `json:"kind"`

	ASN           *uint32  `json:"asn"`
	ASName        *string  `json:"as_name"`
	ASPrefix      *string  `json:"as_prefix"`
	RDAPNetblock  *string  `json:"rdap_netblock"`
	RDAPOrg       *string  `json:"rdap_org"`
	RDAPRegistry  *string  `json:"rdap_registry"`
	PTR           []string `json:"ptr"`
	Provider      *string  `json:"provider"`
	ProviderClass *string  `json:"provider_class"`
	GeoCountry    *string  `json:"geo_country"`
	GeoCity       *string  `json:"geo_city"`

	InternetDBPorts     []int    `json:"internetdb_ports"`
	InternetDBHostnames []string `json:"internetdb_hostnames"`
	InternetDBTags      []string `json:"internetdb_tags"`
	InternetDBCPEs      []string `json:"internetdb_cpes"`
	InternetDBVulns     []string `json:"internetdb_vulns"`

	ReverseIP      []string `json:"reverse_ip"`
	ReverseIPCount *int     `json:"reverse_ip_count"`

	// NotContacted is why --active sent the address nothing; null when it was contacted.
	NotContacted *string    `json:"not_contacted"`
	Ports        []Port     `json:"ports"`
	TLS          []TLSEntry `json:"tls"`
	Web          []WebEntry `json:"web"`

	Failures []Failure `json:"failures"`
}

// NewRecord is the record of a with its keys unknown: its canonical address, the hostnames that
// gave it, its kind and no failures.
func NewRecord(a Address) Record {
	addr := a.Addr.Unmap().WithZone("")
	return Record{
		Address:   addr.String(),
		Hostnames: append([]string{}, a.Hostnames...),
		Kind:      addrkind.Of(addr),
		Failures:  []Failure{},
	}
}

// AddFailure adds f to the record's failures.
func (r *Record) AddFailure(f Failure) { r.Failures = append(r.Failures, f) }

// Failed reports whether s has a failure in the record, a quota one included.
func (r Record) Failed(s Source) bool {
	return slices.ContainsFunc(r.Failures, func(f Failure) bool { return f.Source == s })
}

// Netblock is a registered range as the record shows it: the CIDR when the range is exactly one,
// else "start-end".
func Netblock(start, end netip.Addr) string {
	start, end = start.Unmap(), end.Unmap()
	cidrs := input.RangeCIDRs(start, end)
	switch len(cidrs) {
	case 0:
		return ""
	case 1:
		return cidrs[0].String()
	}
	return start.String() + "-" + end.String()
}

// Expiry is a certificate's last day as YYYY-MM-DD in UTC.
func Expiry(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// MaxBanner is the most bytes of a banner a record keeps.
const MaxBanner = 1024

// BannerText is the unprompted bytes of a port as text: at most MaxBanner bytes, invalid UTF-8
// replaced with U+FFFD.
func BannerText(b []byte) string {
	if len(b) > MaxBanner {
		cut := MaxBanner
		for cut > 0 && !utf8.RuneStart(b[cut]) { // the cut is inside a character: drop it whole
			cut--
		}
		b = b[:cut]
	}
	return strings.ToValidUTF8(string(b), "\uFFFD")
}
