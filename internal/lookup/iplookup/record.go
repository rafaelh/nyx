package iplookup

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/knowledge/addrkind"
	"github.com/rafaelh/nyx/internal/threatdata/abusive"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
)

// Source is where a part of a record comes from.
type Source string

// Source order determines record field order and which failing source supplies an address's
// error code.
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

// sourceRank orders known sources first, leaving unknown sources last.
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
	// Quota marks a spent source allowance. It does not make the address fail and is not
	// retryable until the allowance resets. No source sets it now (a spent HackerTarget quota
	// falls back to PTR records), but the key is part of the stable record.
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

// Port holds one TCP scan result.
type Port struct {
	Port  int    `json:"port"`
	State string `json:"state"`
	// Banner contains unprompted service bytes formatted as text, or null when absent.
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
	// Expiry records the UTC certificate expiry date; see Expiry.
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

// Record holds one address's answer in field order. Unknown scalars are nil; successful empty
// lists are []; failed-source lists are nil. Non-public addresses have null threat matches.
// Hostnames and Failures always encode as lists. Projected controls active-only fields.
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

	// AbusiveNetworks always holds a list for public addresses, empty when unmatched.
	// AbusiveASN contains at most one match: empty for an unlisted/unknown-owner AS, null
	// if Cymru failed. Both are null for non-public addresses.
	AbusiveNetworks []abusive.NetworkMatch `json:"abusive_networks"`
	AbusiveASN      []abusive.ASNMatch     `json:"abusive_asn"`

	// DropNetworks lists matching DROP/DROPv6 entries, most specific first. DropASN
	// contains at most one ASN-DROP match. Null and empty-list behaviour matches the
	// abusive fields.
	DropNetworks []spamhaus.NetworkMatch `json:"drop_networks"`
	DropASN      []spamhaus.ASNMatch     `json:"drop_asn"`

	// NotContacted is why --active sent the address nothing; null when it was contacted.
	NotContacted *string    `json:"not_contacted"`
	Ports        []Port     `json:"ports"`
	TLS          []TLSEntry `json:"tls"`
	Web          []WebEntry `json:"web"`

	Failures []Failure `json:"failures"`
}

// NewRecord records the address and where it came from, leaving lookup data unknown.
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

// Expiry formats a certificate's final validity date in UTC.
func Expiry(t time.Time) string { return t.UTC().Format(time.DateOnly) }

// MaxBanner is the most bytes of a banner a record keeps.
const MaxBanner = 1024

// BannerText caps greetings at MaxBanner bytes and replaces invalid UTF-8.
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
