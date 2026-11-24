package iplookup

import (
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/lookup/batch"
)

// field describes a record key, its active-only status and all required sources. Dependencies
// are included: provider needs cymru because it uses the AS number.
type field struct {
	name    string
	always  bool // present whatever --fields selects
	active  bool // only under --active
	sources []Source
	value   func(*Record) any
}

// activeSources includes ownership classification, InternetDB's extra ports and the probe
// itself.
var activeSources = []Source{SourceCymru, SourceInternetDB, SourceProbe}

// table defines field ordering, selection, help names and validation in one place.
var table = []field{
	{name: "address", always: true, value: func(r *Record) any { return r.Address }},
	{name: "hostnames", always: true, value: func(r *Record) any { return nonNil(r.Hostnames) }},
	{name: "kind", always: true, value: func(r *Record) any { return r.Kind }},
	{name: "asn", sources: []Source{SourceCymru}, value: func(r *Record) any { return r.ASN }},
	{name: "as_name", sources: []Source{SourceCymru}, value: func(r *Record) any { return r.ASName }},
	{name: "as_prefix", sources: []Source{SourceCymru}, value: func(r *Record) any { return r.ASPrefix }},
	{name: "rdap_netblock", sources: []Source{SourceRDAP}, value: func(r *Record) any { return r.RDAPNetblock }},
	{name: "rdap_org", sources: []Source{SourceRDAP}, value: func(r *Record) any { return r.RDAPOrg }},
	{name: "rdap_registry", sources: []Source{SourceRDAP}, value: func(r *Record) any { return r.RDAPRegistry }},
	{name: "ptr", sources: []Source{SourcePTR}, value: func(r *Record) any { return r.PTR }},
	{name: "provider", sources: []Source{SourceCymru}, value: func(r *Record) any { return r.Provider }},
	{name: "provider_class", sources: []Source{SourceCymru}, value: func(r *Record) any { return r.ProviderClass }},
	{name: "geo_country", sources: []Source{SourceRIPEstat}, value: func(r *Record) any { return r.GeoCountry }},
	{name: "geo_city", sources: []Source{SourceRIPEstat}, value: func(r *Record) any { return r.GeoCity }},
	{name: "internetdb_ports", sources: []Source{SourceInternetDB}, value: func(r *Record) any { return r.InternetDBPorts }},
	{name: "internetdb_hostnames", sources: []Source{SourceInternetDB}, value: func(r *Record) any { return r.InternetDBHostnames }},
	{name: "internetdb_tags", sources: []Source{SourceInternetDB}, value: func(r *Record) any { return r.InternetDBTags }},
	{name: "internetdb_cpes", sources: []Source{SourceInternetDB}, value: func(r *Record) any { return r.InternetDBCPEs }},
	{name: "internetdb_vulns", sources: []Source{SourceInternetDB}, value: func(r *Record) any { return r.InternetDBVulns }},
	{name: "reverse_ip", sources: []Source{SourceHackerTarget, SourceCymru}, value: func(r *Record) any { return r.ReverseIP }},
	{name: "reverse_ip_count", sources: []Source{SourceHackerTarget, SourceCymru}, value: func(r *Record) any { return r.ReverseIPCount }},
	{name: "abusive_networks", value: func(r *Record) any { return r.AbusiveNetworks }},
	{name: "abusive_asn", sources: []Source{SourceCymru}, value: func(r *Record) any { return r.AbusiveASN }},
	{name: "drop_networks", value: func(r *Record) any { return r.DropNetworks }},
	{name: "drop_asn", sources: []Source{SourceCymru}, value: func(r *Record) any { return r.DropASN }},
	{name: "not_contacted", active: true, sources: []Source{SourceCymru}, value: func(r *Record) any { return r.NotContacted }},
	{name: "ports", active: true, sources: activeSources, value: func(r *Record) any { return r.Ports }},
	{name: "tls", active: true, sources: activeSources, value: func(r *Record) any { return r.TLS }},
	{name: "web", active: true, sources: activeSources, value: func(r *Record) any { return r.Web }},
	{name: "failures", always: true, value: func(r *Record) any { return nonNil(r.Failures) }},
}

// nonNil ensures empty lists encode as [] rather than null.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ActiveFieldNames is the keys only --active has, in order.
func ActiveFieldNames() []string {
	var names []string
	for _, f := range table {
		if f.active {
			names = append(names, f.name)
		}
	}
	return names
}

// ChoosableFieldNames lists mode-available optional keys. Mandatory keys are included
// regardless of --fields.
func ChoosableFieldNames(active bool) []string {
	var names []string
	for _, f := range table {
		if !f.always && (active || !f.active) {
			names = append(names, f.name)
		}
	}
	return names
}

// ValidFields formats selectable names plus all for error hints.
func ValidFields(active bool) string {
	return "valid fields: " + strings.Join(ChoosableFieldNames(active), ", ") + ", or all"
}

// Fields binds a record-key selection to its lookup mode.
type Fields struct {
	active bool
	has    batch.Selection // nil for the zero selection
}

// keys indexes the table's names.
var keys = func() batch.Keys {
	names := make([]string, len(table))
	for i, f := range table {
		names[i] = f.name
	}
	return batch.NewKeys(names)
}()

// fieldIndex is the position of the key in the table, or -1.
func fieldIndex(name string) int { return keys.Index(name) }

// Select parses comma-separated names or "all" into table order, ignoring blanks. Empty text
// keeps only mandatory keys. Unknown names and active-only fields requested without --active
// are returned separately; either invalidates the selection.
func Select(spec string, active bool) (f Fields, unknown, activeOnly []string) {
	sel := Fields{active: active, has: make(batch.Selection, len(table))}
	for i, t := range table {
		sel.has[i] = t.always
	}
	unknown = keys.Select(spec, func() { sel = AllFields(active) }, func(i int) {
		if table[i].active && !active {
			activeOnly = append(activeOnly, table[i].name)
			return
		}
		sel.has[i] = true
	})
	if unknown != nil || activeOnly != nil {
		return Fields{}, unknown, activeOnly
	}
	return sel, nil, nil
}

// AllFields returns every key permitted in the selected mode.
func AllFields(active bool) Fields {
	f := Fields{active: active, has: make(batch.Selection, len(table))}
	for i, t := range table {
		f.has[i] = t.always || !t.active || active
	}
	return f
}

// Active reports whether the selection was made for --active.
func (f Fields) Active() bool { return f.active }

// Has reports whether the key is selected.
func (f Fields) Has(name string) bool { return f.has.Has(fieldIndex(name)) }

// Names are the selected keys, in the record's order.
func (f Fields) Names() []string {
	var names []string
	for i, t := range table {
		if f.has.Has(i) {
			names = append(names, t.name)
		}
	}
	return names
}

// Needs checks direct and dependent source requirements. Active mode always needs Cymru to
// classify shared infrastructure before probing.
func (f Fields) Needs(s Source) bool {
	if f.has == nil {
		return false
	}
	if s == SourceCymru && f.NeedsSharedCheck() {
		return true
	}
	for i, t := range table {
		if f.has[i] && slices.Contains(t.sources, s) {
			return true
		}
	}
	return false
}

// Sources are the sources Needs reports, in the record's order.
func (f Fields) Sources() []Source {
	var out []Source
	for _, s := range Sources() {
		if f.Needs(s) {
			out = append(out, s)
		}
	}
	return out
}

// Sourceless identifies selected network-list fields that can answer locally for every public
// address, even when all requested sources fail.
func (f Fields) Sourceless() bool {
	for i, t := range table {
		if f.has.Has(i) && !t.always && len(t.sources) == 0 {
			return true
		}
	}
	return false
}

// NeedsProbe enables scanning for selected ports, TLS or web fields.
func (f Fields) NeedsProbe() bool { return f.Needs(SourceProbe) }

// NeedsTLS enables handshakes on open TLS ports when TLS output is selected.
func (f Fields) NeedsTLS() bool { return f.Has("tls") }

// NeedsWeb enables GET / on open web ports when web output is selected.
func (f Fields) NeedsWeb() bool { return f.Has("web") }

// NeedsSharedCheck is always true in active mode, regardless of selected output.
func (f Fields) NeedsSharedCheck() bool { return f.has != nil && f.active }

// Projected encodes selected keys in field-table order.
type Projected struct {
	rec Record
	f   Fields
}

// Project cuts r down to the selection.
func (f Fields) Project(r Record) Projected { return Projected{rec: r, f: f} }

// Record is the record Projected was made from, whole.
func (p Projected) Record() Record { return p.rec }

// Fields is the selection.
func (p Projected) Fields() Fields { return p.f }

// MarshalJSON encodes the selected keys, each as the whole record encodes it.
func (p Projected) MarshalJSON() ([]byte, error) {
	return keys.Marshal(p.f.has, func(i int) any { return table[i].value(&p.rec) })
}
