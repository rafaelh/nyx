package iplookup

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// field is one key of the record: its name, whether only --active has it, and the sources its
// value needs. The sources are its own and the ones it depends on, so the provider lists cymru,
// which gives the AS number the provider is decided from.
type field struct {
	name    string
	always  bool // present whatever --fields selects
	active  bool // only under --active
	sources []Source
	value   func(*Record) any
}

// activeSources are the sources of the probing keys: the shared check (cymru), the ports to scan
// (internetdb) and the scan itself (probe).
var activeSources = []Source{SourceCymru, SourceInternetDB, SourceProbe}

// table is the one field table, in the record's key order. It does the selection, names the keys
// for help and checks the names a caller passes.
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

// nonNil is s, or an empty list when s is nil, so the key encodes as [].
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// FieldNames is every key the mode allows, in the record's key order, the always-present ones
// included.
func FieldNames(active bool) []string { return AllFields(active).Names() }

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

// ChoosableFieldNames is the keys the mode allows that a caller can choose with --fields, in
// order: the always-present ones are in every record whatever is chosen.
func ChoosableFieldNames(active bool) []string {
	var names []string
	for _, f := range table {
		if !f.always && (active || !f.active) {
			names = append(names, f.name)
		}
	}
	return names
}

// ValidFields names every value --fields accepts, for a hint: the keys ChoosableFieldNames gives,
// and all.
func ValidFields(active bool) string {
	return "valid fields: " + strings.Join(ChoosableFieldNames(active), ", ") + ", or all"
}

// Fields is a selection of the record's keys, with the mode it was made for.
type Fields struct {
	active bool
	has    []bool // by position in the table; nil for the zero selection
}

// fieldIndex is the position of the key in the table, or -1.
func fieldIndex(name string) int {
	return slices.IndexFunc(table, func(f field) bool { return f.name == name })
}

// Select reads a --fields value: names separated by commas, or all. Names are trimmed and empty
// ones are ignored, so "" selects only the keys that are always present. The selection is in the
// table's order whatever order the names were given in. unknown holds the names that are not keys
// at all, and activeOnly the names of keys that only --active has, given without it; with either
// the selection is empty.
func Select(spec string, active bool) (f Fields, unknown, activeOnly []string) {
	sel := Fields{active: active, has: make([]bool, len(table))}
	for i, t := range table {
		sel.has[i] = t.always
	}
	for name := range strings.SplitSeq(spec, ",") {
		name = strings.TrimSpace(name)
		i := fieldIndex(name)
		switch {
		case name == "":
		case name == "all":
			sel = AllFields(active)
		case i < 0:
			unknown = append(unknown, name)
		case table[i].active && !active:
			activeOnly = append(activeOnly, name)
		default:
			sel.has[i] = true
		}
	}
	if unknown != nil || activeOnly != nil {
		return Fields{}, unknown, activeOnly
	}
	return sel, nil, nil
}

// AllFields is every key the mode allows, which is what a call without --fields returns.
func AllFields(active bool) Fields {
	f := Fields{active: active, has: make([]bool, len(table))}
	for i, t := range table {
		f.has[i] = t.always || !t.active || active
	}
	return f
}

// Active reports whether the selection was made for --active.
func (f Fields) Active() bool { return f.active }

// Has reports whether the key is selected.
func (f Fields) Has(name string) bool {
	i := fieldIndex(name)
	return i >= 0 && i < len(f.has) && f.has[i]
}

// Names are the selected keys, in the record's order.
func (f Fields) Names() []string {
	var names []string
	for i, t := range table {
		if i < len(f.has) && f.has[i] {
			names = append(names, t.name)
		}
	}
	return names
}

// Needs reports whether the source must be asked for the selection: some selected key takes its
// value from it, or it is what those depend on. Under --active cymru is always needed, since
// whether an address is shared infrastructure is always worked out.
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

// Sourceless reports whether a selected key needs no source, so a public address always has its
// value (the abusive and DROP network matches, from the lists in use, which need no request).
func (f Fields) Sourceless() bool {
	for i, t := range table {
		if i < len(f.has) && f.has[i] && !t.always && len(t.sources) == 0 {
			return true
		}
	}
	return false
}

// NeedsProbe reports whether the TCP scan runs: ports, tls or web is selected.
func (f Fields) NeedsProbe() bool { return f.Needs(SourceProbe) }

// NeedsTLS reports whether a TLS handshake is made on each open TLS port: tls is selected.
func (f Fields) NeedsTLS() bool { return f.Has("tls") }

// NeedsWeb reports whether a GET / is made on each open web port: web is selected.
func (f Fields) NeedsWeb() bool { return f.Has("web") }

// NeedsSharedCheck reports whether an address is shared provider infrastructure must be
// worked out, which it always is under --active whatever is selected.
func (f Fields) NeedsSharedCheck() bool { return f.has != nil && f.active }

// Projected is a record cut down to the selected keys. It encodes only those, in the table's
// order.
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
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	b.WriteByte('{')
	for i, t := range table {
		if i >= len(p.f.has) || !p.f.has[i] {
			continue
		}
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:", t.name)
		if err := enc.Encode(t.value(&p.rec)); err != nil {
			return nil, fmt.Errorf("encoding %s: %w", t.name, err)
		}
		b.Truncate(b.Len() - 1) // Encode's newline
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
