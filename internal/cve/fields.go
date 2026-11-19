package cve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// field is one key of the record and how its value is read.
type field struct {
	name  string // the JSON key, which is also the name --fields takes
	value func(*Record) any
}

// fields is the one field table, in the record's key order. It does the
// selection, gives the names for help and checks the names a caller passes.
var fields = []field{
	{"id", func(r *Record) any { return r.ID }},
	{"status", func(r *Record) any { return r.Status }},
	{"published", func(r *Record) any { return r.Published }},
	{"last_modified", func(r *Record) any { return r.LastModified }},
	{"description", func(r *Record) any { return r.Description }},
	{"cvss_version", func(r *Record) any { return r.CVSSVersion }},
	{"cvss_score", func(r *Record) any { return r.CVSSScore }},
	{"cvss_severity", func(r *Record) any { return r.CVSSSeverity }},
	{"cvss_vector", func(r *Record) any { return r.CVSSVector }},
	{"cvss_source", func(r *Record) any { return r.CVSSSource }},
	{"weaknesses", func(r *Record) any { return r.Weaknesses }},
	{"affected_products", func(r *Record) any { return r.AffectedProducts }},
	{"references", func(r *Record) any { return r.References }},
}

// FieldNames is every field's name, in the record's key order.
func FieldNames() []string {
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.name
	}
	return names
}

// ValidFields names every value --fields accepts, for a hint.
func ValidFields() string {
	return "valid fields: " + strings.Join(FieldNames(), ", ") + ", or all"
}

// Fields is a selection of the record's fields; id is always among them.
type Fields struct{ has []bool } // by position in the table

// Select reads a --fields value: names separated by commas, or all. Names are
// trimmed, empty ones are ignored, and id is always added. The selection is in
// the table's order whatever order the names were given in. The names that are
// not fields are returned as given, and with any the selection is empty.
func Select(spec string) (Fields, []string) {
	f := Fields{has: make([]bool, len(fields))}
	f.has[0] = true // id
	var unknown []string
	for name := range strings.SplitSeq(spec, ",") {
		name = strings.TrimSpace(name)
		i := slices.IndexFunc(fields, func(x field) bool { return x.name == name })
		switch {
		case name == "":
		case name == "all":
			for i := range f.has {
				f.has[i] = true
			}
		case i < 0:
			unknown = append(unknown, name)
		default:
			f.has[i] = true
		}
	}
	if len(unknown) > 0 {
		return Fields{}, unknown
	}
	return f, nil
}

// Has reports whether the field name is selected.
func (f Fields) Has(name string) bool {
	i := slices.IndexFunc(fields, func(x field) bool { return x.name == name })
	return i >= 0 && i < len(f.has) && f.has[i]
}

// Projected is a record cut down to the selected fields. It encodes only
// those keys, in the table's order.
type Projected struct {
	rec Record
	f   Fields
}

// Project cuts r down to the selected fields.
func (f Fields) Project(r Record) Projected { return Projected{rec: r, f: f} }

// MarshalJSON encodes the selected keys, each value as the whole record would
// encode it.
func (p Projected) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	b.WriteByte('{')
	for i, f := range fields {
		if i >= len(p.f.has) || !p.f.has[i] {
			continue
		}
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:", f.name)
		if err := enc.Encode(f.value(&p.rec)); err != nil {
			return nil, fmt.Errorf("encoding %s: %w", f.name, err)
		}
		b.Truncate(b.Len() - 1) // Encode's newline
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
