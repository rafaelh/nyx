package cve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// field is one key of the record and how its value is read.
type field struct {
	name  string // the JSON key, which is also the name --fields takes
	value func(*Projected) any
}

// fields is the one field table, in the record's key order. It does the
// selection, gives the names for help and checks the names a caller passes.
var fields = []field{
	{"id", func(p *Projected) any { return p.rec.ID }},
	{"status", func(p *Projected) any { return p.rec.Status }},
	{"published", func(p *Projected) any { return p.rec.Published }},
	{"last_modified", func(p *Projected) any { return p.rec.LastModified }},
	{"description", func(p *Projected) any { return p.rec.Description }},
	{"cvss_version", func(p *Projected) any { return p.rec.CVSSVersion }},
	{"cvss_score", func(p *Projected) any { return p.rec.CVSSScore }},
	{"cvss_severity", func(p *Projected) any { return p.rec.CVSSSeverity }},
	{"cvss_vector", func(p *Projected) any { return p.rec.CVSSVector }},
	{"cvss_source", func(p *Projected) any { return p.rec.CVSSSource }},
	{"weaknesses", func(p *Projected) any { return p.rec.Weaknesses }},
	{"affected_products_count", func(p *Projected) any { return p.counts[productsList] }},
	{"affected_products", func(p *Projected) any { return p.rec.AffectedProducts }},
	{"references_count", func(p *Projected) any { return p.counts[referencesList] }},
	{"references", func(p *Projected) any { return p.rec.References }},
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
// trimmed, empty ones are ignored, and id is always added. A list brings its
// count with it. The selection is in the table's order whatever order the names
// were given in. The names that are not fields are returned as given, and with
// any the selection is empty.
func Select(spec string) (Fields, []string) {
	f := Fields{has: make([]bool, len(fields))}
	f.has[0] = true // id
	var unknown []string
	for name := range strings.SplitSeq(spec, ",") {
		name = strings.TrimSpace(name)
		i := fieldIndex(name)
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
	for _, l := range lists {
		if f.Has(l.name) {
			f.set(l.count, true)
		}
	}
	return f, nil
}

// The two lists of the record, by their position in lists.
const (
	productsList = iota
	referencesList
)

// list is one of the record's lists: its field name, its count's field name, and
// its section's title and the noun its section uses for its entries.
type list struct{ name, count, title, noun string }

// lists are the two lists of the record.
var lists = [...]list{
	productsList:   {"affected_products", "affected_products_count", "Affected Products", "affected products"},
	referencesList: {"references", "references_count", "References", "references"},
}

// fieldIndex is the position of the field name in the table, or -1.
func fieldIndex(name string) int {
	if i, ok := fieldPos[name]; ok {
		return i
	}
	return -1
}

// fieldPos is each field's position in the table, by name.
var fieldPos = func() map[string]int {
	m := make(map[string]int, len(fields))
	for i, f := range fields {
		m[f.name] = i
	}
	return m
}()

func (f Fields) set(name string, on bool) {
	if i := fieldIndex(name); i >= 0 {
		f.has[i] = on
	}
}

// Has reports whether the field name is selected.
func (f Fields) Has(name string) bool {
	i := fieldIndex(name)
	return i >= 0 && i < len(f.has) && f.has[i]
}

// ShowsList reports whether either list is selected.
func (f Fields) ShowsList() bool {
	return slices.ContainsFunc(lists[:], func(l list) bool { return f.Has(l.name) })
}

// ShowsCount reports whether either list's count is selected, which it is
// whenever its list is.
func (f Fields) ShowsCount() bool {
	return slices.ContainsFunc(lists[:], func(l list) bool { return f.Has(l.count) })
}

// Count is how many entries a list has: its total, under --match how many
// matched, and under --limit how many were left out. Which keys it has depends on
// the flags given and never on the data, so no key's type changes.
type Count struct {
	Total   int  `json:"total"`
	Matched *int `json:"matched,omitempty"`
	Omitted *int `json:"omitted,omitempty"`
}

// entries is how many entries of the list a record has to show: the matching
// ones under --match, else all.
func (c Count) entries() int {
	if c.Matched != nil {
		return *c.Matched
	}
	return c.Total
}

// View is a selection of fields with the cut --match and --limit make of the
// two lists, affected_products and references, and never of any other field.
type View struct {
	Fields
	Match string // keeps the list entries whose text contains it, ignoring case and surrounding space; "" keeps all
	Limit int    // at most this many entries of each list that is shown, after the match; 0 for no limit
}

// DefaultFields is the selection when --fields is not given: every field but the
// two lists, so a record is the same size however long they are.
func DefaultFields() Fields {
	f, _ := Select("all")
	for _, l := range lists {
		f.set(l.name, false)
	}
	return f
}

// Projected is a record cut down to the selected fields, with the counts of its
// two lists whether or not they are selected. It encodes only the selected keys,
// in the table's order.
type Projected struct {
	rec    Record // with its lists cut, and nil when not shown
	f      Fields
	counts [len(lists)]Count // indexed like lists
}

// Project cuts r down to the view: it matches each list, limits what matched, and
// counts both lists. The match is made on the NVD's text as r holds it, so before
// Render cleans or redacts anything. r itself is not changed.
func (v View) Project(r Record) Projected {
	match := strings.ToLower(strings.TrimSpace(v.Match))
	p := Projected{f: v.Fields}
	r.AffectedProducts, p.counts[productsList] = cutList(r.AffectedProducts, match, v.Limit, v.Has(lists[productsList].name), productMatches)
	r.References, p.counts[referencesList] = cutList(r.References, match, v.Limit, v.Has(lists[referencesList].name), referenceMatches)
	p.rec = r
	return p
}

// cutList is the count of a list's entries and, when the list is shown, its entries that match
// (all of them when match is ""), the first limit of those (all of them when limit
// is 0). A list that is not shown is nil, so nothing cleans or redacts its entries.
// match is lower case.
func cutList[T any](entries []T, match string, limit int, shown bool, matches func(T, string) bool) ([]T, Count) {
	c := Count{Total: len(entries)}
	if match != "" {
		var kept []T
		if shown {
			kept = make([]T, 0, len(entries)) // so none matching encodes as [], not null
		}
		n := 0
		for _, e := range entries {
			if matches(e, match) {
				n++
				if shown {
					kept = append(kept, e)
				}
			}
		}
		entries = kept
		c.Matched = new(n)
	}
	if !shown {
		return nil, c
	}
	if limit > 0 {
		c.Omitted = new(max(0, len(entries)-limit))
		entries = entries[:min(limit, len(entries))]
	}
	return entries, c
}

// productMatches reports whether an affected product's line contains match, which
// is lower case. The line is the one human mode shows, from the NVD's own text; for
// a product with no vendor, product or version it is the CPE without its fixed
// cpe:2.3:<part>: prefix.
func productMatches(ap AffectedProduct, match string) bool {
	return strings.Contains(strings.ToLower(productLine(ap, asGiven, stripCPEPrefix)), match)
}

// asGiven is s unchanged: the NVD's text as it wrote it.
func asGiven(s string) string { return s }

// stripCPEPrefix is the CPE without the start every CPE 2.3 name has, cpe:2.3:<part>:, which
// says nothing about the product.
func stripCPEPrefix(cpe string) string { return cpePrefix.ReplaceAllString(cpe, "") }

var cpePrefix = regexp.MustCompile(`^cpe:2\.3:[^:]*:`)

// referenceMatches reports whether a reference's URL, or any one of its tags, contains match, which is lower case.
func referenceMatches(ref Reference, match string) bool {
	return strings.Contains(strings.ToLower(ref.URL), match) ||
		slices.ContainsFunc(ref.Tags, func(t string) bool { return strings.Contains(strings.ToLower(t), match) })
}

// leftOut reports whether the list at i in lists is not shown though the record has
// entries in it (matching entries under --match): what ListHint and the heading of
// the list's count name.
func (p Projected) leftOut(i int) bool { return !p.f.Has(lists[i].name) && p.counts[i].entries() > 0 }

// ListHint is the --json note on how to see the lists the selection leaves out: it names each
// one left out of at least one record, in the table's order. It is "" when none was.
func ListHint(ps []Projected) string {
	var names []string
	for i, l := range lists {
		if slices.ContainsFunc(ps, func(p Projected) bool { return p.leftOut(i) }) {
			names = append(names, l.name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "use --fields " + strings.Join(names, ",") + " (or --fields all) to list them"
}

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
		if err := enc.Encode(f.value(&p)); err != nil {
			return nil, fmt.Errorf("encoding %s: %w", f.name, err)
		}
		b.Truncate(b.Len() - 1) // Encode's newline
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
