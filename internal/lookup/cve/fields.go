package cve

import (
	"regexp"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/lookup/batch"
)

// field pairs a stable record key with its value reader.
type field struct {
	name  string // shared JSON/--fields identifier
	value func(*Projected) any
}

// fields defines key order, selection, help names and validation in one table.
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

// FieldNames preserves record order for help and selection.
func FieldNames() []string {
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.name
	}
	return names
}

// ValidFields formats accepted --fields values for guidance.
func ValidFields() string {
	return "valid fields: " + strings.Join(FieldNames(), ", ") + ", or all"
}

// Fields always includes id alongside selected record fields.
type Fields struct{ has batch.Selection }

// Select parses comma-separated field names or "all", ignoring blanks. It always includes id
// and the counts for selected lists, returning fields in table order. Unknown names are
// returned unchanged and invalidate the selection.
func Select(spec string) (Fields, []string) {
	f := Fields{has: make(batch.Selection, len(fields))}
	f.has[0] = true // id
	unknown := keys.Select(spec, func() {
		for i := range f.has {
			f.has[i] = true
		}
	}, func(i int) { f.has[i] = true })
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

// list describes a list field, its count key and human section wording.
type list struct{ name, count, title, noun string }

// lists are the two lists of the record.
var lists = [...]list{
	productsList:   {"affected_products", "affected_products_count", "Affected Products", "affected products"},
	referencesList: {"references", "references_count", "References", "references"},
}

// keys indexes the stable field names.
var keys = batch.NewKeys(FieldNames())

func (f Fields) set(name string, on bool) {
	if i := keys.Index(name); i >= 0 {
		f.has[i] = on
	}
}

// Has reports whether the field name is selected.
func (f Fields) Has(name string) bool { return f.has.Has(keys.Index(name)) }

// ShowsList reports whether either list is selected.
func (f Fields) ShowsList() bool {
	return slices.ContainsFunc(lists[:], func(l list) bool { return f.Has(l.name) })
}

// ShowsCount includes counts implied by selected lists.
func (f Fields) ShowsCount() bool {
	return slices.ContainsFunc(lists[:], func(l list) bool { return f.Has(l.count) })
}

// Count holds a list's total, matched count under --match and omitted count under --limit.
// Flags determine which keys appear, keeping their types consistent regardless of data.
type Count struct {
	Total   int  `json:"total"`
	Matched *int `json:"matched,omitempty"`
	Omitted *int `json:"omitted,omitempty"`
}

// entries counts matching items, or all items without a filter.
func (c Count) entries() int {
	if c.Matched != nil {
		return *c.Matched
	}
	return c.Total
}

// View applies field selection plus list-only --match/--limit filters to affected_products and
// references.
type View struct {
	Fields
	Match string // case-insensitive trimmed text filter; empty selects all entries
	Limit int    // post-match entry cap per displayed list; zero disables it
}

// DefaultFields omits list contents but includes counts, keeping default output bounded
// regardless of list length.
func DefaultFields() Fields {
	f, _ := Select("all")
	for _, l := range lists {
		f.set(l.name, false)
	}
	return f
}

// Projected contains selected record fields plus list counts. JSON keys follow field-table
// order.
type Projected struct {
	rec    Record // with its lists cut, and nil when not shown
	f      Fields
	counts [len(lists)]Count // indexed like lists
}

// Project filters, limits and counts lists without changing r. Matching uses the original NVD
// text before rendering cleans or redacts it.
func (v View) Project(r Record) Projected {
	match := strings.ToLower(strings.TrimSpace(v.Match))
	p := Projected{f: v.Fields}
	r.AffectedProducts, p.counts[productsList] = cutList(r.AffectedProducts, match, v.Limit, v.Has(lists[productsList].name), productMatches)
	r.References, p.counts[referencesList] = cutList(r.References, match, v.Limit, v.Has(lists[referencesList].name), referenceMatches)
	p.rec = r
	return p
}

// cutList counts matches and returns up to limit entries for a displayed list. Zero limit means
// unlimited; empty match means all entries. Hidden lists return nil, avoiding unnecessary
// cleaning/redaction. match is lowercase.
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

// productMatches searches the same product line shown in human output, using lowercase match
// against original NVD text. Missing product details fall back to the CPE without its fixed
// prefix.
func productMatches(ap AffectedProduct, match string) bool {
	return strings.Contains(strings.ToLower(productLine(ap, asGiven, stripCPEPrefix)), match)
}

// asGiven preserves original NVD text for matching.
func asGiven(s string) string { return s }

// stripCPEPrefix removes structural CPE fields unrelated to product identity.
func stripCPEPrefix(cpe string) string { return cpePrefix.ReplaceAllString(cpe, "") }

var cpePrefix = regexp.MustCompile(`^cpe:2\.3:[^:]*:`)

// referenceMatches searches URL and tags using a lowercase match value.
func referenceMatches(ref Reference, match string) bool {
	return strings.Contains(strings.ToLower(ref.URL), match) ||
		slices.ContainsFunc(ref.Tags, func(t string) bool { return strings.Contains(strings.ToLower(t), match) })
}

// leftOut identifies hidden lists with entries worth displaying, accounting for --match, for
// hints and count headings.
func (p Projected) leftOut(i int) bool { return !p.f.Has(lists[i].name) && p.counts[i].entries() > 0 }

// ListHint names omitted nonempty lists in table order and explains their flags for JSON users.
// It returns "" when no lists were omitted.
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

// MarshalJSON preserves complete-record value encoding for selected keys.
func (p Projected) MarshalJSON() ([]byte, error) {
	return keys.Marshal(p.f.has, func(i int) any { return fields[i].value(&p) })
}
