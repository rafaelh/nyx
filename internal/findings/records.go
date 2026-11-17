package findings

import (
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/cloudstorage"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/store"
)

// This file is everything outside the package needs to know about a stored
// finding record: its key, how to read one back, which ones the summary lists,
// and the files that list them. Adding a category changes only this package.

// originArrow joins the hostname and the address of an origin exposure's target.
const originArrow = " -> "

// Key is the finding's record key: one per hostname for takeovers, one per hostname and address for
// origin exposures (so the row is the same while it moves between possible and confirmed), one per
// type, target and product for end-of-life software (each product on a service is its own finding),
// otherwise category, type and target. ParseKey reverses it, apart from the product.
func (f Finding) Key() string {
	if f.Category == Takeover {
		return f.Category + "|" + f.Target
	}
	if f.Category == OriginExposure {
		host, addr := splitOriginTarget(f.Target)
		return f.Category + "|" + host + "|" + addr
	}
	if f.Category == EOLSoftware {
		product, _ := f.Attrs["product"].(string)
		return f.Category + "|" + f.Type + "|" + f.Target + "|" + product
	}
	return f.Category + "|" + f.Type + "|" + f.Target
}

// ParseKey reads the category, type and target from a finding's record key. A
// takeover or origin-exposure key carries no type, and an end-of-life key's product is not part of
// its target (its file's fromKey reads it).
func ParseKey(key string) (category, typ, target string) {
	category, rest, _ := strings.Cut(key, "|")
	if category == Takeover {
		return category, "", rest
	}
	if category == OriginExposure {
		host, addr, _ := strings.Cut(rest, "|")
		return category, "", originTarget(host, addr)
	}
	typ, target, _ = strings.Cut(rest, "|")
	if category == EOLSoftware {
		target, _, _ = strings.CutLast(target, "|")
	}
	return category, typ, target
}

// FromRecord reads a stored finding record back. A record no longer derived
// keeps no attributes (the store drops them with its last observation), so the
// category, type and target then come from its key.
func FromRecord(r store.Record) Finding {
	category, typ, target := ParseKey(r.Key)
	f := Finding{Category: category, Type: typ, Target: target, Attrs: r.Attrs}
	if v := r.Str("category"); v != "" {
		f.Category = v
	}
	if v := r.Str("type"); v != "" {
		f.Type = v
	}
	if v := r.Str("target"); v != "" {
		f.Target = v
	}
	f.Severity, f.Detail = r.Str("severity"), r.Str("detail")
	return f
}

// FoundText is the text the console prints for a newly found finding in place of its category and
// target, or "" when the category has none. An origin exposure reads "[possible ]origin exposure
// <host> -> <address> (behind <provider>)", and an end-of-life finding "end-of-life <product>
// <version> on <target>" (or "end of support approaching for ...").
func (f Finding) FoundText() string {
	if f.Category == EOLSoftware {
		product, _ := f.Attrs["product"].(string)
		version, _ := f.Attrs["version"].(string)
		what := product + " " + version + " on " + f.Target
		if f.Type == "eol-approaching" {
			return "end of support approaching for " + what
		}
		return "end-of-life " + what
	}
	if f.Category != OriginExposure {
		return ""
	}
	provider, _ := f.Attrs["provider"].(string)
	text := "origin exposure " + f.Target + " (behind " + provider + ")"
	if f.Type != "confirmed" {
		text = "possible " + text
	}
	return text
}

// Headline lists the current high and medium findings among recs, high first,
// then by target: the findings the run summary shows.
func Headline(recs []store.Record) []Finding {
	var out []Finding
	for _, r := range recs {
		if f := FromRecord(r); r.Current && (f.Severity == High || f.Severity == Medium) {
			out = append(out, f)
		}
	}
	slices.SortStableFunc(out, func(a, b Finding) int {
		if a.Severity != b.Severity {
			return rank[b.Severity] - rank[a.Severity]
		}
		return strings.Compare(a.Target, b.Target)
	})
	return out
}

// UnconfirmedRisky counts the current risky-port findings among recs that only a
// third party reports.
func UnconfirmedRisky(recs []store.Record) int {
	n := 0
	for _, r := range recs {
		if cat, _, _ := ParseKey(r.Key); r.Current && cat == Ports && r.Str("confirmed") == "no" {
			n++
		}
	}
	return n
}

// Listing is what the findings files are written from: the records of every
// kind, current or not, and the storage Attribution derived with the findings.
type Listing struct {
	Records map[string][]store.Record
	Storage map[string]StorageAttr
}

// File is a CSV file of findings. The output package writes it like its own
// files, adding the current, first_seen and last_seen columns.
type File struct {
	Name    string
	Columns []string
	Rows    func(Listing) []FileRow
}

// FileRow is one row of a File: its cells, one per column, and the record it lists,
// which dates it.
type FileRow struct {
	Record store.Record
	Cells  []string
}

// riskFiles are the categories with a risk-<category>.csv file, its columns, and
// for a finding no longer derived, the columns its key (with its type and target already parsed
// from it) identifies.
var riskFiles = []struct {
	category string
	columns  []string
	fromKey  func(key, typ, target string) map[string]string
}{
	{Takeover, []string{"severity", "target", "type", "service", "cname", "detail"}, nil},
	{Storage, []string{"severity", "provider", "name", "url", "exists", "public", "listable", "object_count", "first_keys", "referenced_by"},
		func(_, _, target string) map[string]string { return map[string]string{"url": target} }},
	{SensitivePaths, []string{"severity", "url", "path", "status", "size", "signature"},
		func(_, typ, target string) map[string]string { return map[string]string{"path": typ, "url": target} }},
	{Email, []string{"severity", "root", "type", "detail"},
		func(_, _, target string) map[string]string { return map[string]string{"root": target} }},
	{Ports, []string{"severity", "ip", "port", "banner", "hostnames", "confirmed"},
		func(_, _, target string) map[string]string {
			ap, err := netip.ParseAddrPort(target)
			if err != nil {
				return nil
			}
			return map[string]string{"ip": ap.Addr().String(), "port": strconv.Itoa(int(ap.Port()))}
		}},
	{Certificates, []string{"severity", "url", "type", "tls_subject", "tls_issuer", "tls_expiry"},
		func(_, _, target string) map[string]string { return map[string]string{"url": target} }},
	{WebPosture, []string{"severity", "url", "type", "detail"},
		func(_, _, target string) map[string]string { return map[string]string{"url": target} }},
	{OriginExposure, []string{"severity", "hostname", "provider", "address", "found_by", "confirmed_by", "confirmed"},
		func(_, _, target string) map[string]string {
			host, addr := splitOriginTarget(target)
			return map[string]string{"hostname": host, "address": addr}
		}},
	{EOLSoftware, []string{"severity", "target", "hostnames", "type", "product", "version", "end_date", "seen", "confirmed"},
		func(key, _, _ string) map[string]string {
			_, product, _ := strings.CutLast(key, "|")
			return map[string]string{"product": product}
		}},
}

// Files are the findings files: storage-unattributed.csv, then one
// risk-<category>.csv per category.
func Files() []File {
	files := []File{{Name: "storage-unattributed.csv", Columns: storageUnattributedColumns, Rows: storageUnattributedRows}}
	for _, rf := range riskFiles {
		files = append(files, riskFile(rf.category, rf.columns, rf.fromKey))
	}
	return files
}

// riskFile lists every finding record of a category: current ones and those no
// longer derived, which stay on record. The findings are derived
// with scope and visibility already applied, so the file does not filter again.
func riskFile(category string, columns []string, fromKey func(key, typ, target string) map[string]string) File {
	return File{Name: "risk-" + category + ".csv", Columns: columns, Rows: func(l Listing) []FileRow {
		var rows []FileRow
		for _, r := range l.Records[kinds.Finding.Name()] {
			cat, typ, target := ParseKey(r.Key)
			if cat != category {
				continue
			}
			fallback := map[string]string{"type": typ, "target": target}
			if !r.Current && fromKey != nil {
				maps.Copy(fallback, fromKey(r.Key, typ, target))
			}
			cells := make([]string, len(columns))
			for i, c := range columns {
				if cells[i] = cell(r, c); cells[i] == "" && !r.Current {
					cells[i] = fallback[c]
				}
			}
			rows = append(rows, FileRow{Record: r, Cells: cells})
		}
		return rows
	}}
}

var storageUnattributedColumns = []string{"provider", "name", "url", "exists", "public", "listable", "object_count", "first_keys", "generated_from", "severity"}

// storageUnattributedRows lists every existing bucket or container nothing in
// scope references and that a root or organisation input would have guessed.
// A public or listable one is a low finding; a private one is listed, not reported.
func storageUnattributedRows(l Listing) []FileRow {
	var rows []FileRow
	for _, r := range l.Records[kinds.Storage.Name()] {
		a := kinds.Storage.Attrs(r)
		attr, known := l.Storage[r.Key]
		if !isTrue(a.Exists) || !known || attr.Attributed || len(attr.GeneratedFrom) == 0 {
			continue
		}
		listable := ""
		if a.Listable != nil {
			listable = strconv.FormatBool(*a.Listable)
		}
		rows = append(rows, FileRow{Record: r, Cells: []string{a.Provider, a.Name, cloudstorage.URL(a.Provider, a.Name, a.Container), "true", attr.Public,
			listable, a.ObjectCount, strings.Join(a.FirstKeys, ";"), strings.Join(attr.GeneratedFrom, ";"), attr.Severity}})
	}
	return rows
}

// cell renders an attribute for a CSV cell. Numbers come back from the store
// as float64; a list is joined with ";".
func cell(r store.Record, k string) string {
	switch v := r.Attrs[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case []any:
		var parts []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ";")
	}
	return ""
}
