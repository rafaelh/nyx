package findings

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/cloudstorage"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/store"
)

// This file defines the stored-finding interface: keys, decoding, console text, summary
// selection and risk files. Category-specific behaviour stays in categories so new categories
// do not require changes in callers.

// category defines key encoding, decoding, console text and a risk file. Missing categories or
// nil callbacks use "<category>|<type>|<target>" keys with no custom text or file.
type category struct {
	name string
	// key is the part of the record key after "<category>|", and parse reads the type and target
	// back from that part.
	key   func(Finding) string
	parse func(rest string) (typ, target string)
	// found is the text the console prints for a newly found finding in place of its category and
	// target.
	found func(Finding) string
	// columns defines risk-file fields. fromKey recovers extra fields for non-current
	// findings after type and target have been parsed.
	columns []string
	fromKey func(key, typ, target string) map[string]string
}

// categories are the finding categories, in the order of their files.
var categories = []category{
	{
		// One per hostname, whatever the takeover's type.
		name:    Takeover,
		key:     func(f Finding) string { return f.Target },
		parse:   func(rest string) (string, string) { return "", rest },
		columns: []string{"severity", "target", "type", "service", "cname", "detail"},
	},
	{
		name:    Storage,
		columns: []string{"severity", "provider", "name", "url", "exists", "public", "listable", "object_count", "first_keys", "referenced_by"},
		fromKey: targetAs("url"),
	},
	{name: StorageUnattributed}, // listed in storage-unattributed.csv, from the storage records
	{
		name:    SensitivePaths,
		columns: []string{"severity", "url", "path", "status", "size", "signature"},
		fromKey: func(_, typ, target string) map[string]string { return map[string]string{"path": typ, "url": target} },
	},
	{name: Email, columns: []string{"severity", "root", "type", "detail"}, fromKey: targetAs("root")},
	{
		name:    Ports,
		columns: []string{"severity", "ip", "port", "banner", "hostnames", "confirmed"},
		fromKey: func(_, _, target string) map[string]string {
			ap, err := netip.ParseAddrPort(target)
			if err != nil {
				return nil
			}
			return map[string]string{"ip": ap.Addr().String(), "port": strconv.Itoa(int(ap.Port()))}
		},
	},
	{name: Certificates, columns: []string{"severity", "url", "type", "tls_subject", "tls_issuer", "tls_expiry"}, fromKey: targetAs("url")},
	{name: WebPosture, columns: []string{"severity", "url", "type", "detail"}, fromKey: targetAs("url")},
	{
		// Key by hostname/address pair so possible and confirmed origins share a row.
		// Console text includes the provider and marks possible origins.
		name: OriginExposure,
		key: func(f Finding) string {
			host, addr := splitOriginTarget(f.Target)
			return host + "|" + addr
		},
		parse: func(rest string) (string, string) {
			host, addr, _ := strings.Cut(rest, "|")
			return "", originTarget(host, addr)
		},
		found: func(f Finding) string {
			provider, _ := f.Attrs["provider"].(string)
			text := "origin exposure " + f.Target + " (behind " + provider + ")"
			if f.Type != "confirmed" {
				text = "possible " + text
			}
			return text
		},
		columns: []string{"severity", "hostname", "provider", "address", "found_by", "confirmed_by", "confirmed"},
		fromKey: func(_, _, target string) map[string]string {
			host, addr := splitOriginTarget(target)
			return map[string]string{"hostname": host, "address": addr}
		},
	},
	{
		// Key by type, target and product so several products on one service remain
		// distinct findings. Console text includes the product and captured version.
		name: EOLSoftware,
		key: func(f Finding) string {
			product, _ := f.Attrs["product"].(string)
			return f.Type + "|" + f.Target + "|" + product
		},
		parse: func(rest string) (string, string) {
			typ, target, _ := strings.Cut(rest, "|")
			target, _, _ = strings.CutLast(target, "|")
			return typ, target
		},
		found: func(f Finding) string {
			product, _ := f.Attrs["product"].(string)
			version, _ := f.Attrs["version"].(string)
			what := product + " " + version + " on " + f.Target
			if f.Type == "eol-approaching" {
				return "end of support approaching for " + what
			}
			return "end-of-life " + what
		},
		columns: []string{"severity", "target", "hostnames", "type", "product", "version", "end_date", "seen", "confirmed"},
		fromKey: func(key, _, _ string) map[string]string {
			_, product, _ := strings.CutLast(key, "|")
			return map[string]string{"product": product}
		},
	},
	{
		// Key by address so DROP, ASN-DROP and abuse-list matches share one finding as
		// severity changes. Console text uses the strongest matching entry and adds its
		// organisation or SBL details when available.
		name:  AbusiveNetwork,
		key:   func(f Finding) string { return f.Target },
		parse: func(rest string) (string, string) { return "", rest },
		found: func(f Finding) string {
			entry, _ := f.Attrs["entry"].(string)
			org, _ := f.Attrs["org"].(string)
			what := "abusive network " + entry
			switch f.Type {
			case "drop-network":
				what = "Spamhaus DROP network " + entry
			case "drop-asn":
				what = "Spamhaus ASN-DROP " + entry
			case "asn":
				what = "abusive " + entry
			}
			if org == "" { // a list may leave an entry's organisation blank
				return "address " + f.Target + " in " + what
			}
			return "address " + f.Target + " in " + what + " (" + org + ")"
		},
		columns: []string{"severity", "ip", "hostnames", "type", "drop_networks", "drop_asn", "networks", "asn",
			"drop_networks_updated", "drop_asn_updated", "networks_updated", "asns_updated"},
		fromKey: targetAs("ip"),
	},
}

// categoryOf is the category of a name, with only defaults for one not in categories.
func categoryOf(name string) category {
	for _, c := range categories {
		if c.name == name {
			return c
		}
	}
	return category{name: name}
}

// Key delegates to the category's key format, defaulting to "<category>|<type>|<target>".
// ParseKey recovers type and target; category-specific extra data is handled separately.
func (f Finding) Key() string {
	if c := categoryOf(f.Category); c.key != nil {
		return f.Category + "|" + c.key(f)
	}
	return f.Category + "|" + f.Type + "|" + f.Target
}

// ParseKey reads the category, type and target from a finding's record key. A
// takeover or origin-exposure key carries no type.
func ParseKey(key string) (category, typ, target string) {
	category, rest, _ := strings.Cut(key, "|")
	if c := categoryOf(category); c.parse != nil {
		typ, target = c.parse(rest)
		return category, typ, target
	}
	typ, target, _ = strings.Cut(rest, "|")
	return category, typ, target
}

// FromRecord decodes finding attributes, recovering category, type and target from the key when
// a non-current record has lost its observations.
func FromRecord(r store.Record) Finding {
	category, typ, target := ParseKey(r.Key)
	return Finding{
		Category: cmp.Or(r.Str("category"), category),
		Type:     cmp.Or(r.Str("type"), typ),
		Target:   cmp.Or(r.Str("target"), target),
		Severity: r.Str("severity"),
		Detail:   r.Str("detail"),
		Attrs:    r.Attrs,
	}
}

// FoundText returns category-specific console text for a new finding, or "" for the default
// format.
func (f Finding) FoundText() string {
	if c := categoryOf(f.Category); c.found != nil {
		return c.found(f)
	}
	return ""
}

// The finding kind's found line is this package's: kinds cannot import it.
func init() { kinds.SetFindingFound(found) }

// found builds the event fields for a finding: category label, target, severity and optional
// custom text.
func found(r store.Record) map[string]any {
	f := FromRecord(r)
	k, _ := kinds.Get(kinds.Finding.Name())
	out := map[string]any{"category": k.Singular + " " + f.Category, "value": f.Target}
	if f.Severity != "" {
		out["severity"] = f.Severity
	}
	if text := f.FoundText(); text != "" {
		out["text"] = text
	}
	return out
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
		return cmp.Or(rank[b.Severity]-rank[a.Severity], strings.Compare(a.Target, b.Target))
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

// Listing provides all finding-file records, including non-current ones, plus attribution
// calculated with the findings.
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

// targetAs is a fromKey that puts the target in column col.
func targetAs(col string) func(key, typ, target string) map[string]string {
	return func(_, _, target string) map[string]string { return map[string]string{col: target} }
}

// Files are the findings files: storage-unattributed.csv, then one
// risk-<category>.csv per category.
func Files() []File {
	files := []File{{Name: "storage-unattributed.csv", Columns: storageUnattributedColumns, Rows: storageUnattributedRows}}
	for _, c := range categories {
		if c.columns != nil {
			files = append(files, riskFile(c.name, c.columns, c.fromKey))
		}
	}
	return files
}

// riskFile includes current and historical findings. Derivation already applied scope and
// visibility, so the file does not filter them again.
func riskFile(category string, columns []string, fromKey func(key, typ, target string) map[string]string) File {
	return File{Name: "risk-" + category + ".csv", Columns: columns, Rows: func(l Listing) []FileRow {
		var rows []FileRow
		for _, r := range l.Records[kinds.Finding.Name()] {
			cat, typ, target := ParseKey(r.Key)
			if cat != category {
				continue
			}
			var fallback map[string]string // read only for a finding no longer derived
			if !r.Current {
				fallback = map[string]string{"type": typ, "target": target}
				if fromKey != nil {
					maps.Copy(fallback, fromKey(r.Key, typ, target))
				}
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

// storageUnattributedRows lists existing, unreferenced storage that inputs could have guessed.
// Public/listable storage is a low finding; private storage is listed without a finding.
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
