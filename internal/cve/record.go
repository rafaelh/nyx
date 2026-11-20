// Package cve looks CVEs up in the NVD by CVE ID. It owns the CVE record (the
// tool's own flat shape for a CVE, converted from the NVD's entry in one
// place) and its field table; the client that looks one ID up, paced to the
// NVD's rate limit and with each failure classified into an error code of
// clierr; the human layout of records; and the outcome of a batch of IDs. It
// makes its requests through egress and does no other I/O. The command
// (internal/cli) owns the flags, the worker pool and the writing.
//
// The keys of the record are a stable interface: adding one is compatible,
// and renaming, removing or retyping one is a breaking change. The one
// deliberate break so far is that the default selection (DefaultFields) leaves
// out the two lists, which hold their counts instead; all returns every key.
package cve

import (
	"cmp"
	"regexp"
	"strings"
	"time"
)

// Timestamp is a time that encodes as RFC 3339 in UTC, to the second, and as
// null when it is zero.
type Timestamp struct{ time.Time }

// MarshalJSON encodes t as RFC 3339 in UTC, or null.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return []byte(`"` + t.UTC().Format(time.RFC3339) + `"`), nil
}

// Record is a CVE record: the only shape callers see. A nullable value is a
// pointer and nothing is omitted, so the record has every key, and every list
// is [] when empty. What --json writes is a Projected record: the selected keys
// of it, with a count in front of each list.
type Record struct {
	ID           string    `json:"id"`
	Status       string    `json:"status"`
	Published    Timestamp `json:"published"`
	LastModified Timestamp `json:"last_modified"`
	Description  *string   `json:"description"`
	CVSSVersion  *string   `json:"cvss_version"`
	CVSSScore    *float64  `json:"cvss_score"`
	CVSSSeverity *string   `json:"cvss_severity"`
	CVSSVector   *string   `json:"cvss_vector"`
	CVSSSource   *string   `json:"cvss_source"`
	Weaknesses   []string  `json:"weaknesses"`

	AffectedProducts []AffectedProduct `json:"affected_products"`
	References       []Reference       `json:"references"`
}

// Reference is a URL about the CVE, with the NVD's tags for it, such as Vendor
// Advisory or Patch.
type Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// AffectedProduct is one vulnerable CPE match, with its version bounds.
// Vendor, product and version come from the CPE, and each is null where the
// CPE has * (any) or - (not applicable).
type AffectedProduct struct {
	CPE                   string  `json:"cpe"`
	Vendor                *string `json:"vendor"`
	Product               *string `json:"product"`
	Version               *string `json:"version"`
	VersionStartIncluding *string `json:"version_start_including"`
	VersionStartExcluding *string `json:"version_start_excluding"`
	VersionEndIncluding   *string `json:"version_end_including"`
	VersionEndExcluding   *string `json:"version_end_excluding"`
}

// idPattern is the CVE ID form the NVD accepts.
var idPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// NormaliseID trims s and upper-cases it, and reports whether the result is a
// CVE ID in the form the NVD accepts.
func NormaliseID(s string) (string, bool) {
	id := strings.ToUpper(strings.TrimSpace(s))
	return id, idPattern.MatchString(id)
}

// FromNVD converts an NVD entry to its CVE record.
func FromNVD(e *Entry) Record {
	rec := Record{
		ID:           e.ID,
		Status:       e.VulnStatus,
		Published:    nvdTime(e.Published),
		LastModified: nvdTime(e.LastModified),
		Description:  description(e.Descriptions),
		Weaknesses:   weaknesses(e.Weaknesses),

		AffectedProducts: affectedProducts(e.Configurations),
		References:       references(e.References),
	}
	if s, ok := preferredScore(e.Metrics); ok {
		rec.CVSSVersion, rec.CVSSScore, rec.CVSSSeverity = &s.version, &s.value, &s.severity
		rec.CVSSVector, rec.CVSSSource = &s.vector, &s.source
	}
	return rec
}

// description is the first English description, trimmed, else the first of
// any language; nil when the entry has none.
func description(ds []LangString) *string {
	if len(ds) == 0 {
		return nil
	}
	pick := ds[0]
	for _, d := range ds {
		if strings.EqualFold(d.Lang, "en") {
			pick = d
			break
		}
	}
	v := strings.TrimSpace(pick.Value)
	return &v
}

// weaknesses are the English CWE values across the entry's weaknesses,
// de-duplicated in order.
func weaknesses(ws []Weakness) []string {
	values := []string{}
	seen := map[string]bool{}
	for _, w := range ws {
		for _, d := range w.Description {
			v := strings.TrimSpace(d.Value)
			if !strings.EqualFold(d.Lang, "en") || v == "" || seen[v] {
				continue
			}
			seen[v] = true
			values = append(values, v)
		}
	}
	return values
}

// affectedProducts walks every configuration node, nested ones included, and
// keeps the vulnerable matches, each CPE with its version bounds once.
func affectedProducts(configs []Configuration) []AffectedProduct {
	products := []AffectedProduct{}
	type match struct{ cpe, startIncluding, startExcluding, endIncluding, endExcluding string }
	seen := map[match]bool{}
	var walk func(nodes []Node)
	walk = func(nodes []Node) {
		for _, n := range nodes {
			for _, m := range n.CPEMatch {
				k := match{m.Criteria, m.VersionStartIncluding, m.VersionStartExcluding, m.VersionEndIncluding, m.VersionEndExcluding}
				if !m.Vulnerable || seen[k] {
					continue
				}
				seen[k] = true
				products = append(products, affectedProduct(m))
			}
			walk(n.Nodes)
		}
	}
	for _, c := range configs {
		walk(c.Nodes)
	}
	return products
}

func affectedProduct(m CPEMatch) AffectedProduct {
	// cpe:2.3:part:vendor:product:version:...
	fields := splitCPE(m.Criteria)
	field := func(i int) *string {
		// Checked before unescaping: a bare * is "any" and a bare - is "not applicable", while \*
		// is a literal asterisk.
		if i >= len(fields) || fields[i] == "*" || fields[i] == "-" {
			return nil
		}
		v := unescapeCPE(fields[i])
		return &v
	}
	return AffectedProduct{
		CPE:                   m.Criteria,
		Vendor:                field(3),
		Product:               field(4),
		Version:               field(5),
		VersionStartIncluding: nonEmpty(m.VersionStartIncluding),
		VersionStartExcluding: nonEmpty(m.VersionStartExcluding),
		VersionEndIncluding:   nonEmpty(m.VersionEndIncluding),
		VersionEndExcluding:   nonEmpty(m.VersionEndExcluding),
	}
}

// splitCPE splits a CPE 2.3 formatted string on its unescaped colons, leaving
// the escapes in place.
func splitCPE(cpe string) []string {
	var fields []string
	start := 0
	for i := 0; i < len(cpe); i++ {
		switch cpe[i] {
		case '\\':
			i++ // the next character is quoted, a colon included
		case ':':
			fields = append(fields, cpe[start:i])
			start = i + 1
		}
	}
	return append(fields, cpe[start:])
}

// unescapeCPE removes the backslashes that quote characters in a CPE field.
func unescapeCPE(field string) string {
	var b strings.Builder
	for i := 0; i < len(field); i++ {
		if field[i] == '\\' && i+1 < len(field) {
			i++
		}
		b.WriteByte(field[i])
	}
	return b.String()
}

func references(rs []NVDReference) []Reference {
	refs := make([]Reference, 0, len(rs))
	for _, r := range rs {
		tags := r.Tags
		if tags == nil {
			tags = []string{}
		}
		refs = append(refs, Reference{URL: r.URL, Tags: tags})
	}
	return refs
}

// nonEmpty is s, or nil when s is empty.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nvdTime reads an NVD timestamp, which the NVD writes without a zone, in UTC.
// One it cannot read is the zero time, written as null.
func nvdTime(s string) Timestamp {
	// Parsing accepts the fractional seconds the NVD adds though the layout has none.
	t, err := time.Parse("2006-01-02T15:04:05", s)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, s); err != nil {
			return Timestamp{}
		}
	}
	return Timestamp{t.UTC().Truncate(time.Second)}
}

// score is one CVSS score of an entry.
type score struct {
	version, severity, vector, source string
	value                             float64
	primary                           bool
}

// preferredScore picks the score a record carries: the highest CVSS version
// present, and within that version the first Primary score (the NVD's own),
// else the version's first.
func preferredScore(m *Metrics) (score, bool) {
	if m == nil {
		return score{}, false
	}
	of := func(version string, ms []CVSSMetric) []score {
		var out []score
		for _, x := range ms {
			if x.CVSSData != nil {
				out = append(out, newScore(version, x))
			}
		}
		return out
	}
	for _, scores := range [][]score{of("4.0", m.CVSSMetricV40), of("3.1", m.CVSSMetricV31), of("3.0", m.CVSSMetricV30),
		of("2.0", m.CVSSMetricV2)} {
		if len(scores) == 0 {
			continue
		}
		for _, s := range scores {
			if s.primary {
				return s, true
			}
		}
		return scores[0], true
	}
	return score{}, false
}

// newScore is m's score. Its severity is the metric's own (version 2's), else
// its data's.
func newScore(version string, m CVSSMetric) score {
	d := m.CVSSData
	severity := cmp.Or(m.BaseSeverity, d.BaseSeverity)
	return score{version: version, value: d.BaseScore, severity: strings.ToUpper(severity), vector: d.VectorString,
		source: m.Source, primary: m.Type == "Primary"}
}
