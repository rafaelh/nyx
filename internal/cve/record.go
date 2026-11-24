// Package cve fetches NVD records through egress, paces requests, classifies failures and
// formats results. It owns the flat CVE record, field selection and batch outcome; internal/cli
// owns flags, concurrency and output writing.
//
// Record keys are a stable interface. Additions are compatible; removing, renaming or changing
// types breaks callers. DefaultFields selects counts instead of the two lists; selecting all
// includes every field.
package cve

import (
	"cmp"
	"regexp"
	"strings"
	"time"
)

// Timestamp encodes second-precision UTC RFC3339, or null for zero time.
type Timestamp struct{ time.Time }

// MarshalJSON encodes t as RFC 3339 in UTC, or null.
func (t Timestamp) MarshalJSON() ([]byte, error) {
	if t.IsZero() {
		return []byte("null"), nil
	}
	return []byte(`"` + t.UTC().Format(time.RFC3339) + `"`), nil
}

// Record is the complete CVE representation. Pointers encode unknown values as null, and empty
// lists encode as []. JSON output uses Projected to select keys and include list counts.
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

// Reference pairs a CVE-related URL with NVD tags such as Patch or Vendor Advisory.
type Reference struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// AffectedProduct holds a vulnerable CPE match and version bounds. Wildcard or inapplicable
// vendor/product/version components become null.
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

// NormaliseID trims and uppercases IDs before validating NVD syntax.
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

// description prefers the first English text, then any language, returning nil when absent.
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

// weaknesses deduplicates English CWE values in source order.
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

// affectedProducts traverses nested configuration nodes and deduplicates vulnerable
// CPE/version-bound combinations.
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
		// Distinguish wildcard/missing markers before decoding escaped literal
		// asterisks/hyphens.
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

// splitCPE separates unescaped colons without losing field escapes.
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

// unescapeCPE decodes quoted CPE field characters.
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

// nonEmpty converts empty strings to unknown pointers.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nvdTime treats NVD's zone-less timestamps as UTC. Invalid dates become zero time, encoded as
// null.
func nvdTime(s string) Timestamp {
	// Go's timestamp parser accepts NVD fractional seconds even without them in the layout.
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

// preferredScore chooses the highest CVSS version, then its first Primary score or first
// available score.
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

// newScore prefers metric-level v2 severity, then score-data severity.
func newScore(version string, m CVSSMetric) score {
	d := m.CVSSData
	severity := cmp.Or(m.BaseSeverity, d.BaseSeverity)
	return score{version: version, value: d.BaseScore, severity: strings.ToUpper(severity), vector: d.VectorString,
		source: m.Source, primary: m.Type == "Primary"}
}
