package cve

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// Width is the width records are wrapped to: COLUMNS when it is a positive
// number, else 100, and never less than 60.
func Width(columns string) int {
	w := 100
	if n, err := strconv.Atoi(strings.TrimSpace(columns)); err == nil && n > 0 {
		w = n
	}
	return max(w, 60)
}

// Render writes the records for a person to read: each record's header, then
// a section for each part of it the fields select, records separated by a
// blank line. The NVD's text is cleaned of anything that would act on a
// terminal before it is wrapped to width, and is coloured at depth d last.
func Render(w io.Writer, recs []Record, f Fields, d palette.Depth, width int) error {
	if len(recs) == 0 {
		return nil
	}
	rd := renderer{f: f, d: d, width: width}
	blocks := make([]string, len(recs))
	for i, r := range recs {
		blocks[i] = rd.record(r)
	}
	_, err := fmt.Fprintln(w, strings.Join(blocks, "\n\n"))
	return err
}

type renderer struct {
	f     Fields
	d     palette.Depth
	width int
}

// spaces are the characters clean turns into spaces, so that words either
// side of them stay apart; sanitize.Text already does so for tabs.
var spaces = strings.NewReplacer("\n", " ", "\r", " ")

// clean is the NVD's text as it may be shown: newlines, returns and tabs as
// spaces, and no escape sequence or other control character.
func clean(s string) string { return sanitize.Text(spaces.Replace(s)) }

// or is *s cleaned, or fallback when s is nil or blank.
func or(s *string, fallback string) string {
	if s == nil {
		return fallback
	}
	return orEmpty(clean(*s), fallback)
}

func orEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func (r renderer) record(rec Record) string {
	has := r.f.Has
	header := r.d.Bold(clean(rec.ID))
	if has("cvss_severity") {
		header += "  " + r.badge(or(rec.CVSSSeverity, "UNKNOWN"))
	}
	lines := []string{header}
	section := func(heading string, body ...string) {
		if len(body) > 0 {
			lines = append(lines, "", r.d.Bold(heading))
			lines = append(lines, body...)
		}
	}
	var dates []string
	if has("status") {
		dates = append(dates, r.field("Status", orEmpty(clean(rec.Status), "Unknown")))
	}
	if has("published") {
		dates = append(dates, r.field("Published", timestamp(rec.Published)))
	}
	if has("last_modified") {
		dates = append(dates, r.field("Last Modified", timestamp(rec.LastModified)))
	}
	section("Status & Dates", dates...)
	if has("description") {
		section("Description", wrap(or(rec.Description, "No description available."), r.width))
	}
	section("CVSS Score", r.cvss(rec)...)
	if has("weaknesses") {
		ws := make([]string, len(rec.Weaknesses))
		for i, w := range rec.Weaknesses {
			ws[i] = clean(w)
		}
		section("Weaknesses", bullets(ws, "No weaknesses listed.", r.width)...)
	}
	if has("affected_products") {
		products := make([]string, len(rec.AffectedProducts))
		for i, ap := range rec.AffectedProducts {
			products[i] = shortForm(ap)
		}
		section("Affected Products", bullets(products, "No affected products listed.", r.width)...)
	}
	if has("references") {
		section("References", r.references(rec.References)...)
	}
	return strings.Join(lines, "\n")
}

// badge is the severity badge: in brackets without colour, else the palette's.
func (r renderer) badge(severity string) string {
	if r.d == palette.None {
		return "[" + severity + "]"
	}
	return r.d.Badge(palette.Severity, severity)
}

func (r renderer) field(key, value string) string { return r.d.Bold(key+":") + " " + value }

// cvss is the CVSS section's body for the selected cvss_* fields. The severity
// alone needs none: the header's badge shows it.
func (r renderer) cvss(rec Record) []string {
	has := r.f.Has
	if !has("cvss_score") && !has("cvss_vector") && !has("cvss_version") && !has("cvss_source") {
		return nil
	}
	if rec.CVSSScore == nil {
		return []string{"No CVSS score."}
	}
	var lines []string
	if has("cvss_score") {
		score := strconv.FormatFloat(*rec.CVSSScore, 'f', 1, 64)
		if has("cvss_severity") && rec.CVSSSeverity != nil {
			score += " (" + clean(*rec.CVSSSeverity) + ")"
		}
		lines = append(lines, r.field("Base Score", score))
	}
	if has("cvss_vector") {
		lines = append(lines, r.field("Vector", or(rec.CVSSVector, "Unknown")))
	}
	if has("cvss_version") {
		lines = append(lines, r.field("Version", or(rec.CVSSVersion, "Unknown")))
	}
	if has("cvss_source") {
		lines = append(lines, r.field("Source", or(rec.CVSSSource, "Unknown")))
	}
	return lines
}

// references is the References section's body: each URL, with the NVD's tags for it.
func (r renderer) references(refs []Reference) []string {
	if len(refs) == 0 {
		return []string{"No references listed."}
	}
	lines := make([]string, len(refs))
	for i, ref := range refs {
		line := r.d.Text(palette.Semantic, "info", clean(ref.URL))
		if len(ref.Tags) > 0 {
			tags := make([]string, len(ref.Tags))
			for j, t := range ref.Tags {
				tags[j] = clean(t)
			}
			line += " " + r.d.Text(palette.Chrome, "TIMESTAMP", "["+strings.Join(tags, ", ")+"]")
		}
		lines[i] = line
	}
	return lines
}

// shortForm is how an affected product reads to a person: apache log4j (>= 2.0.1, < 2.3.1).
func shortForm(ap AffectedProduct) string {
	var name []string
	for _, part := range []*string{ap.Vendor, ap.Product, ap.Version} {
		if part != nil {
			name = append(name, clean(*part))
		}
	}
	s := strings.Join(name, " ")
	if s == "" {
		s = clean(ap.CPE)
	}
	var bounds []string
	for _, b := range []struct {
		op    string
		value *string
	}{
		{">=", ap.VersionStartIncluding}, {">", ap.VersionStartExcluding},
		{"<=", ap.VersionEndIncluding}, {"<", ap.VersionEndExcluding},
	} {
		if b.value != nil {
			bounds = append(bounds, b.op+" "+clean(*b.value))
		}
	}
	if len(bounds) > 0 {
		s += " (" + strings.Join(bounds, ", ") + ")"
	}
	return s
}

func timestamp(t Timestamp) string {
	if t.IsZero() {
		return "Unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

// bullets are items as a list, each wrapped with its continuation lines
// indented under its text, or fallback alone when there are none.
func bullets(items []string, fallback string, width int) []string {
	if len(items) == 0 {
		return []string{fallback}
	}
	lines := make([]string, len(items))
	for i, item := range items {
		lines[i] = "- " + strings.ReplaceAll(wrap(item, width-2), "\n", "\n  ")
	}
	return lines
}

// wrap breaks text into lines of at most width runes, at spaces.
func wrap(text string, width int) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	current := words[0]
	for _, word := range words[1:] {
		if len([]rune(current))+1+len([]rune(word)) <= width {
			current += " " + word
			continue
		}
		lines = append(lines, current)
		current = word
	}
	return strings.Join(append(lines, current), "\n")
}
