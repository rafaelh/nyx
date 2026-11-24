package cve

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// Render formats selected CVE fields with a header and sections, separating records with blank
// lines. Plain streams use wrapped text; terminals add bars, indentation and colour.
//
// Source values are cleaned, then redacted, wrapped and coloured. This order masks keys
// reconstructed by cleaning and prevents wrapping from splitting a key before redaction. Nil
// red disables masking. Dates show loc time followed by the same instant in UTC.
func Render(w io.Writer, recs []Projected, s layout.Stream, red *config.Redactor, loc *time.Location) error {
	if len(recs) == 0 {
		return nil
	}
	if red != nil {
		scrubbed := make([]Projected, len(recs))
		for i, p := range recs {
			p.rec = redactRecord(p.rec, red)
			scrubbed[i] = p
		}
		recs = scrubbed
	}
	blocks := make([]string, len(recs))
	if s.Terminal {
		tr := termRenderer{s: s.Fixed(), loc: loc} // so every record has one width
		for i, p := range recs {
			blocks[i] = tr.record(p)
		}
	} else {
		rd := renderer{d: s.Depth, width: s.Cols(), loc: loc}
		for i, p := range recs {
			blocks[i] = rd.record(p)
		}
	}
	_, err := fmt.Fprintln(w, strings.Join(blocks, "\n\n"))
	return err
}

// redactRecord cleans strings before redacting them. Later cleaning is idempotent, preserving
// layout behaviour.
func redactRecord(rec Record, red *config.Redactor) Record {
	str := func(s string) string { return red.Redact(sanitize.Line(s)) }
	ptr := func(p *string) *string {
		if p == nil {
			return nil
		}
		v := str(*p)
		return &v
	}
	out := rec
	out.ID, out.Status = str(rec.ID), str(rec.Status)
	out.Description, out.CVSSVersion, out.CVSSSeverity = ptr(rec.Description), ptr(rec.CVSSVersion), ptr(rec.CVSSSeverity)
	out.CVSSVector, out.CVSSSource = ptr(rec.CVSSVector), ptr(rec.CVSSSource)
	if rec.Weaknesses != nil {
		out.Weaknesses = make([]string, len(rec.Weaknesses))
		for i, w := range rec.Weaknesses {
			out.Weaknesses[i] = str(w)
		}
	}
	if rec.AffectedProducts != nil {
		out.AffectedProducts = make([]AffectedProduct, len(rec.AffectedProducts))
		for i, ap := range rec.AffectedProducts {
			out.AffectedProducts[i] = AffectedProduct{
				CPE: str(ap.CPE), Vendor: ptr(ap.Vendor), Product: ptr(ap.Product), Version: ptr(ap.Version),
				VersionStartIncluding: ptr(ap.VersionStartIncluding), VersionStartExcluding: ptr(ap.VersionStartExcluding),
				VersionEndIncluding: ptr(ap.VersionEndIncluding), VersionEndExcluding: ptr(ap.VersionEndExcluding),
			}
		}
	}
	if rec.References != nil {
		out.References = make([]Reference, len(rec.References))
		for i, ref := range rec.References {
			out.References[i] = Reference{URL: str(ref.URL)}
			if ref.Tags != nil {
				out.References[i].Tags = make([]string, len(ref.Tags))
				for j, t := range ref.Tags {
					out.References[i].Tags[j] = str(t)
				}
			}
		}
	}
	return out
}

type renderer struct {
	d     palette.Depth
	width int
	loc   *time.Location
}

// or supplies cleaned nonblank text or a fallback.
func or(s *string, fallback string) string {
	if s == nil {
		return fallback
	}
	return orEmpty(sanitize.Line(*s), fallback)
}

func orEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func (r renderer) record(p Projected) string {
	rec, has := p.rec, p.f.Has
	header := r.d.Bold(sanitize.Line(rec.ID))
	if has("cvss_severity") {
		header += "  " + r.badge(or(rec.CVSSSeverity, unknownSeverity))
	}
	lines := []string{header}
	section := func(heading, tip string, body []string) {
		if len(body) > 0 {
			h := r.d.Bold(heading)
			if tip != "" {
				h += " " + muted(r.d)(tip)
			}
			lines = append(lines, "", h)
			lines = append(lines, body...)
		}
	}
	section("Status & Dates", "", r.fields(dateFields(rec, has, r.loc)))
	if has("description") {
		section("Description", "", []string{wrap(or(rec.Description, "No description available."), r.width)})
	}
	if kvs, selected := cvssFields(rec, has); selected && kvs == nil {
		section("CVSS Score", "", []string{noCVSSScore})
	} else {
		section("CVSS Score", "", r.fields(kvs))
	}
	if has("weaknesses") {
		section("Weaknesses", "", bullets(cleaned(rec.Weaknesses), "No weaknesses listed.", r.width))
	}
	plain := func(s string) []string { return []string{s} }
	if b, ok := p.listBody(productsList); ok {
		section(b.heading, b.tip, b.lines(func() []string { return bullets(shortForms(rec.AffectedProducts), "", r.width) }, plain))
	}
	if b, ok := p.listBody(referencesList); ok {
		section(b.heading, b.tip, b.lines(func() []string { return r.references(rec.References) }, plain))
	}
	return strings.Join(lines, "\n")
}

// listBody describes a list section: heading, entries or replacement text, a flag for hidden
// entries and any omitted count.
type listBody struct {
	heading string
	tip     string // "" when the entries are shown, or there are none to list
	text    string // "" when the entries are the body
	more    string // "" when none were left out
}

// lines formats entries or replacement text, followed by the omitted-count line, through the
// text layout callback.
func (b listBody) lines(entries func() []string, text func(string) []string) []string {
	var out []string
	if b.text != "" {
		out = text(b.text)
	} else {
		out = entries()
	}
	if b.more != "" {
		out = append(out, text(b.more)...)
	}
	return out
}

// listBody builds the selected list section, or a count-only section when the list is hidden.
// It returns false if neither is selected.
func (p Projected) listBody(i int) (listBody, bool) {
	l, c := lists[i], p.counts[i]
	listed := strconv.Itoa(c.Total)
	matching := fmt.Sprintf("%d of %d match", c.entries(), c.Total)
	nothing := "No " + l.noun + " listed."
	switch {
	case p.f.Has(l.name):
		b := listBody{heading: l.title + " (" + listed + ")"}
		if c.Matched != nil {
			b.heading = l.title + " (" + matching + ")"
		}
		switch {
		case c.entries() > 0: // a limit is at least 1, so some are shown
		case c.Total > 0:
			b.text = "No " + l.noun + " match."
		default:
			b.text = nothing
		}
		if c.Omitted != nil && *c.Omitted > 0 {
			b.more = fmt.Sprintf("%d more not shown", *c.Omitted)
		}
		return b, true
	case p.f.Has(l.count):
		b := listBody{heading: l.title, text: listed + " listed"}
		if p.leftOut(i) {
			b.tip = "(--fields " + l.name + " to show)"
		}
		switch {
		case c.Total == 0:
			b.text = nothing
		case c.Matched != nil:
			b.text = matching
		}
		return b, true
	}
	return listBody{}, false
}

// badge uses palette styling or bracketed plain severity.
func (r renderer) badge(severity string) string {
	if r.d == palette.None {
		return "[" + severity + "]"
	}
	return r.d.Badge(palette.Severity, severity)
}

// fields formats bold labelled values with colons.
func (r renderer) fields(kvs []kv) []string {
	var lines []string
	for _, f := range kvs {
		lines = append(lines, r.d.Bold(f.label+":")+" "+f.value)
	}
	return lines
}

// muted is the style of the muted colour.
func muted(d palette.Depth) func(string) string {
	return func(s string) string { return d.Text(palette.Semantic, "muted", s) }
}

// cleaned sanitises all source strings before layout.
func cleaned(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = sanitize.Line(s)
	}
	return out
}

// kv pairs a section label with a cleaned value.
type kv struct{ label, value string }

// dateFields selects values for Status & Dates.
func dateFields(rec Record, has func(string) bool, loc *time.Location) []kv {
	var kvs []kv
	if has("status") {
		kvs = append(kvs, kv{"Status", orEmpty(sanitize.Line(rec.Status), "Unknown")})
	}
	if has("published") {
		kvs = append(kvs, kv{"Published", localTime(rec.Published, loc)})
	}
	if has("last_modified") {
		kvs = append(kvs, kv{"Last Modified", localTime(rec.LastModified, loc)})
	}
	return kvs
}

// noCVSSScore supplies the selected-but-unavailable score message.
const noCVSSScore = "No CVSS score."

// cvssFields returns selected CVSS details and whether the section was requested. A selected
// but empty section means no score. Severity alone uses the header badge and does not select
// this section.
func cvssFields(rec Record, has func(string) bool) (kvs []kv, selected bool) {
	if !has("cvss_score") && !has("cvss_vector") && !has("cvss_version") && !has("cvss_source") {
		return nil, false
	}
	if rec.CVSSScore == nil {
		return nil, true
	}
	if has("cvss_score") {
		score := strconv.FormatFloat(*rec.CVSSScore, 'f', 1, 64)
		if has("cvss_severity") && rec.CVSSSeverity != nil {
			score += " (" + sanitize.Line(*rec.CVSSSeverity) + ")"
		}
		kvs = append(kvs, kv{"Base Score", score})
	}
	if has("cvss_vector") {
		kvs = append(kvs, kv{"Vector", or(rec.CVSSVector, "Unknown")})
	}
	if has("cvss_version") {
		kvs = append(kvs, kv{"Version", or(rec.CVSSVersion, "Unknown")})
	}
	if has("cvss_source") {
		kvs = append(kvs, kv{"Source", or(rec.CVSSSource, "Unknown")})
	}
	return kvs, true
}

// references formats URLs and their NVD tags.
func (r renderer) references(refs []Reference) []string {
	lines := make([]string, len(refs))
	for i, ref := range refs {
		line := r.d.Text(palette.Semantic, "info", sanitize.Line(ref.URL))
		if len(ref.Tags) > 0 {
			line += " " + muted(r.d)("["+strings.Join(cleaned(ref.Tags), ", ")+"]")
		}
		lines[i] = line
	}
	return lines
}

// shortForm formats product identity and version bounds for people.
func shortForm(ap AffectedProduct) string { return productLine(ap, sanitize.Line, sanitize.Line) }

// shortForms are the products' short forms.
func shortForms(aps []AffectedProduct) []string {
	out := make([]string, len(aps))
	for i, ap := range aps {
		out[i] = shortForm(ap)
	}
	return out
}

// productLine combines product identity and version bounds, falling back to the CPE if identity
// is absent. tidy lets rendering clean source text while matching uses the original text in the
// same format.
func productLine(ap AffectedProduct, tidy, cpe func(string) string) string {
	var name []string
	for _, part := range []*string{ap.Vendor, ap.Product, ap.Version} {
		if part != nil {
			name = append(name, tidy(*part))
		}
	}
	s := strings.Join(name, " ")
	if s == "" {
		s = cpe(ap.CPE)
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
			bounds = append(bounds, b.op+" "+tidy(*b.value))
		}
	}
	if len(bounds) > 0 {
		s += " (" + strings.Join(bounds, ", ") + ")"
	}
	return s
}

// localTime formats a local date and 12-hour time followed by its UTC timestamp.
func localTime(t Timestamp, loc *time.Location) string {
	if t.IsZero() {
		return "Unknown"
	}
	return t.In(loc).Format("2006-01-02 3:04 PM") + " (UTC " + t.UTC().Format(time.RFC3339) + ")"
}

// bullets wraps list items beneath their text, using fallback when empty.
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

// wrap breaks text at spaces within the rune-width limit.
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

// unknownSeverity labels absent scores.
const unknownSeverity = "UNKNOWN"

// Bar lays out a terminal record header with ID on the left and selected severity on the right.
// Colour mode fills the bar with the severity style and leaves barMargin plain. Unknown or
// unrecognised severity uses DEBUG styling. Without selected severity, only the ID appears.
// Without colour, severity uses brackets. ID and severity are cleaned before layout.
func Bar(s layout.Stream, id, severity string, hasSeverity bool) string {
	id = sanitize.Line(id)
	label := orEmpty(sanitize.Line(severity), unknownSeverity)
	cols := s.Cols()
	d := s.Depth
	if !s.Coloured() {
		if !hasSeverity {
			return id
		}
		tag := "[" + label + "]"
		return layout.PadRight(id+" ", cols-layout.Measure(tag)) + tag
	}
	cols -= len(barMargin)
	if !hasSeverity {
		// Unknown severity labels use DEBUG styling.
		return d.BadgeText(palette.Severity, unknownSeverity, layout.PadRight(" "+id, cols)) + barMargin
	}
	return d.BadgeText(palette.Severity, label, layout.PadRight(" "+id+" ", cols-1-layout.Measure(label))+label+" ") + barMargin
}

// barMargin leaves trailing header-bar space uncoloured.
const barMargin = "  "

// termRenderer adds a header bar and indented, wrapped sections. Values are cleaned before
// wrapping and coloured last, as in plain output.
type termRenderer struct {
	s   layout.Stream // its width fixed for the whole write
	loc *time.Location
}

// indent controls section-body padding.
const indent = 2

func (r termRenderer) record(p Projected) string {
	rec, has := p.rec, p.f.Has
	lines := []string{Bar(r.s, rec.ID, or(rec.CVSSSeverity, ""), has("cvss_severity"))}
	// Keep the muted hint whole after its heading.
	section := func(heading, tip string, body []string) {
		if len(body) > 0 {
			var after []layout.Span
			if tip != "" {
				after = []layout.Span{{Text: " "}, {Text: tip, Style: muted(r.s.Depth), Keep: true}}
			}
			lines = append(lines, "")
			lines = append(lines, layout.Heading(r.s, heading, false, after...)...)
			lines = append(lines, body...)
		}
	}
	section("Status & Dates", "", r.fields(dateFields(rec, has, r.loc)))
	if has("description") {
		section("Description", "", r.text(or(rec.Description, "No description available.")))
	}
	if kvs, selected := cvssFields(rec, has); selected && kvs == nil {
		section("CVSS Score", "", r.text(noCVSSScore))
	} else {
		section("CVSS Score", "", r.fields(kvs))
	}
	if has("weaknesses") {
		section("Weaknesses", "", r.bullets(cleaned(rec.Weaknesses), "No weaknesses listed."))
	}
	if b, ok := p.listBody(productsList); ok {
		section(b.heading, b.tip, b.lines(func() []string { return r.bullets(shortForms(rec.AffectedProducts), "") }, r.text))
	}
	if b, ok := p.listBody(referencesList); ok {
		section(b.heading, b.tip, b.lines(func() []string { return r.references(rec.References) }, r.text))
	}
	return strings.Join(lines, "\n")
}

// squash normalises whitespace so terminal wrapping sees the same words as plain layout.
func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// hang wraps plain text under its prefix.
func (r termRenderer) hang(prefix, text string) []string {
	return layout.Hang(prefix, layout.Plain(squash(text)), r.s.Cols(), layout.Spaces)
}

// text is a paragraph indented two spaces.
func (r termRenderer) text(s string) []string { return r.hang(strings.Repeat(" ", indent), s) }

// fields aligns values after the longest label, indents two spaces and wraps continuation lines
// beneath each value. Coloured labels are bold and omit colons.
func (r termRenderer) fields(kvs []kv) []string {
	longest := 0
	for _, f := range kvs {
		longest = max(longest, layout.Measure(f.label))
	}
	col := indent + longest + 2
	var out []string
	for _, f := range kvs {
		head := strings.Repeat(" ", indent) + r.s.Depth.Bold(f.label) + strings.Repeat(" ", col-indent-layout.Measure(f.label))
		out = append(out, r.hang(head, f.value)...)
	}
	return out
}

// bullets aligns wrapped entries beneath their text, or uses an indented fallback for empty
// lists.
func (r termRenderer) bullets(items []string, fallback string) []string {
	if len(items) == 0 {
		return r.text(fallback)
	}
	const mark = "  - "
	var out []string
	for _, item := range items {
		out = append(out, r.hang(mark, item)...)
	}
	return out
}

// references keeps each URL whole in the info colour and wraps muted NVD tags beneath it at
// four-space indentation.
func (r termRenderer) references(refs []Reference) []string {
	d := r.s.Depth
	info := func(x string) string { return d.Text(palette.Semantic, "info", x) }
	var out []string
	for _, ref := range refs {
		spans := []layout.Span{{Text: squash(sanitize.Line(ref.URL)), Style: info}}
		if len(ref.Tags) > 0 {
			tags := make([]string, len(ref.Tags))
			for i, t := range ref.Tags {
				tags[i] = squash(sanitize.Line(t))
			}
			spans = append(spans, layout.Span{Text: " "}, layout.Span{Text: "[" + strings.Join(tags, ", ") + "]", Style: muted(d)})
		}
		ls := layout.Wrap(spans, r.s.Cols(), indent, 2*indent, layout.Spaces)
		out = append(out, strings.Repeat(" ", indent)+ls[0])
		out = append(out, ls[1:]...)
	}
	return out
}
