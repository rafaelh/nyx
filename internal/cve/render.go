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

// Render writes the records for a person to read: each record's header, then
// a section for each part of it the fields select, records separated by a
// blank line. The NVD's text is cleaned of anything that would act on a
// terminal before it is wrapped to width, and is coloured at the stream's
// depth last.
//
// A stream that is not a terminal gets the plain layout, wrapped at the
// stream's width (COLUMNS, else 100, and at least 60). A terminal gets the
// layout of termRenderer: a header bar, indented sections and wrapped values.
//
// red masks every configured key in the records' text. Each value is cleaned of
// anything that would act on a terminal first and redacted second, so a key that
// cleaning joins back together is still masked, and redacted before it is
// wrapped, so no line break can split a key and hide it. A nil red masks nothing.
func Render(w io.Writer, recs []Projected, s layout.Stream, red *config.Redactor) error {
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
		tr := termRenderer{s: s.Fixed()} // so every record has one width
		for i, p := range recs {
			blocks[i] = tr.record(p)
		}
	} else {
		rd := renderer{d: s.Depth, width: s.Cols()}
		for i, p := range recs {
			blocks[i] = rd.record(p)
		}
	}
	_, err := fmt.Fprintln(w, strings.Join(blocks, "\n\n"))
	return err
}

// redactRecord is rec with each string cleaned and then redacted. Cleaning again
// later changes nothing, so the layout is as it is without a redactor.
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
}

// or is *s cleaned, or fallback when s is nil or blank.
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
		dates = append(dates, r.field("Status", orEmpty(sanitize.Line(rec.Status), "Unknown")))
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
	section("CVSS Score", r.cvss(rec, has)...)
	if has("weaknesses") {
		ws := make([]string, len(rec.Weaknesses))
		for i, w := range rec.Weaknesses {
			ws[i] = sanitize.Line(w)
		}
		section("Weaknesses", bullets(ws, "No weaknesses listed.", r.width)...)
	}
	plain := func(s string) []string { return []string{s} }
	if b, ok := p.listBody(productsList); ok {
		section(b.heading, b.lines(func() []string { return bullets(shortForms(rec.AffectedProducts), "", r.width) }, plain)...)
	}
	if b, ok := p.listBody(referencesList); ok {
		section(b.heading, b.lines(func() []string { return r.references(rec.References) }, plain)...)
	}
	return strings.Join(lines, "\n")
}

// listBody is what a list's section says: its heading, a line of text in place of
// the entries when there are none to show, and how many entries were left out.
type listBody struct {
	heading string
	text    string // "" when the entries are the body
	more    string // "" when none were left out
}

// lines is the section's body: the entries, or the text in their place, then the
// line saying how many were left out, each line of text laid out by text.
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

// listBody is the section of the list at i in lists: its entries under a heading
// with their number when the list is shown, else its count alone as the body. It
// reports false when neither is selected.
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
func (r renderer) cvss(rec Record, has func(string) bool) []string {
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
			score += " (" + sanitize.Line(*rec.CVSSSeverity) + ")"
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
	lines := make([]string, len(refs))
	for i, ref := range refs {
		line := r.d.Text(palette.Semantic, "info", sanitize.Line(ref.URL))
		if len(ref.Tags) > 0 {
			tags := make([]string, len(ref.Tags))
			for j, t := range ref.Tags {
				tags[j] = sanitize.Line(t)
			}
			line += " " + r.d.Text(palette.Chrome, "TIMESTAMP", "["+strings.Join(tags, ", ")+"]")
		}
		lines[i] = line
	}
	return lines
}

// shortForm is how an affected product reads to a person: apache log4j (>= 2.0.1, < 2.3.1).
func shortForm(ap AffectedProduct) string { return productLine(ap, sanitize.Line, sanitize.Line) }

// shortForms are the products' short forms.
func shortForms(aps []AffectedProduct) []string {
	out := make([]string, len(aps))
	for i, ap := range aps {
		out[i] = shortForm(ap)
	}
	return out
}

// productLine is the line of an affected product, its vendor, product and version
// (its CPE, passed through cpe, when it has none of them) and its version bounds,
// with each of the NVD's other values passed through tidy. Display cleans them
// and matching leaves them as the NVD wrote them, so the two read the same line.
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

// unknownSeverity is the label of a record with no severity.
const unknownSeverity = "UNKNOWN"

// Bar is the bar that opens a record on a terminal: the CVE ID at the left and
// the severity label at the right, as wide as the stream's layout width. With
// colour it is a space, the ID, padding, the label and a space, all in the badge
// style the severity takes. A missing severity (empty, with hasSeverity set)
// reads UNKNOWN, and a value the palette does not know keeps its own text; both
// take the DEBUG style. Without hasSeverity (cvss_severity was not selected) the
// bar holds only the ID, padded to the width, in the DEBUG style. Without colour
// the bar is the ID and the label in brackets at either end of the line, or the
// ID alone without hasSeverity. The ID and the severity are cleaned first.
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
		return id + strings.Repeat(" ", max(1, cols-layout.Measure(id)-layout.Measure(tag))) + tag
	}
	if !hasSeverity {
		// A label the severity table does not hold gets the DEBUG style.
		return d.BadgeText(palette.Severity, unknownSeverity, layout.PadRight(" "+id, cols))
	}
	pad := max(1, cols-1-layout.Measure(id)-layout.Measure(label)-1)
	return d.BadgeText(palette.Severity, label, " "+id+strings.Repeat(" ", pad)+label+" ")
}

// termRenderer lays records out for a terminal: a header bar, then each section
// under a heading with no rule, its text indented two spaces and wrapped to the
// width. Every NVD value is cleaned, then wrapped, then coloured, as in the
// plain layout.
type termRenderer struct {
	s layout.Stream // its width fixed for the whole write
}

// indent is the indentation of every line of a section's body.
const indent = 2

// kv is a field of a section: a label and its cleaned value.
type kv struct{ label, value string }

func (r termRenderer) record(p Projected) string {
	rec, has := p.rec, p.f.Has
	lines := []string{Bar(r.s, rec.ID, or(rec.CVSSSeverity, ""), has("cvss_severity"))}
	section := func(heading string, body []string) {
		if len(body) > 0 {
			lines = append(lines, "")
			lines = append(lines, layout.Heading(r.s, heading, false)...)
			lines = append(lines, body...)
		}
	}
	var dates []kv
	if has("status") {
		dates = append(dates, kv{"Status", orEmpty(sanitize.Line(rec.Status), "Unknown")})
	}
	if has("published") {
		dates = append(dates, kv{"Published", timestamp(rec.Published)})
	}
	if has("last_modified") {
		dates = append(dates, kv{"Last Modified", timestamp(rec.LastModified)})
	}
	section("Status & Dates", r.fields(dates))
	if has("description") {
		section("Description", r.text(or(rec.Description, "No description available.")))
	}
	section("CVSS Score", r.cvss(rec, has))
	if has("weaknesses") {
		ws := make([]string, len(rec.Weaknesses))
		for i, w := range rec.Weaknesses {
			ws[i] = sanitize.Line(w)
		}
		section("Weaknesses", r.bullets(ws, "No weaknesses listed."))
	}
	if b, ok := p.listBody(productsList); ok {
		section(b.heading, b.lines(func() []string { return r.bullets(shortForms(rec.AffectedProducts), "") }, r.text))
	}
	if b, ok := p.listBody(referencesList); ok {
		section(b.heading, b.lines(func() []string { return r.references(rec.References) }, r.text))
	}
	return strings.Join(lines, "\n")
}

// squash is text with each run of spaces as one space and none at either end,
// so it wraps as the plain layout's words do.
func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// hang is plain text wrapped at spaces after prefix, its continuation lines
// under its first.
func (r termRenderer) hang(prefix, text string) []string {
	return layout.Hang(prefix, layout.Plain(squash(text)), r.s.Cols(), layout.Spaces)
}

// text is a paragraph indented two spaces.
func (r termRenderer) text(s string) []string { return r.hang(strings.Repeat(" ", indent), s) }

// fields are labelled values: labels indented two spaces, bold with colour and
// without a colon, then the values in one column two spaces after the longest
// label, wrapping under themselves.
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

// bullets are items as a list, each a dash two spaces in with its continuation
// lines under its text, or fallback alone, indented, when there are none.
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

// cvss is the CVSS section's body, as the plain layout's, for a terminal.
func (r termRenderer) cvss(rec Record, has func(string) bool) []string {
	if !has("cvss_score") && !has("cvss_vector") && !has("cvss_version") && !has("cvss_source") {
		return nil
	}
	if rec.CVSSScore == nil {
		return r.text("No CVSS score.")
	}
	var kvs []kv
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
	return r.fields(kvs)
}

// references are each URL, whole, in the info colour, then the NVD's tags for it
// as a list in the timestamp colour that wraps at spaces, under the URL's text at 4.
func (r termRenderer) references(refs []Reference) []string {
	d := r.s.Depth
	info := func(x string) string { return d.Text(palette.Semantic, "info", x) }
	chrome := func(x string) string { return d.Text(palette.Chrome, "TIMESTAMP", x) }
	var out []string
	for _, ref := range refs {
		spans := []layout.Span{{Text: squash(sanitize.Line(ref.URL)), Style: info}}
		if len(ref.Tags) > 0 {
			tags := make([]string, len(ref.Tags))
			for i, t := range ref.Tags {
				tags[i] = squash(sanitize.Line(t))
			}
			spans = append(spans, layout.Span{Text: " "}, layout.Span{Text: "[" + strings.Join(tags, ", ") + "]", Style: chrome})
		}
		ls := layout.Wrap(spans, r.s.Cols(), indent, 2*indent, layout.Spaces)
		out = append(out, strings.Repeat(" ", indent)+ls[0])
		out = append(out, ls[1:]...)
	}
	return out
}
