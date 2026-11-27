package iplookup

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/term/layout"
	"github.com/rafaelh/nyx/internal/term/palette"
	"github.com/rafaelh/nyx/internal/term/sanitize"
	"github.com/rafaelh/nyx/internal/threatdata/abusive"
)

// Render writes selected record sections, separating addresses with blank lines. Empty values
// are left out, and a section left with nothing is left out with its heading; failed-source
// values display as unknown with details under Failures. Source and target text is cleaned
// before wrapping, then coloured. Terminal output adds aligned labels and headings, in two
// columns when the terminal is wide enough; plain output uses the stream width. The CLI writes
// errors and warnings separately.
func Render(w io.Writer, recs []Projected, s layout.Stream) error {
	if len(recs) == 0 {
		return nil
	}
	blocks := make([]string, len(recs))
	if s.Terminal {
		tr := termRenderer{d: s.Depth, width: s.Cols()} // so every record has one width
		for i, p := range recs {
			blocks[i] = tr.record(p)
		}
	} else {
		pr := plainRenderer{d: s.Depth, width: s.Cols()}
		for i, p := range recs {
			blocks[i] = pr.record(p)
		}
	}
	_, err := fmt.Fprintln(w, strings.Join(blocks, "\n\n"))
	return err
}

// What a row of a section is.
const (
	rowField = iota // a label and its value
	rowItem         // an entry of a list, shown as a bullet
	rowText         // a line of text
)

// row is one line of a section, its text already cleaned. A list's value keeps its entries so a
// terminal can colour them, and says whether they are hostnames.
type row struct {
	kind         int
	label, value string
	entries      []string
	hosts        bool
}

// section is a titled group of rows. An alert section's heading is coloured to draw attention.
type section struct {
	title string
	rows  []row
	alert bool
}

// none and unknown distinguish empty successful values from failed sources. A none value is
// never shown.
const (
	none    = "none"
	unknown = "unknown"
)

// body builds human sections from selected record fields.
type body struct {
	rec *Record
	has func(string) bool
}

// empty distinguishes no result from a failed source: none versus unknown. If only Cymru's
// AS-name lookup failed, an already known AS number still supports provider and dependent
// fields.
func (b body) empty(key string) string {
	i := fieldIndex(key)
	if i < 0 {
		return none
	}
	failed := func(s Source) bool {
		if s == SourceCymru && key != "as_name" && b.rec.ASN != nil {
			return false
		}
		return b.rec.Failed(s)
	}
	if slices.ContainsFunc(table[i].sources, failed) {
		return unknown
	}
	return none
}

// str formats a scalar or its missing-value placeholder.
func (b body) str(key string, p *string) string {
	if p == nil {
		return b.empty(key)
	}
	if v := sanitize.Squash(*p); v != "" {
		return v
	}
	return none
}

// list is a labelled row of entries joined with commas, or of the empty/unknown placeholder.
func (b body) list(key, label string, items []string, hosts bool) row {
	var cleaned []string
	for _, it := range items {
		if v := sanitize.Squash(it); v != "" {
			cleaned = append(cleaned, v)
		}
	}
	if len(cleaned) == 0 {
		return row{kind: rowField, label: label, value: b.empty(key)}
	}
	return row{kind: rowField, label: label, value: strings.Join(cleaned, ", "), entries: cleaned, hosts: hosts}
}

func (b body) sections() []section {
	rec, has := b.rec, b.has
	var out []section
	add := func(title string, rows []row) {
		if len(rows) > 0 {
			out = append(out, section{title: title, rows: rows})
		}
	}
	alert := func(title string, rows []row) {
		if len(rows) > 0 {
			out = append(out, section{title: title, rows: rows, alert: true})
		}
	}
	field := func(rows *[]row, key, label, value string) {
		if has(key) && value != none {
			*rows = append(*rows, row{kind: rowField, label: label, value: value})
		}
	}
	list := func(rows *[]row, key, label string, items []string, hosts bool) {
		if r := b.list(key, label, items, hosts); has(key) && r.value != none {
			*rows = append(*rows, r)
		}
	}
	var owner []row
	asn := b.empty("asn")
	if rec.ASN != nil {
		asn = "AS" + strconv.FormatUint(uint64(*rec.ASN), 10)
	}
	field(&owner, "asn", "ASN", asn)
	field(&owner, "as_name", "Name", b.str("as_name", rec.ASName))
	field(&owner, "as_prefix", "Prefix", b.str("as_prefix", rec.ASPrefix))
	add("Owner", owner)

	var registration []row
	field(&registration, "rdap_netblock", "Netblock", b.str("rdap_netblock", rec.RDAPNetblock))
	field(&registration, "rdap_org", "Organisation", b.str("rdap_org", rec.RDAPOrg))
	field(&registration, "rdap_registry", "Registry", b.str("rdap_registry", rec.RDAPRegistry))
	add("Registration", registration)

	var names []row
	list(&names, "ptr", "PTR", rec.PTR, true)
	add("Names", names)

	var provider []row
	field(&provider, "provider", "Provider", b.str("provider", rec.Provider))
	field(&provider, "provider_class", "Class", b.str("provider_class", rec.ProviderClass))
	add("Provider", provider)

	var location []row
	field(&location, "geo_country", "Country", b.str("geo_country", rec.GeoCountry))
	field(&location, "geo_city", "City", b.str("geo_city", rec.GeoCity))
	add("Location", location)

	var exposure []row
	ports := make([]string, len(rec.InternetDBPorts))
	for i, p := range rec.InternetDBPorts {
		ports[i] = strconv.Itoa(p)
	}
	if rec.InternetDBPorts == nil {
		ports = nil
	}
	list(&exposure, "internetdb_ports", "Ports", ports, false)
	list(&exposure, "internetdb_hostnames", "Hostnames", rec.InternetDBHostnames, true)
	list(&exposure, "internetdb_tags", "Tags", rec.InternetDBTags, false)
	list(&exposure, "internetdb_cpes", "CPEs", rec.InternetDBCPEs, false)
	list(&exposure, "internetdb_vulns", "Vulns", rec.InternetDBVulns, false)
	add("Exposure", exposure)

	var reverse []row
	count := b.empty("reverse_ip_count")
	if rec.ReverseIPCount != nil {
		count = strconv.Itoa(*rec.ReverseIPCount)
	}
	field(&reverse, "reverse_ip_count", "Count", count)
	list(&reverse, "reverse_ip", "Names", rec.ReverseIP, true)
	add("Reverse IP", reverse)

	if has("abusive_networks") {
		alert("Abusive networks", b.items("abusive_networks", len(rec.AbusiveNetworks), rec.AbusiveNetworks == nil, func(i int) string {
			m := rec.AbusiveNetworks[i]
			return matchLine(m.Network, m.ScoreTag, m.AbuseScore, m.Org, m.OrgType, m.Updated)
		}))
	}
	if has("abusive_asn") {
		alert("Abusive ASN", b.items("abusive_asn", len(rec.AbusiveASN), rec.AbusiveASN == nil, func(i int) string {
			m := rec.AbusiveASN[i]
			return matchLine("AS"+strconv.Itoa(m.ASN), m.ScoreTag, m.AbuseScore, m.Org, m.OrgType, m.Updated)
		}))
	}
	if has("drop_networks") {
		alert("Spamhaus DROP networks", b.items("drop_networks", len(rec.DropNetworks), rec.DropNetworks == nil, func(i int) string {
			m := rec.DropNetworks[i]
			return dropLine(m.CIDR, m.Updated, m.SBLID, m.RIR)
		}))
	}
	if has("drop_asn") {
		alert("Spamhaus ASN-DROP", b.items("drop_asn", len(rec.DropASN), rec.DropASN == nil, func(i int) string {
			m := rec.DropASN[i]
			return dropLine("AS"+strconv.Itoa(m.ASN), m.Updated, m.ASName, m.Country, m.Domain, m.RIR)
		}))
	}

	if v := b.str("not_contacted", rec.NotContacted); has("not_contacted") && v != none {
		add("Not contacted", []row{{kind: rowText, value: v}})
	}
	if has("ports") {
		add("Ports", b.items("ports", len(rec.Ports), rec.Ports == nil, func(i int) string { return portLine(rec.Ports[i]) }))
	}
	if has("tls") {
		add("TLS", b.items("tls", len(rec.TLS), rec.TLS == nil, func(i int) string { return tlsLine(rec.TLS[i]) }))
	}
	if has("web") {
		add("Web", b.items("web", len(rec.Web), rec.Web == nil, func(i int) string { return webLine(rec.Web[i]) }))
	}
	if has("failures") {
		add("Failures", b.items("failures", len(rec.Failures), false, func(i int) string { return failureLine(rec.Failures[i]) }))
	}
	return out
}

// items formats list entries, or no rows for an empty list. A failed source's nil list
// displays as unknown.
func (b body) items(key string, n int, nilList bool, line func(int) string) []row {
	if n == 0 {
		if nilList && b.empty(key) == unknown {
			return []row{{kind: rowText, value: unknown}}
		}
		return nil
	}
	rows := make([]row, n)
	for i := range rows {
		rows[i] = row{kind: rowItem, value: sanitize.Squash(line(i))}
	}
	return rows
}

// text cleans a string pointer, returning "" for nil.
func text(p *string) string {
	if p == nil {
		return ""
	}
	return sanitize.Squash(*p)
}

// join is the non-empty parts, separated by "; ".
func join(parts ...string) string {
	return strings.Join(slices.DeleteFunc(parts, func(s string) bool { return s == "" }), "; ")
}

func portLine(p Port) string {
	line := fmt.Sprintf("%d %s", p.Port, sanitize.Line(p.State))
	if banner := text(p.Banner); banner != "" {
		line += ": " + banner
	}
	return line
}

func tlsLine(e TLSEntry) string {
	name := "no server name"
	if n := text(e.ServerName); n != "" {
		name = n
	}
	var names string
	if len(e.Names) > 0 {
		cleaned := make([]string, len(e.Names))
		for i, n := range e.Names {
			cleaned[i] = sanitize.Squash(n)
		}
		names = "names " + strings.Join(cleaned, ", ")
	}
	var issuer, expiry string
	if v := text(e.Issuer); v != "" {
		issuer = "issuer " + v
	}
	if v := text(e.Expiry); v != "" {
		expiry = "expires " + v
	}
	return fmt.Sprintf("%d %s: %s", e.Port, name, join(sanitize.Line(e.Outcome), issuer, expiry, names))
}

func webLine(e WebEntry) string {
	host := sanitize.Squash(e.Host)
	if strings.Contains(host, ":") { // an IPv6 address
		host = "[" + host + "]"
	}
	var status, server, title, location string
	if e.Status != nil {
		status = "status " + strconv.Itoa(*e.Status)
	}
	if v := text(e.Server); v != "" {
		server = "server " + v
	}
	if v := text(e.Title); v != "" {
		title = `title "` + v + `"`
	}
	if v := text(e.Location); v != "" {
		location = "redirects to " + v
	}
	return fmt.Sprintf("%d %s://%s/: %s", e.Port, sanitize.Line(e.Scheme), host, join(sanitize.Line(e.Outcome), status, server, title, location))
}

func failureLine(f Failure) string {
	flags := []string{string(f.Code)}
	if f.Transient {
		flags = append(flags, "transient")
	}
	if f.Quota {
		flags = append(flags, "quota")
	}
	return fmt.Sprintf("%s: %s (%s)", sanitize.Line(string(f.Source)), sanitize.Squash(f.Message), strings.Join(flags, ", "))
}

// header separates the address from its contributing hostnames and kind so the address can be
// styled independently: bold, in the amber of help's examples.
func header(rec *Record) (address, rest string) {
	rest = ""
	if len(rec.Hostnames) > 0 {
		hosts := make([]string, len(rec.Hostnames))
		for i, h := range rec.Hostnames {
			hosts[i] = sanitize.Squash(h)
		}
		rest = " (" + strings.Join(hosts, ", ") + ")"
	}
	return sanitize.Squash(rec.Address), rest + " [" + sanitize.Squash(string(rec.Kind)) + "]"
}

// plainRenderer lays records out for a stream that is not a terminal.
type plainRenderer struct {
	d     palette.Depth
	width int
}

func (r plainRenderer) record(p Projected) string {
	rec := p.rec
	address, rest := header(&rec)
	lines := r.hang("", 0, address+rest)
	lines[0] = r.d.BoldText(palette.Semantic, "example", address) + strings.TrimPrefix(lines[0], address)
	for _, s := range (body{&rec, p.f.Has}).sections() {
		title := r.d.Bold(s.title)
		if s.alert {
			title = r.d.BoldText(palette.Semantic, "alert", s.title)
		}
		lines = append(lines, "", title)
		for _, row := range s.rows {
			switch row.kind {
			case rowField:
				lines = append(lines, r.hang(r.d.Bold(row.label+":")+" ", layout.Measure(row.label)+2, row.value)...)
			case rowItem:
				lines = append(lines, r.hang("- ", 2, row.value)...)
			default:
				lines = append(lines, r.hang("", 0, row.value)...)
			}
		}
	}
	return strings.Join(lines, "\n")
}

// hang wraps at spaces after prefix, indenting continuation lines by two spaces when a prefix
// exists. first is the prefix's cell width. Words are never split.
func (r plainRenderer) hang(prefix string, first int, text string) []string {
	rest := 0
	if first > 0 {
		rest = 2
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{strings.TrimRight(prefix, " ")}
	}
	lines := []string{prefix + words[0]}
	used := first + layout.Measure(words[0])
	for _, w := range words[1:] {
		if n := layout.Measure(w); used+1+n <= r.width {
			lines[len(lines)-1] += " " + w
			used += 1 + n
			continue
		}
		lines = append(lines, strings.Repeat(" ", rest)+w)
		used = rest + layout.Measure(w)
	}
	return lines
}

// termRenderer lays out headed sections with two-space indentation, aligned labels and wrapped
// text. The labelled sections that lead a record go in two columns when the width allows.
type termRenderer struct {
	d     palette.Depth
	width int // fixed for the whole write
}

// indent is the indentation of every line of a section's body.
const indent = 2

// Two columns are each at least minColumn cells, gutter cells apart. The default width, used
// when no width is known, gives one column.
const (
	minColumn = 50
	gutter    = 4
)

func (r termRenderer) record(p Projected) string {
	rec := p.rec
	address, rest := header(&rec)
	style := func(x string) string { return r.d.BoldText(palette.Semantic, "example", x) }
	spans := []layout.Span{{Text: address, Style: style, Keep: true}, {Text: rest}}
	lines := layout.Wrap(spans, r.width, 0, indent, layout.Spaces)
	secs := (body{&rec, p.f.Has}).sections()
	if cols, n := r.columns(secs); n > 0 {
		lines = append(append(lines, ""), cols...)
		secs = secs[n:]
	}
	for _, s := range secs {
		lines = append(lines, "")
		lines = append(lines, r.section(s, r.width)...)
	}
	return strings.Join(lines, "\n")
}

// columns lays the leading sections that hold only labelled values down a left column and
// then a right one, split where the taller column is shortest (the left on a tie), and returns
// the lines and how many sections they hold. It returns none when fewer than two such sections
// lead, when the width allows one column, or when a word too long to wrap would push the
// columns past the width. Lists are left to span the width, as their lines are long.
func (r termRenderer) columns(secs []section) ([]string, int) {
	n := 0
	for n < len(secs) && !slices.ContainsFunc(secs[n].rows, func(x row) bool { return x.kind != rowField }) {
		n++
	}
	if n < 2 || r.width < 2*minColumn+gutter {
		return nil, 0
	}
	w := (r.width - gutter) / 2
	blocks := make([][]string, n)
	for i, s := range secs[:n] {
		blocks[i] = r.section(s, w)
	}
	split, tallest := 0, 0
	for k := 1; k < n; k++ {
		if h := max(height(blocks[:k]), height(blocks[k:])); split == 0 || h <= tallest {
			split, tallest = k, h
		}
	}
	left, right := stack(blocks[:split]), stack(blocks[split:])
	lw := max(w, widest(left))
	if lw+gutter+widest(right) > r.width {
		return nil, 0
	}
	out := make([]string, max(len(left), len(right)))
	for i := range out {
		if i < len(left) {
			out[i] = left[i]
		}
		if i < len(right) && right[i] != "" {
			out[i] = layout.PadRight(out[i], lw+gutter) + right[i]
		}
	}
	return out, n
}

// height is the lines blocks take stacked with a blank line between each.
func height(blocks [][]string) int {
	h := len(blocks) - 1
	for _, b := range blocks {
		h += len(b)
	}
	return h
}

// stack joins blocks with a blank line between each.
func stack(blocks [][]string) []string {
	var out []string
	for i, b := range blocks {
		if i > 0 {
			out = append(out, "")
		}
		out = append(out, b...)
	}
	return out
}

// widest is the cell width of the longest line.
func widest(lines []string) int {
	w := 0
	for _, l := range lines {
		w = max(w, layout.Measure(l))
	}
	return w
}

// section lays out a heading, in bold info or, for an alert, in setup's red, then its rows,
// their labelled values aligned in one column and everything wrapped at width.
func (r termRenderer) section(s section, width int) []string {
	role := "info"
	if s.alert {
		role = "alert"
	}
	style := func(x string) string { return r.d.BoldText(palette.Semantic, role, x) }
	out := layout.Wrap([]layout.Span{{Text: s.title, Style: style}}, width, 0, 0, layout.Spaces)
	longest := 0
	for _, row := range s.rows {
		if row.kind == rowField {
			longest = max(longest, layout.Measure(row.label))
		}
	}
	pad := strings.Repeat(" ", indent)
	for _, row := range s.rows {
		switch row.kind {
		case rowField:
			head := pad + r.d.Bold(row.label) + strings.Repeat(" ", longest-layout.Measure(row.label)+2)
			out = append(out, layout.Hang(head, r.value(row), width, layout.Spaces)...)
		case rowItem:
			out = append(out, layout.Hang(pad+"- ", layout.Plain(row.value), width, layout.Spaces)...)
		default:
			out = append(out, layout.Hang(pad, layout.Plain(row.value), width, layout.Spaces)...)
		}
	}
	return out
}

// levelRoles colour a hostname's TLD, the domain under it and the one under that.
var levelRoles = [3]string{"tld", "domain", "subdomain"}

// value is a row's value as spans: a list's separating commas faint, and each hostname's dots
// pale and its last three labels coloured by level, so the entries of a long list stand apart.
func (r termRenderer) value(x row) []layout.Span {
	if len(x.entries) == 0 {
		return layout.Plain(x.value)
	}
	role := func(name string) func(string) string {
		return func(s string) string { return r.d.Text(palette.Semantic, name, s) }
	}
	var spans []layout.Span
	for i, e := range x.entries {
		if i > 0 {
			spans = append(spans, layout.Span{Text: ", ", Style: role("separator")})
		}
		if !x.hosts {
			spans = append(spans, layout.Span{Text: e})
			continue
		}
		name, dotted := strings.CutSuffix(e, ".")
		labels := strings.Split(name, ".")
		for j, l := range labels {
			if j > 0 {
				spans = append(spans, layout.Span{Text: ".", Style: role("dot")})
			}
			span := layout.Span{Text: l}
			if level := len(labels) - 1 - j; level < len(levelRoles) {
				span.Style = role(levelRoles[level])
			}
			spans = append(spans, span)
		}
		if dotted {
			spans = append(spans, layout.Span{Text: ".", Style: role("dot")})
		}
	}
	return spans
}

// matchLine formats an abuse-list match and its date. Snapshot text is cleaned like any
// external source text.
func matchLine(entry, tag string, score float64, org, typ, updated string) string {
	return fmt.Sprintf("%s: %s, %s%%, %s (%s), updated %s", sanitize.Squash(entry), sanitize.Squash(tag),
		abusive.ScoreText(score), sanitize.Squash(org), sanitize.Squash(typ), sanitize.Squash(updated))
}

// dropLine formats a Spamhaus entry, available details and list date, cleaning all external
// text.
func dropLine(entry, updated string, details ...string) string {
	parts := []string{}
	for _, d := range details {
		if d = sanitize.Squash(d); d != "" {
			parts = append(parts, d)
		}
	}
	parts = append(parts, "updated "+sanitize.Squash(updated))
	return sanitize.Squash(entry) + ": " + strings.Join(parts, ", ")
}
