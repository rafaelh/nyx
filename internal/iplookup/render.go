package iplookup

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/layout"
	"github.com/rafaelh/nyx/internal/palette"
	"github.com/rafaelh/nyx/internal/sanitize"
)

// Render writes the records for a person to read: each record's header (its address, the
// hostnames that gave it and its kind), then a labelled section for each part of it the fields
// select, records separated by a blank line. A section none of whose keys is selected is left
// out. A selected value that is empty reads none, and one whose source failed reads unknown (the
// failure is under Failures). Every string from a source or a target is cleaned of anything that
// would act on a terminal before it is wrapped, and coloured at the stream's depth last.
//
// A stream that is not a terminal gets the plain layout, wrapped at the stream's width (COLUMNS,
// else 100, and at least 60). A terminal gets headings, indented sections and aligned labels. The
// CLI writes the error: lines and the warnings; Render writes records only.
func Render(w io.Writer, recs []Projected, s layout.Stream) error {
	if len(recs) == 0 {
		return nil
	}
	blocks := make([]string, len(recs))
	if s.Terminal {
		tr := termRenderer{s: s.Fixed()} // so every record has one width
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

// squash is text with each run of spaces as one space and none at either end.
func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// What a row of a section is.
const (
	rowField = iota // a label and its value
	rowItem         // an entry of a list, shown as a bullet
	rowText         // a line of text
)

// row is one line of a section, its text already cleaned.
type row struct {
	kind         int
	label, value string
}

// section is a titled group of rows.
type section struct {
	title string
	rows  []row
}

// none and unknown are what an empty value and a value whose source failed read.
const (
	none    = "none"
	unknown = "unknown"
)

// body is a record cut to its selection, as the sections a person reads.
type body struct {
	rec *Record
	has func(string) bool
}

// empty is the word for a selected key that has no value: unknown when a source the key needs
// failed, else none. A Team Cymru failure leaves only the AS name unknown once the AS number is
// known, since the provider and what waits on it are decided from the number.
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

// str is a value as text, or the word for a missing one.
func (b body) str(key string, p *string) string {
	if p == nil {
		return b.empty(key)
	}
	if v := squash(sanitize.Line(*p)); v != "" {
		return v
	}
	return none
}

// list is a list as comma separated text, or the word for a missing or empty one.
func (b body) list(key string, items []string) string {
	var cleaned []string
	for _, it := range items {
		if v := squash(sanitize.Line(it)); v != "" {
			cleaned = append(cleaned, v)
		}
	}
	if len(cleaned) == 0 {
		return b.empty(key)
	}
	return strings.Join(cleaned, ", ")
}

func (b body) sections() []section {
	rec, has := b.rec, b.has
	var out []section
	add := func(title string, rows []row) {
		if len(rows) > 0 {
			out = append(out, section{title, rows})
		}
	}
	field := func(rows *[]row, key, label, value string) {
		if has(key) {
			*rows = append(*rows, row{rowField, label, value})
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
	field(&names, "ptr", "PTR", b.list("ptr", rec.PTR))
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
	field(&exposure, "internetdb_ports", "Ports", b.list("internetdb_ports", ports))
	field(&exposure, "internetdb_hostnames", "Hostnames", b.list("internetdb_hostnames", rec.InternetDBHostnames))
	field(&exposure, "internetdb_tags", "Tags", b.list("internetdb_tags", rec.InternetDBTags))
	field(&exposure, "internetdb_cpes", "CPEs", b.list("internetdb_cpes", rec.InternetDBCPEs))
	field(&exposure, "internetdb_vulns", "Vulns", b.list("internetdb_vulns", rec.InternetDBVulns))
	add("Exposure", exposure)

	var reverse []row
	count := b.empty("reverse_ip_count")
	if rec.ReverseIPCount != nil {
		count = strconv.Itoa(*rec.ReverseIPCount)
	}
	field(&reverse, "reverse_ip_count", "Count", count)
	field(&reverse, "reverse_ip", "Names", b.list("reverse_ip", rec.ReverseIP))
	add("Reverse IP", reverse)

	if has("abusive_networks") {
		add("Abusive networks", b.items("abusive_networks", len(rec.AbusiveNetworks), rec.AbusiveNetworks == nil, func(i int) string {
			m := rec.AbusiveNetworks[i]
			return matchLine(m.Network, m.ScoreTag, m.AbuseScore, m.Org, m.OrgType, m.Updated)
		}))
	}
	if has("abusive_asn") {
		add("Abusive ASN", b.items("abusive_asn", len(rec.AbusiveASN), rec.AbusiveASN == nil, func(i int) string {
			m := rec.AbusiveASN[i]
			return matchLine("AS"+strconv.Itoa(m.ASN), m.ScoreTag, m.AbuseScore, m.Org, m.OrgType, m.Updated)
		}))
	}

	if has("not_contacted") {
		add("Not contacted", []row{{rowText, "", b.str("not_contacted", rec.NotContacted)}})
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

// items are the n entries of a list as item rows, or the word for an empty list as a text row. The
// list of a source that failed is nil, so a nil list reads unknown when that source did.
func (b body) items(key string, n int, nilList bool, line func(int) string) []row {
	if n == 0 {
		word := none
		if nilList {
			word = b.empty(key)
		}
		return []row{{rowText, "", word}}
	}
	rows := make([]row, n)
	for i := range rows {
		rows[i] = row{rowItem, "", squash(line(i))}
	}
	return rows
}

// text is a pointer to a string as cleaned text, or "" when it is nil.
func text(p *string) string {
	if p == nil {
		return ""
	}
	return squash(sanitize.Line(*p))
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
			cleaned[i] = squash(sanitize.Line(n))
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
	host := squash(sanitize.Line(e.Host))
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
	return fmt.Sprintf("%s: %s (%s)", sanitize.Line(string(f.Source)), squash(sanitize.Line(f.Message)), strings.Join(flags, ", "))
}

// header is the first line of a record: the address, the hostnames that gave it and its kind,
// as the address (bold when styled) and the rest of the line.
func header(rec *Record) (address, rest string) {
	rest = ""
	if len(rec.Hostnames) > 0 {
		hosts := make([]string, len(rec.Hostnames))
		for i, h := range rec.Hostnames {
			hosts[i] = squash(sanitize.Line(h))
		}
		rest = " (" + strings.Join(hosts, ", ") + ")"
	}
	return squash(sanitize.Line(rec.Address)), rest + " [" + squash(sanitize.Line(string(rec.Kind))) + "]"
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
	lines[0] = r.d.Bold(address) + strings.TrimPrefix(lines[0], address)
	for _, s := range (body{&rec, p.f.Has}).sections() {
		lines = append(lines, "", r.d.Bold(s.title))
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

// hang is text wrapped at spaces after prefix, which is first cells wide; later lines are
// indented by two spaces for a prefix, none without one. A word is never broken, so a long one
// runs past the width.
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

// termRenderer lays records out for a terminal: each section under a heading with no rule, its text
// indented two spaces and wrapped to the width, its labels in a column.
type termRenderer struct {
	s layout.Stream // its width fixed for the whole write
}

// indent is the indentation of every line of a section's body.
const indent = 2

func (r termRenderer) record(p Projected) string {
	rec := p.rec
	address, rest := header(&rec)
	bold := r.s.Depth.Bold
	spans := []layout.Span{{Text: address, Style: bold, Keep: true}, {Text: rest}}
	lines := layout.Wrap(spans, r.s.Cols(), 0, indent, layout.Spaces)
	for _, s := range (body{&rec, p.f.Has}).sections() {
		lines = append(lines, "")
		lines = append(lines, layout.Heading(r.s, s.title, false)...)
		lines = append(lines, r.rows(s.rows)...)
	}
	return strings.Join(lines, "\n")
}

// rows lays a section's rows out, its labelled values aligned in one column.
func (r termRenderer) rows(rows []row) []string {
	longest := 0
	for _, row := range rows {
		if row.kind == rowField {
			longest = max(longest, layout.Measure(row.label))
		}
	}
	var out []string
	for _, row := range rows {
		switch row.kind {
		case rowField:
			head := strings.Repeat(" ", indent) + r.s.Depth.Bold(row.label) + strings.Repeat(" ", longest-layout.Measure(row.label)+2)
			out = append(out, layout.Hang(head, layout.Plain(row.value), r.s.Cols(), layout.Spaces)...)
		case rowItem:
			out = append(out, layout.Hang("  - ", layout.Plain(row.value), r.s.Cols(), layout.Spaces)...)
		default:
			out = append(out, layout.Hang(strings.Repeat(" ", indent), layout.Plain(row.value), r.s.Cols(), layout.Spaces)...)
		}
	}
	return out
}

// matchLine is an abusive list's match as one line: the entry, its score tag, abuse score,
// organisation and type, and the date of its list. Its text came from a snapshot and is cleaned
// like any third party's.
func matchLine(entry, tag string, score float64, org, typ, updated string) string {
	clean := func(s string) string { return squash(sanitize.Line(s)) }
	return fmt.Sprintf("%s: %s, %s%%, %s (%s), updated %s", clean(entry), clean(tag),
		abusive.ScoreText(score), clean(org), clean(typ), clean(updated))
}
