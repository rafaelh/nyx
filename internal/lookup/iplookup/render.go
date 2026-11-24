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
// display as none; failed-source values display as unknown with details under Failures. Source
// and target text is cleaned before wrapping, then coloured. Terminal output adds aligned
// labels and headings; plain output uses the stream width. The CLI writes errors and warnings
// separately.
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

// none and unknown distinguish empty successful values from failed sources.
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

// list joins entries with commas or displays the empty/unknown placeholder.
func (b body) list(key string, items []string) string {
	var cleaned []string
	for _, it := range items {
		if v := sanitize.Squash(it); v != "" {
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
	if has("drop_networks") {
		add("Spamhaus DROP networks", b.items("drop_networks", len(rec.DropNetworks), rec.DropNetworks == nil, func(i int) string {
			m := rec.DropNetworks[i]
			return dropLine(m.CIDR, m.Updated, m.SBLID, m.RIR)
		}))
	}
	if has("drop_asn") {
		add("Spamhaus ASN-DROP", b.items("drop_asn", len(rec.DropASN), rec.DropASN == nil, func(i int) string {
			m := rec.DropASN[i]
			return dropLine("AS"+strconv.Itoa(m.ASN), m.Updated, m.ASName, m.Country, m.Domain, m.RIR)
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

// items formats list entries or an empty/unknown placeholder. A failed source's nil list
// displays as unknown.
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
		rows[i] = row{rowItem, "", sanitize.Squash(line(i))}
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
// styled independently.
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
// text.
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
			out = append(out, layout.Labelled(r.s, indent, longest, layout.Field{Label: row.label, Value: row.value})...)
		case rowItem:
			out = append(out, layout.Hang("  - ", layout.Plain(row.value), r.s.Cols(), layout.Spaces)...)
		default:
			out = append(out, layout.Hang(strings.Repeat(" ", indent), layout.Plain(row.value), r.s.Cols(), layout.Spaces)...)
		}
	}
	return out
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
