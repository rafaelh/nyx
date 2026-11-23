// Package spamhaus holds Spamhaus's three Don't Route Or Peer lists and says which entries an
// address falls under. It does no I/O: it parses the files Spamhaus serves and the bundle nyx keeps
// them in, checks them, and matches against them. A copy of the bundle is embedded in the binary.
//
// # Terms
//
// DROP and DROPv6 list netblocks, each a CIDR under an SBL ID, with its regional internet registry
// (RIR). ASN-DROP lists AS numbers, each with its AS name, country, domain and RIR. Each list ends
// with a metadata line, whose timestamp is the list's date and whose records count is the number of
// entries the list says it has.
//
// An entry of DROP or DROPv6 is its (CIDR, SBL ID) pair, so one CIDR under two SBL IDs is two
// entries. An entry of ASN-DROP is its ASN. A match is an entry that applies to an address, with
// its list's date: an address matches a network entry when the CIDR holds it, and an ASN entry when
// its origin AS is the listed one.
//
// A bundle is the three files, in the order drop_v4, drop_v6, asndrop, each after a marker line
// such as {"list":"drop_v4"}, with the file's lines exactly as Spamhaus served them.
package spamhaus

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/rafaelh/nyx/internal/sanitize"
)

//go:embed builtin.jsonl
var builtin []byte

// minShare is the share, in percent, of the records a list's metadata gives that it must hold.
const minShare = 90

// The names of the three lists, as the bundle's marker lines give them.
const (
	ListV4  = "drop_v4"
	ListV6  = "drop_v6"
	ListASN = "asndrop"
)

// Meta is a list's final metadata line.
type Meta struct {
	Timestamp time.Time // the list's date, to the second
	Records   int       // the number of entries the list says it has
	Copyright string    // "" when the line has none
	Terms     string    // "" when the line has none
}

// Updated is the list's date as nyx writes it: RFC 3339, in UTC, to the second.
func (m Meta) Updated() string { return m.Timestamp.UTC().Format(time.RFC3339) }

// NetworkEntry is one row of DROP or DROPv6. RIR is "" when the row's is null or absent.
type NetworkEntry struct {
	CIDR  netip.Prefix
	SBLID string
	RIR   string
}

// ASNEntry is one row of ASN-DROP. A field that is null or absent in the row is "".
type ASNEntry struct {
	ASN     int
	ASName  string
	Country string
	Domain  string
	RIR     string
}

// NetworkList is DROP or DROPv6 as parsed: its entries in file order, its metadata, and the file's
// bytes, which a bundle holds as they are.
type NetworkList struct {
	Meta    Meta
	Entries []NetworkEntry
	Raw     []byte
}

// ASNList is ASN-DROP as parsed: its entries in file order, its metadata, and the file's bytes.
type ASNList struct {
	Meta    Meta
	Entries []ASNEntry
	Raw     []byte

	byASN map[int]int // the index in Entries of each ASN, built by the parse; nil on a list made by hand
}

// Lists is the three lists, ready to match. Each list may come from a different parse.
type Lists struct {
	V4   NetworkList
	V6   NetworkList
	ASNs ASNList
}

// NetworkMatch is a DROP or DROPv6 entry that holds an address, its text sanitised, with its list's
// date (RFC 3339 UTC).
type NetworkMatch struct {
	CIDR    string `json:"cidr"`
	SBLID   string `json:"sbl_id"`
	RIR     string `json:"rir"`
	Updated string `json:"updated"`
}

// ASNMatch is the ASN-DROP entry of an address's origin AS, its text sanitised, with its list's
// date (RFC 3339 UTC).
type ASNMatch struct {
	ASN     int    `json:"asn"`
	ASName  string `json:"as_name"`
	Country string `json:"country"`
	Domain  string `json:"domain"`
	RIR     string `json:"rir"`
	Updated string `json:"updated"`
}

// Builtin is the bundle embedded in the binary. The caller must not change it.
func Builtin() []byte { return builtin }

// ParseDrop reads and checks DROP (v6 false) or DROPv6 (v6 true) as Spamhaus serves it. It refuses
// a row that does not parse or lacks its CIDR or SBL ID, a CIDR that is not canonical or not of the
// list's family, a control character in any text it reads, an entry listed twice, a list whose last
// line is not its metadata, and a list holding fewer than 90% of the records its metadata gives.
// Fields it does not read are ignored, whatever they hold.
func ParseDrop(b []byte, v6 bool) (NetworkList, error) {
	meta, rows, err := splitFile(b)
	if err != nil {
		return NetworkList{}, err
	}
	l := NetworkList{Meta: meta, Raw: b, Entries: make([]NetworkEntry, 0, len(rows))}
	type pair struct {
		cidr netip.Prefix
		sbl  string
	}
	seen := make(map[pair]bool, len(rows))
	for _, r := range rows {
		var row struct {
			CIDR  *string `json:"cidr"`
			SBLID *string `json:"sblid"`
			RIR   *string `json:"rir"`
		}
		if err := json.Unmarshal(r.text, &row); err != nil {
			return NetworkList{}, fmt.Errorf("line %d: %w", r.line, err)
		}
		if row.CIDR == nil || *row.CIDR == "" {
			return NetworkList{}, fmt.Errorf("line %d: the row has no cidr", r.line)
		}
		if row.SBLID == nil || *row.SBLID == "" {
			return NetworkList{}, fmt.Errorf("line %d: the row has no sblid", r.line)
		}
		e := NetworkEntry{SBLID: *row.SBLID, RIR: str(row.RIR)}
		if hasControl(*row.CIDR, e.SBLID, e.RIR) {
			return NetworkList{}, fmt.Errorf("line %d: the row holds a control character", r.line)
		}
		if e.CIDR, err = netip.ParsePrefix(*row.CIDR); err != nil {
			return NetworkList{}, fmt.Errorf("line %d: the cidr %q is not a CIDR", r.line, *row.CIDR)
		}
		if e.CIDR != e.CIDR.Masked() {
			return NetworkList{}, fmt.Errorf("line %d: the cidr %q has host bits set", r.line, *row.CIDR)
		}
		if a := e.CIDR.Addr(); (v6 && (!a.Is6() || a.Is4In6())) || (!v6 && !a.Is4()) {
			return NetworkList{}, fmt.Errorf("line %d: the cidr %q is not of the list's address family", r.line, *row.CIDR)
		}
		k := pair{e.CIDR, e.SBLID}
		if seen[k] {
			return NetworkList{}, fmt.Errorf("line %d: %s under %s is listed twice", r.line, e.CIDR, e.SBLID)
		}
		seen[k] = true
		l.Entries = append(l.Entries, e)
	}
	if err := checkCount(meta, len(l.Entries)); err != nil {
		return NetworkList{}, err
	}
	return l, nil
}

// ParseASNDrop reads and checks ASN-DROP as Spamhaus serves it, with the rules of ParseDrop, and
// an ASN that must be from 1 to 4294967295.
func ParseASNDrop(b []byte) (ASNList, error) {
	meta, rows, err := splitFile(b)
	if err != nil {
		return ASNList{}, err
	}
	l := ASNList{Meta: meta, Raw: b, Entries: make([]ASNEntry, 0, len(rows)), byASN: make(map[int]int, len(rows))}
	for _, r := range rows {
		var row struct {
			ASN    *int64  `json:"asn"`
			RIR    *string `json:"rir"`
			Domain *string `json:"domain"`
			CC     *string `json:"cc"`
			ASName *string `json:"asname"`
		}
		if err := json.Unmarshal(r.text, &row); err != nil {
			return ASNList{}, fmt.Errorf("line %d: %w", r.line, err)
		}
		if row.ASN == nil {
			return ASNList{}, fmt.Errorf("line %d: the row has no asn", r.line)
		}
		if *row.ASN < 1 || *row.ASN > maxASN {
			return ASNList{}, fmt.Errorf("line %d: AS%d is not an AS number (1 to %d)", r.line, *row.ASN, maxASN)
		}
		e := ASNEntry{ASN: int(*row.ASN), ASName: str(row.ASName), Country: str(row.CC), Domain: str(row.Domain), RIR: str(row.RIR)}
		if hasControl(e.ASName, e.Country, e.Domain, e.RIR) {
			return ASNList{}, fmt.Errorf("line %d: the row holds a control character", r.line)
		}
		if _, ok := l.byASN[e.ASN]; ok {
			return ASNList{}, fmt.Errorf("line %d: AS%d is listed twice", r.line, e.ASN)
		}
		l.byASN[e.ASN] = len(l.Entries)
		l.Entries = append(l.Entries, e)
	}
	if err := checkCount(meta, len(l.Entries)); err != nil {
		return ASNList{}, err
	}
	return l, nil
}

// maxASN is the largest AS number: 32 bits.
const maxASN = 4294967295

// str is the text of an optional field: "" when it is null or absent.
func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// hasControl reports whether any text holds a C0 or C1 control character (or DEL).
func hasControl(texts ...string) bool {
	for _, t := range texts {
		if strings.ContainsFunc(t, unicode.IsControl) {
			return true
		}
	}
	return false
}

// checkCount refuses a list that holds fewer than 90% of the records its metadata gives.
func checkCount(m Meta, held int) error {
	if held*100 < m.Records*minShare {
		return fmt.Errorf("the metadata gives %d records but the list holds %d (under %d%%)", m.Records, held, minShare)
	}
	return nil
}

// row is one data line of a file: its text and its line number.
type row struct {
	text []byte
	line int
}

// splitFile splits a file into its data lines and its final metadata line, which it reads.
func splitFile(b []byte) (Meta, []row, error) {
	var rows []row
	for i, line := range bytes.Split(b, []byte{'\n'}) {
		if line = bytes.TrimSpace(line); len(line) > 0 {
			rows = append(rows, row{line, i + 1})
		}
	}
	if len(rows) == 0 {
		return Meta{}, nil, errors.New("the list is empty: it has no metadata line")
	}
	last := rows[len(rows)-1]
	rows = rows[:len(rows)-1]
	var m struct {
		Type      string  `json:"type"`
		Timestamp *int64  `json:"timestamp"`
		Records   *int    `json:"records"`
		Copyright *string `json:"copyright"`
		Terms     *string `json:"terms"`
	}
	if err := json.Unmarshal(last.text, &m); err != nil {
		return Meta{}, nil, fmt.Errorf("line %d: the last line is not a metadata line: %w", last.line, err)
	}
	switch {
	case m.Type != "metadata":
		return Meta{}, nil, fmt.Errorf("line %d: the last line is not the metadata line", last.line)
	case m.Timestamp == nil || *m.Timestamp <= 0:
		return Meta{}, nil, fmt.Errorf("line %d: the metadata has no timestamp", last.line)
	case m.Records == nil || *m.Records < 0:
		return Meta{}, nil, fmt.Errorf("line %d: the metadata has no records count", last.line)
	case hasControl(str(m.Copyright), str(m.Terms)):
		return Meta{}, nil, fmt.Errorf("line %d: the metadata holds a control character", last.line)
	}
	return Meta{Timestamp: time.Unix(*m.Timestamp, 0).UTC(), Records: *m.Records, Copyright: str(m.Copyright), Terms: str(m.Terms)}, rows, nil
}

// Bundle is the bundle of the three files' bytes: each after its marker line, in the order
// drop_v4, drop_v6, asndrop. A file that does not end in a newline is given one.
func Bundle(v4, v6, asn []byte) []byte {
	var out bytes.Buffer
	for _, f := range []struct {
		name string
		b    []byte
	}{{ListV4, v4}, {ListV6, v6}, {ListASN, asn}} {
		fmt.Fprintf(&out, "{\"list\":%q}\n", f.name)
		out.Write(f.b)
		if len(f.b) > 0 && f.b[len(f.b)-1] != '\n' {
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

// ParseBundle reads and checks a bundle. It fails as a whole when any list fails, or when the
// marker lines are not the three lists in order.
func ParseBundle(b []byte) (Lists, error) {
	type section struct {
		name       string
		start, end int // the section's bytes: the lines after its marker, up to the next one
	}
	var sections []section
	for off := 0; off < len(b); {
		end := len(b)
		if i := bytes.IndexByte(b[off:], '\n'); i >= 0 {
			end = off + i + 1
		}
		line := bytes.TrimSpace(b[off:end])
		if name, ok := marker(line); ok {
			sections = append(sections, section{name: name, start: end, end: end})
		} else if len(sections) == 0 {
			if len(line) > 0 {
				return Lists{}, errors.New("the bundle has lines before its first marker")
			}
		} else {
			sections[len(sections)-1].end = end
		}
		off = end
	}
	want := []string{ListV4, ListV6, ListASN}
	if len(sections) != len(want) {
		return Lists{}, fmt.Errorf("the bundle has %d lists, want %d (%s)", len(sections), len(want), strings.Join(want, ", "))
	}
	for i, sec := range sections {
		if sec.name != want[i] {
			return Lists{}, fmt.Errorf("list %d of the bundle is %q, want %q", i+1, sec.name, want[i])
		}
	}
	var l Lists
	var err error
	if l.V4, err = ParseDrop(b[sections[0].start:sections[0].end], false); err != nil {
		return Lists{}, fmt.Errorf("%s: %w", ListV4, err)
	}
	if l.V6, err = ParseDrop(b[sections[1].start:sections[1].end], true); err != nil {
		return Lists{}, fmt.Errorf("%s: %w", ListV6, err)
	}
	if l.ASNs, err = ParseASNDrop(b[sections[2].start:sections[2].end]); err != nil {
		return Lists{}, fmt.Errorf("%s: %w", ListASN, err)
	}
	return l, nil
}

// marker reads a marker line, such as {"list":"drop_v4"}: an object whose one key is "list".
func marker(line []byte) (string, bool) {
	var m map[string]json.RawMessage
	if len(line) == 0 || line[0] != '{' || json.Unmarshal(line, &m) != nil || len(m) != 1 {
		return "", false
	}
	var name string
	if raw, ok := m["list"]; !ok || json.Unmarshal(raw, &name) != nil {
		return "", false
	}
	return name, true
}

// Networks returns every DROP or DROPv6 entry whose CIDR holds the address (unmapped), the longest
// prefix first and entries of one length in file order. It returns an empty list when none does.
func (l Lists) Networks(a netip.Addr) []NetworkMatch {
	a = a.Unmap()
	list := l.V6
	if a.Is4() {
		list = l.V4
	}
	var hits []NetworkEntry
	for _, e := range list.Entries {
		if e.CIDR.Contains(a) {
			hits = append(hits, e)
		}
	}
	slices.SortStableFunc(hits, func(x, y NetworkEntry) int { return y.CIDR.Bits() - x.CIDR.Bits() })
	out := make([]NetworkMatch, 0, len(hits))
	updated := list.Meta.Updated()
	for _, e := range hits {
		out = append(out, NetworkMatch{CIDR: e.CIDR.String(), SBLID: sanitize.Line(e.SBLID), RIR: sanitize.Line(e.RIR), Updated: updated})
	}
	return out
}

// ASN returns the ASN-DROP entry of the AS: a list of one match, or an empty one when it is not
// listed.
func (l Lists) ASN(n int) []ASNMatch {
	i, ok := l.ASNs.byASN[n]
	if l.ASNs.byASN == nil { // a list made by hand has no index
		i = slices.IndexFunc(l.ASNs.Entries, func(e ASNEntry) bool { return e.ASN == n })
		ok = i >= 0
	}
	if !ok {
		return []ASNMatch{}
	}
	e := l.ASNs.Entries[i]
	return []ASNMatch{{ASN: e.ASN, ASName: sanitize.Line(e.ASName), Country: sanitize.Line(e.Country), Domain: sanitize.Line(e.Domain),
		RIR: sanitize.Line(e.RIR), Updated: l.ASNs.Meta.Updated()}}
}
