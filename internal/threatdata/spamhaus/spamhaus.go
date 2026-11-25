// Package spamhaus parses, validates and matches DROP, DROPv6 and ASN-DROP data without I/O. It
// includes an embedded bundle.
//
// Network entries identify a CIDR/SBL-ID pair; ASN entries identify an AS number. Metadata
// supplies list date and stated record count. Matches add that date to entries covering an
// address or its origin ASN.
//
// Bundles preserve all source bytes in drop_v4, drop_v6, asndrop order, each preceded by a JSON
// list marker.
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
	"sync"
	"time"
	"unicode"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/term/sanitize"
)

//go:embed builtin.jsonl
var builtin []byte

// minShare enforces the metadata completeness threshold as a percentage.
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

// Updated formats the source date as second-precision UTC RFC3339.
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

// NetworkList preserves entries, metadata and original bytes for a DROP/DROPv6 list.
type NetworkList struct {
	Meta    Meta
	Entries []NetworkEntry
	Raw     []byte

	idx *netIndex // built by the parse; nil on a list made by hand
}

// netIndex finds the entries containing an address without scanning them all.
type netIndex struct {
	order  []int        // indices in Entries, ordered by first address
	maxEnd []netip.Addr // maxEnd[i] is the greatest last address of the entries order[:i+1]
}

// index builds the list's netIndex.
func (l NetworkList) index() *netIndex {
	ix := &netIndex{order: make([]int, len(l.Entries)), maxEnd: make([]netip.Addr, len(l.Entries))}
	for i := range ix.order {
		ix.order[i] = i
	}
	slices.SortFunc(ix.order, func(x, y int) int {
		return l.Entries[x].CIDR.Masked().Addr().Compare(l.Entries[y].CIDR.Masked().Addr())
	})
	for i, e := range ix.order {
		ix.maxEnd[i] = input.LastAddr(l.Entries[e].CIDR)
		if i > 0 && ix.maxEnd[i-1].Compare(ix.maxEnd[i]) > 0 {
			ix.maxEnd[i] = ix.maxEnd[i-1]
		}
	}
	return ix
}

// containing returns the indices in Entries of the entries containing a, in no particular order.
func (l NetworkList) containing(a netip.Addr) []int {
	var hits []int
	ix := l.idx
	if ix == nil || len(ix.order) != len(l.Entries) {
		for i, e := range l.Entries {
			if e.CIDR.Contains(a) {
				hits = append(hits, i)
			}
		}
		return hits
	}
	// Skip entries starting after a; stop scanning backwards when no earlier entry can reach it.
	n, _ := slices.BinarySearchFunc(ix.order, a, func(i int, a netip.Addr) int {
		if l.Entries[i].CIDR.Masked().Addr().Compare(a) <= 0 {
			return -1
		}
		return 1
	})
	for n--; n >= 0 && ix.maxEnd[n].Compare(a) >= 0; n-- {
		if i := ix.order[n]; l.Entries[i].CIDR.Contains(a) {
			hits = append(hits, i)
		}
	}
	return hits
}

// ASNList preserves ASN-DROP entries, metadata and source bytes.
type ASNList struct {
	Meta    Meta
	Entries []ASNEntry
	Raw     []byte

	byASN map[int]int // the index in Entries of each ASN, built by the parse; nil on a list made by hand
}

// Lists combines independently parsed sources for matching.
type Lists struct {
	V4   NetworkList
	V6   NetworkList
	ASNs ASNList
}

// NetworkMatch adds sanitised text and a UTC source timestamp to a containing DROP entry.
type NetworkMatch struct {
	CIDR    string `json:"cidr"`
	SBLID   string `json:"sbl_id"`
	RIR     string `json:"rir"`
	Updated string `json:"updated"`
}

// ASNMatch adds sanitised text and a UTC source timestamp to an origin-AS match.
type ASNMatch struct {
	ASN     int    `json:"asn"`
	ASName  string `json:"as_name"`
	Country string `json:"country"`
	Domain  string `json:"domain"`
	RIR     string `json:"rir"`
	Updated string `json:"updated"`
}

// Builtin exposes embedded bundle bytes as read-only data.
func Builtin() []byte { return builtin }

// Default returns the once-parsed embedded bundle. Treat it as read-only. Invalid embedded data
// panics and is checked by tests.
var Default = sync.OnceValue(func() *Lists {
	l, err := ParseBundle(builtin)
	if err != nil {
		panic("spamhaus: the embedded bundle is unreadable: " + err.Error())
	}
	return &l
})

// ParseDrop validates DROP or DROPv6 according to v6. It requires canonical family-matching
// CIDRs, SBL IDs, unique entries and final metadata. Control characters anywhere in a line are
// rejected, including unknown fields. At least 90% of the stated records must be present; other
// unknown fields are ignored.
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
		if jsonHasControl(r.text) {
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
	l.idx = l.index()
	return l, nil
}

// ParseASNDrop applies the same integrity checks as ParseDrop, requiring AS numbers in
// 1..4294967295.
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
		if jsonHasControl(r.text) {
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

// str normalises absent/null optional text to "".
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

// jsonHasControl checks all JSON keys/string values recursively, including unknown fields.
func jsonHasControl(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	for {
		t, err := d.Token()
		if err != nil {
			return false // the end of the text: the caller has already decoded it
		}
		if s, ok := t.(string); ok && hasControl(s) {
			return true
		}
	}
}

// checkCount enforces 90% of the metadata's stated total.
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

// splitFile separates data rows from the required final metadata row.
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
	case jsonHasControl(last.text):
		return Meta{}, nil, fmt.Errorf("line %d: the metadata holds a control character", last.line)
	}
	return Meta{Timestamp: time.Unix(*m.Timestamp, 0).UTC(), Records: *m.Records, Copyright: str(m.Copyright), Terms: str(m.Terms)}, rows, nil
}

// Bundle preserves the three source files after their markers in fixed order, adding a final
// newline where needed.
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

// ParseBundle validates all three lists and their marker order. Any invalid list rejects the
// whole bundle.
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

// marker accepts a one-key JSON list marker.
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

// Networks unmaps addresses and returns containing DROP/DROPv6 entries, longest prefix first
// then file order. No match returns an empty list.
func (l Lists) Networks(a netip.Addr) []NetworkMatch {
	a = a.Unmap()
	list := l.V6
	if a.Is4() {
		list = l.V4
	}
	hits := list.containing(a)
	slices.SortFunc(hits, func(x, y int) int {
		if c := list.Entries[y].CIDR.Bits() - list.Entries[x].CIDR.Bits(); c != 0 {
			return c
		}
		return x - y // file order
	})
	out := make([]NetworkMatch, 0, len(hits))
	updated := list.Meta.Updated()
	for _, i := range hits {
		e := list.Entries[i]
		out = append(out, NetworkMatch{CIDR: e.CIDR.String(), SBLID: sanitize.Line(e.SBLID), RIR: sanitize.Line(e.RIR), Updated: updated})
	}
	return out
}

// ASN returns one ASN-DROP match or an empty list.
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
