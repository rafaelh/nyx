// This package holds a snapshot of ipapi.is's two lists of the most abusive networks and
// ASNs, and says which entries an address falls under. An integration with their paid service will
// be added in the future - the snapshot avoids spamming them with queries. It does no I/O: the
// snapshot is one JSON file embedded in the binary, refreshed by running `make threat-data`, and
// a copy downloaded by an update (parsed from ipapi.is's pages by [ParseNetworksPage] and
// [ParseASNsPage], and kept in the same format) may supersede it. The package reads a snapshot and
// matches against it; which copy is in use is for the caller to decide.
//
// # Terms
//
// An abusive network list is ipapi.is's "Most Abusive Networks": IP ranges, each ranked, with a
// score tag, an abuse score (a percentage), the organisation that holds it and its type. An
// abusive ASN list is its "Most Abusive ASNs": the same fields for an AS number. Each list has the
// date ipapi.is says it was last updated.
//
// An entry is one row of a list. A match is an entry that applies to an address: the entry's
// fields and its list's date, as [NetworkMatch] or [ASNMatch]. An address matches a network entry
// when a listed range holds it, and an ASN entry when its origin AS is the listed one.
//
// The snapshot's file holds every entry as ipapi.is gave it, and the number of entries each page
// stated: [Validate] and [ValidateCounts] check it, and
// [Snapshot.Networks] and [Snapshot.ASN] sanitise the text of a match (organisation, score tag and
// type) as other third-party text is, so no output carries it raw.
package abusive

import (
	"bytes"
	"cmp"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/net/html"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/sanitize"
)

//go:embed snapshot.json
var embedded []byte

// NetworkEntry is one row of the abusive network list: an inclusive range of one family.
type NetworkEntry struct {
	Rank       int        `json:"rank"`
	Start      netip.Addr `json:"start"`
	End        netip.Addr `json:"end"`
	ScoreTag   string     `json:"score_tag"`
	AbuseScore float64    `json:"abuse_score"` // the percentage, 0 to 100
	Org        string     `json:"org"`
	OrgType    string     `json:"org_type"`
}

// ASNEntry is one row of the abusive ASN list.
type ASNEntry struct {
	Rank       int     `json:"rank"`
	ASN        int     `json:"asn"`
	ScoreTag   string  `json:"score_tag"`
	AbuseScore float64 `json:"abuse_score"` // the percentage, 0 to 100
	Org        string  `json:"org"`
	OrgType    string  `json:"org_type"`
}

// List is one list: its entries, the YYYY-MM-DD date ipapi.is says it was last updated, and the
// number of entries its page says it lists.
type List[E any] struct {
	Updated string `json:"updated"`
	Stated  int    `json:"stated"`
	Entries []E    `json:"entries"`
}

// Snapshot is both lists, as the file holds them. Network entries are sorted by start, then end,
// and ASN entries by ASN. Only a snapshot from [Load] or [Default] can be matched against.
type Snapshot struct {
	Nets List[NetworkEntry] `json:"networks"`
	ASNs List[ASNEntry]     `json:"asns"`

	idx *index // built by Load
}

// NetworkMatch is a network entry that holds an address. Network is the range as rdap_netblock
// writes one: a CIDR when the range is exactly one, otherwise start-end.
type NetworkMatch struct {
	Network    string  `json:"network"`
	Rank       int     `json:"rank"`
	ScoreTag   string  `json:"score_tag"`
	AbuseScore float64 `json:"abuse_score"`
	Org        string  `json:"org"`
	OrgType    string  `json:"org_type"`
	Updated    string  `json:"updated"` // the list's date, YYYY-MM-DD
}

// ASNMatch is the ASN entry of an address's origin AS.
type ASNMatch struct {
	ASN        int     `json:"asn"`
	Rank       int     `json:"rank"`
	ScoreTag   string  `json:"score_tag"`
	AbuseScore float64 `json:"abuse_score"`
	Org        string  `json:"org"`
	OrgType    string  `json:"org_type"`
	Updated    string  `json:"updated"` // the list's date, YYYY-MM-DD
}

var (
	defaultOnce sync.Once
	defaultSnap *Snapshot
)

// Default is the snapshot embedded in the binary, parsed once. It panics on a bad embed, as
// provider.Default does: a test validates the file.
func Default() *Snapshot {
	defaultOnce.Do(func() {
		s, err := Parse(embedded)
		if err != nil {
			panic("abusive: the embedded snapshot is unreadable: " + err.Error())
		}
		defaultSnap = Load(s)
	})
	return defaultSnap
}

// Parse reads a snapshot file. It does not validate it (see Validate).
func Parse(b []byte) (Snapshot, error) {
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Snapshot{}, fmt.Errorf("reading the abusive-network snapshot: %w", err)
	}
	return s, nil
}

// ParseLenient reads a snapshot file as Parse does, but ignores fields it does not know, so that a
// file written by a newer nyx stays readable. It does not validate it (see Validate).
func ParseLenient(b []byte) (Snapshot, error) {
	var s Snapshot
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&s); err != nil {
		return Snapshot{}, fmt.Errorf("reading the abusive-network snapshot: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Snapshot{}, errors.New("reading the abusive-network snapshot: data after the snapshot")
	}
	return s, nil
}

// minShare is the share, in percent, of the entries a list states that it must hold: below it the
// page was cut short or its layout has changed.
const minShare = 90

// ValidateCounts checks that each list states how many entries it has (at least 1) and holds at
// least 90% of them.
func ValidateCounts(s Snapshot) error {
	if err := validCount("networks", s.Nets.Stated, len(s.Nets.Entries)); err != nil {
		return err
	}
	return validCount("asns", s.ASNs.Stated, len(s.ASNs.Entries))
}

func validCount(list string, stated, held int) error {
	if stated < 1 {
		return fmt.Errorf("%s list: the stated count %d is not a positive number", list, stated)
	}
	if held*100 < stated*minShare {
		return fmt.Errorf("%s list: states %d entries but holds %d (under %d%%)", list, stated, held, minShare)
	}
	return nil
}

// ParsePages reads ipapi.is's most-abusive networks and ASNs pages into a snapshot that passes
// Validate and ValidateCounts. A page dated later than tomorrow in UTC, by now, is refused. A page
// is not refused for being old: whether a list is newer than the copy in use is for the caller.
func ParsePages(networks, asns []byte, now time.Time) (Snapshot, error) {
	nets, err := ParseNetworksPage(networks, now)
	if err != nil {
		return Snapshot{}, fmt.Errorf("networks page: %w", err)
	}
	as, err := ParseASNsPage(asns, now)
	if err != nil {
		return Snapshot{}, fmt.Errorf("ASNs page: %w", err)
	}
	return Snapshot{Nets: nets, ASNs: as}, nil
}

// ParseNetworksPage reads the most-abusive networks page into its list, sorted, with the rules of
// ParsePages for that list alone.
func ParseNetworksPage(page []byte, now time.Time) (List[NetworkEntry], error) {
	p, err := readPage(page, networkColumns, now)
	if err != nil {
		return List[NetworkEntry]{}, err
	}
	list := List[NetworkEntry]{Updated: p.updated, Stated: p.stated, Entries: []NetworkEntry{}}
	for i, row := range p.rows {
		e, err := commonFields(row, p.col)
		if err != nil {
			return List[NetworkEntry]{}, fmt.Errorf("row %d: %w", i+1, err)
		}
		start, end, err := parseRange(row[p.col["entry"]])
		if err != nil {
			return List[NetworkEntry]{}, fmt.Errorf("row %d: %w", i+1, err)
		}
		list.Entries = append(list.Entries, NetworkEntry{Rank: e.rank, Start: start, End: end, ScoreTag: e.tag,
			AbuseScore: e.score, Org: e.org, OrgType: e.typ})
	}
	slices.SortFunc(list.Entries, CompareNetworks)
	if err := validNetworks(list); err != nil {
		return List[NetworkEntry]{}, err
	}
	return list, nil
}

// ParseASNsPage reads the most-abusive ASNs page into its list, sorted, with the rules of
// ParsePages for that list alone.
func ParseASNsPage(page []byte, now time.Time) (List[ASNEntry], error) {
	p, err := readPage(page, asnColumns, now)
	if err != nil {
		return List[ASNEntry]{}, err
	}
	list := List[ASNEntry]{Updated: p.updated, Stated: p.stated, Entries: []ASNEntry{}}
	for i, row := range p.rows {
		e, err := commonFields(row, p.col)
		if err != nil {
			return List[ASNEntry]{}, fmt.Errorf("row %d: %w", i+1, err)
		}
		cell := row[p.col["entry"]]
		digits, ok := strings.CutPrefix(strings.ToLower(cell), "as")
		n, perr := strconv.ParseUint(digits, 10, 32)
		if !ok || perr != nil || n < 1 {
			return List[ASNEntry]{}, fmt.Errorf("row %d: the ASN %q is not as<n> with n from 1 to 4294967295", i+1, cell)
		}
		list.Entries = append(list.Entries, ASNEntry{Rank: e.rank, ASN: int(n), ScoreTag: e.tag, AbuseScore: e.score, Org: e.org, OrgType: e.typ})
	}
	slices.SortFunc(list.Entries, func(a, b ASNEntry) int { return a.ASN - b.ASN })
	if err := validASNs(list); err != nil {
		return List[ASNEntry]{}, err
	}
	return list, nil
}

// Marshal is the snapshot as its file holds it: JSON with one entry to a line, so that a refresh
// diffs as the entries that changed. Text is not escaped for HTML, so an organisation reads as it
// is written.
func Marshal(s Snapshot) []byte {
	var b bytes.Buffer
	b.WriteString("{\n")
	writeList(&b, "networks", s.Nets, ",")
	writeList(&b, "asns", s.ASNs, "")
	b.WriteString("}\n")
	return b.Bytes()
}

// writeList writes one list of the snapshot file, one entry to a line, and then sep.
func writeList[E any](b *bytes.Buffer, name string, l List[E], sep string) {
	fmt.Fprintf(b, " %q: {\n  \"updated\": %q,\n  \"stated\": %d,\n  \"entries\": [\n", name, l.Updated, l.Stated)
	for i, e := range l.Entries {
		var eb bytes.Buffer
		enc := json.NewEncoder(&eb)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(e) // plain structs of strings and numbers
		b.Write(bytes.TrimRight(eb.Bytes(), "\n"))
		if i < len(l.Entries)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("  ]\n }" + sep + "\n")
}

// maxASN is the largest AS number: 32 bits.
const maxASN = 4294967295

// Validate checks a snapshot file's contents: entries sorted and without repeats, each range
// valid, of one family and in order, each AS number in 1 to 4294967295, each rank at least 1, each
// abuse score 0 to 100, each date a day, and no C0 or C1 control character in any text. The
// refresh calls it before writing, and a test calls it on the embedded file. It does not check the
// stated counts (see ValidateCounts).
func Validate(s Snapshot) error {
	if err := validNetworks(s.Nets); err != nil {
		return err
	}
	return validASNs(s.ASNs)
}

// validNetworks is the networks half of Validate.
func validNetworks(l List[NetworkEntry]) error {
	if err := validDate("networks", l.Updated); err != nil {
		return err
	}
	for i, e := range l.Entries {
		at := fmt.Sprintf("networks entry %d", i+1)
		if !e.Start.IsValid() || !e.End.IsValid() || e.Start.Is4() != e.End.Is4() || e.Start.Compare(e.End) > 0 {
			return fmt.Errorf("%s: %s-%s is not a range of one family in order", at, e.Start, e.End)
		}
		if i > 0 {
			p := l.Entries[i-1]
			switch c := CompareNetworks(p, e); {
			case c == 0:
				return fmt.Errorf("%s: %s is listed twice", at, input.RangeText(e.Start, e.End))
			case c > 0:
				return fmt.Errorf("%s: %s is out of order", at, input.RangeText(e.Start, e.End))
			}
		}
		if err := validFields(at, e.Rank, e.AbuseScore, e.ScoreTag, e.Org, e.OrgType); err != nil {
			return err
		}
	}
	return nil
}

// validASNs is the ASNs half of Validate.
func validASNs(l List[ASNEntry]) error {
	if err := validDate("asns", l.Updated); err != nil {
		return err
	}
	for i, e := range l.Entries {
		at := fmt.Sprintf("asns entry %d", i+1)
		if e.ASN < 1 || e.ASN > maxASN {
			return fmt.Errorf("%s: AS%d is not an AS number", at, e.ASN)
		}
		if i > 0 {
			switch p := l.Entries[i-1].ASN; {
			case p == e.ASN:
				return fmt.Errorf("%s: AS%d is listed twice", at, e.ASN)
			case p > e.ASN:
				return fmt.Errorf("%s: AS%d is out of order", at, e.ASN)
			}
		}
		if err := validFields(at, e.Rank, e.AbuseScore, e.ScoreTag, e.Org, e.OrgType); err != nil {
			return err
		}
	}
	return nil
}

// CompareNetworks orders network entries as the snapshot file holds them: by start, then end.
func CompareNetworks(a, b NetworkEntry) int {
	if c := a.Start.Compare(b.Start); c != 0 {
		return c
	}
	return a.End.Compare(b.End)
}

func validDate(list, d string) error {
	if _, err := time.Parse(time.DateOnly, d); err != nil {
		return fmt.Errorf("%s list: the date %q is not YYYY-MM-DD", list, d)
	}
	return nil
}

func validFields(at string, rank int, score float64, texts ...string) error {
	if rank < 1 {
		return fmt.Errorf("%s: rank %d is below 1", at, rank)
	}
	if !(score >= 0 && score <= 100) {
		return fmt.Errorf("%s: abuse score %v is not 0 to 100", at, score)
	}
	for _, t := range texts {
		if HasControl(t) {
			return fmt.Errorf("%s: %q holds a control character", at, t)
		}
	}
	return nil
}

// HasControl reports whether the text holds a C0 or C1 control character (or DEL).
func HasControl(s string) bool { return strings.ContainsFunc(s, unicode.IsControl) }

// ScoreText is an abuse score as nyx writes it: the shortest decimal, with no exponent.
func ScoreText(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// network is a network entry as it is matched and reported.
type network struct {
	start, end netip.Addr
	sizeHi     uint64 // the range's size less one, as a 128-bit number
	sizeLo     uint64
	order      int // the entry's place in its list, the last tiebreak between matches
	match      NetworkMatch
}

// index is a snapshot ready to match: text formatted and sanitised once. nets is sorted by start
// (every IPv4 range before every IPv6 one), and maxEnd[i] is the greatest end among nets[:i+1], so
// a lookup finds the ranges that start at or before an address by binary search and walks back
// only while one of them could still reach it.
type index struct {
	nets   []network
	maxEnd []netip.Addr
	asns   map[int]ASNMatch
}

// Load returns the snapshot prepared for matching.
func Load(s Snapshot) *Snapshot {
	s.idx = build(s)
	return &s
}

func build(s Snapshot) *index {
	ix := &index{asns: make(map[int]ASNMatch, len(s.ASNs.Entries))}
	for _, e := range s.Nets.Entries {
		text := input.RangeText(e.Start, e.End)
		if text == "" {
			continue // an invalid range holds nothing
		}
		start, end := e.Start.Unmap(), e.End.Unmap()
		hi, lo := span(start, end)
		ix.nets = append(ix.nets, network{start: start, end: end, sizeHi: hi, sizeLo: lo, order: len(ix.nets), match: NetworkMatch{
			Network: sanitize.Line(text), Rank: e.Rank, ScoreTag: sanitize.Line(e.ScoreTag), AbuseScore: e.AbuseScore,
			Org: sanitize.Line(e.Org), OrgType: sanitize.Line(e.OrgType), Updated: s.Nets.Updated}})
	}
	slices.SortFunc(ix.nets, func(x, y network) int { return x.start.Compare(y.start) })
	ix.maxEnd = make([]netip.Addr, len(ix.nets))
	for i, n := range ix.nets {
		ix.maxEnd[i] = n.end
		if i > 0 && ix.maxEnd[i-1].Compare(n.end) > 0 {
			ix.maxEnd[i] = ix.maxEnd[i-1]
		}
	}
	for _, e := range s.ASNs.Entries {
		ix.asns[e.ASN] = ASNMatch{ASN: e.ASN, Rank: e.Rank, ScoreTag: sanitize.Line(e.ScoreTag), AbuseScore: e.AbuseScore,
			Org: sanitize.Line(e.Org), OrgType: sanitize.Line(e.OrgType), Updated: s.ASNs.Updated}
	}
	return ix
}

// span is end minus start, two addresses of one family, as the high and low halves of 128 bits.
func span(start, end netip.Addr) (hi, lo uint64) {
	s, e := start.As16(), end.As16()
	lo, borrow := bits.Sub64(binary.BigEndian.Uint64(e[8:]), binary.BigEndian.Uint64(s[8:]), 0)
	hi, _ = bits.Sub64(binary.BigEndian.Uint64(e[:8]), binary.BigEndian.Uint64(s[:8]), borrow)
	return hi, lo
}

// Networks returns every network entry that holds the address (unmapped, as nyx treats addresses
// everywhere), the smallest range first and ranges of one size by rank. An IPv6 address matches
// only IPv6 ranges. It returns an empty list when nothing holds it.
func (s *Snapshot) Networks(a netip.Addr) []NetworkMatch {
	a = a.Unmap()
	var hits []network
	ix := s.idx
	// The ranges that start after a cannot hold it; of the others, none at or before i reaches a
	// once maxEnd[i] is below it.
	i, _ := slices.BinarySearchFunc(ix.nets, a, func(n network, a netip.Addr) int {
		if n.start.Compare(a) <= 0 {
			return -1
		}
		return 1
	})
	for i--; i >= 0 && ix.maxEnd[i].Compare(a) >= 0; i-- {
		if n := ix.nets[i]; n.start.Is4() == a.Is4() && a.Compare(n.end) <= 0 {
			hits = append(hits, n)
		}
	}
	slices.SortFunc(hits, func(x, y network) int {
		if c := cmp.Compare(x.sizeHi, y.sizeHi); c != 0 {
			return c
		}
		if c := cmp.Compare(x.sizeLo, y.sizeLo); c != 0 {
			return c
		}
		if c := x.match.Rank - y.match.Rank; c != 0 {
			return c
		}
		if c := x.start.Compare(y.start); c != 0 {
			return c
		}
		return cmp.Compare(x.order, y.order)
	})
	out := make([]NetworkMatch, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.match)
	}
	return out
}

// ASN returns the entry of the AS: a list of one match, or an empty one when it is not listed.
func (s *Snapshot) ASN(n int) []ASNMatch {
	if m, ok := s.idx.asns[n]; ok {
		return []ASNMatch{m}
	}
	return []ASNMatch{}
}

// ---- reading a page ----

var (
	updatedRE = regexp.MustCompile(`Data last updated on\s+(\p{L}+ \d{1,2}, \d{4})`)
	statedRE  = regexp.MustCompile(`lists the ([\d,]+) most abusive`)
)

// parsedPage is what a fetched page gives before its rows are read.
type parsedPage struct {
	updated string     // YYYY-MM-DD
	stated  int        // the number of entries the page says it lists
	rows    [][]string // the cells of each row, by the position of the header
	col     map[string]int
}

// columns are the headers a page's table must have, by the name a row's reader asks for. A header
// may be written more than one way.
type columns []struct {
	name string
	alts []string
}

var (
	networkColumns = columns{{"rank", []string{"Rank"}}, {"entry", []string{"Network"}}, {"tag", []string{"Score Tag"}},
		{"score", []string{"Abuse Score"}}, {"org", []string{headerOrg}}, {"type", []string{"Type", "Org Type"}}}
	asnColumns = columns{{"rank", []string{"Rank"}}, {"entry", []string{"ASN"}}, {"tag", []string{"Score Tag"}},
		{"score", []string{"Abuse Score"}}, {"org", []string{headerOrg}}, {"type", []string{"Org Type", "Type"}}}
)

func (c columns) String() string {
	names := make([]string, len(c))
	for i, col := range c {
		names[i] = col.alts[0]
	}
	return strings.Join(names, ", ")
}

// readPage parses the HTML and checks what every list's page must say: its date (not later than
// tomorrow), the number of entries it lists and a table with the headers. It returns the table's
// rows.
func readPage(b []byte, cols columns, now time.Time) (parsedPage, error) {
	doc, err := html.Parse(bytes.NewReader(rawC1(b)))
	if err != nil {
		return parsedPage{}, fmt.Errorf("unreadable HTML: %w", err)
	}
	text := strings.Join(strings.Fields(textOf(doc)), " ")
	var p parsedPage
	if p.updated, err = pageDate(text, now); err != nil {
		return parsedPage{}, err
	}
	m := statedRE.FindStringSubmatch(text)
	if m == nil {
		return parsedPage{}, errors.New(`the page does not state how many entries it lists ("lists the N most abusive"): its layout has changed, so no count can be checked`)
	}
	if p.stated, err = strconv.Atoi(strings.ReplaceAll(m[1], ",", "")); err != nil || p.stated < 1 {
		return parsedPage{}, fmt.Errorf("the stated count %q is not a number", m[1])
	}
	table, col := findTable(doc, cols)
	if table == nil {
		return parsedPage{}, fmt.Errorf("no table has the headers %s", cols)
	}
	p.col = col
	need := 0
	for _, i := range col {
		need = max(need, i+1)
	}
	for _, tr := range descendants(table, "tr") {
		cells := directCells(tr, "td")
		if len(cells) == 0 {
			continue
		}
		if len(cells) < need {
			return parsedPage{}, fmt.Errorf("row %d has %d cells, want at least %d (the headers need that many)", len(p.rows)+1, len(cells), need)
		}
		row := make([]string, len(cells))
		for i, c := range cells {
			row[i] = strings.Trim(textOf(c), " \t\r\n")
			if HasControl(row[i]) {
				return parsedPage{}, fmt.Errorf("row %d: %q holds a control character", len(p.rows)+1, row[i])
			}
		}
		p.rows = append(p.rows, row)
	}
	if len(p.rows)*100 < p.stated*minShare {
		return parsedPage{}, fmt.Errorf("the page states %d entries but its table has %d rows (under %d%%)", p.stated, len(p.rows), minShare)
	}
	return p, nil
}

// numRefRE is a whole numeric character reference, hex or decimal, its semicolon optional as HTML
// allows. All its digits are taken, so &#x8F66; is one reference and never &#x8F followed by 66;.
var numRefRE = regexp.MustCompile(`&#(?:[xX]([0-9a-fA-F]+)|([0-9]+));?`)

// rawC1 writes each numeric reference to a C1 code point (0x80 to 0x9f) as the raw character, and
// leaves every other reference as it is. The HTML parser would decode most C1 references through
// Windows-1252 (&#x85; is an ellipsis), so the row's control check would never see them; raw, they
// reach it and the page is refused.
func rawC1(b []byte) []byte {
	return numRefRE.ReplaceAllFunc(b, func(ref []byte) []byte {
		m := numRefRE.FindSubmatch(ref)
		n, err := strconv.ParseUint(string(m[1]), 16, 32)
		if len(m[1]) == 0 {
			n, err = strconv.ParseUint(string(m[2]), 10, 32)
		}
		if err != nil || n < 0x80 || n > 0x9f {
			return ref
		}
		return []byte(string(rune(n)))
	})
}

// pageDate reads the "last updated" date and checks it against the clock: not later than tomorrow
// in UTC, which lets ipapi.is's own time zone be a day ahead. How it compares with the copy in use
// is not its business.
func pageDate(text string, now time.Time) (string, error) {
	m := updatedRE.FindStringSubmatch(text)
	if m == nil {
		return "", errors.New(`the page has no "Data last updated on" date`)
	}
	t, err := time.Parse("January 2, 2006", m[1])
	if err != nil {
		return "", fmt.Errorf("the date %q is not a date", m[1])
	}
	date := t.Format(time.DateOnly)
	if tomorrow := now.UTC().AddDate(0, 0, 1).Format(time.DateOnly); date > tomorrow {
		return "", fmt.Errorf("the page's date %s is in the future (later than %s, tomorrow in UTC)", date, tomorrow)
	}
	return date, nil
}

// findTable is the first table whose header cells include every column, and the position of each.
func findTable(doc *html.Node, cols columns) (*html.Node, map[string]int) {
	for _, table := range descendants(doc, "table") {
		var heads []string
		for _, tr := range descendants(table, "tr") {
			if ths := directCells(tr, "th"); len(ths) > 0 {
				for _, th := range ths {
					heads = append(heads, strings.Join(strings.Fields(textOf(th)), " "))
				}
				break
			}
		}
		pos := map[string]int{}
		for _, c := range cols {
			for _, alt := range c.alts {
				if i := slices.IndexFunc(heads, func(h string) bool { return strings.EqualFold(h, alt) }); i >= 0 {
					pos[c.name] = i
					break
				}
			}
		}
		if len(pos) == len(cols) {
			return table, pos
		}
	}
	return nil, nil
}

// descendants are the elements called tag below n, in document order, not looking into a nested
// table.
func descendants(n *html.Node, tag string) []*html.Node {
	var out []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == tag {
				out = append(out, c)
			}
			if c.Type == html.ElementNode && c.Data == "table" && tag != "table" {
				continue
			}
			walk(c)
		}
	}
	walk(n)
	return out
}

// directCells are the td or th children of a row.
func directCells(tr *html.Node, tag string) []*html.Node {
	var out []*html.Node
	for c := tr.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == tag {
			out = append(out, c)
		}
	}
	return out
}

// textOf is the text of a node and everything in it, without scripts and styles.
func textOf(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		switch {
		case n.Type == html.TextNode:
			b.WriteString(n.Data)
		case n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style"):
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

// ---- reading the rows ----

// pageFields are the columns the two lists share, read.
type pageFields struct {
	rank          int
	tag, org, typ string
	score         float64
}

func commonFields(row []string, col map[string]int) (pageFields, error) {
	var f pageFields
	rank := row[col["rank"]]
	n, err := strconv.Atoi(rank)
	if err != nil || n < 1 {
		return f, fmt.Errorf("the rank %q is not a positive whole number", rank)
	}
	f.rank = n
	score := row[col["score"]]
	num, ok := strings.CutSuffix(score, "%")
	v, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
	if !ok || err != nil || math.IsNaN(v) || !(v >= 0 && v <= 100) {
		return f, fmt.Errorf("the abuse score %q is not a percentage from 0 to 100", score)
	}
	f.score = v
	f.tag = row[col["tag"]]
	if f.tag == "" {
		return f, errors.New("the score tag is empty")
	}
	f.org, f.typ = row[col["org"]], row[col["type"]]
	return f, nil
}

// parseRange reads "start - end": two addresses of one family, the start not after the end.
func parseRange(cell string) (start, end netip.Addr, err error) {
	s, e, ok := strings.Cut(cell, " - ")
	if !ok {
		return start, end, fmt.Errorf("the network %q is not \"start - end\"", cell)
	}
	start, err1 := netip.ParseAddr(strings.TrimSpace(s))
	end, err2 := netip.ParseAddr(strings.TrimSpace(e))
	if err1 != nil || err2 != nil || start.Zone() != "" || end.Zone() != "" {
		return start, end, fmt.Errorf("the network %q does not hold two addresses", cell)
	}
	start, end = start.Unmap(), end.Unmap()
	if start.Is4() != end.Is4() {
		return start, end, fmt.Errorf("the network %q mixes IPv4 and IPv6 (a range has one address family)", cell)
	}
	if start.Compare(end) > 0 {
		return start, end, fmt.Errorf("the network %q is not in order: its start is after its end", cell)
	}
	return start, end, nil
}

// headerOrg is the organisation column's header as ipapi.is spells it.
const headerOrg = "Organization" //nolint:misspell // the page's own spelling
