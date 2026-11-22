// This package holds a snapshot of ipapi.is's two lists of the most abusive networks and
// ASNs, and says which entries an address falls under. An integration with their paid service will
// be added in the future - the snapshot avoids spamming them with queries. It does no I/O: the
// snapshot is one JSON file embedded in the binary, refreshed by running `make abusive-data`.
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
// The snapshot's file holds every entry as ipapi.is gave it: [Validate] checks it, and
// [Snapshot.Networks] and [Snapshot.ASN] sanitise the text of a match (organisation, score tag and
// type) as other third-party text is, so no output carries it raw.
package abusive

import (
	"bytes"
	"cmp"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

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

// List is one list: its entries and the YYYY-MM-DD date ipapi.is says it was last updated.
type List[E any] struct {
	Updated string `json:"updated"`
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
	fmt.Fprintf(b, " %q: {\n  \"updated\": %q,\n  \"entries\": [\n", name, l.Updated)
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
// refresh calls it before writing, and a test calls it on the embedded file.
func Validate(s Snapshot) error {
	if err := validDate("networks", s.Nets.Updated); err != nil {
		return err
	}
	if err := validDate("asns", s.ASNs.Updated); err != nil {
		return err
	}
	for i, e := range s.Nets.Entries {
		at := fmt.Sprintf("networks entry %d", i+1)
		if !e.Start.IsValid() || !e.End.IsValid() || e.Start.Is4() != e.End.Is4() || e.Start.Compare(e.End) > 0 {
			return fmt.Errorf("%s: %s-%s is not a range of one family in order", at, e.Start, e.End)
		}
		if i > 0 {
			p := s.Nets.Entries[i-1]
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
	for i, e := range s.ASNs.Entries {
		at := fmt.Sprintf("asns entry %d", i+1)
		if e.ASN < 1 || e.ASN > maxASN {
			return fmt.Errorf("%s: AS%d is not an AS number", at, e.ASN)
		}
		if i > 0 {
			switch p := s.ASNs.Entries[i-1].ASN; {
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
