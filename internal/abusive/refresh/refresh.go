package main

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/input"
)

// options are what one refresh reads and writes. now is the clock, in UTC.
type options struct {
	networks, asns, snapshot string // the two fetched pages and the snapshot file
	now                      time.Time
}

// refresh parses the two pages, checks them against the current snapshot, writes the new one and
// prints what changed to out. Nothing is written unless both pages pass every check: both lists
// are in the one file, which is replaced as a whole.
func refresh(o options, out io.Writer) error {
	netPage, err := os.ReadFile(o.networks)
	if err != nil {
		return fmt.Errorf("reading the networks page: %w", err)
	}
	asnPage, err := os.ReadFile(o.asns)
	if err != nil {
		return fmt.Errorf("reading the ASNs page: %w", err)
	}
	old, err := readSnapshot(o.snapshot)
	if err != nil {
		return err
	}
	nets, err := parseNetworks(netPage, old.Nets.Updated, o.now)
	if err != nil {
		return fmt.Errorf("networks page: %w", err)
	}
	asns, err := parseASNs(asnPage, old.ASNs.Updated, o.now)
	if err != nil {
		return fmt.Errorf("ASNs page: %w", err)
	}
	next := abusive.Snapshot{Nets: nets, ASNs: asns}
	if err := abusive.Validate(next); err != nil {
		return err
	}
	if err := writeAtomic(o.snapshot, abusive.Marshal(next)); err != nil {
		return err
	}
	_, err = io.WriteString(out, summary(old, next))
	return err
}

// readSnapshot is the current snapshot, or an empty one when there is no file yet. A file that
// cannot be read is an error, so that a refresh never replaces what it could not understand.
func readSnapshot(path string) (abusive.Snapshot, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return abusive.Snapshot{}, nil
	}
	if err != nil {
		return abusive.Snapshot{}, err
	}
	return abusive.Parse(b)
}

// writeAtomic writes data to a temporary file beside path and renames it into place, so the file
// is the old one or the new one and never half of either.
func writeAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(f.Name())
		}
	}()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Chmod(f.Name(), 0o644); err != nil { //nolint:gosec // the snapshot is source, read by everyone
		return err
	}
	return os.Rename(f.Name(), path)
}

// ---- reading a page ----

// minShare is the share of the entries a page states that it must list: below it the page was cut
// short or its layout has changed.
const minShare = 90

var (
	updatedRE = regexp.MustCompile(`Data last updated on\s+(\p{L}+ \d{1,2}, \d{4})`)
	statedRE  = regexp.MustCompile(`lists the ([\d,]+) most abusive`)
)

// parsedPage is what a fetched page gives before its rows are read.
type parsedPage struct {
	updated string     // YYYY-MM-DD
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

// readPage parses the HTML and checks what every list's page must say: its date (not older than
// previous, nor later than tomorrow), the number of entries it lists and a table with the
// headers. It returns the table's rows.
func readPage(b []byte, cols columns, previous string, now time.Time) (parsedPage, error) {
	doc, err := html.Parse(bytes.NewReader(b))
	if err != nil {
		return parsedPage{}, fmt.Errorf("unreadable HTML: %w", err)
	}
	text := strings.Join(strings.Fields(textOf(doc)), " ")
	var p parsedPage
	if p.updated, err = pageDate(text, previous, now); err != nil {
		return parsedPage{}, err
	}
	m := statedRE.FindStringSubmatch(text)
	if m == nil {
		return parsedPage{}, errors.New(`the page does not state how many entries it lists ("lists the N most abusive"): its layout has changed, so no count can be checked`)
	}
	stated, err := strconv.Atoi(strings.ReplaceAll(m[1], ",", ""))
	if err != nil || stated < 1 {
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
			if abusive.HasControl(row[i]) {
				return parsedPage{}, fmt.Errorf("row %d: %q holds a control character", len(p.rows)+1, row[i])
			}
		}
		p.rows = append(p.rows, row)
	}
	if len(p.rows)*100 < stated*minShare {
		return parsedPage{}, fmt.Errorf("the page states %d entries but its table has %d rows (under %d%%)", stated, len(p.rows), minShare)
	}
	return p, nil
}

// pageDate reads the "last updated" date and checks it against the snapshot's date for the list
// and the clock: not older than the snapshot's, and not later than tomorrow in UTC, which lets
// ipapi.is's own time zone be a day ahead.
func pageDate(text, previous string, now time.Time) (string, error) {
	m := updatedRE.FindStringSubmatch(text)
	if m == nil {
		return "", errors.New(`the page has no "Data last updated on" date`)
	}
	t, err := time.Parse("January 2, 2006", m[1])
	if err != nil {
		return "", fmt.Errorf("the date %q is not a date", m[1])
	}
	date := t.Format(time.DateOnly)
	if previous != "" && date < previous {
		return "", fmt.Errorf("the page's date %s is older than the snapshot's %s", date, previous)
	}
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

func parseNetworks(b []byte, previous string, now time.Time) (abusive.List[abusive.NetworkEntry], error) {
	p, err := readPage(b, networkColumns, previous, now)
	if err != nil {
		return abusive.List[abusive.NetworkEntry]{}, err
	}
	list := abusive.List[abusive.NetworkEntry]{Updated: p.updated, Entries: []abusive.NetworkEntry{}}
	for i, row := range p.rows {
		e, err := commonFields(row, p.col)
		if err != nil {
			return list, fmt.Errorf("row %d: %w", i+1, err)
		}
		start, end, err := parseRange(row[p.col["entry"]])
		if err != nil {
			return list, fmt.Errorf("row %d: %w", i+1, err)
		}
		list.Entries = append(list.Entries, abusive.NetworkEntry{Rank: e.rank, Start: start, End: end, ScoreTag: e.tag,
			AbuseScore: e.score, Org: e.org, OrgType: e.typ})
	}
	slices.SortFunc(list.Entries, abusive.CompareNetworks) // abusive.Validate then rejects a repeat
	return list, nil
}

func parseASNs(b []byte, previous string, now time.Time) (abusive.List[abusive.ASNEntry], error) {
	p, err := readPage(b, asnColumns, previous, now)
	if err != nil {
		return abusive.List[abusive.ASNEntry]{}, err
	}
	list := abusive.List[abusive.ASNEntry]{Updated: p.updated, Entries: []abusive.ASNEntry{}}
	for i, row := range p.rows {
		e, err := commonFields(row, p.col)
		if err != nil {
			return list, fmt.Errorf("row %d: %w", i+1, err)
		}
		cell := row[p.col["entry"]]
		digits, ok := strings.CutPrefix(strings.ToLower(cell), "as")
		n, perr := strconv.ParseUint(digits, 10, 32)
		if !ok || perr != nil || n < 1 {
			return list, fmt.Errorf("row %d: the ASN %q is not as<n> with n from 1 to 4294967295", i+1, cell)
		}
		list.Entries = append(list.Entries, abusive.ASNEntry{Rank: e.rank, ASN: int(n), ScoreTag: e.tag, AbuseScore: e.score, Org: e.org, OrgType: e.typ})
	}
	slices.SortFunc(list.Entries, func(a, b abusive.ASNEntry) int { return a.ASN - b.ASN }) // abusive.Validate then rejects a repeat
	return list, nil
}

// fields are the columns the two lists share, read.
type fields struct {
	rank          int
	tag, org, typ string
	score         float64
}

func commonFields(row []string, col map[string]int) (fields, error) {
	var f fields
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

// ---- the summary ----

// entry is one entry of a list as the summary compares and prints it: the network or AS that
// identifies it, the four fields a change is reported in, and a line to print when it is added or
// removed. The rank is left out, so a rank that alone moved is no change.
type entry struct {
	id     string
	fields [4]string // score tag, abuse score, organisation, type
}

// fieldNames name entry.fields.
var fieldNames = [4]string{"score_tag", "abuse_score", "org", "org_type"}

func (e entry) line() string {
	return fmt.Sprintf("%s: %s %s%% %s (%s)", e.id, e.fields[0], e.fields[1], e.fields[2], e.fields[3])
}

func networkEntries(s abusive.Snapshot) []entry {
	out := make([]entry, len(s.Nets.Entries))
	for i, e := range s.Nets.Entries {
		out[i] = entry{input.RangeText(e.Start, e.End), [4]string{e.ScoreTag, abusive.ScoreText(e.AbuseScore), e.Org, e.OrgType}}
	}
	return out
}

func asnEntries(s abusive.Snapshot) []entry {
	out := make([]entry, len(s.ASNs.Entries))
	for i, e := range s.ASNs.Entries {
		out[i] = entry{"AS" + strconv.Itoa(e.ASN), [4]string{e.ScoreTag, abusive.ScoreText(e.AbuseScore), e.Org, e.OrgType}}
	}
	return out
}

// diff lists what was added, removed and changed, each as the line the summary prints, in the order
// of the lists.
func diff(before, after []entry) (added, removed, changed []string) {
	byID := func(es []entry) map[string]entry {
		m := make(map[string]entry, len(es))
		for _, e := range es {
			m[e.id] = e
		}
		return m
	}
	prev, cur := byID(before), byID(after)
	for _, e := range after {
		p, ok := prev[e.id]
		switch {
		case !ok:
			added = append(added, e.line())
		case p.fields != e.fields:
			var parts []string
			for i, name := range fieldNames {
				if p.fields[i] != e.fields[i] {
					parts = append(parts, fmt.Sprintf("%s: %s -> %s", name, p.fields[i], e.fields[i]))
				}
			}
			changed = append(changed, e.id+": "+strings.Join(parts, "; "))
		}
	}
	for _, e := range before {
		if _, ok := cur[e.id]; !ok {
			removed = append(removed, e.line())
		}
	}
	return added, removed, changed
}

// writeList prints what changed in one list under a heading that names its dates.
func writeList(b *strings.Builder, name, was, now string, before, after []entry) {
	added, removed, changed := diff(before, after)
	dates := now
	if was != now {
		dates = cmp.Or(was, "none") + " -> " + now
	}
	if len(added)+len(removed)+len(changed) == 0 {
		fmt.Fprintf(b, "%s (%s): no entries changed\n", name, dates)
		return
	}
	fmt.Fprintf(b, "%s (%s): %d added, %d removed, %d changed\n", name, dates, len(added), len(removed), len(changed))
	for _, g := range []struct {
		what  string
		lines []string
	}{{"added", added}, {"removed", removed}, {"changed", changed}} {
		for _, l := range g.lines {
			fmt.Fprintf(b, "  %s: %s\n", g.what, l)
		}
	}
}

// summary says what the refresh changed, and what the maintainer must do next.
func summary(old, next abusive.Snapshot) string {
	var b strings.Builder
	writeList(&b, "networks", old.Nets.Updated, next.Nets.Updated, networkEntries(old), networkEntries(next))
	writeList(&b, "asns", old.ASNs.Updated, next.ASNs.Updated, asnEntries(old), asnEntries(next))
	fmt.Fprintf(&b, "Update README.md to give the new dates: networks %s, ASNs %s.\n", next.Nets.Updated, next.ASNs.Updated)
	return b.String()
}

// headerOrg is the organisation column's header as ipapi.is spells it.
const headerOrg = "Organization" //nolint:misspell // the page's own spelling
