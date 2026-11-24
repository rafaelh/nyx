// Package threatdatatest builds threat-data fixtures for tests: Spamhaus DROP files in the format
// Spamhaus serves, and ipapi.is entries, snapshots and pages. It holds only pure builders; the fake
// HTTP servers stay in test files, as only internal/egress may import net/http.
package threatdatatest

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/threatdata/abusive"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
)

// The credit a generated Spamhaus file carries, as Spamhaus's own do.
const (
	Copyright = "(c) 2026 The Spamhaus Project SLU"
	Terms     = "https://www.spamhaus.org/drop/terms/"
)

// NetRow is one DROP or DROPv6 row in the source format; an empty RIR is null.
func NetRow(cidr, sblid, rir string) string {
	r := "null"
	if rir != "" {
		r = fmt.Sprintf("%q", rir)
	}
	return fmt.Sprintf(`{"cidr":%q,"sblid":%q,"rir":%s}`, cidr, sblid, r)
}

// ASNRow is one ASN-DROP row in the source format.
func ASNRow(asn int, asname, cc, domain, rir string) string {
	return fmt.Sprintf(`{"asn":%d,"rir":%q,"domain":%q,"cc":%q,"asname":%q}`, asn, rir, domain, cc, asname)
}

// MetaLine is a Spamhaus metadata line dated at that states records, with the credit.
func MetaLine(at time.Time, records int) string {
	return fmt.Sprintf(`{"type":"metadata","timestamp":%d,"size":1234,"records":%d,"copyright":%q,"terms":%q}`,
		at.Unix(), records, Copyright, Terms)
}

// DropFile is a Spamhaus file of the rows, then a metadata line dated at that states their number,
// each line ending in a newline.
func DropFile(at time.Time, rows ...string) []byte {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	b.WriteString(MetaLine(at, len(rows)) + "\n")
	return []byte(b.String())
}

// Lists parses the three files, failing the test if one does not parse.
func Lists(tb testing.TB, v4, v6, asn []byte) *spamhaus.Lists {
	tb.Helper()
	l4, err := spamhaus.ParseDrop(v4, false)
	if err != nil {
		tb.Fatalf("drop_v4: %v", err)
	}
	l6, err := spamhaus.ParseDrop(v6, true)
	if err != nil {
		tb.Fatalf("drop_v6: %v", err)
	}
	la, err := spamhaus.ParseASNDrop(asn)
	if err != nil {
		tb.Fatalf("asndrop: %v", err)
	}
	return &spamhaus.Lists{V4: l4, V6: l6, ASNs: la}
}

// GenV4Row, GenV6Row and GenASNRow are entry i of a generated list.
func GenV4Row(i int) string {
	return NetRow(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), fmt.Sprintf("SBL%d", 100000+i), "ripencc")
}

func GenV6Row(i int) string {
	return NetRow(fmt.Sprintf("2001:db8:%x::/48", i), fmt.Sprintf("SBL%d", 200000+i), "apnic")
}

func GenASNRow(i int) string {
	return ASNRow(64500+i, fmt.Sprintf("BAD-AS-%d", i), "US", fmt.Sprintf("bad%d.example", i), "arin")
}

// GenRows is entries from to from+n-1 of a generated list.
func GenRows(row func(int) string, from, n int) []string {
	out := make([]string, 0, n)
	for i := from; i < from+n; i++ {
		out = append(out, row(i))
	}
	return out
}

// GenDropFile is a generated list of entries from to from+n-1, dated at, that states n records.
func GenDropFile(row func(int) string, at time.Time, from, n int) []byte {
	return DropFile(at, GenRows(row, from, n)...)
}

// GenNetwork and GenASN are entry i of a generated ipapi.is list, in the snapshot format.
func GenNetwork(i int) abusive.NetworkEntry {
	return abusive.NetworkEntry{Rank: i + 1, Start: netip.MustParseAddr(fmt.Sprintf("172.%d.%d.0", 16+i/200, i%200)),
		End: netip.MustParseAddr(fmt.Sprintf("172.%d.%d.255", 16+i/200, i%200)), ScoreTag: "High", AbuseScore: 50, Org: fmt.Sprintf("Org %d", i), OrgType: "isp"}
}

func GenASN(i int) abusive.ASNEntry {
	return abusive.ASNEntry{Rank: i + 1, ASN: 65000 + i, ScoreTag: "High", AbuseScore: 50, Org: fmt.Sprintf("AS Org %d", i), OrgType: "isp"}
}

// GenSnapshot is an ipapi.is copy of generated networks from nFrom to nFrom+nn-1 and ASNs from
// aFrom to aFrom+an-1, each list stating its number of entries.
func GenSnapshot(netsDate string, nFrom, nn int, asnsDate string, aFrom, an int) abusive.Snapshot {
	s := abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: netsDate, Stated: nn, Entries: []abusive.NetworkEntry{}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: asnsDate, Stated: an, Entries: []abusive.ASNEntry{}},
	}
	for i := nFrom; i < nFrom+nn; i++ {
		s.Nets.Entries = append(s.Nets.Entries, GenNetwork(i))
	}
	for i := aFrom; i < aFrom+an; i++ {
		s.ASNs.Entries = append(s.ASNs.Entries, GenASN(i))
	}
	return s
}

// headerOrg is the page's spelling of its organisation column.
const headerOrg = "Organization" //nolint:misspell // the page's own spelling

// pageDate is a YYYY-MM-DD date as the pages write it.
func pageDate(d string) string {
	t, _ := time.Parse(time.DateOnly, d)
	return t.Format("January 2, 2006")
}

// NetworksPage is ipapi.is's most-abusive networks page, dated d (YYYY-MM-DD), stating stated
// entries and listing generated networks from to from+n-1.
func NetworksPage(d string, stated, from, n int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><span>Data last updated on <strong>%s</strong></span><p>The table lists the <strong>%d</strong> most abusive networks on the Internet.</p>`, pageDate(d), stated)
	b.WriteString(`<table><thead><tr><th>Rank</th><th>Network</th><th>Num Hosts</th><th>Score Tag</th><th>Abuse Score</th><th>` + headerOrg + `</th><th>Type</th></tr></thead><tbody>`)
	for i := from; i < from+n; i++ {
		e := GenNetwork(i)
		fmt.Fprintf(&b, `<tr><td>%d</td><td><a>%s - %s</a></td><td>256</td><td><span>High</span></td><td>50%%</td><td>%s</td><td><span>isp</span></td></tr>`,
			e.Rank, e.Start, e.End, e.Org)
	}
	b.WriteString(`</tbody></table></body></html>`)
	return []byte(b.String())
}

// ASNsPage is ipapi.is's most-abusive ASNs page, dated d (YYYY-MM-DD), stating stated entries and
// listing generated ASNs from to from+n-1.
func ASNsPage(d string, stated, from, n int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, `<html><body><span>Data last updated on <strong>%s</strong></span><p>The table lists the <strong>%d</strong> most abusive ASNs.</p>`, pageDate(d), stated)
	b.WriteString(`<table><thead><tr><th>Rank</th><th>ASN</th><th>Num IPs and Routes</th><th>Score Tag</th><th>Abuse Score</th><th>` + headerOrg + `</th><th>Org Type</th></tr></thead><tbody>`)
	for i := from; i < from+n; i++ {
		e := GenASN(i)
		fmt.Fprintf(&b, `<tr><td>%d</td><td><a>as%d</a></td><td>1</td><td><span>High</span></td><td>50%%</td><td>%s</td><td><span>isp</span></td></tr>`, e.Rank, e.ASN, e.Org)
	}
	b.WriteString(`</tbody></table></body></html>`)
	return []byte(b.String())
}
