package cli_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// Helpers of the threat-data tests: Spamhaus's lists as a test's built-in copy, the downloaded
// copies a test writes into the harness's threat-data directory, and counting fakes on the two
// hosts an update contacts.
//
// The harness's clock is 2026-11-01, and the copies embedded in the binary are dated later and
// move with each refresh, so no test here names their dates: each gives its own built-in copy
// (the harness's abusive and drop) and dates its downloaded copies after it.

// The credit a fixed Spamhaus list carries in its metadata.
const (
	dropCopyright = "(c) 2026 The Spamhaus Project SLU"
	dropTerms     = "https://www.spamhaus.org/drop/terms/"
)

// Entries every fixed Spamhaus list holds besides a test's own, so that no list is empty. No test
// address is inside them.
var (
	dropFillerV4  = spamhaus.NetworkEntry{CIDR: netip.MustParsePrefix("198.18.0.0/15"), SBLID: "SBL999901", RIR: "arin"}
	dropFillerV6  = spamhaus.NetworkEntry{CIDR: netip.MustParsePrefix("2001:db8:ffff::/48"), SBLID: "SBL999902", RIR: "ripencc"}
	dropFillerASN = spamhaus.ASNEntry{ASN: 4200000001, ASName: "FILLER-AS", Country: "ZZ", Domain: "filler.example", RIR: "arin"}
)

func dropNet(cidr, sbl, rir string) spamhaus.NetworkEntry {
	return spamhaus.NetworkEntry{CIDR: netip.MustParsePrefix(cidr), SBLID: sbl, RIR: rir}
}

func dropASN(asn int, name, cc, domain, rir string) spamhaus.ASNEntry {
	return spamhaus.ASNEntry{ASN: asn, ASName: name, Country: cc, Domain: domain, RIR: rir}
}

// dropListsAt is Spamhaus's three lists, all dated at, holding the entries (each network entry in
// the list of its family) after the filler entries, as parsed from the files Spamhaus would serve.
func dropListsAt(tb testing.TB, at time.Time, nets []spamhaus.NetworkEntry, asns []spamhaus.ASNEntry) *spamhaus.Lists {
	tb.Helper()
	return dropListsOn(tb, at, at, at, nets, asns)
}

// dropListsOn is dropListsAt with a date for each list: DROP, DROPv6 and ASN-DROP.
func dropListsOn(tb testing.TB, v4At, v6At, asnAt time.Time, nets []spamhaus.NetworkEntry, asns []spamhaus.ASNEntry) *spamhaus.Lists {
	tb.Helper()
	l, err := spamhaus.ParseBundle([]byte(dropBundleOf(v4At, v6At, asnAt, nets, asns)))
	if err != nil {
		tb.Fatalf("the fixed Spamhaus lists do not parse: %v", err)
	}
	return &l
}

// dropBundleOf is the bundle of Spamhaus's three files holding the entries (each network entry in
// the list of its family) after the filler entries, each file dated as given.
func dropBundleOf(v4At, v6At, asnAt time.Time, nets []spamhaus.NetworkEntry, asns []spamhaus.ASNEntry) string {
	v4, v6 := []spamhaus.NetworkEntry{dropFillerV4}, []spamhaus.NetworkEntry{dropFillerV6}
	for _, n := range nets {
		if n.CIDR.Addr().Is4() {
			v4 = append(v4, n)
		} else {
			v6 = append(v6, n)
		}
	}
	all := append([]spamhaus.ASNEntry{dropFillerASN}, asns...)
	return dropBundleText(dropFileText(v4At, dropRows(v4)), dropFileText(v6At, dropRows(v6)), dropFileText(asnAt, asnDropRows(all)))
}

// ---- downloaded copies ----

// threatDir is the threat-data directory of the harness's runs: beside the default config file.
func threatDir(h *harness) string {
	return filepath.Join(h.env["XDG_CONFIG_HOME"], "nyx", "threat-data")
}

// writeThreatFile writes one file of the threat-data directory, creating the directory.
func writeThreatFile(t *testing.T, h *harness, name, body string) {
	t.Helper()
	dir := threatDir(h)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// dropFileText is one Spamhaus file as Spamhaus serves it: a JSON object to a line, then the
// metadata line, whose records count is the number of rows.
func dropFileText(at time.Time, rows []string) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	size := b.Len()
	fmt.Fprintf(&b, `{"type":"metadata","timestamp":%d,"size":%d,"records":%d,"copyright":%q,"terms":%q}`+"\n",
		at.Unix(), size, len(rows), dropCopyright, dropTerms)
	return b.String()
}

// dropRows are the rows of DROP or DROPv6 for the entries; an empty RIR is null.
func dropRows(nets []spamhaus.NetworkEntry) []string {
	var out []string
	for _, n := range nets {
		rir := "null"
		if n.RIR != "" {
			rir = fmt.Sprintf("%q", n.RIR)
		}
		out = append(out, fmt.Sprintf(`{"cidr":%q,"sblid":%q,"rir":%s}`, n.CIDR.String(), n.SBLID, rir))
	}
	return out
}

// asnDropRows are the rows of ASN-DROP for the entries.
func asnDropRows(asns []spamhaus.ASNEntry) []string {
	var out []string
	for _, a := range asns {
		out = append(out, fmt.Sprintf(`{"asn":%d,"rir":%q,"domain":%q,"cc":%q,"asname":%q}`, a.ASN, a.RIR, a.Domain, a.Country, a.ASName))
	}
	return out
}

// dropBundleText is a downloaded copy of Spamhaus's lists (spamhaus.jsonl): each file after its
// marker line, in the order drop_v4, drop_v6, asndrop.
func dropBundleText(v4, v6, asn string) string {
	return `{"list":"drop_v4"}` + "\n" + v4 + `{"list":"drop_v6"}` + "\n" + v6 + `{"list":"asndrop"}` + "\n" + asn
}

// writeDownloadedDrop writes a downloaded copy of Spamhaus's three lists, all dated at, holding the
// entries after the filler entries, as dropListsAt does.
func writeDownloadedDrop(t *testing.T, h *harness, at time.Time, nets []spamhaus.NetworkEntry, asns []spamhaus.ASNEntry) {
	t.Helper()
	writeThreatFile(t, h, "spamhaus.jsonl", dropBundleOf(at, at, at, nets, asns))
}

// Entries every downloaded copy of ipapi.is's lists holds besides a test's own, so that neither
// list is empty. No test address is inside them.
var (
	abFillerNet = abusive.NetworkEntry{Rank: 9999, Start: netip.MustParseAddr("198.18.0.0"), End: netip.MustParseAddr("198.19.255.255"),
		ScoreTag: "High", AbuseScore: 1, Org: "Filler Org", OrgType: "isp"}
	abFillerASN = abusive.ASNEntry{Rank: 9998, ASN: 4200000001, ScoreTag: "High", AbuseScore: 1, Org: "Filler AS", OrgType: "isp"}
)

// writeDownloadedAbusive writes a downloaded copy of ipapi.is's two lists (ipapi.json), in the
// format of the built-in snapshot: the entries and the filler entries, sorted, each list stating the
// number of entries it holds.
func writeDownloadedAbusive(t *testing.T, h *harness, netsDate, asnsDate string, nets []abusive.NetworkEntry, asns []abusive.ASNEntry) {
	t.Helper()
	nets = append(slices.Clone(nets), abFillerNet)
	slices.SortFunc(nets, func(a, b abusive.NetworkEntry) int {
		if c := a.Start.Compare(b.Start); c != 0 {
			return c
		}
		return a.End.Compare(b.End)
	})
	asns = append(slices.Clone(asns), abFillerASN)
	slices.SortFunc(asns, func(a, b abusive.ASNEntry) int { return a.ASN - b.ASN })
	writeAbusiveSnapshot(t, h, abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: netsDate, Stated: len(nets), Entries: nets},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: asnsDate, Stated: len(asns), Entries: asns},
	})
}

func writeAbusiveSnapshot(t *testing.T, h *harness, s abusive.Snapshot) {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	writeThreatFile(t, h, "ipapi.json", string(b))
}

// ---- what a run says ----

// unreadableLines are the lines of stderr that warn of an unreadable downloaded copy.
func unreadableLines(h *harness) []string {
	var out []string
	for l := range strings.SplitSeq(h.stderr.String(), "\n") {
		if strings.Contains(l, "is unreadable") {
			out = append(out, l)
		}
	}
	return out
}

// isUnreadableWarning reports whether a message is the warning of an unreadable downloaded copy of
// the source (spamhaus or ipapi.is) in dir: "the downloaded <source> data in <dir> is unreadable
// (<reason>), so nyx uses its built-in copy; run nyx setup --update-threat-data to replace it".
func isUnreadableWarning(msg, source, dir string) bool {
	head, rest, ok := strings.Cut(msg, " data in "+dir+" is unreadable (")
	if !ok || !strings.HasPrefix(head, "the downloaded ") || !strings.Contains(strings.ToLower(head), strings.ToLower(source)) {
		return false
	}
	reason, tail, ok := strings.Cut(rest, "), so nyx uses its built-in copy; run nyx setup --update-threat-data to replace it")
	return ok && reason != "" && strings.TrimSpace(tail) == ""
}

// staleHintLines are the lines of stderr that say the threat data in use is old.
func staleHintLines(h *harness) []string {
	var out []string
	for l := range strings.SplitSeq(h.stderr.String(), "\n") {
		if strings.Contains(l, "--update-threat-data") && !strings.Contains(l, "is unreadable") {
			out = append(out, l)
		}
	}
	return out
}

// ---- the two hosts an update contacts ----

// threatCanaries are counting fakes on www.spamhaus.org and ipapi.is, which SourceBaseURLs points
// the harness's runs at. Nothing but an update may reach them.
type threatCanaries struct {
	spamhaus, ipapi atomic.Int32

	mu  sync.Mutex
	log []string // each request's host, method and URI
}

// newThreatCanaries starts the fakes and points the harness at them. Call it after anything that
// replaces h.eopts.SourceBaseURLs (newNVD does).
func newThreatCanaries(t *testing.T, h *harness) *threatCanaries {
	t.Helper()
	c := &threatCanaries{}
	serve := func(n *atomic.Int32, host string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			n.Add(1)
			c.mu.Lock()
			c.log = append(c.log, host+" "+r.Method+" "+r.URL.RequestURI())
			c.mu.Unlock()
			http.NotFound(rw, r)
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	if h.eopts.SourceBaseURLs == nil {
		h.eopts.SourceBaseURLs = map[string]string{}
	}
	h.eopts.SourceBaseURLs[threatdata.SpamhausHost] = serve(&c.spamhaus, threatdata.SpamhausHost)
	h.eopts.SourceBaseURLs[threatdata.IpapiHost] = serve(&c.ipapi, threatdata.IpapiHost)
	return c
}

// untouched fails the test if either fake was sent anything.
func (c *threatCanaries) untouched(t *testing.T, what string) {
	t.Helper()
	if n, m := c.spamhaus.Load(), c.ipapi.Load(); n != 0 || m != 0 {
		c.mu.Lock()
		defer c.mu.Unlock()
		t.Errorf("%s sent %d requests to %s and %d to %s: %v", what, n, threatdata.SpamhausHost, m, threatdata.IpapiHost, c.log)
	}
}
