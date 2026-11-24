package cli_test

import (
	"encoding/json"
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

	"github.com/rafaelh/nyx/internal/threatdata"
	"github.com/rafaelh/nyx/internal/threatdata/abusive"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
	tdt "github.com/rafaelh/nyx/internal/threatdata/threatdatatest"
)

// Threat tests supply fixed built-ins older than their downloads. Embedded dates move after
// refreshes and would make fixture selection/staleness unstable.

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

// dropListsAt builds parsed source-format lists with filler plus test entries at one fixed
// date.
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

// dropBundleOf builds source-byte bundles with family-specific entries and requested dates.
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
	return string(spamhaus.Bundle(tdt.DropFile(v4At, dropRows(v4)...), tdt.DropFile(v6At, dropRows(v6)...), tdt.DropFile(asnAt, asnDropRows(all)...)))
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

// dropRows are the rows of DROP or DROPv6 for the entries; an empty RIR is null.
func dropRows(nets []spamhaus.NetworkEntry) []string {
	var out []string
	for _, n := range nets {
		out = append(out, tdt.NetRow(n.CIDR.String(), n.SBLID, n.RIR))
	}
	return out
}

// asnDropRows are the rows of ASN-DROP for the entries.
func asnDropRows(asns []spamhaus.ASNEntry) []string {
	var out []string
	for _, a := range asns {
		out = append(out, tdt.ASNRow(a.ASN, a.ASName, a.Country, a.Domain, a.RIR))
	}
	return out
}

// writeDownloadedDrop writes a downloaded copy of Spamhaus's three lists, all dated at, holding the
// entries after the filler entries, as dropListsAt does.
func writeDownloadedDrop(t *testing.T, h *harness, at time.Time, nets []spamhaus.NetworkEntry, asns []spamhaus.ASNEntry) {
	t.Helper()
	writeThreatFile(t, h, "spamhaus.jsonl", dropBundleOf(at, at, at, nets, asns))
}

// Filler keeps downloaded lists nonempty without matching test addresses.
var (
	abFillerNet = abusive.NetworkEntry{Rank: 9999, Start: netip.MustParseAddr("198.18.0.0"), End: netip.MustParseAddr("198.19.255.255"),
		ScoreTag: "High", AbuseScore: 1, Org: "Filler Org", OrgType: "isp"}
	abFillerASN = abusive.ASNEntry{Rank: 9998, ASN: 4200000001, ScoreTag: "High", AbuseScore: 1, Org: "Filler AS", OrgType: "isp"}
)

// writeDownloadedAbusive writes sorted fixture/filler entries with accurate counts in snapshot
// format.
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

// unreadableLines extracts download-fallback warnings from stderr.
func unreadableLines(h *harness) []string {
	var out []string
	for l := range strings.SplitSeq(h.stderr.String(), "\n") {
		if strings.Contains(l, "is unreadable") {
			out = append(out, l)
		}
	}
	return out
}

// isUnreadableWarning recognises a source/path-specific fallback notice without depending on
// its variable failure reason.
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
