package findings_test

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/recon/analysis/findings"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/scope"
	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/threatdata/abusive"
	"github.com/rafaelh/nyx/internal/threatdata/spamhaus"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// abusiveWorld is a scope for example.com and 198.51.100.0/24, with the addresses the test names.
type abusiveWorld struct {
	hosts     []inventory.Host
	res       []inventory.Resolution
	wildcards []inventory.Wildcard
	owners    map[netip.Addr]provider.Owner
	recs      map[string][]store.Record
	excl      []string
	history   map[netip.Addr]bool // the addresses only DNS history names
	snap      *abusive.Snapshot
	drop      *spamhaus.Lists
}

func newAbusiveWorld() *abusiveWorld {
	return &abusiveWorld{owners: map[netip.Addr]provider.Owner{}, recs: map[string][]store.Record{}, history: map[netip.Addr]bool{}}
}

// host adds a current hostname and its A records. Whether it is in scope is the scope's decision.
func (w *abusiveWorld) host(name string, addrs ...string) {
	w.hosts = append(w.hosts, inventory.Host{Name: name, Producers: []string{"crtsh"}})
	for _, a := range addrs {
		w.res = append(w.res, inventory.Resolution{Name: name, Type: "A", Value: a})
	}
}

// ipRec adds a current ip record that the procedures observe.
func (w *abusiveWorld) ipRec(addr string, procedures ...string) {
	r := rec("ip", addr)
	r.Producers = procedures
	w.recs["ip"] = append(w.recs["ip"], r)
}

func (w *abusiveWorld) owner(addr string, asn int) {
	w.owners[ip(addr)] = provider.Owner{ASN: asn, Known: true}
	w.recs["ip_owner"] = append(w.recs["ip_owner"], rec("ip_owner", addr, "asn", float64(asn), "prefix", "x", "holder", "x"))
}

func (w *abusiveWorld) netblockOwner(unit string, asn int) {
	w.recs["netblock_owner"] = append(w.recs["netblock_owner"], rec("netblock_owner", unit, "asn", float64(asn), "prefix", unit))
}

func (w *abusiveWorld) input(t *testing.T) findings.Input {
	t.Helper()
	inv := inventory.New(inventory.Data{Hosts: w.hosts, Resolutions: w.res, Wildcards: w.wildcards, Owners: w.owners}, provider.Default())
	xs, err := input.ParseExclusions(w.excl)
	if err != nil {
		t.Fatal(err)
	}
	sc := scope.New(scope.Config{
		Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Exclusions: xs, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly(),
	})
	recs := w.recs
	return findings.Input{Scope: sc, Inv: inv, Today: "2026-11-01", Roots: []string{"example.com"},
		Records:     func(k kinds.Named) []store.Record { return recs[k.Name()] },
		Abusive:     w.snap,
		Drop:        w.drop,
		HistoryOnly: func(a netip.Addr) bool { return w.history[a] }}
}

func (w *abusiveWorld) derive(t *testing.T) map[string]findings.Finding {
	t.Helper()
	out := map[string]findings.Finding{}
	for _, f := range derive(w.input(t)) {
		if f.Category == findings.AbusiveNetwork {
			out[f.Target] = f
		}
	}
	return out
}

func netEntry(rank int, start, end, tag string, score float64, org, typ string) abusive.NetworkEntry {
	return abusive.NetworkEntry{Rank: rank, Start: ip(start), End: ip(end), ScoreTag: tag, AbuseScore: score, Org: org, OrgType: typ}
}

// snapshotOf is a snapshot of the entries, ready to match.
func snapshotOf(nets []abusive.NetworkEntry, asns []abusive.ASNEntry) *abusive.Snapshot {
	return abusive.Load(abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: "2026-11-21", Entries: nets},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: "2026-11-20", Entries: asns},
	})
}

// everything covers all fixture addresses so matching assertions also reveal omissions.
func everything() *abusive.Snapshot {
	return snapshotOf([]abusive.NetworkEntry{
		netEntry(7001, "203.0.113.0", "203.0.113.255", "High", 80, "Acme Hosting", "hosting"),
		netEntry(7002, "198.51.100.0", "198.51.100.255", "High", 70, "Netblock Org", "isp"),
		netEntry(7003, "104.16.0.0", "104.16.255.255", "High", 60, "Shared Org", "isp"),
		netEntry(7004, "192.0.2.0", "192.0.2.255", "High", 60, "Candidate Org", "isp"),
	}, nil)
}

// Abuse checks include in-scope hostname addresses and current netblock IPs, excluding
// candidates, exclusions and history-only evidence.
func TestAbusive_WhichAddressesAreChecked(t *testing.T) {
	t.Parallel()
	// The same addresses are checked against ipapi.is's lists and against Spamhaus's.
	t.Run("ipapi.is", func(t *testing.T) {
		t.Parallel()
		w := newAbusiveWorld()
		w.snap = everything()
		checkedAddresses(t, w)
	})
	t.Run("Spamhaus DROP", func(t *testing.T) {
		t.Parallel()
		w := newAbusiveWorld()
		w.drop = dropEverything(t)
		checkedAddresses(t, w)
	})
}

func checkedAddresses(t *testing.T, w *abusiveWorld) {
	t.Helper()
	w.excl = []string{"203.0.113.64/28", "ex.example.com", "198.51.100.64/28"}
	w.host("app.example.com", "203.0.113.9")
	w.host("cdn.example.com", "104.16.0.5") // shared provider infrastructure
	w.owner("104.16.0.5", 13335)
	w.wildcards = []inventory.Wildcard{{Zone: "w.example.com", Addrs: []netip.Addr{ip("203.0.113.50")}}}
	w.host("x.w.example.com", "203.0.113.50") // resolves only because of the wildcard
	w.host("cand.other.org", "192.0.2.20")    // a candidate: not in scope
	w.host("incidr.example.com", "203.0.113.70")
	w.host("ex.example.com", "203.0.113.80") // excluded by name, not shared
	// Netblock addresses are named by records of other kinds.
	w.ipRec("198.51.100.7", "rdns")
	w.ipRec("198.51.100.8", "shodan")
	w.ipRec("198.51.100.70", "rdns") // inside an excluded CIDR, inside an in-scope netblock
	w.ipRec("198.51.100.9", "dnshistory")
	w.history[ip("198.51.100.9")] = true
	w.ipRec("198.51.100.10", "dnshistory", "rdns")
	w.ipRec("203.0.113.99", "shodan") // outside the netblocks, and no in-scope name resolves to it
	got := w.derive(t)
	var addrs []string
	for a := range got {
		addrs = append(addrs, a)
	}
	slices.Sort(addrs)
	want := []string{"104.16.0.5", "198.51.100.10", "198.51.100.7", "198.51.100.8", "203.0.113.50", "203.0.113.9"}
	if !slices.Equal(addrs, want) {
		t.Errorf("flagged %v\nwant    %v", addrs, want)
	}
}

// A hostname flagged address carries its in-scope hostnames (sorted), including a wildcard-only one.
func TestAbusive_HostnamesAreTheInScopeNames(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.snap = everything()
	w.host("b.example.com", "203.0.113.9")
	w.host("a.example.com", "203.0.113.9")
	w.host("cand.other.org", "203.0.113.9") // a candidate name is not listed
	w.recs["ip_hostname"] = []store.Record{rec("ip_hostname", "203.0.113.9|ptr.example.com", "ip", "203.0.113.9", "hostname", "ptr.example.com", "source", "rdns")}
	got := w.derive(t)["203.0.113.9"]
	if h, _ := got.Attrs["hostnames"].(string); h != "a.example.com;b.example.com" {
		// The reverse name is not an in-scope hostname record, so it is not named.
		t.Errorf("hostnames = %q", h)
	}
}

// Severity: medium when any network entry matches (with or without the AS), low for the AS alone.
func TestAbusive_SeverityAndTheASThatIsUsed(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.snap = snapshotOf(
		[]abusive.NetworkEntry{netEntry(1, "203.0.113.0", "203.0.113.255", "High", 80, "Net Org", "hosting")},
		[]abusive.ASNEntry{{Rank: 2, ASN: 64050, ScoreTag: "Very High", AbuseScore: 100, Org: "Bad AS", OrgType: "Spamhaus ASN-DROP"}})
	// Outside the netblocks the AS is the address's ip_owner.
	w.host("both.example.com", "203.0.113.5")
	w.owner("203.0.113.5", 64050)
	w.host("asn-only.example.com", "104.16.0.5")
	w.owner("104.16.0.5", 64050)
	w.host("net-only.example.com", "203.0.113.6")
	w.owner("203.0.113.6", 64999)
	w.host("unknown-owner.example.com", "203.0.113.7") // no owner: only the network entries are checked
	// Inside a netblock it is the netblock_owner of the unit, whatever ip_owner might say.
	w.ipRec("198.51.100.5", "rdns")
	w.netblockOwner("198.51.100.0/24", 64050)
	got := w.derive(t)
	for _, tc := range []struct{ addr, typ, sev string }{
		{"203.0.113.5", "network", "medium"},
		{"104.16.0.5", "asn", "low"},
		{"203.0.113.6", "network", "medium"},
		{"203.0.113.7", "network", "medium"},
		{"198.51.100.5", "asn", "low"},
	} {
		f, ok := got[tc.addr]
		if !ok || f.Type != tc.typ || f.Severity != tc.sev {
			t.Errorf("%s = %+v (found %v), want %s/%s", tc.addr, f, ok, tc.typ, tc.sev)
		}
	}
	// An ip_owner inside a netblock is not read: only the unit's netblock_owner is.
	inside := newAbusiveWorld()
	inside.snap = w.snap
	inside.ipRec("198.51.100.200", "rdns")
	inside.owner("198.51.100.200", 64050)
	if got := inside.derive(t); len(got) != 0 {
		t.Errorf("an ip_owner inside a netblock was used: %+v", got)
	}
	if f := got["203.0.113.5"]; len(f.Attrs["asn"].([]string)) != 1 || len(f.Attrs["networks"].([]string)) != 1 {
		t.Errorf("both matches are carried: %+v", f.Attrs)
	}
}

// The unit's owner answers for every address of the /24, and a netblock smaller than a /24 is its own unit.
func TestAbusive_NetblockOwnerAppliesToTheUnit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, typ string
		list      func(t *testing.T, w *abusiveWorld)
	}{
		{"ipapi.is", "asn", func(_ *testing.T, w *abusiveWorld) {
			w.snap = snapshotOf(nil, []abusive.ASNEntry{{Rank: 1, ASN: 64050, ScoreTag: "High", AbuseScore: 90, Org: "Bad AS", OrgType: "hosting"}})
		}},
		{"Spamhaus ASN-DROP", "drop-asn", func(t *testing.T, w *abusiveWorld) {
			w.drop = dropListsOf(t, nil, nil, []string{dropASNRow(64050, "BAD-AS", "RU", "bad.example", "ripencc")})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newAbusiveWorld()
			tc.list(t, w)
			for _, a := range []string{"198.51.100.1", "198.51.100.254"} {
				w.ipRec(a, "rdns")
			}
			w.netblockOwner("198.51.100.0/24", 64050)
			got := w.derive(t)
			for _, a := range []string{"198.51.100.1", "198.51.100.254"} {
				if got[a].Type != tc.typ {
					t.Errorf("%s = %+v, want type %s", a, got[a], tc.typ)
				}
			}
			// The owner of another unit does not apply.
			w.netblockOwner("198.51.101.0/24", 64999)
			if got := w.derive(t); len(got) != 2 {
				t.Errorf("flagged %d, want 2", len(got))
			}
			// An ip_owner inside a netblock is not read: only the unit's netblock_owner is.
			inside := newAbusiveWorld()
			inside.snap, inside.drop = w.snap, w.drop
			inside.ipRec("198.51.100.200", "rdns")
			inside.owner("198.51.100.200", 64050)
			if got := inside.derive(t); len(got) != 0 {
				t.Errorf("an ip_owner inside a netblock was used: %+v", got)
			}
		})
	}
}

// Finding attributes preserve match metadata without rank and use a type-independent address
// key.
func TestAbusive_FindingContent(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.snap = snapshotOf(
		[]abusive.NetworkEntry{
			netEntry(7771, "203.0.113.0", "203.0.113.255", "High", 80.5, "Outer Org", "isp"),
			netEntry(7772, "203.0.113.16", "203.0.113.18", "Very High", 99, "Inner Org", "hosting"),
		},
		[]abusive.ASNEntry{{Rank: 7773, ASN: 64050, ScoreTag: "Very High", AbuseScore: 100, Org: "Bad AS", OrgType: "Spamhaus ASN-DROP"}})
	w.host("app.example.com", "203.0.113.17")
	w.owner("203.0.113.17", 64050)
	f := w.derive(t)["203.0.113.17"]
	if f.Category != "abusive-network" || f.Type != "network" || f.Severity != "medium" || f.Target != "203.0.113.17" {
		t.Fatalf("finding = %+v", f)
	}
	if f.Key() != "abusive-network|203.0.113.17" {
		t.Errorf("key = %q", f.Key())
	}
	cat, typ, target := findings.ParseKey(f.Key())
	if cat != "abusive-network" || typ != "" || target != "203.0.113.17" {
		t.Errorf("ParseKey = %q %q %q", cat, typ, target)
	}
	for _, want := range []string{"203.0.113.16-203.0.113.18", "203.0.113.0/24", "AS64050", "Very High", "99%", "80.5%", "Inner Org", "Outer Org", "Bad AS", "hosting", "Spamhaus ASN-DROP", "2026-11-21", "2026-11-20"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("detail %q lacks %q", f.Detail, want)
		}
	}
	if strings.Contains(f.Detail, "777") {
		t.Errorf("detail carries a rank: %q", f.Detail)
	}
	// The attrs are the risk file's columns; the most specific entry comes first.
	wantNets := []string{"203.0.113.16-203.0.113.18 Very High 99% Inner Org (hosting)", "203.0.113.0/24 High 80.5% Outer Org (isp)"}
	if got := f.Attrs["networks"].([]string); !slices.Equal(got, wantNets) {
		t.Errorf("networks = %v, want %v", got, wantNets)
	}
	if got := f.Attrs["asn"].([]string); !slices.Equal(got, []string{"AS64050 Very High 100% Bad AS (Spamhaus ASN-DROP)"}) {
		t.Errorf("asn = %v", got)
	}
	for k, want := range map[string]string{"ip": "203.0.113.17", "hostnames": "app.example.com", "networks_updated": "2026-11-21", "asns_updated": "2026-11-20", "severity": "medium", "type": "network"} {
		if f.Attrs[k] != want {
			t.Errorf("attr %s = %v, want %q", k, f.Attrs[k], want)
		}
	}
	for k, v := range f.Attrs {
		if s, ok := v.(string); ok && strings.Contains(s, "777") {
			t.Errorf("attr %s carries a rank: %q", k, s)
		}
	}
	if got := f.FoundText(); got != "address 203.0.113.17 in abusive network 203.0.113.16-203.0.113.18 (Inner Org)" {
		t.Errorf("found = %q", got)
	}
}

// An ASN-only finding says so, names the AS and has no networks date.
func TestAbusive_ASNOnlyFinding(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.snap = snapshotOf(nil, []abusive.ASNEntry{{Rank: 1, ASN: 64050, ScoreTag: "High", AbuseScore: 90, Org: "Bad AS", OrgType: "hosting"}})
	w.host("app.example.com", "203.0.113.17")
	w.owner("203.0.113.17", 64050)
	f := w.derive(t)["203.0.113.17"]
	if f.Type != "asn" || f.Severity != "low" {
		t.Fatalf("finding = %+v", f)
	}
	if got := f.FoundText(); got != "address 203.0.113.17 in abusive AS64050 (Bad AS)" {
		t.Errorf("found = %q", got)
	}
	if f.Attrs["networks_updated"] != "" || f.Attrs["asns_updated"] != "2026-11-20" || len(f.Attrs["networks"].([]string)) != 0 {
		t.Errorf("attrs = %+v", f.Attrs)
	}
}

// An entry whose organisation is blank has a found line with no empty parentheses.
func TestAbusive_FoundLineWithABlankOrganisation(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.snap = snapshotOf(nil, []abusive.ASNEntry{{Rank: 1, ASN: 64050, ScoreTag: "High", AbuseScore: 90, OrgType: "unknown"}})
	w.host("app.example.com", "203.0.113.17")
	w.owner("203.0.113.17", 64050)
	if got := w.derive(t)["203.0.113.17"].FoundText(); got != "address 203.0.113.17 in abusive AS64050" {
		t.Errorf("found = %q", got)
	}
}

// Text from the snapshot is sanitised in the finding.
func TestAbusive_TextIsSanitised(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.snap = snapshotOf([]abusive.NetworkEntry{netEntry(1, "203.0.113.0", "203.0.113.255", "Hi\x1b[31mgh", 80, "Evil\x1b]0;x\x07 Org\u202e", "is\x07p")}, nil)
	w.host("app.example.com", "203.0.113.17")
	f := w.derive(t)["203.0.113.17"]
	all := f.Detail + f.FoundText() + strings.Join(f.Attrs["networks"].([]string), "|")
	if strings.ContainsAny(all, "\x1b\x07\u202e") {
		t.Errorf("unsanitised text: %q", all)
	}
}

// No snapshot, an empty one, or addresses that are not listed give no finding.
func TestAbusive_NothingListedNothingFound(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.host("app.example.com", "203.0.113.17")
	if got := w.derive(t); len(got) != 0 {
		t.Errorf("no snapshot: %v", got)
	}
	w.snap = snapshotOf(nil, nil)
	if got := w.derive(t); len(got) != 0 {
		t.Errorf("empty snapshot: %v", got)
	}
	w.snap = snapshotOf([]abusive.NetworkEntry{netEntry(1, "192.0.2.0", "192.0.2.255", "High", 80, "Elsewhere", "isp")}, nil)
	if got := w.derive(t); len(got) != 0 {
		t.Errorf("an unlisted address: %v", got)
	}
}

// A finding that is no longer derived keeps its row in the risk file, with the address from its key.
func TestAbusive_RiskFile(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.snap = everything()
	w.host("app.example.com", "203.0.113.17")
	f := w.derive(t)["203.0.113.17"]
	var file findings.File
	for _, x := range findings.Files() {
		if x.Name == "risk-abusive-network.csv" {
			file = x
		}
	}
	if file.Name == "" {
		t.Fatal("no risk-abusive-network.csv")
	}
	if want := []string{"severity", "ip", "hostnames", "type", "drop_networks", "drop_asn", "networks", "asn",
		"drop_networks_updated", "drop_asn_updated", "networks_updated", "asns_updated"}; !slices.Equal(file.Columns, want) {
		t.Errorf("columns = %v, want %v", file.Columns, want)
	}
	// The store hands attributes back as JSON decodes them: lists as []any.
	stored, err := json.Marshal(f.Attrs)
	if err != nil {
		t.Fatal(err)
	}
	var attrs map[string]any
	if err := json.Unmarshal(stored, &attrs); err != nil {
		t.Fatal(err)
	}
	current := store.Record{Kind: "finding", Key: f.Key(), Current: true, Attrs: attrs}
	gone := store.Record{Kind: "finding", Key: "abusive-network|203.0.113.99", Current: false}
	rows := file.Rows(findings.Listing{Records: map[string][]store.Record{"finding": {current, gone}}})
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2", len(rows))
	}
	if len(rows[0].Cells) != 12 {
		t.Fatalf("row = %v, want 12 cells", rows[0].Cells)
	}
	if got := rows[0].Cells; got[0] != "medium" || got[1] != "203.0.113.17" || got[2] != "app.example.com" || got[3] != "network" || got[10] != "2026-11-21" {
		t.Errorf("row = %v", got)
	}
	if got := rows[0].Cells[6]; !strings.Contains(got, "203.0.113.0/24 High 80% Acme Hosting (hosting)") {
		t.Errorf("networks cell = %q", got)
	}
	if got := rows[1].Cells; got[1] != "203.0.113.99" {
		t.Errorf("a finding no longer derived has ip %q, want the one in its key", got[1])
	}
}

// --- Spamhaus DROP ---

// The dates of the test DROP lists: each list has its own, as Spamhaus's do.
var (
	dropV4Time  = time.Date(2026, 10, 1, 8, 30, 5, 0, time.UTC)
	dropV6Time  = time.Date(2026, 9, 30, 23, 59, 59, 0, time.UTC)
	dropASNTime = time.Date(2026, 10, 2, 0, 0, 1, 0, time.UTC)
)

const (
	dropV4Date  = "2026-10-01T08:30:05Z"
	dropV6Date  = "2026-09-30T23:59:59Z"
	dropASNDate = "2026-10-02T00:00:01Z"
)

// dropNetRow builds one source-format network row.
func dropNetRow(cidr, sbl, rir string) string {
	return fmt.Sprintf(`{"cidr":%q,"sblid":%q,"rir":%q}`, cidr, sbl, rir)
}

// dropASNRow builds one source-format ASN row.
func dropASNRow(asn int, name, cc, domain, rir string) string {
	return fmt.Sprintf(`{"asn":%d,"rir":%q,"domain":%q,"cc":%q,"asname":%q}`, asn, rir, domain, cc, name)
}

// dropFile writes source rows followed by metadata.
func dropFile(at time.Time, rows []string) []byte {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	fmt.Fprintf(&b, `{"type":"metadata","timestamp":%d,"size":1,"records":%d,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}`+"\n",
		at.Unix(), len(rows))
	return []byte(b.String())
}

// dropListsOf is the three lists of the rows, each with its own date.
func dropListsOf(t *testing.T, v4, v6, asns []string) *spamhaus.Lists {
	t.Helper()
	l4, err := spamhaus.ParseDrop(dropFile(dropV4Time, v4), false)
	if err != nil {
		t.Fatalf("DROP: %v", err)
	}
	l6, err := spamhaus.ParseDrop(dropFile(dropV6Time, v6), true)
	if err != nil {
		t.Fatalf("DROPv6: %v", err)
	}
	la, err := spamhaus.ParseASNDrop(dropFile(dropASNTime, asns))
	if err != nil {
		t.Fatalf("ASN-DROP: %v", err)
	}
	return &spamhaus.Lists{V4: l4, V6: l6, ASNs: la}
}

// dropEverything lists in DROP every network the address tests use, as everything does in ipapi.is's list.
func dropEverything(t *testing.T) *spamhaus.Lists {
	t.Helper()
	return dropListsOf(t, []string{
		dropNetRow("203.0.113.0/24", "SBL1", "arin"),
		dropNetRow("198.51.100.0/24", "SBL2", "arin"),
		dropNetRow("104.16.0.0/16", "SBL3", "arin"),
		dropNetRow("192.0.2.0/24", "SBL4", "arin"),
	}, nil, nil)
}

// strs accepts derived or decoded list attributes and returns nil for other values.
func strs(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		out := make([]string, 0, len(l))
		for _, x := range l {
			s, _ := x.(string)
			out = append(out, s)
		}
		return out
	}
	return nil
}

// abusiveOf is every abusive-network finding of the address.
func abusiveOf(fs []findings.Finding, addr string) []findings.Finding {
	var out []findings.Finding
	for _, f := range fs {
		if f.Category == findings.AbusiveNetwork && f.Target == addr {
			out = append(out, f)
		}
	}
	return out
}

// The four kinds of match, as the bits of a combination.
const (
	matchDropNet = 1 << iota
	matchDropASN
	matchIpapiNet
	matchIpapiASN
)

// Combination m has the addresses of 203.0.113.<16m>/28, and the AS 64600+m.
func comboBlock(m int) string { return fmt.Sprintf("203.0.113.%d/28", 16*m) }
func comboAddr(m int) string  { return fmt.Sprintf("203.0.113.%d", 16*m+1) }

// comboName names the kinds of match in combination m.
func comboName(m int) string {
	var parts []string
	for i, n := range []string{"drop-network", "drop-asn", "network", "asn"} {
		if m&(1<<i) != 0 {
			parts = append(parts, n)
		}
	}
	if parts == nil {
		return "no match"
	}
	return strings.Join(parts, "+")
}

// comboWorld has one address for each of the 16 combinations, listed by the kinds of match its
// combination names.
func comboWorld(t *testing.T) *abusiveWorld {
	t.Helper()
	w := newAbusiveWorld()
	var v4, asnDrop []string
	var nets []abusive.NetworkEntry
	var asns []abusive.ASNEntry
	for m := range 16 {
		a, as := comboAddr(m), 64600+m
		w.host(fmt.Sprintf("h%d.example.com", m), a)
		w.owner(a, as)
		if m&matchDropNet != 0 {
			v4 = append(v4, dropNetRow(comboBlock(m), fmt.Sprintf("SBL%d", 100+m), "ripencc"))
		}
		if m&matchDropASN != 0 {
			asnDrop = append(asnDrop, dropASNRow(as, fmt.Sprintf("DROP-AS-%d", m), "RU", "bad.example", "ripencc"))
		}
		if m&matchIpapiNet != 0 {
			nets = append(nets, netEntry(m+1, fmt.Sprintf("203.0.113.%d", 16*m), fmt.Sprintf("203.0.113.%d", 16*m+15), "High", 80, fmt.Sprintf("Net Org %d", m), "hosting"))
		}
		if m&matchIpapiASN != 0 {
			asns = append(asns, abusive.ASNEntry{Rank: m + 1, ASN: as, ScoreTag: "High", AbuseScore: 90, Org: fmt.Sprintf("AS Org %d", m), OrgType: "isp"})
		}
	}
	w.snap = snapshotOf(nets, asns)
	w.drop = dropListsOf(t, v4, nil, asnDrop)
	return w
}

// comboWant is the type, severity, entry and organisation of combination m's finding: its
// strongest match's.
func comboWant(m int) (typ, sev, entry, org string) {
	as := 64600 + m
	switch {
	case m&matchDropNet != 0:
		return "drop-network", "high", comboBlock(m), fmt.Sprintf("SBL%d", 100+m)
	case m&matchDropASN != 0:
		return "drop-asn", "medium", fmt.Sprintf("AS%d", as), fmt.Sprintf("DROP-AS-%d", m)
	case m&matchIpapiNet != 0:
		return "network", "medium", comboBlock(m), fmt.Sprintf("Net Org %d", m)
	}
	return "asn", "low", fmt.Sprintf("AS%d", as), fmt.Sprintf("AS Org %d", m)
}

// One address produces one finding at its strongest match's severity while retaining every
// matching entry.
func TestDrop_TypeAndSeverityOfEveryCombination(t *testing.T) {
	t.Parallel()
	all := derive(comboWorld(t).input(t))
	if got := abusiveOf(all, comboAddr(0)); len(got) != 0 {
		t.Errorf("no match: %+v, want no finding", got)
	}
	for m := 1; m < 16; m++ {
		a, name := comboAddr(m), comboName(m)
		mine := abusiveOf(all, a)
		if len(mine) != 1 {
			t.Errorf("%s: %d findings for %s, want one", name, len(mine), a)
			continue
		}
		f := mine[0]
		typ, sev, entry, org := comboWant(m)
		if f.Type != typ || f.Severity != sev || f.Attrs["type"] != typ || f.Attrs["severity"] != sev {
			t.Errorf("%s: type %q severity %q (attrs %v %v), want %s %s", name, f.Type, f.Severity, f.Attrs["type"], f.Attrs["severity"], typ, sev)
		}
		if f.Key() != "abusive-network|"+a {
			t.Errorf("%s: key %q", name, f.Key())
		}
		if f.Attrs["entry"] != entry || f.Attrs["org"] != org {
			t.Errorf("%s: entry %v org %v, want %q %q", name, f.Attrs["entry"], f.Attrs["org"], entry, org)
		}
		for i, attr := range []string{"drop_networks", "drop_asn", "networks", "asn"} {
			if got, want := len(strs(f.Attrs[attr])), m>>i&1; got != want {
				t.Errorf("%s: %s has %d entries, want %d: %v", name, attr, got, want, f.Attrs[attr])
			}
		}
	}
}

// DROP findings preserve ordered network/ASN details, dates, console text and additional abuse
// matches.
func TestDrop_FindingContent(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.snap = snapshotOf(
		[]abusive.NetworkEntry{netEntry(1, "203.0.113.0", "203.0.113.255", "High", 80, "Net Org", "hosting")},
		[]abusive.ASNEntry{{Rank: 2, ASN: 64500, ScoreTag: "Very High", AbuseScore: 100, Org: "Bad AS", OrgType: "isp"}})
	w.drop = dropListsOf(t,
		[]string{
			dropNetRow("203.0.113.0/24", "SBL5", "lacnic"),
			dropNetRow("203.0.113.16/28", "SBL6", "ripencc"),
			dropNetRow("192.0.2.0/24", "SBL7", "arin"), // holds nothing of the engagement
		}, nil,
		[]string{dropASNRow(64500, "BAD-AS", "RU", "example.net", "ripencc"), dropASNRow(64501, "OTHER-AS", "CN", "other.example", "apnic")})
	w.host("app.example.com", "203.0.113.17")
	w.owner("203.0.113.17", 64500)
	f := w.derive(t)["203.0.113.17"]
	if f.Category != "abusive-network" || f.Type != "drop-network" || f.Severity != "high" || f.Key() != "abusive-network|203.0.113.17" {
		t.Fatalf("finding = %+v", f)
	}
	if got, want := strs(f.Attrs["drop_networks"]), []string{"203.0.113.16/28 SBL6 (ripencc)", "203.0.113.0/24 SBL5 (lacnic)"}; !slices.Equal(got, want) {
		t.Errorf("drop_networks = %q, want %q", got, want)
	}
	if got, want := strs(f.Attrs["drop_asn"]), []string{"AS64500 BAD-AS RU example.net (ripencc)"}; !slices.Equal(got, want) {
		t.Errorf("drop_asn = %q, want %q", got, want)
	}
	if got, want := strs(f.Attrs["networks"]), []string{"203.0.113.0/24 High 80% Net Org (hosting)"}; !slices.Equal(got, want) {
		t.Errorf("networks = %q, want %q", got, want)
	}
	if got, want := strs(f.Attrs["asn"]), []string{"AS64500 Very High 100% Bad AS (isp)"}; !slices.Equal(got, want) {
		t.Errorf("asn = %q, want %q", got, want)
	}
	for k, want := range map[string]string{
		"ip": "203.0.113.17", "hostnames": "app.example.com",
		"drop_networks_updated": dropV4Date, "drop_asn_updated": dropASNDate,
		"networks_updated": "2026-11-21", "asns_updated": "2026-11-20",
		"entry": "203.0.113.16/28", "org": "SBL6",
	} {
		if f.Attrs[k] != want {
			t.Errorf("attr %s = %v, want %q", k, f.Attrs[k], want)
		}
	}
	if got := f.FoundText(); got != "address 203.0.113.17 in Spamhaus DROP network 203.0.113.16/28 (SBL6)" {
		t.Errorf("found = %q", got)
	}
}

// ASN-only DROP evidence yields a medium finding without network-specific fields.
func TestDrop_ASNOnlyFinding(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.drop = dropListsOf(t, nil, nil, []string{dropASNRow(64500, "BAD-AS", "RU", "example.net", "ripencc")})
	w.host("app.example.com", "203.0.113.17")
	w.owner("203.0.113.17", 64500)
	f := w.derive(t)["203.0.113.17"]
	if f.Type != "drop-asn" || f.Severity != "medium" {
		t.Fatalf("finding = %+v", f)
	}
	if f.Attrs["entry"] != "AS64500" || f.Attrs["org"] != "BAD-AS" {
		t.Errorf("entry %v org %v, want AS64500 BAD-AS", f.Attrs["entry"], f.Attrs["org"])
	}
	if got := strs(f.Attrs["drop_networks"]); len(got) != 0 {
		t.Errorf("drop_networks = %q, want none", got)
	}
	if got, want := strs(f.Attrs["drop_asn"]), []string{"AS64500 BAD-AS RU example.net (ripencc)"}; !slices.Equal(got, want) {
		t.Errorf("drop_asn = %q, want %q", got, want)
	}
	if f.Attrs["drop_networks_updated"] != "" || f.Attrs["drop_asn_updated"] != dropASNDate {
		t.Errorf("dates = %v %v", f.Attrs["drop_networks_updated"], f.Attrs["drop_asn_updated"])
	}
	if got := f.FoundText(); !strings.Contains(got, "203.0.113.17") || !strings.Contains(got, "AS64500") {
		t.Errorf("found = %q, want the address and the AS", got)
	}
}

// An IPv6 address is checked against DROPv6, and its date is that list's.
func TestDrop_IPv6AddressAndItsListsDate(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.drop = dropListsOf(t, []string{dropNetRow("0.0.0.0/0", "SBL40", "arin")},
		[]string{dropNetRow("2001:db8::/32", "SBL10", "apnic"), dropNetRow("2001:db8:12::/48", "SBL11", "arin")}, nil)
	w.hosts = append(w.hosts, inventory.Host{Name: "v6.example.com", Producers: []string{"crtsh"}})
	w.res = append(w.res, inventory.Resolution{Name: "v6.example.com", Type: "AAAA", Value: "2001:db8:12::5"})
	f := w.derive(t)["2001:db8:12::5"]
	if f.Type != "drop-network" || f.Severity != "high" {
		t.Fatalf("finding = %+v", f)
	}
	if got, want := strs(f.Attrs["drop_networks"]), []string{"2001:db8:12::/48 SBL11 (arin)", "2001:db8::/32 SBL10 (apnic)"}; !slices.Equal(got, want) {
		t.Errorf("drop_networks = %q, want %q", got, want)
	}
	if f.Attrs["drop_networks_updated"] != dropV6Date {
		t.Errorf("drop_networks_updated = %v, want %s", f.Attrs["drop_networks_updated"], dropV6Date)
	}
	if got := f.FoundText(); got != "address 2001:db8:12::5 in Spamhaus DROP network 2001:db8:12::/48 (SBL11)" {
		t.Errorf("found = %q", got)
	}
}

// DROP is checked whether or not there is an ipapi.is snapshot, and lists that hold nothing of the
// engagement give no finding.
func TestDrop_WithoutTheIpapiSnapshot(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.host("app.example.com", "203.0.113.17")
	w.drop = dropListsOf(t, nil, nil, nil)
	if got := w.derive(t); len(got) != 0 {
		t.Errorf("empty lists: %v", got)
	}
	w.drop = dropListsOf(t, []string{dropNetRow("192.0.2.0/24", "SBL1", "arin")}, nil, nil)
	if got := w.derive(t); len(got) != 0 {
		t.Errorf("an unlisted address: %v", got)
	}
	w.drop = dropListsOf(t, []string{dropNetRow("203.0.113.0/24", "SBL1", "arin")}, nil, nil)
	if f := w.derive(t)["203.0.113.17"]; f.Type != "drop-network" || f.Severity != "high" {
		t.Errorf("no snapshot, a DROP network: %+v", f)
	}
}

// A DROP match changes only its address's abusive-network finding: every other finding is the
// same with and without it.
func TestDrop_OnlyTheFindingChanges(t *testing.T) {
	t.Parallel()
	world := func(drop *spamhaus.Lists) []findings.Finding {
		w := newAbusiveWorld()
		w.drop = drop
		w.ipRec("198.51.100.5", "rdns")
		w.netblockOwner("198.51.100.0/24", 64500)
		w.host("app.example.com", "198.51.100.5")
		w.recs["reported_port"] = []store.Record{rec("reported_port", "198.51.100.5:3389", "ip", "198.51.100.5", "port", 3389.0, "banner", "rdp")}
		w.recs["open_port"] = []store.Record{rec("open_port", "198.51.100.5:23", "ip", "198.51.100.5", "port", 23.0, "banner", "telnet")}
		w.recs["email_posture"] = []store.Record{rec("email_posture", "example.com", "mx", "m", "spf", "", "dmarc", "", "spf_records", 0.0)}
		in := w.input(t)
		in.Settings = config.Defaults()
		return derive(in)
	}
	without := world(nil)
	with := world(dropListsOf(t, []string{dropNetRow("198.51.100.0/24", "SBL1", "arin")}, nil,
		[]string{dropASNRow(64500, "BAD-AS", "RU", "example.net", "ripencc")}))
	others := func(fs []findings.Finding) []findings.Finding {
		return slices.DeleteFunc(slices.Clone(fs), func(f findings.Finding) bool { return f.Category == findings.AbusiveNetwork })
	}
	if len(others(without)) < 2 {
		t.Fatalf("the world has too few other findings to compare: %v", summarise(without))
	}
	if !reflect.DeepEqual(others(with), others(without)) {
		t.Errorf("other findings changed:\nwith DROP    %v\nwithout DROP %v", summarise(others(with)), summarise(others(without)))
	}
	if got := abusiveOf(with, "198.51.100.5"); len(got) != 1 || got[0].Type != "drop-network" {
		t.Errorf("abusive findings with DROP = %+v", got)
	}
	if got := abusiveOf(without, "198.51.100.5"); len(got) != 0 {
		t.Errorf("abusive findings without DROP = %+v", got)
	}
}

// Stable address keys survive strength/type changes; no remaining match removes the finding.
func TestDrop_OneFindingWhateverItsStrongestMatch(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.host("app.example.com", "203.0.113.17")
	w.owner("203.0.113.17", 64500)
	w.snap = snapshotOf([]abusive.NetworkEntry{netEntry(1, "203.0.113.0", "203.0.113.255", "High", 80, "Net Org", "hosting")}, nil)
	w.drop = dropListsOf(t, []string{dropNetRow("203.0.113.0/24", "SBL1", "arin")}, nil, []string{dropASNRow(64500, "BAD-AS", "RU", "", "")})
	high := w.derive(t)["203.0.113.17"]
	w.drop = dropListsOf(t, nil, nil, []string{dropASNRow(64500, "BAD-AS", "RU", "", "")})
	dropASN := w.derive(t)["203.0.113.17"]
	w.drop = nil
	medium := w.derive(t)["203.0.113.17"]
	for _, c := range []struct {
		f        findings.Finding
		typ, sev string
	}{{high, "drop-network", "high"}, {dropASN, "drop-asn", "medium"}, {medium, "network", "medium"}} {
		if c.f.Type != c.typ || c.f.Severity != c.sev || c.f.Key() != "abusive-network|203.0.113.17" {
			t.Errorf("finding = %s %s %q, want %s %s under abusive-network|203.0.113.17", c.f.Type, c.f.Severity, c.f.Key(), c.typ, c.sev)
		}
	}
	w.snap = nil
	if got := w.derive(t); len(got) != 0 {
		t.Errorf("no match left: %v", got)
	}
}

// Text from Spamhaus's lists is cleaned of what acts on a terminal in the finding.
func TestDrop_TextIsSanitised(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.drop = dropListsOf(t, []string{dropNetRow("203.0.113.0/24", "SBL\u202e1", "ar\u2066in")}, nil,
		[]string{dropASNRow(64500, "BAD\u202eAS", "R\u200fU", "exa\u2067mple.net", "ripe\u200encc")})
	w.host("app.example.com", "203.0.113.17")
	w.owner("203.0.113.17", 64500)
	f := w.derive(t)["203.0.113.17"]
	if f.Type != "drop-network" {
		t.Fatalf("finding = %+v", f)
	}
	all := f.Detail + f.FoundText() + strings.Join(strs(f.Attrs["drop_networks"]), "|") + strings.Join(strs(f.Attrs["drop_asn"]), "|")
	if strings.ContainsAny(all, "\u202e\u2066\u2067\u200e\u200f") {
		t.Errorf("unsanitised text: %q", all)
	}
	if !strings.Contains(all, "SBL1") || !strings.Contains(all, "BADAS") {
		t.Errorf("the entries' text is missing: %q", all)
	}
}

// Risk files include semicolon-joined matches and dates from each applicable source list.
func TestDrop_RiskFile(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.snap = everything()
	w.drop = dropListsOf(t,
		[]string{dropNetRow("203.0.113.0/24", "SBL5", "lacnic"), dropNetRow("203.0.113.16/28", "SBL6", "ripencc")}, nil,
		[]string{dropASNRow(64500, "BAD-AS", "RU", "example.net", "ripencc")})
	w.host("app.example.com", "203.0.113.17")
	w.owner("203.0.113.17", 64500)
	f := w.derive(t)["203.0.113.17"]
	var file findings.File
	for _, x := range findings.Files() {
		if x.Name == "risk-abusive-network.csv" {
			file = x
		}
	}
	stored, err := json.Marshal(f.Attrs)
	if err != nil {
		t.Fatal(err)
	}
	var attrs map[string]any
	if err := json.Unmarshal(stored, &attrs); err != nil {
		t.Fatal(err)
	}
	rows := file.Rows(findings.Listing{Records: map[string][]store.Record{"finding": {{Kind: "finding", Key: f.Key(), Current: true, Attrs: attrs}}}})
	if len(rows) != 1 {
		t.Fatalf("%d rows, want 1", len(rows))
	}
	cells := map[string]string{}
	for i, c := range file.Columns {
		if i < len(rows[0].Cells) {
			cells[c] = rows[0].Cells[i]
		}
	}
	for col, want := range map[string]string{
		"severity": "high", "ip": "203.0.113.17", "hostnames": "app.example.com", "type": "drop-network",
		"drop_networks":         "203.0.113.16/28 SBL6 (ripencc);203.0.113.0/24 SBL5 (lacnic)",
		"drop_asn":              "AS64500 BAD-AS RU example.net (ripencc)",
		"networks":              "203.0.113.0/24 High 80% Acme Hosting (hosting)",
		"asn":                   "",
		"drop_networks_updated": dropV4Date, "drop_asn_updated": dropASNDate,
		"networks_updated": "2026-11-21", "asns_updated": "",
	} {
		if cells[col] != want {
			t.Errorf("%s = %q, want %q", col, cells[col], want)
		}
	}
}

// Severity descriptions distinguish Spamhaus and active ipapi.is data.
func TestDrop_SeverityTableRows(t *testing.T) {
	t.Parallel()
	before := map[string]string{
		"network": "an address of the engagement is in a network ipapi.is lists among the most abusive on the internet (a snapshot built into nyx; nothing is requested)",
		"asn":     "an address of the engagement is announced by an AS ipapi.is lists among the most abusive, and no listed network holds it",
	}
	rows := map[string]findings.Row{}
	for _, r := range findings.SeverityTable() {
		if r.Category == findings.AbusiveNetwork {
			rows[r.Type] = r
		}
	}
	for typ, want := range map[string]struct{ sev, names string }{
		"drop-network": {"high", "Spamhaus DROP"},
		"drop-asn":     {"medium", "Spamhaus ASN-DROP"},
		"network":      {"medium", "ipapi.is"},
		"asn":          {"low", "ipapi.is"},
	} {
		r, ok := rows[typ]
		if !ok {
			t.Errorf("no abusive-network/%s row", typ)
			continue
		}
		if r.Severity != want.sev || findings.Severity(findings.AbusiveNetwork, typ) != want.sev {
			t.Errorf("%s: severity %q (Severity gives %q), want %s", typ, r.Severity, findings.Severity(findings.AbusiveNetwork, typ), want.sev)
		}
		if !strings.Contains(r.Meaning, want.names) {
			t.Errorf("%s: meaning %q does not name %s", typ, r.Meaning, want.names)
		}
		if old, ok := before[typ]; ok && r.Meaning == old {
			t.Errorf("%s: meaning is not reworded: %q", typ, r.Meaning)
		}
	}
	// nyx help findings lists each DROP type with its severity and Spamhaus.
	help := findings.HelpTable()
	for typ, sev := range map[string]string{"drop-network": "high", "drop-asn": "medium"} {
		var line string
		for l := range strings.SplitSeq(help, "\n") {
			if f := strings.Fields(l); len(f) > 2 && f[0] == findings.AbusiveNetwork && f[1] == typ {
				line = l
			}
		}
		if f := strings.Fields(line); len(f) < 3 || f[2] != sev || !strings.Contains(line, "Spamhaus") {
			t.Errorf("help line for %s = %q, want its severity %s and Spamhaus", typ, line, sev)
		}
	}
}
