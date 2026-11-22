package findings_test

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
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
}

func newAbusiveWorld() *abusiveWorld {
	return &abusiveWorld{owners: map[netip.Addr]provider.Owner{}, recs: map[string][]store.Record{}, history: map[netip.Addr]bool{}}
}

// host adds a current hostname and its A records. Whether it is in scope is the scope's decision.
func (w *abusiveWorld) host(name string, addrs ...string) {
	w.hosts = append(w.hosts, inventory.Host{Name: name, Stages: []string{"crtsh"}})
	for _, a := range addrs {
		w.res = append(w.res, inventory.Resolution{Name: name, Type: "A", Value: a})
	}
}

// ipRec adds a current ip record that the stages observe.
func (w *abusiveWorld) ipRec(addr string, stages ...string) {
	r := rec("ip", addr)
	r.Stages = stages
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

// everything lists every address the tests use, so that what is flagged is what is checked.
func everything() *abusive.Snapshot {
	return snapshotOf([]abusive.NetworkEntry{
		netEntry(7001, "203.0.113.0", "203.0.113.255", "High", 80, "Acme Hosting", "hosting"),
		netEntry(7002, "198.51.100.0", "198.51.100.255", "High", 70, "Netblock Org", "isp"),
		netEntry(7003, "104.16.0.0", "104.16.255.255", "High", 60, "Shared Org", "isp"),
		netEntry(7004, "192.0.2.0", "192.0.2.255", "High", 60, "Candidate Org", "isp"),
	}, nil)
}

// Which addresses are checked: those of in-scope names (shared and wildcard-only ones included) and
// those of current ip records inside the netblocks that are not only named by DNS history. Never a
// candidate's address, an excluded address or one that history alone names.
func TestAbusive_WhichAddressesAreChecked(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.snap = everything()
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
	w := newAbusiveWorld()
	w.snap = snapshotOf(nil, []abusive.ASNEntry{{Rank: 1, ASN: 64050, ScoreTag: "High", AbuseScore: 90, Org: "Bad AS", OrgType: "hosting"}})
	for _, a := range []string{"198.51.100.1", "198.51.100.254"} {
		w.ipRec(a, "rdns")
	}
	w.netblockOwner("198.51.100.0/24", 64050)
	got := w.derive(t)
	for _, a := range []string{"198.51.100.1", "198.51.100.254"} {
		if got[a].Type != "asn" {
			t.Errorf("%s = %+v", a, got[a])
		}
	}
	// The owner of another unit does not apply.
	w.netblockOwner("198.51.101.0/24", 64999)
	if got := w.derive(t); len(got) != 2 {
		t.Errorf("flagged %d, want 2", len(got))
	}
}

// What a finding holds: every entry with its tag, score, organisation, type and date, no rank, the
// attrs the risk file reads, a found line and a key that does not change with its type.
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
	if want := []string{"severity", "ip", "hostnames", "type", "networks", "asn", "networks_updated", "asns_updated"}; !slices.Equal(file.Columns, want) {
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
	if got := rows[0].Cells; got[0] != "medium" || got[1] != "203.0.113.17" || got[2] != "app.example.com" || got[3] != "network" || got[6] != "2026-11-21" {
		t.Errorf("row = %v", got)
	}
	if got := rows[0].Cells[4]; !strings.Contains(got, "203.0.113.0/24 High 80% Acme Hosting (hosting)") {
		t.Errorf("networks cell = %q", got)
	}
	if got := rows[1].Cells; got[1] != "203.0.113.99" {
		t.Errorf("a finding no longer derived has ip %q, want the one in its key", got[1])
	}
}
