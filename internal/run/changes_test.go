package run

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

var targets = map[string]bool{"httpprobe": true, "portscan": true}

// diff is the changes compare lists, without the rows it carries.
func diff(b *baseline, cur []entry, passive bool) []output.Change {
	changes, _ := b.compare(cur, passive, targets)
	return changes
}

// byKey indexes changes by "change kind key".
func byKey(cs []output.Change) map[string]output.Change {
	m := map[string]output.Change{}
	for _, c := range cs {
		m[c.Change+" "+c.Kind+" "+c.Key] = c
	}
	return m
}

// Compare visibility transitions: absent→shown is new, hidden→shown returned, shown→hidden
// gone, and shown→shown unchanged.
func TestDiff_NewReturnedGone(t *testing.T) {
	t.Parallel()
	b := newBaseline([]store.ShownRow{
		{Kind: "web service", Key: "https://kept.a.com", Scope: "in-scope", Producers: []string{"web"}},
		{Kind: "web service", Key: "https://lost.a.com", Scope: "in-scope", Producers: []string{"web"}},
	}, map[entryKey]bool{
		{"web service", "https://kept.a.com"}: true, {"web service", "https://lost.a.com"}: true,
		{"web service", "https://back.a.com"}: true,
	})
	cur := []entry{
		{label: "web service", key: "https://kept.a.com", scope: "in-scope", shown: true},
		{label: "web service", key: "https://lost.a.com", shown: false, first: "2026-10-01", last: "2026-10-20"},
		{label: "web service", key: "https://back.a.com", scope: "in-scope", shown: true, first: "2026-09-01", last: "2026-11-01"},
		{label: "web service", key: "https://fresh.a.com", scope: "in-scope", shown: true, first: "2026-11-01", last: "2026-11-01"},
	}
	got := byKey(diff(b, cur, false))
	if len(got) != 3 {
		t.Fatalf("got %d changes, want 3: %v", len(got), got)
	}
	if c := got["new web service https://fresh.a.com"]; c.Scope != "in-scope" || !c.Current || c.FirstSeen != "2026-11-01" {
		t.Errorf("new = %+v", c)
	}
	if c := got["returned web service https://back.a.com"]; !c.Current || c.FirstSeen != "2026-09-01" || c.LastSeen != "2026-11-01" {
		t.Errorf("returned = %+v", c)
	}
	// A gone row shows the scope it had when it was shown, and is not current.
	if c := got["gone web service https://lost.a.com"]; c.Scope != "in-scope" || c.Current || c.FirstSeen != "2026-10-01" || c.LastSeen != "2026-10-20" {
		t.Errorf("gone = %+v", c)
	}
}

// New findings use current severity; gone findings use baseline severity after attributes
// disappear.
func TestDiff_FindingSeverity(t *testing.T) {
	t.Parallel()
	b := newBaseline([]store.ShownRow{{Kind: "finding", Key: "certificates|expiring|https://a.com", Severity: "low", Producers: []string{"findings"}}}, map[entryKey]bool{{"finding", "certificates|expiring|https://a.com"}: true})
	cur := []entry{
		{label: "finding", key: "certificates|expiring|https://a.com", shown: false},
		{label: "finding", key: "certificates|expired|https://a.com", severity: "medium", shown: true},
	}
	got := byKey(diff(b, cur, false))
	if c := got["new finding certificates|expired|https://a.com"]; c.Severity != "medium" {
		t.Errorf("new finding = %+v", c)
	}
	if c := got["gone finding certificates|expiring|https://a.com"]; c.Severity != "low" {
		t.Errorf("gone finding = %+v", c)
	}
}

// With no baseline (a first run) there are no changes, however much is shown.
func TestDiff_FirstRun(t *testing.T) {
	t.Parallel()
	var b *baseline
	cur := []entry{{label: "hostname", key: "a.com", shown: true}}
	if got := diff(b, cur, false); len(got) != 0 {
		t.Errorf("a first run reported %v", got)
	}
}

// Passive comparisons carry target-only missing entries forward, but still report missing
// third-party/derived records and all additions/returns.
func TestDiff_PassiveRule(t *testing.T) {
	t.Parallel()
	rows := []store.ShownRow{
		{Kind: "web service", Key: "target-only", Producers: []string{"httpprobe"}},
		{Kind: "web service", Key: "two-targets", Producers: []string{"httpprobe", "portscan"}},
		{Kind: "web service", Key: "mixed", Producers: []string{"crtsh", "httpprobe"}},
		{Kind: "hostname", Key: "third-party", Producers: []string{"crtsh"}},
		{Kind: "finding", Key: "certificates|expired|x", Severity: "medium", Producers: []string{"findings"}},
		{Kind: "candidate", Key: "x.org", Producers: []string{"candidate-rank"}},
		{Kind: "third party", Key: "a.com|cname|github.io", Producers: []string{"thirdparty-cname"}}, // what an analysis stores
		{Kind: "address", Key: "192.0.2.1"},                                                          // no procedure at all
	}
	cur := []entry{
		{label: "web service", key: "fresh", shown: true},
	}
	passive := byKey(diff(newBaseline(rows, nil), cur, true))
	for _, k := range []string{"gone web service target-only", "gone web service two-targets"} {
		if _, ok := passive[k]; ok {
			t.Errorf("passive run reported %q", k)
		}
	}
	for _, k := range []string{"gone web service mixed", "gone hostname third-party", "gone finding certificates|expired|x",
		"gone candidate x.org", "gone third party a.com|cname|github.io", "gone address 192.0.2.1", "new web service fresh"} {
		if _, ok := passive[k]; !ok {
			t.Errorf("passive run missed %q: %v", k, passive)
		}
	}
	// Carry unverified disappearances into the next active comparison.
	_, carried := newBaseline(rows, nil).compare(cur, true, targets)
	var carriedKeys []string
	for _, r := range carried {
		carriedKeys = append(carriedKeys, r.Key)
	}
	if !slices.Equal(carriedKeys, []string{"target-only", "two-targets"}) {
		t.Errorf("carried = %v", carriedKeys)
	}
	if _, carried := newBaseline(rows, nil).compare(cur, false, targets); len(carried) != 0 {
		t.Errorf("an active run carried %v", carried)
	}
	active := byKey(diff(newBaseline(rows, nil), cur, false))
	if _, ok := active["gone web service target-only"]; !ok {
		t.Error("an active run did not report the target-only record gone")
	}
}

// The changes are sorted: new, then returned, then gone, then by kind and key.
func TestDiff_Order(t *testing.T) {
	t.Parallel()
	b := newBaseline([]store.ShownRow{{Kind: "hostname", Key: "gone.a.com"}}, map[entryKey]bool{{"hostname", "back.a.com"}: true})
	cur := []entry{
		{label: "web service", key: "z", shown: true},
		{label: "hostname", key: "b.a.com", shown: true},
		{label: "hostname", key: "a.a.com", shown: true},
		{label: "hostname", key: "back.a.com", shown: true},
	}
	var got []string
	for _, c := range diff(b, cur, false) {
		got = append(got, c.Change+" "+c.Kind+" "+c.Key)
	}
	want := []string{"new hostname a.a.com", "new hostname b.a.com", "new web service z", "returned hostname back.a.com", "gone hostname gone.a.com"}
	if !slices.Equal(got, want) {
		t.Errorf("order\n got %v\nwant %v", got, want)
	}
}

func snapshot(t *testing.T, sc *scope.Scope, inv *inventory.Inventory, recs map[string][]store.Record) output.Snapshot {
	t.Helper()
	return output.Snapshot{Today: "2026-11-01", Scope: sc, Inv: inv, Records: recs, Vis: kinds.NewVisibility(sc, inv), ASNNetblocks: map[string]string{}}
}

func rec(kind, key string, current bool, attrs map[string]any, procedures ...string) store.Record {
	return store.Record{Kind: kind, Key: key, Current: current, Attrs: attrs, Producers: procedures, FirstSeen: "2026-10-01", LastSeen: "2026-11-01"}
}

func entryOf(es []entry, label, key string) *entry {
	for i := range es {
		if es[i].label == label && es[i].key == key {
			return &es[i]
		}
	}
	return nil
}

// Output labels define comparison entries; internal/evidence kinds are omitted and non-current
// records count as hidden history.
func TestEntriesOf_FollowTheFiles(t *testing.T) {
	t.Parallel()
	sc := scope.New(scope.Config{Roots: []string{"a.com"}})
	inv := inventory.New(inventory.Data{}, provider.Default())
	snap := snapshot(t, sc, inv, map[string][]store.Record{
		"hostname":       {rec("hostname", "www.a.com", true, nil, "crtsh"), rec("hostname", "old.a.com", false, nil), rec("hostname", "cand.org", true, nil, "crtsh")},
		"root":           {rec("root", "other.org", true, nil)},
		"web_service":    {rec("web_service", "https://www.a.com", true, map[string]any{"host": "www.a.com"}, "httpprobe"), rec("web_service", "https://x.org", true, map[string]any{"host": "x.org"})},
		"web_posture":    {rec("web_posture", "https://www.a.com", true, nil)},
		"candidate_rank": {rec("candidate_rank", "root|other.org", true, nil)},
		"finding":        {rec("finding", "certificates|expired|https://www.a.com", true, map[string]any{"severity": "medium"}, "findings")},
		"ip":             {rec("ip", "192.0.2.1", true, nil)},
	})
	es := entriesOf(snap)
	for _, c := range []struct {
		label, key string
		shown      bool
		scope      string
	}{
		{"hostname", "www.a.com", true, "in-scope"},
		{"hostname", "old.a.com", false, "in-scope"},
		{"candidate", "cand.org", true, "candidate"},
		{"candidate", "other.org", true, "candidate"},
		{"web service", "https://www.a.com", true, "in-scope"},
		{"web service", "https://x.org", false, "in-scope"}, // its host is not in scope
		{"finding", "certificates|expired|https://www.a.com", true, ""},
		{"address", "192.0.2.1", true, ""},
	} {
		e := entryOf(es, c.label, c.key)
		if e == nil {
			t.Errorf("no entry for %s %s", c.label, c.key)
			continue
		}
		if e.shown != c.shown || e.scope != c.scope {
			t.Errorf("%s %s: shown %v scope %q, want %v %q", c.label, c.key, e.shown, e.scope, c.shown, c.scope)
		}
	}
	if e := entryOf(es, "finding", "certificates|expired|https://www.a.com"); e != nil && e.severity != "medium" {
		t.Errorf("finding severity = %q", e.severity)
	}
	if e := entryOf(es, "web service", "https://www.a.com"); e != nil && !slices.Equal(e.producers, []string{"httpprobe"}) {
		t.Errorf("producers = %v", e.producers)
	}
	for _, e := range es {
		if e.label == "" || e.key == "" {
			t.Errorf("an entry has no label or key: %+v", e)
		}
		if e.key == "root|other.org" {
			t.Errorf("internal or evidence kinds listed: %+v", e)
		}
	}
}

// A name only a wildcard answers is not a shown hostname.
func TestEntriesOf_WildcardOnlyHostIsNotShown(t *testing.T) {
	t.Parallel()
	sc := scope.New(scope.Config{Roots: []string{"a.com"}, WildcardOnly: map[string]bool{"w.a.com": true}})
	wc := netip.MustParseAddr("192.0.2.1")
	inv := inventory.New(inventory.Data{
		Hosts:       []inventory.Host{{Name: "w.a.com"}, {Name: "real.a.com"}},
		Resolutions: []inventory.Resolution{{Name: "w.a.com", Type: "A", Value: "192.0.2.1"}, {Name: "real.a.com", Type: "A", Value: "192.0.2.9"}},
		Wildcards:   []inventory.Wildcard{{Zone: "a.com", Addrs: []netip.Addr{wc}}},
	}, provider.Default())
	snap := snapshot(t, sc, inv, map[string][]store.Record{
		"hostname": {rec("hostname", "w.a.com", true, nil), rec("hostname", "real.a.com", true, nil)},
	})
	es := entriesOf(snap)
	if e := entryOf(es, "hostname", "w.a.com"); e == nil || e.shown {
		t.Errorf("wildcard-only host = %+v", e)
	}
	if e := entryOf(es, "hostname", "real.a.com"); e == nil || !e.shown {
		t.Errorf("real host = %+v", e)
	}
}

// Comparison entries deduplicate values exactly as output rows do across exclusions, DNS claims
// and port reports.
func TestEntriesOf_OneEntryPerFileRow(t *testing.T) {
	t.Parallel()
	sc := scope.New(scope.Config{Roots: []string{"a.com"}, Exclusions: nil})
	inv := inventory.New(inventory.Data{}, provider.Default())
	snap := snapshot(t, sc, inv, map[string][]store.Record{
		"resolution":    {rec("resolution", "www.a.com|A|192.0.2.1", true, nil, "resolve")},
		"dns_claim":     {rec("dns_claim", "www.a.com|A|192.0.2.1", true, nil, "shodan")},
		"unresolved":    {rec("unresolved", "nx.a.com", true, nil, "resolve")},
		"third_party":   {rec("third_party", "a.com|ns|dns.example", true, map[string]any{"root": "a.com", "domain": "dns.example"}, "dnsroot")},
		"code_mention":  {rec("code_mention", "https://github.com/x/y/blob/z", true, map[string]any{"root": "a.com"}, "github")},
		"email_posture": {rec("email_posture", "a.com", true, nil, "email")},
	})
	es := entriesOf(snap)
	n := 0
	for _, e := range es {
		if e.label == "resolution" && e.key == "www.a.com|A|192.0.2.1" {
			n++
			if !slices.Equal(e.producers, []string{"resolve", "shodan"}) {
				t.Errorf("resolution entry = %+v", e)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d resolution entries, want 1", n)
	}
	for _, c := range [][2]string{{"unresolved name", "nx.a.com"}, {"email posture", "a.com"}, {"code mention", "https://github.com/x/y/blob/z"}} {
		if entryOf(es, c[0], c[1]) == nil {
			t.Errorf("no %s entry for %s", c[0], c[1])
		}
	}
}

// A port nyx found open and a port a third party reported at one address are one
// open port.
func TestEntriesOf_OpenPortFromBothSources(t *testing.T) {
	t.Parallel()
	sc := scope.New(scope.Config{Roots: []string{"a.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}})
	inv := inventory.New(inventory.Data{}, provider.Default())
	snap := snapshot(t, sc, inv, map[string][]store.Record{
		"open_port":     {rec("open_port", "192.0.2.1:22", true, nil, "portscan")},
		"reported_port": {rec("reported_port", "192.0.2.1:22", true, nil, "shodan")},
	})
	es := entriesOf(snap)
	var found []*entry
	for i := range es {
		if es[i].label == "open port" {
			found = append(found, &es[i])
		}
	}
	if len(found) != 1 || !found[0].shown || !slices.Equal(found[0].producers, []string{"portscan", "shodan"}) {
		t.Errorf("open port entries = %+v", found)
	}
}
