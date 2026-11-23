package run

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/engagement"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/store"
)

// events records what a Runner emits.
type events struct {
	mu  sync.Mutex
	got []report.Event
}

func (e *events) Emit(ev report.Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.got = append(e.got, ev)
}

// found are the found events emitted for the finding target.
func (e *events) found(target string) []report.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []report.Event
	for _, ev := range e.got {
		if ev.Type == "found" && ev.Fields["value"] == target {
			out = append(out, ev)
		}
	}
	return out
}

// The address the threat-data tests check: app.example.com's, announced by AS64500.
const (
	dropAddr = "203.0.113.17"
	dropKey  = "abusive-network|" + dropAddr
)

var dropListTime = time.Date(2026, 10, 1, 8, 30, 5, 0, time.UTC)

// dropFile is a DROP or ASN-DROP list as Spamhaus serves it: its rows, then its metadata line.
func dropFile(rows ...string) []byte {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	fmt.Fprintf(&b, `{"type":"metadata","timestamp":%d,"size":1,"records":%d,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}`+"\n",
		dropListTime.Unix(), len(rows))
	return []byte(b.String())
}

// dropLists are the lists of DROP rows and ASN-DROP rows, with an empty DROPv6.
func dropLists(t *testing.T, v4, asns []string) *spamhaus.Lists {
	t.Helper()
	l4, err := spamhaus.ParseDrop(dropFile(v4...), false)
	if err != nil {
		t.Fatal(err)
	}
	l6, err := spamhaus.ParseDrop(dropFile(), true)
	if err != nil {
		t.Fatal(err)
	}
	la, err := spamhaus.ParseASNDrop(dropFile(asns...))
	if err != nil {
		t.Fatal(err)
	}
	return &spamhaus.Lists{V4: l4, V6: l6, ASNs: la}
}

// ipapiNetwork is an ipapi.is snapshot whose network list holds the address's /24.
func ipapiNetwork() *abusive.Snapshot {
	return abusive.Load(abusive.Snapshot{
		Nets: abusive.List[abusive.NetworkEntry]{Updated: "2026-10-01", Entries: []abusive.NetworkEntry{{
			Rank: 1, Start: netip.MustParseAddr("203.0.113.0"), End: netip.MustParseAddr("203.0.113.255"),
			ScoreTag: "High", AbuseScore: 80, Org: "Net Org", OrgType: "hosting"}}},
		ASNs: abusive.List[abusive.ASNEntry]{Updated: "2026-10-01"},
	})
}

// threatWorld is the input the findings deriver reads: example.com's scope, with app.example.com
// resolving to addr, announced by AS64500, and the finding records already stored.
func threatWorld(addr string, stored ...store.Record) deriveInput {
	a := netip.MustParseAddr(addr)
	inv := inventory.New(inventory.Data{
		Hosts:       []inventory.Host{{Name: "app.example.com", Stages: []string{"crtsh"}}},
		Resolutions: []inventory.Resolution{{Name: "app.example.com", Type: "A", Value: addr}},
		Owners:      map[netip.Addr]provider.Owner{a: {ASN: 64500, Known: true}},
	}, provider.Default())
	sc := scope.New(scope.Config{Roots: []string{"example.com"}, Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly()})
	recs := map[string][]store.Record{
		kinds.Hostname.Name(): {rec("hostname", "app.example.com", true, nil, "crtsh")},
		kinds.Finding.Name():  stored,
	}
	return deriveInput{Scope: sc, Inv: inv, Vis: kinds.NewVisibility(sc, inv), Inputs: input.Parsed{Roots: []string{"example.com"}},
		Today: "2026-11-01", Records: func(k kinds.Named) []store.Record { return recs[k.Name()] }}
}

// storedFinding is a current abusive-network finding of the address, as a run stored it.
func storedFinding(typ, severity string) store.Record {
	return rec("finding", dropKey, true, map[string]any{"category": "abusive-network", "type": typ, "severity": severity,
		"target": dropAddr, "ip": dropAddr}, "findings")
}

// obsOf is the derived observation of the key, and whether there is one.
func obsOf(obs []store.Obs, key string) (store.Obs, bool) {
	for _, o := range obs {
		if o.Key == key {
			return o, true
		}
	}
	return store.Obs{}, false
}

// The run's DROP lists reach the findings: an address a DROP network holds is a high drop-network
// finding.
func TestDeriveFindings_CheckTheRunsDropLists(t *testing.T) {
	t.Parallel()
	ev := &events{}
	r := &Runner{cfg: Config{Emitter: ev, Drop: dropNetwork(t)}}
	obs, after := r.deriveFindings(threatWorld(dropAddr))
	o, ok := obsOf(obs, dropKey)
	if !ok || o.Attrs["type"] != "drop-network" || o.Attrs["severity"] != "high" {
		t.Fatalf("finding of %s = %+v (derived %v), want a high drop-network", dropAddr, o.Attrs, ok)
	}
	if after != nil {
		after(true)
	}
	if got := ev.found(dropAddr); len(got) != 0 {
		t.Errorf("a new finding was announced by the hook (the store announces it): %+v", got)
	}
}

// dropNetwork is a DROP list holding the address's /24.
func dropNetwork(t *testing.T) *spamhaus.Lists {
	t.Helper()
	return dropLists(t, []string{`{"cidr":"203.0.113.0/24","sblid":"SBL5","rir":"lacnic"}`}, nil)
}

// A finding whose strongest match rises from ipapi.is's network to DROP's is announced again.
func TestDeriveFindings_ARiseToDropNetworkIsAnnounced(t *testing.T) {
	t.Parallel()
	ev := &events{}
	r := &Runner{cfg: Config{Emitter: ev, Abusive: ipapiNetwork(), Drop: dropNetwork(t)}}
	obs, after := r.deriveFindings(threatWorld(dropAddr, storedFinding("network", "medium")))
	if o, ok := obsOf(obs, dropKey); !ok || o.Attrs["type"] != "drop-network" || o.Attrs["severity"] != "high" {
		t.Fatalf("finding = %+v (derived %v), want a high drop-network", o.Attrs, ok)
	}
	if after == nil {
		t.Fatal("no hook")
	}
	after(true)
	got := ev.found(dropAddr)
	if len(got) != 1 {
		t.Fatalf("announced %d times, want once: %+v", len(got), ev.got)
	}
	if got[0].Fields["severity"] != "high" || got[0].Fields["text"] != "address 203.0.113.17 in Spamhaus DROP network 203.0.113.0/24 (SBL5)" {
		t.Errorf("announcement = %+v", got[0].Fields)
	}
}

// A finding whose strongest match rises from ipapi.is's AS to ASN-DROP's is announced again.
func TestDeriveFindings_ARiseToDropASNIsAnnounced(t *testing.T) {
	t.Parallel()
	ev := &events{}
	asnOnly := abusive.Load(abusive.Snapshot{ASNs: abusive.List[abusive.ASNEntry]{Updated: "2026-10-01",
		Entries: []abusive.ASNEntry{{Rank: 1, ASN: 64500, ScoreTag: "High", AbuseScore: 90, Org: "Bad AS", OrgType: "isp"}}}})
	r := &Runner{cfg: Config{Emitter: ev, Abusive: asnOnly,
		Drop: dropLists(t, nil, []string{`{"asn":64500,"rir":"ripencc","domain":"example.net","cc":"RU","asname":"BAD-AS"}`})}}
	obs, after := r.deriveFindings(threatWorld(dropAddr, storedFinding("asn", "low")))
	if o, ok := obsOf(obs, dropKey); !ok || o.Attrs["type"] != "drop-asn" || o.Attrs["severity"] != "medium" {
		t.Fatalf("finding = %+v (derived %v), want a medium drop-asn", o.Attrs, ok)
	}
	after(true)
	if got := ev.found(dropAddr); len(got) != 1 || got[0].Fields["severity"] != "medium" {
		t.Errorf("announcements = %+v, want one at medium", got)
	}
}

// A finding whose strongest match weakens (DROP drops the address, ipapi.is still lists it) stays
// the one finding at the lower type and severity, and is not announced.
func TestDeriveFindings_AWeakerMatchKeepsOneFinding(t *testing.T) {
	t.Parallel()
	ev := &events{}
	r := &Runner{cfg: Config{Emitter: ev, Abusive: ipapiNetwork(), Drop: dropLists(t, nil, nil)}}
	obs, after := r.deriveFindings(threatWorld(dropAddr, storedFinding("drop-network", "high")))
	var mine []store.Obs
	for _, o := range obs {
		if strings.HasPrefix(o.Key, "abusive-network|") {
			mine = append(mine, o)
		}
	}
	if len(mine) != 1 || mine[0].Key != dropKey || mine[0].Attrs["type"] != "network" || mine[0].Attrs["severity"] != "medium" {
		t.Fatalf("abusive findings = %+v, want one medium network under %s", mine, dropKey)
	}
	if after != nil {
		after(true)
	}
	if got := ev.found(dropAddr); len(got) != 0 {
		t.Errorf("a weaker finding was announced: %+v", got)
	}
}

// A finding with no match left is no longer derived, so it stops being current.
func TestDeriveFindings_NoMatchLeftIsNoFinding(t *testing.T) {
	t.Parallel()
	ev := &events{}
	r := &Runner{cfg: Config{Emitter: ev, Abusive: abusive.Load(abusive.Snapshot{}), Drop: dropLists(t, nil, nil)}}
	obs, after := r.deriveFindings(threatWorld(dropAddr, storedFinding("drop-network", "high")))
	if o, ok := obsOf(obs, dropKey); ok {
		t.Errorf("a finding with no match left is still derived: %+v", o.Attrs)
	}
	if after != nil {
		after(true)
	}
	if got := ev.found(dropAddr); len(got) != 0 {
		t.Errorf("announced: %+v", got)
	}
}

// A Runner given no DROP lists checks the ones built into the binary.
func TestNew_DropDefaultsToTheBuiltInLists(t *testing.T) {
	t.Parallel()
	built, err := spamhaus.ParseBundle(spamhaus.Builtin())
	if err != nil {
		t.Fatalf("the built-in bundle: %v", err)
	}
	if len(built.V4.Entries) == 0 {
		t.Fatal("the built-in bundle has no DROP entry")
	}
	addr := built.V4.Entries[0].CIDR.Addr().String()
	eng, err := engagement.Open(t.TempDir(), engagement.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	r := New(Config{Engagement: eng, Emitter: &events{}, NoFsync: true})
	obs, _ := r.deriveFindings(threatWorld(addr))
	if o, ok := obsOf(obs, "abusive-network|"+addr); !ok || o.Attrs["type"] != "drop-network" {
		t.Errorf("the first built-in DROP entry's address %s = %+v (derived %v), want a drop-network finding", addr, o.Attrs, ok)
	}
}
