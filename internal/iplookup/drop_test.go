package iplookup

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/spamhaus"
)

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

// dropFile is a list as Spamhaus serves it: its rows, then its metadata line.
func dropFile(at time.Time, rows []string) []byte {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r + "\n")
	}
	fmt.Fprintf(&b, `{"type":"metadata","timestamp":%d,"size":1,"records":%d,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}`+"\n",
		at.Unix(), len(rows))
	return []byte(b.String())
}

// testDrop are the lists the lookups are checked against: 8.8.4.4 is in a /24 inside a /16 (whose
// RIR is null), pub6 in an IPv6 /32, and AS15169 (the populated owner) is in ASN-DROP.
func testDrop(t *testing.T) *spamhaus.Lists {
	t.Helper()
	l4, err := spamhaus.ParseDrop(dropFile(dropV4Time, []string{
		`{"cidr":"8.8.0.0/16","sblid":"SBL6","rir":null}`,
		`{"cidr":"8.8.4.0/24","sblid":"SBL5","rir":"arin"}`,
		`{"cidr":"9.9.9.0/24","sblid":"SBL7","rir":"ripencc"}`,
		`{"cidr":"10.0.0.0/8","sblid":"SBL8","rir":"arin"}`,
	}), false)
	if err != nil {
		t.Fatal(err)
	}
	l6, err := spamhaus.ParseDrop(dropFile(dropV6Time, []string{`{"cidr":"2001:4860::/32","sblid":"SBL10","rir":"apnic"}`}), true)
	if err != nil {
		t.Fatal(err)
	}
	la, err := spamhaus.ParseASNDrop(dropFile(dropASNTime, []string{
		`{"asn":15169,"rir":"arin","domain":"google.example","cc":"US","asname":"GOOGLE-BAD"}`,
		`{"asn":64999,"rir":"ripencc","domain":"","cc":"RU","asname":"OTHER"}`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	return &spamhaus.Lists{V4: l4, V6: l6, ASNs: la}
}

var listedAS = []spamhaus.ASNMatch{{ASN: 15169, ASName: "GOOGLE-BAD", Country: "US", Domain: "google.example", RIR: "arin", Updated: dropASNDate}}

func dropWorld(t *testing.T, spec string) *world {
	t.Helper()
	w := newWorld(t, false, spec)
	w.cfg.Drop = testDrop(t)
	return w
}

// drop_networks needs no request: every DROP entry that holds the address, the most specific
// first, each with its list's date, an empty RIR as "". The address always answers, and nothing
// is asked of anyone.
func TestDrop_NetworksNeedNoRequest(t *testing.T) {
	t.Parallel()
	w := dropWorld(t, "drop_networks")
	res := w.lookup(pubAddr, "1.1.1.1", pub6, "::ffff:8.8.4.4")
	if len(res) != 4 {
		t.Fatalf("got %d results, want 4", len(res))
	}
	want := map[string][]spamhaus.NetworkMatch{
		pubAddr: {
			{CIDR: "8.8.4.0/24", SBLID: "SBL5", RIR: "arin", Updated: dropV4Date},
			{CIDR: "8.8.0.0/16", SBLID: "SBL6", RIR: "", Updated: dropV4Date},
		},
		"1.1.1.1": {},
		pub6:      {{CIDR: "2001:4860::/32", SBLID: "SBL10", RIR: "apnic", Updated: dropV6Date}},
	}
	for i, r := range res {
		rec := r.Record
		addr := rec.Address
		wantNets := want[addr]
		if i == 3 {
			wantNets = want[pubAddr] // a mapped address is matched as its IPv4 address
		}
		if rec.DropNetworks == nil || !slices.Equal(rec.DropNetworks, wantNets) {
			t.Errorf("%s (input %d): drop_networks = %#v, want %#v", addr, i, rec.DropNetworks, wantNets)
		}
		if !r.Answered || len(rec.Failures) != 0 {
			t.Errorf("%s: answered %v, failures %+v; want an answer and no failure", addr, r.Answered, rec.Failures)
		}
	}
	if q := w.dns.queries(); len(q) != 0 {
		t.Errorf("DNS was asked: %v", q)
	}
	if w.http.total() != 0 {
		t.Errorf("a third party was asked: %v", w.http.asked)
	}
}

// drop_asn is the ASN-DROP entry of the origin AS Team Cymru gives, sharing that lookup with
// abusive_asn: [] when the AS is not listed or Team Cymru knows no owner, and null with Team
// Cymru's failure when the origin lookup failed.
func TestDrop_ASNFollowsTheOriginAS(t *testing.T) {
	t.Parallel()
	t.Run("listed", func(t *testing.T) {
		t.Parallel()
		w := dropWorld(t, "abusive_asn,drop_asn")
		w.populate(pubAddr)
		res := only(t, w.lookup(pubAddr))
		if !slices.Equal(res.Record.DropASN, listedAS) || len(res.Record.Failures) != 0 {
			t.Errorf("drop_asn = %#v, failures %+v; want %#v", res.Record.DropASN, res.Record.Failures, listedAS)
		}
		if n := w.dns.queried(originName(pubAddr)); n != 1 {
			t.Errorf("the origin was asked %d times, want once for both keys", n)
		}
	})
	t.Run("not listed", func(t *testing.T) {
		t.Parallel()
		w := dropWorld(t, "drop_asn")
		w.populate(pubAddr)
		w.ownedBy(pubAddr, 64500, "8.8.4.0/24", "FINE")
		r := only(t, w.lookup(pubAddr)).Record
		if r.DropASN == nil || len(r.DropASN) != 0 || len(r.Failures) != 0 {
			t.Errorf("drop_asn = %#v, failures %+v; want []", r.DropASN, r.Failures)
		}
	})
	t.Run("no owner", func(t *testing.T) {
		t.Parallel()
		w := dropWorld(t, "drop_asn") // Team Cymru says NXDOMAIN
		r := only(t, w.lookup(pubAddr)).Record
		if r.DropASN == nil || len(r.DropASN) != 0 || len(r.Failures) != 0 {
			t.Errorf("drop_asn = %#v, failures %+v; want []", r.DropASN, r.Failures)
		}
	})
	t.Run("the holder's name failed", func(t *testing.T) {
		t.Parallel()
		w := dropWorld(t, "drop_asn")
		w.populate(pubAddr)
		w.dns.set("AS15169.asn.cymru.com", egress.TypeTXT, egress.DNSResult{RCode: egress.RCodeServFail})
		r := only(t, w.lookup(pubAddr)).Record
		if !slices.Equal(r.DropASN, listedAS) {
			t.Errorf("drop_asn = %#v, want the entry of the AS the origin gave", r.DropASN)
		}
	})
	for _, tc := range []struct {
		spec     string
		answered bool // the address still has its record, and the call ends partial
	}{{"drop_asn", false}, {"drop_networks,drop_asn", true}} {
		t.Run("the origin failed, "+tc.spec, func(t *testing.T) {
			t.Parallel()
			w := dropWorld(t, tc.spec)
			w.populate(pubAddr)
			w.dns.set(originName(pubAddr), egress.TypeTXT, egress.DNSResult{RCode: egress.RCodeServFail})
			res := only(t, w.lookup(pubAddr))
			r := res.Record
			if r.DropASN != nil {
				t.Errorf("drop_asn = %#v, want null", r.DropASN)
			}
			if _, ok := failureOf(r, SourceCymru); !ok {
				t.Errorf("failures = %+v, want Team Cymru's", r.Failures)
			}
			if res.Answered != tc.answered {
				t.Errorf("answered = %v, want %v", res.Answered, tc.answered)
			}
			if tc.answered && len(r.DropNetworks) != 2 {
				t.Errorf("drop_networks = %#v, want the two entries", r.DropNetworks)
			}
		})
	}
}

// A non-public address is checked against no list: both keys are null, even when a DROP entry
// holds it, and nothing is asked.
func TestDrop_NonPublicIsNull(t *testing.T) {
	t.Parallel()
	w := dropWorld(t, "all")
	r := only(t, w.lookup("10.0.0.1")).Record
	if r.Kind != addrkind.Kind("private") {
		t.Fatalf("kind = %s", r.Kind)
	}
	if r.DropNetworks != nil || r.DropASN != nil {
		t.Errorf("drop_networks %#v, drop_asn %#v; want both null", r.DropNetworks, r.DropASN)
	}
	if len(w.dns.queries()) != 0 || w.http.total() != 0 {
		t.Errorf("asked %v and %v", w.dns.queries(), w.http.asked)
	}
}

// Every key of the default selection is set for a public address that every source answers for.
func TestDrop_InTheDefaultSelection(t *testing.T) {
	t.Parallel()
	w := dropWorld(t, "all")
	w.populate(pubAddr)
	r := only(t, w.lookup(pubAddr)).Record
	if len(r.DropNetworks) != 2 || !slices.Equal(r.DropASN, listedAS) {
		t.Errorf("drop_networks %#v, drop_asn %#v", r.DropNetworks, r.DropASN)
	}
}

// With no lists given, the ones built into the binary are used.
func TestDrop_NoListsMeansTheBuiltInOnes(t *testing.T) {
	t.Parallel()
	built, err := spamhaus.ParseBundle(spamhaus.Builtin())
	if err != nil {
		t.Fatalf("the built-in bundle: %v", err)
	}
	var entry spamhaus.NetworkEntry
	for _, e := range built.V4.Entries {
		if addrkind.Of(e.CIDR.Addr()) == addrkind.Public {
			entry = e
			break
		}
	}
	if !entry.CIDR.IsValid() {
		t.Fatal("the built-in bundle has no DROP entry of a public address")
	}
	w := newWorld(t, false, "drop_networks")
	r := only(t, w.lookup(entry.CIDR.Addr().String())).Record
	if !slices.ContainsFunc(r.DropNetworks, func(m spamhaus.NetworkMatch) bool {
		return m.CIDR == entry.CIDR.String() && m.SBLID == entry.SBLID && m.Updated == built.V4.Meta.Updated()
	}) {
		t.Errorf("drop_networks of %s = %#v, want the built-in entry %v", entry.CIDR.Addr(), r.DropNetworks, entry)
	}
}
