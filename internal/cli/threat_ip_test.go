package cli_test

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/abusive"
	"github.com/rafaelh/nyx/internal/spamhaus"
)

// nyx ip's drop_networks and drop_asn keys: the entries of Spamhaus's DROP lists that hold the
// address, and the ASN-DROP entry of its origin AS, from the threat data in use (the tests' own
// built-in copy, or a downloaded copy they write). Nothing is requested for the lists.

// ipDropLists hold ipAbusiveAddr in a /24 under two SBL IDs and in a /28 whose RIR is null, and list
// AS 64050. DROP is dated 2026-10-20 08:30:05 UTC and ASN-DROP 2026-10-21 01:02:03 UTC.
func ipDropLists(tb testing.TB) *spamhaus.Lists {
	tb.Helper()
	return dropListsOn(tb, time.Date(2026, 10, 20, 8, 30, 5, 0, time.UTC), builtInAt, time.Date(2026, 10, 21, 1, 2, 3, 0, time.UTC),
		[]spamhaus.NetworkEntry{
			dropNet("93.184.216.0/24", "SBL10", "ripencc"),
			dropNet("93.184.216.32/28", "SBL11", ""),
			dropNet("93.184.216.0/24", "SBL12", "arin"),
			dropNet("10.0.0.0/8", "SBL13", "arin"), // a private range, which nyx never matches
		},
		[]spamhaus.ASNEntry{dropASN(64050, "BAD-AS", "RU", "bad.example", "ripencc")})
}

var ipStamp = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// The record carries every DROP entry that holds the address, the most specific first and one CIDR's
// entries in the order of the list, and the ASN-DROP entry of its origin AS, with the keys in order,
// a null RIR as "" and each list's date to the second in RFC 3339 UTC (ipapi.is's stay YYYY-MM-DD).
func TestIPDrop_TheRecordCarriesTheMatches(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.drop = ipDropLists(t)
	w.h.abusive = ipAbusiveSnapshot()
	w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
	w.sealProbes([]string{ipAbusiveAddr})
	rec := w.record(ipAbusiveAddr)
	if !slices.Equal(rec.keys, ipDefaultKeys) {
		t.Errorf("keys %v, want %v", rec.keys, ipDefaultKeys)
	}
	raw := string(rec.raw)
	for _, want := range []string{
		`"drop_networks":[{"cidr":"93.184.216.32/28","sbl_id":"SBL11","rir":"","updated":"2026-10-20T08:30:05Z"},` +
			`{"cidr":"93.184.216.0/24","sbl_id":"SBL10","rir":"ripencc","updated":"2026-10-20T08:30:05Z"},` +
			`{"cidr":"93.184.216.0/24","sbl_id":"SBL12","rir":"arin","updated":"2026-10-20T08:30:05Z"}]`,
		`"drop_asn":[{"asn":64050,"as_name":"BAD-AS","country":"RU","domain":"bad.example","rir":"ripencc","updated":"2026-10-21T01:02:03Z"}]`,
		`"abusive_asn":[{"asn":64050,`, // the keys follow abusive_asn
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("the record lacks %s:\n%s", want, raw)
		}
	}
	for _, key := range []string{"drop_networks", "drop_asn"} {
		for _, v := range rec.list(key) {
			if m, _ := v.(map[string]any); !ipStamp.MatchString(fmt.Sprint(m["updated"])) {
				t.Errorf("%s updated = %v, want RFC 3339 UTC to the second", key, m["updated"])
			}
		}
	}
	for _, v := range rec.list("abusive_networks") {
		if m, _ := v.(map[string]any); !ipDate.MatchString(fmt.Sprint(m["updated"])) {
			t.Errorf("abusive_networks updated = %v, want YYYY-MM-DD", m["updated"])
		}
	}
	if len(rec.failures()) != 0 {
		t.Errorf("failures %+v", rec.failures())
	}
}

// Addresses and ASes the lists do not hold give empty lists; so does an address Team Cymru knows no
// owner of, whose drop_asn is [] and not null.
func TestIPDrop_NothingListedGivesEmptyLists(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.drop = ipDropLists(t)
	w.seed("8.8.4.4")                                     // an unlisted address of an unlisted AS
	w.seed("8.8.4.5", func(f *ipFacts) { f.ASN = 0 })     // no origin: Team Cymru answers NXDOMAIN
	w.seed(ipAbusiveAddr, func(f *ipFacts) { f.ASN = 0 }) // listed networks, no owner
	env := w.lookup("8.8.4.4", "8.8.4.5", ipAbusiveAddr)
	if len(env.Records) != 3 {
		t.Fatalf("%d records, want 3", len(env.Records))
	}
	for _, r := range env.Records {
		nets, asn := len(r.list("drop_networks")), len(r.list("drop_asn"))
		if r.isNull("drop_networks") || r.isNull("drop_asn") || !r.emptyValue("drop_asn") || asn != 0 {
			t.Errorf("%s: drop_networks %v, drop_asn %v, want lists and an empty drop_asn", r.address(), r.m["drop_networks"], r.m["drop_asn"])
		}
		if want := map[bool]int{true: 3, false: 0}[r.address() == ipAbusiveAddr]; nets != want {
			t.Errorf("%s: %d DROP entries, want %d", r.address(), nets, want)
		}
	}
}

// When Team Cymru fails, the DROP network entries still come out, drop_asn is null, the failure is
// listed and the call ends partial (exit 7), also when only the two keys are selected.
func TestIPDrop_TeamCymruFailing(t *testing.T) { // mutation target
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"every source", nil},
		{"only the keys", []string{"--fields", "drop_networks,drop_asn"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newIPWorld(t)
			w.h.drop = ipDropLists(t)
			w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
			w.dns.Rcode(cymruOriginName(ipAbusiveAddr), 2) // SERVFAIL
			env, _ := w.partial(append([]string{ipAbusiveAddr}, tc.args...)...)
			if len(env.Records) != 1 {
				t.Fatalf("%d records, want the address's record to be kept", len(env.Records))
			}
			rec := env.Records[0]
			if !rec.isNull("drop_asn") {
				t.Errorf("drop_asn = %v, want null", rec.m["drop_asn"])
			}
			if len(rec.list("drop_networks")) != 3 {
				t.Errorf("drop_networks = %v, want the three entries", rec.m["drop_networks"])
			}
			if f := rec.failureOf("cymru"); !f.Transient {
				t.Errorf("failure %+v", f)
			}
		})
	}
}

// A non-public address has both keys null, even inside a listed range, and is sent nowhere.
func TestIPDrop_NonPublicAddressHasNullKeys(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.drop = ipDropLists(t)
	rec := w.record("10.0.0.1")
	if !rec.isNull("drop_networks") || !rec.isNull("drop_asn") {
		t.Errorf("drop_networks = %v, drop_asn = %v, want both null", rec.m["drop_networks"], rec.m["drop_asn"])
	}
	w.untouched()
}

// drop_networks selected alone asks nothing, and the address answers: a listed one with its entries
// and an unlisted one with [].
func TestIPDrop_NetworksAloneAnswerWithNoRequest(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.drop = ipDropLists(t)
	env := w.lookup(ipAbusiveAddr, "8.8.4.4", "--fields", "drop_networks")
	if len(env.Records) != 2 {
		t.Fatalf("%d records, want 2", len(env.Records))
	}
	for _, rec := range env.Records {
		if want := ipExpectKeys("drop_networks"); !slices.Equal(rec.keys, want) {
			t.Errorf("keys %v, want %v", rec.keys, want)
		}
		if want := map[bool]int{true: 3, false: 0}[rec.address() == ipAbusiveAddr]; rec.isNull("drop_networks") || len(rec.list("drop_networks")) != want {
			t.Errorf("%s: drop_networks = %v, want %d entries", rec.address(), rec.m["drop_networks"], want)
		}
		if len(rec.failures()) != 0 {
			t.Errorf("%s: failures %+v", rec.address(), rec.failures())
		}
	}
	w.untouched() // no request of any kind
}

// drop_asn asks Team Cymru for the origin AS once, with abusive_asn, and gives its ASN-DROP entry.
func TestIPDrop_ASNAsksTheOriginOnce(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.drop = ipDropLists(t)
	w.h.abusive = ipAbusiveSnapshot()
	w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
	rec := w.record(ipAbusiveAddr, "--fields", "abusive_asn,drop_asn")
	if want := ipExpectKeys("abusive_asn", "drop_asn"); !slices.Equal(rec.keys, want) {
		t.Errorf("keys %v, want %v", rec.keys, want)
	}
	if l := rec.list("drop_asn"); len(l) != 1 || l[0].(map[string]any)["asn"] != 64050.0 {
		t.Errorf("drop_asn = %v, want AS64050's entry", rec.m["drop_asn"])
	}
	if n := w.dns.Count(cymruOriginName(ipAbusiveAddr), "TXT"); n != 1 {
		t.Errorf("Team Cymru's origin was asked %d times, want once", n)
	}
	if w.httpRequests() != 0 {
		t.Errorf("HTTP requests %d", w.httpRequests())
	}
}

// nyx ip --help lists drop_networks and drop_asn right after abusive_asn among the --fields names.
func TestIPDrop_HelpListsTheKeysInOrder(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if code := h.execRoot("ip", "--help"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	fields := ipoFieldsLine(t, h.stdout.String())
	var names []string
	for _, tok := range strings.FieldsFunc(fields, func(r rune) bool { return r == ',' || r == ' ' || r == ':' || r == '(' || r == ')' }) {
		if slices.Contains(ipoFieldNames(), tok) {
			names = append(names, tok)
		}
	}
	at := slices.Index(names, "abusive_asn")
	if at < 0 || at+2 >= len(names) || names[at+1] != "drop_networks" || names[at+2] != "drop_asn" {
		t.Errorf("the --fields names %v do not have drop_networks, drop_asn right after abusive_asn: %s", names, fields)
	}
}

// The date of each list is written the same way in the nyx ip record and in recon's risk file: a
// Spamhaus list's to the second in RFC 3339 UTC, an ipapi.is list's as YYYY-MM-DD.
func TestThreatDates_TheRecordAndTheRiskFileAgree(t *testing.T) {
	t.Parallel()
	aest := time.FixedZone("AEST", 10*3600)
	drop := dropListsOn(t, time.Date(2026, 10, 20, 8, 30, 5, 0, aest), builtInAt, time.Date(2026, 10, 21, 23, 59, 59, 0, aest),
		[]spamhaus.NetworkEntry{dropNet("93.184.216.0/24", "SBL10", "ripencc")},
		[]spamhaus.ASNEntry{dropASN(64050, "BAD-AS", "RU", "bad.example", "ripencc")})
	snap := abSnapshotOn("2026-10-18", "2026-10-17", []abusive.NetworkEntry{abNet(1, "93.184.216.0", "93.184.216.255", "High", 80, "Org", "isp")},
		[]abusive.ASNEntry{abASN(2, 64050, "High", 70, "Bad AS", "isp")})
	want := map[string]string{"drop_networks": "2026-10-19T22:30:05Z", "drop_asn": "2026-10-21T13:59:59Z",
		"abusive_networks": "2026-10-18", "abusive_asn": "2026-10-17"}

	w := newIPWorld(t)
	w.h.drop, w.h.abusive = drop, snap
	w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
	rec := w.record(ipAbusiveAddr)
	for key, date := range want {
		l := rec.list(key)
		if len(l) != 1 || l[0].(map[string]any)["updated"] != date {
			t.Errorf("nyx ip %s = %v, want one entry updated %s", key, rec.m[key], date)
		}
	}

	x := newAbWorld(t)
	x.h.drop, x.h.abusive = drop, snap
	x.names("app.example.com")
	x.host("app.example.com", ipAbusiveAddr)
	x.owner(ipAbusiveAddr, 64050, "BAD-AS")
	x.mustPassive()
	r := x.row(ipAbusiveAddr)
	for col, key := range map[string]string{"drop_networks_updated": "drop_networks", "drop_asn_updated": "drop_asn",
		"networks_updated": "abusive_networks", "asns_updated": "abusive_asn"} {
		if r[col] != want[key] {
			t.Errorf("risk file %s = %q, want %q (as nyx ip gives it)", col, r[col], want[key])
		}
	}
}

// With neither XDG_CONFIG_HOME nor HOME set, nyx ip uses the built-in copy, old as it may be, with
// no warning and no stale hint.
func TestIPDrop_NoDirectoryUsesTheBuiltInCopy(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		w.h.abusive = abSnapshotOn(staleIpapiNets, staleIpapiASNs, nil, nil)
		w.h.drop = staleDrop(t, []spamhaus.NetworkEntry{dropNet("93.184.216.0/24", "SBL10", "ripencc")}, nil)
		writeThreatFile(t, w.h, "spamhaus.jsonl", "this is not a bundle\n") // where the directory was: never read
		w.h.setenv("XDG_CONFIG_HOME", "")
		w.h.setenv("HOME", "")
		args := []string{ipAbusiveAddr, "--fields", "drop_networks,abusive_networks"}
		if !jsonMode {
			if code := w.run(args...); code != 0 {
				t.Fatalf("exit %d: %s", code, w.h.stderr.String())
			}
			if s := w.h.stderr.String(); strings.Contains(s, "unreadable") || strings.Contains(s, "threat") || strings.Contains(s, "hint:") {
				t.Errorf("stderr = %q, want no warning or hint", s)
			}
			if !strings.Contains(w.h.stdout.String(), "SBL10") {
				t.Errorf("the built-in copy's entry is not in the output:\n%s", w.h.stdout.String())
			}
			continue
		}
		rec := w.record(args...)
		if l := rec.list("drop_networks"); len(l) != 1 {
			t.Errorf("drop_networks = %v, want the built-in copy's entry", rec.m["drop_networks"])
		}
		if ws := w.h.ipEnvelope().Meta.Warnings; len(ws) != 0 {
			t.Errorf("meta.warnings = %q, want none", ws)
		}
	}
}

// unreadableIPWorld is an ip world whose built-in copies hold 93.184.216.0/24 (DROP and ipapi.is),
// with an unreadable downloaded copy of each source.
func unreadableIPWorld(t *testing.T) *ipWorld {
	t.Helper()
	w := newIPWorld(t)
	w.h.drop = dropListsAt(t, builtInAt, []spamhaus.NetworkEntry{dropNet("93.184.216.0/24", "SBL10", "ripencc")}, nil)
	w.h.abusive = abSnapshotOn(builtInDay, builtInDay, []abusive.NetworkEntry{abNet(1, "93.184.216.0", "93.184.216.255", "High", 80, "Old Org", "isp")}, nil)
	writeThreatFile(t, w.h, "spamhaus.jsonl", unreadableDrop[1].body) // drop_v6 has no metadata row
	writeAbusiveSnapshot(t, w.h, unreadableIpapi[0].snap)             // under 90% of its stated count
	return w
}

// wantUnreadable fails the test unless msgs warn of an unreadable copy exactly once for each of
// the sources (spamhaus, ipapi.is) and of no other.
func wantUnreadable(t *testing.T, h *harness, msgs []string, sources ...string) {
	t.Helper()
	var got []string
	for _, m := range msgs {
		for _, s := range []string{"spamhaus", "ipapi.is"} {
			if isUnreadableWarning(m, s, threatDir(h)) {
				got = append(got, s)
			}
		}
	}
	if !sameSet(got, sources) {
		t.Errorf("warnings of %v, want one each of %v: %q", got, sources, msgs)
	}
}

// An unreadable downloaded copy falls back, as a whole source, to the built-in copy: nyx ip warns
// once for each such source its keys read, on stderr (under --quiet too) or in meta.warnings under
// --json, and stops once a good copy is in place.
func TestIPDrop_AnUnreadableCopyFallsBackToTheBuiltInOne(t *testing.T) {
	t.Parallel()
	t.Run("human and quiet", func(t *testing.T) {
		t.Parallel()
		w := unreadableIPWorld(t)
		for _, extra := range [][]string{nil, {"--quiet"}} {
			if code := w.run(append([]string{ipAbusiveAddr, "--fields", "drop_networks,abusive_networks"}, extra...)...); code != 0 {
				t.Fatalf("%v: exit %d: %s", extra, code, w.h.stderr.String())
			}
			wantUnreadable(t, w.h, w.h.logMsgs("WARN"), "spamhaus", "ipapi.is")
			if n := len(unreadableLines(w.h)); n != 2 {
				t.Errorf("%v: %d warning lines, want 2:\n%s", extra, n, w.h.stderr.String())
			}
		}
	})
	t.Run("json", func(t *testing.T) {
		t.Parallel()
		w := unreadableIPWorld(t)
		env := w.lookup(ipAbusiveAddr, "8.8.4.4", "--fields", "drop_networks,abusive_networks")
		wantUnreadable(t, w.h, env.Meta.Warnings, "spamhaus", "ipapi.is")
		if l := unreadableLines(w.h); len(l) != 0 {
			t.Errorf("under --json the warning is on stderr: %q", l)
		}
		if len(env.Records) != 2 {
			t.Fatalf("%d records, want 2", len(env.Records))
		}
		for _, r := range env.Records {
			want := map[bool]int{true: 1, false: 0}[r.address() == ipAbusiveAddr] // the built-in copies' entries
			if len(r.list("drop_networks")) != want || len(r.list("abusive_networks")) != want {
				t.Errorf("%s: drop_networks %v, abusive_networks %v, want the built-in copies' matches", r.address(), r.m["drop_networks"], r.m["abusive_networks"])
			}
		}
	})
	t.Run("only the sources the keys read", func(t *testing.T) {
		t.Parallel()
		w := unreadableIPWorld(t)
		w.seed(ipAbusiveAddr)
		for _, c := range []struct {
			fields  string
			sources []string
		}{
			{"asn", nil},
			{"drop_networks", []string{"spamhaus"}},
			{"abusive_networks", []string{"ipapi.is"}},
		} {
			env := w.lookup(ipAbusiveAddr, "--fields", c.fields)
			wantUnreadable(t, w.h, env.Meta.Warnings, c.sources...)
		}
	})
	t.Run("after a good copy", func(t *testing.T) {
		t.Parallel()
		w := unreadableIPWorld(t)
		writeDownloadedDrop(t, w.h, downloadedAt, []spamhaus.NetworkEntry{dropNet("8.8.4.0/24", "SBL20", "arin")}, nil)
		writeDownloadedAbusive(t, w.h, downloadedDay, downloadedDay, []abusive.NetworkEntry{abNet(1, "8.8.4.0", "8.8.4.255", "High", 80, "New Org", "isp")}, nil)
		rec := w.record("8.8.4.4", "--fields", "drop_networks,abusive_networks")
		wantUnreadable(t, w.h, w.h.ipEnvelope().Meta.Warnings)
		if len(rec.list("drop_networks")) != 1 || len(rec.list("abusive_networks")) != 1 {
			t.Errorf("drop_networks %v, abusive_networks %v, want the downloaded copies' matches", rec.m["drop_networks"], rec.m["abusive_networks"])
		}
	})
}
