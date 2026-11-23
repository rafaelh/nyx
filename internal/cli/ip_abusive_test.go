package cli_test

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/abusive"
)

// nyx ip's abusive_networks and abusive_asn keys: the entries of ipapi.is's two lists that hold the
// address or its origin AS, from the copy built into nyx (the test's own here, the harness's abusive,
// which Deps.ThreatBuiltIn carries, since the addresses of the tests are not on the real lists).
// Nothing is requested for the lists.

const ipAbusiveAddr = "93.184.216.34"

// ipAbusiveSnapshot lists the address in a /24 and a /28 inside it, and AS 64050.
func ipAbusiveSnapshot() *abusive.Snapshot {
	return abSnapshot([]abusive.NetworkEntry{
		abNet(4001, "93.184.216.0", "93.184.216.255", "High", 80.5, "Outer Org", "isp"),
		abNet(4002, "93.184.216.32", "93.184.216.47", "Very High", 100, "Inner, Org & Co", "hosting"),
	}, []abusive.ASNEntry{abASN(4003, 64050, "Very High", 99.25, "Bad AS Pty Ltd", "Spamhaus ASN-DROP")})
}

var ipDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// The record carries every network entry that holds the address, the most specific first, and the
// entry of its origin AS; numbers are numbers and the rest strings.
func TestIPAbusive_TheRecordCarriesTheMatches(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.abusive = ipAbusiveSnapshot()
	w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
	w.sealProbes([]string{ipAbusiveAddr})
	rec := w.record(ipAbusiveAddr)
	if !slices.Equal(rec.keys, ipDefaultKeys) {
		t.Errorf("keys %v, want %v", rec.keys, ipDefaultKeys)
	}
	nets := rec.list("abusive_networks")
	if len(nets) != 2 {
		t.Fatalf("abusive_networks = %v", rec.m["abusive_networks"])
	}
	first, second := nets[0].(map[string]any), nets[1].(map[string]any)
	if first["network"] != "93.184.216.32/28" || second["network"] != "93.184.216.0/24" {
		t.Errorf("networks %v then %v, want the /28 then the /24", first["network"], second["network"])
	}
	wantFirst := map[string]any{"network": "93.184.216.32/28", "rank": 4002.0, "score_tag": "Very High", "abuse_score": 100.0,
		"org": "Inner, Org & Co", "org_type": "hosting", "updated": "2026-11-21"}
	if fmt.Sprint(first) != fmt.Sprint(wantFirst) {
		t.Errorf("first match = %v\nwant         %v", first, wantFirst)
	}
	asn := rec.list("abusive_asn")
	if len(asn) != 1 {
		t.Fatalf("abusive_asn = %v", rec.m["abusive_asn"])
	}
	m := asn[0].(map[string]any)
	wantASN := map[string]any{"asn": 64050.0, "rank": 4003.0, "score_tag": "Very High", "abuse_score": 99.25, "org": "Bad AS Pty Ltd",
		"org_type": "Spamhaus ASN-DROP", "updated": "2026-11-20"}
	if fmt.Sprint(m) != fmt.Sprint(wantASN) {
		t.Errorf("asn match = %v\nwant       %v", m, wantASN)
	}
	// In the JSON, rank, asn and abuse_score are numbers and every other value is a string; the entry is first.
	raw := string(rec.raw)
	for _, want := range []string{`"abusive_networks":[{"network":"93.184.216.32/28","rank":4002,"score_tag":"Very High","abuse_score":100,`,
		`"abusive_asn":[{"asn":64050,"rank":4003,"score_tag":"Very High","abuse_score":99.25,`} {
		if !strings.Contains(raw, want) {
			t.Errorf("the record lacks %s:\n%s", want, raw)
		}
	}
	for _, mm := range []map[string]any{first, second, m} {
		if !ipDate.MatchString(mm["updated"].(string)) {
			t.Errorf("updated = %v", mm["updated"])
		}
	}
	if len(rec.failures()) != 0 {
		t.Errorf("failures %+v", rec.failures())
	}
}

// Addresses and ASes the lists do not hold give empty lists; so does an address Team Cymru knows no
// owner of, and its ASN key is null.
func TestIPAbusive_NothingListedGivesEmptyLists(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.abusive = ipAbusiveSnapshot()
	w.seed("8.8.4.4")                                     // an unlisted address of an unlisted AS
	w.seed("8.8.4.5", func(f *ipFacts) { f.ASN = 0 })     // no origin: Team Cymru answers NXDOMAIN
	w.seed(ipAbusiveAddr, func(f *ipFacts) { f.ASN = 0 }) // listed networks, no owner
	env := w.lookup("8.8.4.4", "8.8.4.5", ipAbusiveAddr)
	for _, r := range env.Records {
		switch r.address() {
		case "8.8.4.4", "8.8.4.5":
			if !r.emptyValue("abusive_networks") || r.isNull("abusive_networks") || !r.emptyValue("abusive_asn") || r.isNull("abusive_asn") {
				t.Errorf("%s: %v %v, want [] and []", r.address(), r.m["abusive_networks"], r.m["abusive_asn"])
			}
		default:
			if len(r.list("abusive_networks")) != 2 || r.isNull("abusive_asn") || len(r.list("abusive_asn")) != 0 {
				t.Errorf("%s: %v %v, want two networks and []", r.address(), r.m["abusive_networks"], r.m["abusive_asn"])
			}
		}
	}
}

// Only the first origin AS of a multi-origin answer is checked.
func TestIPAbusive_OnlyTheFirstOriginASIsChecked(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.abusive = abSnapshot(nil, []abusive.ASNEntry{abASN(1, 64050, "High", 90, "First", "isp"), abASN(2, 64051, "High", 91, "Second", "isp")})
	w.dns.TXT(cymruOriginName("8.8.4.4"), "64050 64051 | 8.8.4.0/24 | US | arin | 2000-01-01")
	w.dns.TXT("as64050.asn.cymru.com", "64050 | US | arin | 2000-01-01 | FIRST, US")
	rec := w.record("8.8.4.4", "--fields", "asn,abusive_asn")
	asn := rec.list("abusive_asn")
	if len(asn) != 1 || asn[0].(map[string]any)["asn"] != 64050.0 || rec.m["asn"] != 64050.0 {
		t.Errorf("asn %v, abusive_asn %v: want AS64050 alone", rec.m["asn"], rec.m["abusive_asn"])
	}
}

// When Team Cymru fails, the network matches still come out, the ASN match is null, the failure is
// listed and the call ends partial (exit 7). The snapshot is a source that always answers, so the
// record is kept even when Team Cymru is the only source asked.
func TestIPAbusive_TeamCymruFailing(t *testing.T) { // mutation target
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"every source", nil},
		{"only the keys", []string{"--fields", "abusive_networks,abusive_asn"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newIPWorld(t)
			w.h.abusive = ipAbusiveSnapshot()
			w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
			w.dns.Rcode(cymruOriginName(ipAbusiveAddr), 2) // SERVFAIL
			env, _ := w.partial(append([]string{ipAbusiveAddr}, tc.args...)...)
			if len(env.Records) != 1 {
				t.Fatalf("%d records, want the address's record to be kept", len(env.Records))
			}
			rec := env.Records[0]
			if !rec.isNull("abusive_asn") {
				t.Errorf("abusive_asn = %v, want null", rec.m["abusive_asn"])
			}
			if len(rec.list("abusive_networks")) != 2 {
				t.Errorf("abusive_networks = %v, want the two network matches", rec.m["abusive_networks"])
			}
			if f := rec.failureOf("cymru"); !f.Transient {
				t.Errorf("failure %+v", f)
			}
		})
	}
}

// When the origin is known and only the name of the AS fails, the ASN match is set.
func TestIPAbusive_ASNameFailureKeepsTheASNMatch(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.abusive = ipAbusiveSnapshot()
	w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
	w.dns.Rcode("as64050.asn.cymru.com", 2)
	env, _ := w.partial(ipAbusiveAddr)
	rec := env.Records[0]
	if len(rec.list("abusive_asn")) != 1 || rec.isNull("abusive_asn") {
		t.Errorf("abusive_asn = %v, want the AS64050 match", rec.m["abusive_asn"])
	}
	if rec.failureOf("cymru").Code == "" || !rec.isNull("as_name") {
		t.Errorf("record %s", rec.raw)
	}
}

// A non-public address has both keys null, and is sent nowhere.
func TestIPAbusive_NonPublicAddressHasNullKeys(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.abusive = abSnapshot([]abusive.NetworkEntry{abNet(1, "10.0.0.0", "10.255.255.255", "High", 80, "Private Org", "isp")}, nil)
	rec := w.record("10.0.0.1")
	if !rec.isNull("abusive_networks") || !rec.isNull("abusive_asn") {
		t.Errorf("abusive_networks = %v, abusive_asn = %v, want both null", rec.m["abusive_networks"], rec.m["abusive_asn"])
	}
	w.untouched()
}

// Each key can be picked alone. The network matches need nothing beyond resolving a hostname; the ASN
// match asks Team Cymru; failures stays last.
func TestIPAbusive_FieldsPickTheKeysAlone(t *testing.T) {
	t.Parallel()
	t.Run("networks for an address", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.h.abusive = ipAbusiveSnapshot()
		rec := w.record(ipAbusiveAddr, "--fields", "abusive_networks")
		if want := ipExpectKeys("abusive_networks"); !slices.Equal(rec.keys, want) {
			t.Errorf("keys %v, want %v", rec.keys, want)
		}
		if len(rec.list("abusive_networks")) != 2 {
			t.Errorf("abusive_networks = %v", rec.m["abusive_networks"])
		}
		w.untouched() // no request of any kind
	})
	t.Run("networks for a hostname", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.h.abusive = ipAbusiveSnapshot()
		w.dns.A("host.example.org", ipAbusiveAddr)
		rec := w.record("host.example.org", "--fields", "abusive_networks")
		if len(rec.list("abusive_networks")) != 2 || rec.strs("hostnames")[0] != "host.example.org" {
			t.Errorf("record %s", rec.raw)
		}
		if got := w.dns.Queried("TXT"); len(got) != 0 {
			t.Errorf("Team Cymru was asked: %v", got)
		}
		if w.httpRequests() != 0 || len(dnsNames(w.dns)) == 0 {
			t.Errorf("HTTP requests %d, queries %v: want only the resolution", w.httpRequests(), dnsNames(w.dns))
		}
		for _, n := range dnsNames(w.dns) {
			if n != "host.example.org" {
				t.Errorf("a query for %s: only the hostname is resolved", n)
			}
		}
	})
	t.Run("asn", func(t *testing.T) {
		t.Parallel()
		w := newIPWorld(t)
		w.h.abusive = ipAbusiveSnapshot()
		w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
		rec := w.record(ipAbusiveAddr, "--fields", "abusive_asn")
		if want := ipExpectKeys("abusive_asn"); !slices.Equal(rec.keys, want) {
			t.Errorf("keys %v, want %v", rec.keys, want)
		}
		if len(rec.list("abusive_asn")) != 1 {
			t.Errorf("abusive_asn = %v", rec.m["abusive_asn"])
		}
		if w.dns.Count(cymruOriginName(ipAbusiveAddr), "TXT") == 0 {
			t.Error("Team Cymru was not asked")
		}
		if w.httpRequests() != 0 {
			t.Errorf("HTTP requests %d", w.httpRequests())
		}
	})
}

// In a batch, one address's Team Cymru failure leaves the others whole, and the call is partial.
func TestIPAbusive_OneFailureLeavesTheOtherAddressesWhole(t *testing.T) {
	t.Parallel()
	w := newIPWorld(t)
	w.h.abusive = abSnapshot([]abusive.NetworkEntry{abNet(1, "8.8.4.0", "8.8.4.255", "High", 80, "Block Org", "isp")},
		[]abusive.ASNEntry{abASN(2, 64500, "High", 70, "Example AS", "isp")})
	for _, a := range []string{"8.8.4.4", "8.8.4.5", "8.8.4.6"} {
		w.seed(a)
	}
	w.dns.Rcode(cymruOriginName("8.8.4.5"), 2)
	env, f := w.partial("8.8.4.4", "8.8.4.5", "8.8.4.6", "--fields", "abusive_networks,abusive_asn")
	if len(env.Records) != 3 || !slices.Equal(env.addresses(), []string{"8.8.4.4", "8.8.4.5", "8.8.4.6"}) {
		t.Fatalf("records %v", env.addresses())
	}
	for _, r := range env.Records {
		if len(r.list("abusive_networks")) != 1 {
			t.Errorf("%s: abusive_networks = %v", r.address(), r.m["abusive_networks"])
		}
		if r.address() == "8.8.4.5" {
			if !r.isNull("abusive_asn") || len(r.failures()) != 1 {
				t.Errorf("8.8.4.5: %s", r.raw)
			}
			continue
		}
		if len(r.list("abusive_asn")) != 1 || len(r.failures()) != 0 {
			t.Errorf("%s: %s", r.address(), r.raw)
		}
	}
	if !strings.Contains(f.msg, "3 of 3 inputs returned, 1 failed") {
		t.Errorf("error %+v", f)
	}
}

// Text from the snapshot is sanitised in the JSON and the human layout.
func TestIPAbusive_SnapshotTextIsSanitised(t *testing.T) {
	t.Parallel()
	for _, jsonMode := range modes {
		w := newIPWorld(t)
		w.h.abusive = abSnapshot([]abusive.NetworkEntry{abNet(1, "93.184.216.0", "93.184.216.255", "Hi\x1b[31mgh", 80, "Evil\x1b]0;x\x07 Org\u202e", "is\np")},
			[]abusive.ASNEntry{abASN(2, 64050, "High", 70, "A\x1b[2Jb", "t\x00")})
		w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
		args := []string{ipAbusiveAddr, "--fields", "abusive_networks,abusive_asn"}
		var code int
		if jsonMode {
			code = w.runJSON(args...)
		} else {
			code = w.run(args...)
		}
		if code != 0 {
			t.Fatalf("exit %d: %s", code, w.h.stderr.String())
		}
		out := w.h.stdout.String()
		if strings.ContainsAny(out, "\x1b\x07\u202e\x00") || strings.Contains(out, `\u001b`) || strings.Contains(out, `\u202e`) || strings.Contains(out, `\u0007`) {
			t.Errorf("json=%v: unsanitised output %q", jsonMode, out)
		}
		if !strings.Contains(out, "Evil") || !strings.Contains(out, "Org") {
			t.Errorf("json=%v: the text itself was lost: %q", jsonMode, out)
		}
	}
}

// The human layout: a line for each match, none, unknown when Team Cymru failed, and none for a
// non-public address.
func TestIPAbusive_HumanLayout(t *testing.T) {
	t.Parallel()
	args := []string{"--fields", "abusive_networks,abusive_asn"}
	w := newIPWorld(t)
	w.h.abusive = ipAbusiveSnapshot()
	w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
	w.seed("8.8.4.4")
	if code := w.run(append([]string{ipAbusiveAddr, "8.8.4.4", "10.0.0.1"}, args...)...); code != 0 {
		t.Fatalf("exit %d: %s", code, w.h.stderr.String())
	}
	out := w.h.stdout.String()
	for _, want := range []string{
		"Abusive networks\n- 93.184.216.32/28: Very High, 100%, Inner, Org & Co (hosting), updated 2026-11-21\n- 93.184.216.0/24: High, 80.5%, Outer Org (isp), updated 2026-11-21\n",
		"Abusive ASN\n- AS64050: Very High, 99.25%, Bad AS Pty Ltd (Spamhaus ASN-DROP), updated 2026-11-20\n",
		"8.8.4.4 [public]\n\nAbusive networks\nnone\n\nAbusive ASN\nnone\n",
		"10.0.0.1 [private]\n\nAbusive networks\nnone\n\nAbusive ASN\nnone\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks\n%s\nin\n%s", want, out)
		}
	}
	// Team Cymru failing reads unknown.
	w2 := newIPWorld(t)
	w2.h.abusive = ipAbusiveSnapshot()
	w2.seed(ipAbusiveAddr)
	w2.dns.Rcode(cymruOriginName(ipAbusiveAddr), 2)
	if code := w2.run(append([]string{ipAbusiveAddr}, args...)...); code != 7 {
		t.Fatalf("exit %d, want 7", code)
	}
	if !strings.Contains(w2.h.stdout.String(), "Abusive ASN\nunknown\n") || !strings.Contains(w2.h.stdout.String(), "Abusive networks\n- 93.184.216.32/28") {
		t.Errorf("output %q", w2.h.stdout.String())
	}
}

// A match is information only: --active contacts exactly the addresses and ports it would without the
// lists, and says the same of why it did not contact one.
func TestIPAbusive_ActiveIsNotChangedByAMatch(t *testing.T) { // mutation target
	t.Parallel()
	type result struct {
		contacted    []string
		notContacted map[string]any
		ports        map[string]any
	}
	probe := func(snap *abusive.Snapshot) result {
		w := activeWorld(t)
		w.h.abusive = snap
		w.seed("93.184.216.34", ipOwnedBy(64050, "BAD-AS"))
		w.seed("104.16.0.1", ipCloudflare...) // shared provider infrastructure: not contacted
		w.sealProbes([]string{"93.184.216.34", "104.16.0.1"})
		env := w.lookup("93.184.216.34", "104.16.0.1", "--active", "--fields", "not_contacted,ports,abusive_networks,abusive_asn")
		r := result{contacted: w.contacted(), notContacted: map[string]any{}, ports: map[string]any{}}
		for _, rec := range env.Records {
			r.notContacted[rec.address()] = rec.m["not_contacted"]
			r.ports[rec.address()] = len(rec.list("ports"))
		}
		return r
	}
	listed := probe(abSnapshot([]abusive.NetworkEntry{
		abNet(1, "93.184.216.0", "93.184.216.255", "High", 80, "Block Org", "isp"),
		abNet(2, "104.16.0.0", "104.16.255.255", "High", 80, "Shared Org", "isp"),
	}, []abusive.ASNEntry{abASN(3, 64050, "High", 70, "Bad AS", "isp"), abASN(4, 13335, "High", 70, "Cloudflare", "hosting")}))
	empty := probe(abSnapshot(nil, nil))
	if !slices.Equal(listed.contacted, empty.contacted) || fmt.Sprint(listed.notContacted) != fmt.Sprint(empty.notContacted) || fmt.Sprint(listed.ports) != fmt.Sprint(empty.ports) {
		t.Errorf("with the lists %+v\nwithout   %+v", listed, empty)
	}
	if empty.notContacted["104.16.0.1"] == nil || len(empty.contacted) == 0 {
		t.Errorf("the fixture is not testing anything: %+v", empty)
	}
}

// ---- recon and nyx ip agree ----

// For the same address, origin AS and snapshot, recon's finding names exactly the entries nyx ip reports.
func TestAbusive_ReconAndIPAgree(t *testing.T) {
	t.Parallel()
	snap := ipAbusiveSnapshot()
	w := newIPWorld(t)
	w.h.abusive = snap
	w.seed(ipAbusiveAddr, ipOwnedBy(64050, "BAD-AS"))
	rec := w.record(ipAbusiveAddr)
	var fromIP []string
	for _, v := range rec.list("abusive_networks") {
		m := v.(map[string]any)
		fromIP = append(fromIP, fmt.Sprintf("%v %v %v%% %v (%v)", m["network"], m["score_tag"], m["abuse_score"], m["org"], m["org_type"]))
	}
	var asnIP []string
	for _, v := range rec.list("abusive_asn") {
		m := v.(map[string]any)
		asnIP = append(asnIP, fmt.Sprintf("AS%v %v %v%% %v (%v)", m["asn"], m["score_tag"], m["abuse_score"], m["org"], m["org_type"]))
	}

	x := newAbWorld(t)
	x.h.abusive = snap
	x.names("app.example.com")
	x.host("app.example.com", ipAbusiveAddr) // outside the netblocks: the AS is its ip_owner
	x.owner(ipAbusiveAddr, 64050, "BAD-AS")
	x.mustPassive()
	r := x.row(ipAbusiveAddr)
	if r == nil {
		t.Fatal("recon did not flag the address")
	}
	if got := strings.Join(fromIP, ";"); r["networks"] != got {
		t.Errorf("recon networks %q, nyx ip %q", r["networks"], got)
	}
	if got := strings.Join(asnIP, ";"); r["asn"] != got {
		t.Errorf("recon asn %q, nyx ip %q", r["asn"], got)
	}
}

// While abusive_networks is selected, as it is by default, the snapshot is a source that always
// answers: an address whose every other source failed still has its record, with the network
// matches and nulls, and the call is partial (exit 7) and not a failed input.
func TestIPAbusive_EverySourceFailingStillHasARecord(t *testing.T) {
	t.Parallel()
	const addr = "93.184.216.34"
	servfail := 2
	w := newIPWorld(t)
	w.h.abusive = ipAbusiveSnapshot()
	w.seed(addr)
	w.dns.Rcode(cymruOriginName(addr), servfail)
	w.rdap[hostARIN].setAll(ipStatus(500))
	w.dns.Rcode(reverseName(addr), servfail)
	w.geo.setAll(ipStatus(500))
	w.idb.setAll(ipStatus(500))
	w.ht.setAll(ipStatus(500))
	env, f := w.partial(addr)
	if len(env.Records) != 1 {
		t.Fatalf("%d records, want 1", len(env.Records))
	}
	rec := env.Records[0]
	if len(rec.list("abusive_networks")) != 2 || !rec.isNull("abusive_asn") || !rec.isNull("asn") || len(rec.failures()) != 5 { // HackerTarget waits on Team Cymru and is not asked
		t.Errorf("record %s", rec.raw)
	}
	if !f.transient {
		t.Errorf("error %+v", f)
	}
}
