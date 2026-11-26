package dns

import (
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/addrkind"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/scope"
)

var (
	testNSType  = rootType{"NS", egress.TypeNS}
	testTXTType = rootType{"TXT", egress.TypeTXT}
)

// recordScope is a scope of the roots, with the names given excluded.
func recordScope(t *testing.T, roots []string, excluded ...string) *scope.Scope {
	t.Helper()
	var excl []input.Exclusion
	for _, e := range excluded {
		x, err := input.ParseExclusion(e)
		if err != nil {
			t.Fatal(err)
		}
		excl = append(excl, x)
	}
	return scope.New(scope.Config{Roots: roots, Exclusions: excl})
}

func noAddrShared(netip.Addr) bool { return false }

// answers are records of one type owned by name.
func ownedAnswers(name, typ string, values ...string) []egress.Answer {
	out := make([]egress.Answer, len(values))
	for i, v := range values {
		out[i] = egress.Answer{Name: name, Type: typ, Value: v, TTL: 300}
	}
	return out
}

// decodedObs is a handler's observations, read back through the kind handles.
type decodedObs struct {
	rows      []kinds.ResolutionAttrs
	hostnames []string
	third     []kinds.ThirdPartyAttrs
	netblocks []string
	other     []string
}

func decodeObs(obs []run.Observation) decodedObs {
	var d decodedObs
	for _, o := range obs {
		r := store.Record{Kind: o.Kind, Key: o.Key, Attrs: o.Attrs, Current: true}
		switch o.Kind {
		case kinds.Resolution.Name():
			d.rows = append(d.rows, kinds.Resolution.Attrs(r))
		case kinds.Hostname.Name():
			d.hostnames = append(d.hostnames, o.Key)
		case kinds.ThirdParty.Name():
			d.third = append(d.third, kinds.ThirdParty.Attrs(r))
		case kinds.Netblock.Name():
			d.netblocks = append(d.netblocks, o.Key)
		default:
			d.other = append(d.other, o.Kind+" "+o.Key)
		}
	}
	return d
}

// rowValues are the values of the rows, each checked to be of name and typ.
func (d decodedObs) rowValues(t *testing.T, name, typ string) []string {
	t.Helper()
	var out []string
	for _, r := range d.rows {
		if r.Name != name || r.Type != typ {
			t.Errorf("row %s %s %q, want name %s and type %s", r.Name, r.Type, r.Value, name, typ)
		}
		out = append(out, r.Value)
	}
	return out
}

// thirdParties are the third parties of the mechanism, as "root|domain|depth".
func (d decodedObs) thirdParties(mechanism string) []string {
	var out []string
	for _, a := range d.third {
		if a.Mechanism == mechanism {
			out = append(out, a.Root+"|"+a.Domain+"|"+strconv.Itoa(a.Depth))
		}
	}
	return out
}

func sameStrings(got, want []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want)))
}

// Only records owned by the asked name are kept: an alias's answer names its target as the owner
// of the target's records, and none of them is a row, a hostname, a third party or a candidate.
func TestRecordObservations_OwnRecordsOnly(t *testing.T) {
	t.Parallel()
	const name, target = "dev.example.com", "target.example.net"
	sc := recordScope(t, []string{"example.com"})
	cases := []struct {
		t           rootType
		own, others []string
	}{
		{testNSType, []string{"ns1.dev.example.com"}, []string{"ns9.example.com", "ns.foreign.net"}},
		{mxType, []string{"10 mail.example.com"}, []string{"10 mx9.example.com", "20 mx.foreign.net"}},
		{testTXTType, []string{"v=spf1 ip4:192.0.3.0/24 -all"},
			[]string{"v=spf1 ip4:198.51.101.0/24 include:_spf.foreign.net -all", "MS=ms9", "see api9.example.com"}},
	}
	for _, c := range cases {
		t.Run(c.t.name, func(t *testing.T) {
			t.Parallel()
			in := recordInput{name: name, root: "example.com", t: c.t, sc: sc, shared: noAddrShared, spfThirdParties: true}
			d := decodeObs(recordObservations(in, append(ownedAnswers(name, c.t.name, c.own...), ownedAnswers(target, c.t.name, c.others...)...)))
			if got := d.rowValues(t, name, c.t.name); !slices.Equal(got, c.own) {
				t.Errorf("rows = %q, want only the name's own %q", got, c.own)
			}
			for _, h := range d.hostnames {
				if h == "ns9.example.com" || h == "mx9.example.com" || h == "api9.example.com" {
					t.Errorf("hostname %s comes from another owner's record", h)
				}
			}
			if len(d.third) != 0 {
				t.Errorf("third parties from another owner's records: %+v", d.third)
			}
			if c.t == testTXTType && !slices.Equal(d.netblocks, []string{"192.0.3.0/24"}) {
				t.Errorf("netblocks = %q, want only the name's own 192.0.3.0/24", d.netblocks)
			}
		})
	}
}

// A row per NS record. An in-scope target under a root is a hostname; a target with a _ label or
// an excluded target is not; a target outside scope is an ns third party of the name's input
// root with its registrable domain, at depth 0.
func TestRecordObservations_NSTargets(t *testing.T) {
	t.Parallel()
	const name, root = "a.corp.example.com", "corp.example.com"
	sc := recordScope(t, []string{"example.com", "corp.example.com"}, "ns2.example.com")
	values := []string{"ns1.corp.example.com", "ns2.example.com", "_ns.example.com", "ns-1.awsdns-01.org", "dns1.other.co.uk"}
	in := recordInput{name: name, root: root, t: testNSType, sc: sc, shared: noAddrShared}
	d := decodeObs(recordObservations(in, ownedAnswers(name, "NS", values...)))
	if got := d.rowValues(t, name, "NS"); !sameStrings(got, values) {
		t.Errorf("NS rows = %q, want %q", got, values)
	}
	if want := []string{"ns1.corp.example.com"}; !slices.Equal(d.hostnames, want) {
		t.Errorf("hostnames = %q, want %q (not the excluded, _-labelled or outside targets)", d.hostnames, want)
	}
	ns := d.thirdParties(kinds.MechanismNS)
	for _, want := range []string{root + "|awsdns-01.org|0", root + "|other.co.uk|0"} {
		if !slices.Contains(ns, want) {
			t.Errorf("ns third parties = %q, want %s", ns, want)
		}
	}
	if len(d.netblocks)+len(d.other) != 0 {
		t.Errorf("unexpected observations: netblocks %q, others %q", d.netblocks, d.other)
	}
}

// A row per MX record, with the value as egress gives it. An in-scope target is a hostname; a
// target with a _ label or an excluded one is not; one outside scope is an mx third party.
func TestRecordObservations_MXTargets(t *testing.T) {
	t.Parallel()
	const name, root = "shop.example.com", "example.com"
	sc := recordScope(t, []string{"example.com"}, "mx2.example.com")
	values := []string{"10 mail.example.com", "20 aspmx.l.google.com", "30 _mx.example.com", "40 mx2.example.com"}
	in := recordInput{name: name, root: root, t: mxType, sc: sc, shared: noAddrShared}
	d := decodeObs(recordObservations(in, ownedAnswers(name, "MX", values...)))
	if got := d.rowValues(t, name, "MX"); !sameStrings(got, values) {
		t.Errorf("MX rows = %q, want %q", got, values)
	}
	if want := []string{"mail.example.com"}; !slices.Equal(d.hostnames, want) {
		t.Errorf("hostnames = %q, want %q", d.hostnames, want)
	}
	if mx := d.thirdParties(kinds.MechanismMX); !slices.Contains(mx, root+"|google.com|0") {
		t.Errorf("mx third parties = %q, want %s|google.com|0", mx, root)
	}
	if len(d.netblocks)+len(d.other) != 0 {
		t.Errorf("unexpected observations: netblocks %q, others %q", d.netblocks, d.other)
	}
}

// The null MX is a row and names no host.
func TestRecordObservations_NullMX(t *testing.T) {
	t.Parallel()
	const name = "shop.example.com"
	in := recordInput{name: name, root: "example.com", t: mxType, sc: recordScope(t, []string{"example.com"}), shared: noAddrShared}
	obs := recordObservations(in, ownedAnswers(name, "MX", "0 ."))
	d := decodeObs(obs)
	if got := d.rowValues(t, name, "MX"); !slices.Equal(got, []string{"0 ."}) {
		t.Errorf("MX rows = %q, want the null MX", got)
	}
	if len(obs) != 1 {
		t.Errorf("observations = %+v, want only the row", obs)
	}
}

// A row per TXT record. A hostname written in a value is read in lower case and is a hostname when
// it is in scope, under a root, not the asked name and not an input root. A name followed by
// labels outside scope, a name with a _ label, an excluded name and one outside scope give none.
func TestRecordObservations_TXTHostnames(t *testing.T) {
	t.Parallel()
	const name = "www.example.com"
	sc := recordScope(t, []string{"example.com", "example.org"}, "secret.example.com")
	values := []string{
		"site api.example.com; also www.example.com and example.org",
		"contact https://Portal.Example.COM/login",
		"redirect www.example.com.evil.net",
		"policy _dmarc.example.com",
		"excluded secret.example.com and partner.net",
	}
	in := recordInput{name: name, root: "example.com", t: testTXTType, sc: sc, shared: noAddrShared, spfThirdParties: true}
	d := decodeObs(recordObservations(in, ownedAnswers(name, "TXT", values...)))
	if got := d.rowValues(t, name, "TXT"); !sameStrings(got, values) {
		t.Errorf("TXT rows = %q, want %q", got, values)
	}
	if want := []string{"api.example.com", "portal.example.com"}; !sameStrings(d.hostnames, want) {
		t.Errorf("hostnames = %q, want %q", d.hostnames, want)
	}
}

// A TXT value that verifies a known platform is a txt-verification third party of the root,
// whether or not spf third parties are written.
func TestRecordObservations_TXTVerification(t *testing.T) {
	t.Parallel()
	const name = "www.example.com"
	sc := recordScope(t, []string{"example.com"})
	for _, spf := range []bool{true, false} {
		in := recordInput{name: name, root: "example.com", t: testTXTType, sc: sc, shared: noAddrShared, spfThirdParties: spf}
		d := decodeObs(recordObservations(in, ownedAnswers(name, "TXT", "MS=ms1")))
		var got []string
		for _, a := range d.third {
			got = append(got, a.Root+"|"+a.Mechanism+"|"+a.Provider)
		}
		if want := []string{"example.com|txt-verification|Microsoft 365"}; !slices.Equal(got, want) {
			t.Errorf("spf third parties %v: third parties = %q, want %q", spf, got, want)
		}
		if rows := d.rowValues(t, name, "TXT"); !slices.Equal(rows, []string{"MS=ms1"}) {
			t.Errorf("spf third parties %v: TXT rows = %q", spf, rows)
		}
	}
}

// Each ip4 and ip6 term with no qualifier or +, whose range is at most a /16 or /32 and public,
// gives a netblock keyed by its masked prefix, a single address as a /32 or /128. A -, ~ or ?
// term, a wider range, a non-public range and a malformed term give none.
func TestRecordObservations_SPFNetblocks(t *testing.T) {
	t.Parallel()
	const name = "mail.example.com"
	record := "v=spf1 ip4:192.0.3.0/24 +ip4:198.51.101.7 IP4:203.0.114.9/25 ip4:52.4.0.0/16" +
		" ip6:2a00:1450:4000::/48 ip6:2a00:1450:4001::5 ip6:2a00:1450::/32" +
		" -ip4:52.5.0.0/16 ~ip4:52.6.0.0/16 ?ip4:52.7.0.0/16" +
		" ip4:52.0.0.0/15 ip6:2a02::/31" +
		" ip4:10.1.0.0/16 ip4:192.0.2.0/24 ip4:192.168.1.1 ip4:127.0.0.1 ip4:224.0.0.0/24 ip6:2001:db8::/48 ip6:fc00::/48" +
		" ip4:300.1.1.1 ip4:192.0.3.0/33 -all"
	want := []string{
		"192.0.3.0/24", "198.51.101.7/32", "203.0.114.0/25", "52.4.0.0/16",
		"2a00:1450:4000::/48", "2a00:1450:4001::5/128", "2a00:1450::/32",
	}
	for _, p := range want {
		if a := netip.MustParsePrefix(p).Addr(); addrkind.Of(a) != addrkind.Public {
			t.Fatalf("fixture %s is %s, not public", p, addrkind.Of(a))
		}
	}
	in := recordInput{name: name, root: "example.com", t: testTXTType, sc: recordScope(t, []string{"example.com"}), shared: noAddrShared, spfThirdParties: true}
	d := decodeObs(recordObservations(in, ownedAnswers(name, "TXT", record)))
	if !sameStrings(d.netblocks, want) {
		t.Errorf("netblocks = %q,\nwant %q", d.netblocks, want)
	}
	if rows := d.rowValues(t, name, "TXT"); !slices.Equal(rows, []string{record}) {
		t.Errorf("TXT rows = %q", rows)
	}
}

// A range whose first and last addresses are both known shared provider addresses gives no
// netblock; a single address there does, and so does a range with only its first address shared.
func TestRecordObservations_SPFSharedRanges(t *testing.T) {
	t.Parallel()
	const name = "mail.example.com"
	pool := netip.MustParsePrefix("192.0.3.0/24")
	firstOnly := netip.MustParseAddr("198.51.101.0")
	shared := func(a netip.Addr) bool { return pool.Contains(a) || a == firstOnly }
	in := recordInput{name: name, root: "example.com", t: testTXTType, sc: recordScope(t, []string{"example.com"}), shared: shared}
	d := decodeObs(recordObservations(in, ownedAnswers(name, "TXT", "v=spf1 ip4:192.0.3.0/24 ip4:192.0.3.10 ip4:198.51.101.0/24 -all")))
	if want := []string{"192.0.3.10/32", "198.51.101.0/24"}; !sameStrings(d.netblocks, want) {
		t.Errorf("netblocks = %q, want %q", d.netblocks, want)
	}
}

// The domains of include, redirect, a, mx and exists terms outside scope are spf third parties of
// the root at the name's depth, when asked for; when not, there are none, and the record's
// addresses are still netblocks.
func TestRecordObservations_SPFThirdParties(t *testing.T) {
	t.Parallel()
	const name, root = "mail.example.com", "example.com"
	sc := recordScope(t, []string{"example.com"})
	record := "v=spf1 ip4:192.0.3.0/24 include:_spf.google.com a:smtp.vendor.net mx:mx.vendor.org exists:check.vendor.io redirect=_spf.provider.net"
	domains := []string{"_spf.google.com", "smtp.vendor.net", "mx.vendor.org", "check.vendor.io", "_spf.provider.net"}
	for _, depth := range []int{0, 2} {
		in := recordInput{name: name, root: root, t: testTXTType, sc: sc, depth: depth, shared: noAddrShared, spfThirdParties: true}
		d := decodeObs(recordObservations(in, ownedAnswers(name, "TXT", record)))
		var want []string
		for _, dom := range domains {
			want = append(want, root+"|"+dom+"|"+strconv.Itoa(depth))
		}
		if got := d.thirdParties(kinds.MechanismSPF); !sameStrings(got, want) {
			t.Errorf("depth %d: spf third parties = %q,\nwant %q", depth, got, want)
		}
	}
	in := recordInput{name: name, root: root, t: testTXTType, sc: sc, depth: 1, shared: noAddrShared}
	d := decodeObs(recordObservations(in, ownedAnswers(name, "TXT", record)))
	if got := d.thirdParties(kinds.MechanismSPF); len(got) != 0 {
		t.Errorf("spf third parties written when not asked for: %q", got)
	}
	if !slices.Equal(d.netblocks, []string{"192.0.3.0/24"}) {
		t.Errorf("netblocks = %q, want 192.0.3.0/24 without spf third parties too", d.netblocks)
	}
}

// redirect= is ignored when the record has all.
func TestRecordObservations_SPFRedirectBesideAll(t *testing.T) {
	t.Parallel()
	const name, root = "mail.example.com", "example.com"
	in := recordInput{name: name, root: root, t: testTXTType, sc: recordScope(t, []string{"example.com"}), shared: noAddrShared, spfThirdParties: true}
	d := decodeObs(recordObservations(in, ownedAnswers(name, "TXT", "v=spf1 include:spf.protection.outlook.com redirect=_spf.ignored.net ~all")))
	if got, want := d.thirdParties(kinds.MechanismSPF), []string{root + "|spf.protection.outlook.com|0"}; !slices.Equal(got, want) {
		t.Errorf("spf third parties = %q, want %q", got, want)
	}
}

// A name with two v=spf1 records has no usable SPF record: both are rows, and neither gives a
// netblock or an spf third party. A verification beside them still counts.
func TestRecordObservations_TwoSPFRecords(t *testing.T) {
	t.Parallel()
	const name = "mail.example.com"
	values := []string{"v=spf1 ip4:192.0.3.0/24 include:_spf.google.com -all", "v=spf1 ip4:198.51.101.0/24 -all", "MS=ms1"}
	in := recordInput{name: name, root: "example.com", t: testTXTType, sc: recordScope(t, []string{"example.com"}), shared: noAddrShared, spfThirdParties: true}
	d := decodeObs(recordObservations(in, ownedAnswers(name, "TXT", values...)))
	if got := d.rowValues(t, name, "TXT"); !sameStrings(got, values) {
		t.Errorf("TXT rows = %q, want %q", got, values)
	}
	if len(d.netblocks) != 0 {
		t.Errorf("netblocks = %q, want none", d.netblocks)
	}
	if got := d.thirdParties(kinds.MechanismSPF); len(got) != 0 {
		t.Errorf("spf third parties = %q, want none", got)
	}
	if got := d.thirdParties(kinds.MechanismTXTVerification); len(got) != 1 {
		t.Errorf("txt-verification third parties = %q, want one", got)
	}
}

func depthsEqual(t *testing.T, got, want map[string]int) {
	t.Helper()
	if !maps.Equal(got, want) {
		t.Errorf("includedDepths =\n%v,\nwant\n%v", got, want)
	}
}

// The walk follows include and redirect domains in scope under a root, _ labels allowed, one
// level per hop. a, mx and exists domains, excluded and outside domains, and input roots are not
// included; a started name stays at depth 0.
func TestIncludedDepths_Walk(t *testing.T) {
	t.Parallel()
	sc := recordScope(t, []string{"example.com", "example.org"}, "blocked.example.com")
	txt := map[string][]string{
		"example.com": {"google-site-verification=abc",
			"v=spf1 include:_spf.example.com include:_spf.google.com a:mail.example.com mx:mx.example.com exists:x.example.com -all"},
		"_spf.example.com":  {"v=spf1 include:_spf2.example.com redirect=_r.example.com"},
		"_spf2.example.com": {"v=spf1 ip4:192.0.3.0/24 -all"},
		"_r.example.com":    {"v=spf1 include:www.example.com include:blocked.example.com include:example.org -all"},
		"www.example.com":   {"v=spf1 include:_spf.example.com -all"},
	}
	got := includedDepths([]string{"example.com", "example.org", "www.example.com"}, txt, sc)
	depthsEqual(t, got, map[string]int{
		"example.com": 0, "example.org": 0, "www.example.com": 0,
		"_spf.example.com": 1, "_spf2.example.com": 2, "_r.example.com": 2,
	})
}

// A name has its smallest depth: a long chain from one start and a short one from another meet
// at the short one's depth, a diamond counts once, and a started name included again stays at 0.
func TestIncludedDepths_SmallestDepth(t *testing.T) {
	t.Parallel()
	sc := recordScope(t, []string{"example.com"})
	txt := map[string][]string{
		"s.example.com": {"v=spf1 include:p.example.com include:a.example.com -all"},
		"p.example.com": {"v=spf1 include:q.example.com include:a.example.com -all"},
		"q.example.com": {"v=spf1 include:r.example.com -all"},
		"t.example.com": {"v=spf1 include:r.example.com include:s.example.com -all"},
	}
	got := includedDepths([]string{"s.example.com", "t.example.com"}, txt, sc)
	depthsEqual(t, got, map[string]int{
		"s.example.com": 0, "t.example.com": 0,
		"p.example.com": 1, "a.example.com": 1, "r.example.com": 1, "q.example.com": 2,
	})
}

// Includes that loop end.
func TestIncludedDepths_Loop(t *testing.T) {
	t.Parallel()
	sc := recordScope(t, []string{"example.com"})
	txt := map[string][]string{
		"example.com":   {"v=spf1 include:a.example.com -all"},
		"a.example.com": {"v=spf1 include:b.example.com -all"},
		"b.example.com": {"v=spf1 include:a.example.com include:b.example.com redirect=a.example.com"},
	}
	got := includedDepths([]string{"example.com"}, txt, sc)
	depthsEqual(t, got, map[string]int{"example.com": 0, "a.example.com": 1, "b.example.com": 2})
}

// A redirect is followed only when the record has no all.
func TestIncludedDepths_RedirectBesideAll(t *testing.T) {
	t.Parallel()
	sc := recordScope(t, []string{"example.com"})
	txt := map[string][]string{
		"example.com":   {"v=spf1 include:a.example.com redirect=b.example.com ~all"},
		"c.example.com": {"v=spf1 redirect=d.example.com"},
	}
	got := includedDepths([]string{"example.com", "c.example.com"}, txt, sc)
	depthsEqual(t, got, map[string]int{"example.com": 0, "c.example.com": 0, "a.example.com": 1, "d.example.com": 1})
}

// A name with two SPF records includes nothing.
func TestIncludedDepths_TwoSPFRecords(t *testing.T) {
	t.Parallel()
	sc := recordScope(t, []string{"example.com"})
	txt := map[string][]string{
		"example.com": {"v=spf1 include:a.example.com -all", "v=spf1 include:b.example.com -all"},
	}
	got := includedDepths([]string{"example.com"}, txt, sc)
	depthsEqual(t, got, map[string]int{"example.com": 0})
}

// An input root that a record includes is not an included domain.
func TestIncludedDepths_InputRootNotIncluded(t *testing.T) {
	t.Parallel()
	sc := recordScope(t, []string{"example.com", "example.org"})
	txt := map[string][]string{
		"www.example.com": {"v=spf1 include:example.org include:example.com include:_spf.example.com -all"},
	}
	got := includedDepths([]string{"www.example.com"}, txt, sc)
	depthsEqual(t, got, map[string]int{"www.example.com": 0, "_spf.example.com": 1})
}

// An address written where a target name belongs is neither a hostname nor a third party.
func TestRecordObservations_AddressTargets(t *testing.T) {
	t.Parallel()
	const name = "shop.example.com"
	sc := recordScope(t, []string{"example.com"})
	for _, c := range []struct {
		t     rootType
		value string
	}{{mxType, "5 192.0.3.25"}, {testNSType, "192.0.3.53"}} {
		in := recordInput{name: name, root: "example.com", t: c.t, sc: sc, shared: noAddrShared}
		d := decodeObs(recordObservations(in, ownedAnswers(name, c.t.name, c.value)))
		if got := d.rowValues(t, name, c.t.name); !slices.Equal(got, []string{c.value}) {
			t.Errorf("%s rows = %q, want the record", c.t.name, got)
		}
		if len(d.hostnames)+len(d.third) != 0 {
			t.Errorf("%s %q: hostnames %q, third parties %+v, want none", c.t.name, c.value, d.hostnames, d.third)
		}
	}
}
