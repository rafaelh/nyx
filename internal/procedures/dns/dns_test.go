package dns_test

import (
	"context"
	"net/netip"
	"regexp"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/egress/egresstest"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/procedures/dns"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
)

func clients(t *testing.T, d *egresstest.DNS) egress.Clients {
	t.Helper()
	eg := egress.New(egress.Options{ResolverAddrs: []string{d.Addr}, DNSTimeout: 300 * time.Millisecond, RateDNS: 100000})
	eg.SetPolicy(&egress.Policy{Scope: scope.New(scope.Config{})})
	return eg.Clients(false, nil)
}

// The probe labels come from an injectable source; there are always two, and they differ.
func TestWildcardProbeLabels(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	labels := []string{"aaaa", "aaaa", "bbbb"} // the second draw repeats the first
	i := 0
	st := dns.NewWildcard(func() string { l := labels[i]; i++; return l })
	obs, err := st.Run(context.Background(), run.Job{Key: "example.com"}, clients(t, d))
	if err != nil || len(obs) != 0 {
		t.Fatalf("no wildcard: %+v %v", obs, err)
	}
	if got := d.Queried("A"); len(got) != 2 || got[0] != "aaaa.example.com" || got[1] != "bbbb.example.com" {
		t.Errorf("probes = %v", got)
	}
}

func TestDefaultWildcardLabelsAreRandom16(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	d.Wildcard("example.com", "203.0.113.1")
	obs, err := dns.NewWildcard(nil).Run(context.Background(), run.Job{Key: "example.com"}, clients(t, d))
	if err != nil || len(obs) != 1 || obs[0].Kind != "wildcard" || obs[0].Key != "example.com" {
		t.Fatalf("%+v %v", obs, err)
	}
	re := regexp.MustCompile(`^[0-9a-f]{16}\.example\.com$`)
	for _, n := range d.Queried("A") {
		if !re.MatchString(n) {
			t.Errorf("probe name %q is not a random 16-char label", n)
		}
	}
	if addrs := kinds.Wildcard.Attrs(store.Record{Attrs: obs[0].Attrs}).Addrs; len(addrs) != 1 || addrs[0] != "203.0.113.1" {
		t.Errorf("attrs = %v", obs[0].Attrs)
	}
}

// A SERVFAIL on a probe is a transient failure, never "not a wildcard".
func TestWildcardServFailIsAnError(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	d.RcodeSuffix("example.com", 2) // SERVFAIL
	if obs, err := dns.NewWildcard(nil).Run(context.Background(), run.Job{Key: "example.com"}, clients(t, d)); err == nil {
		t.Errorf("a SERVFAIL probe must fail the check, got %+v", obs)
	}
}

// A probe that answered proves the wildcard even if another probe SERVFAILs.
func TestWildcardAnswerWinsOverServFail(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	d.Wildcard("example.com", "203.0.113.1")
	d.Rcode("bbbb.example.com", 2) // SERVFAIL
	labels := []string{"aaaa", "bbbb"}
	i := 0
	st := dns.NewWildcard(func() string { l := labels[i]; i++; return l })
	obs, err := st.Run(context.Background(), run.Job{Key: "example.com"}, clients(t, d))
	if err != nil || len(obs) != 1 || obs[0].Kind != "wildcard" {
		t.Errorf("want the wildcard recorded: %+v %v", obs, err)
	}
}

// A wildcard CNAME that dangles (NXDOMAIN) is still a wildcard, so the
// permutations it makes "exist" come out wildcard-only.
func TestWildcardDanglingCNAME(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	d.WildcardCNAME("example.com", "gone.herokuapp.com")
	obs, err := dns.NewWildcard(nil).Run(context.Background(), run.Job{Key: "example.com"}, clients(t, d))
	if err != nil || len(obs) != 1 || obs[0].Kind != "wildcard" || obs[0].Attrs["cname"] != "gone.herokuapp.com" {
		t.Fatalf("want the wildcard recorded with its cname: %+v %v", obs, err)
	}
}

// A resolver failure is transient; an address Cymru does not know is a result.
func TestIPOwnerFailureModes(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	st := dns.NewIPOwner()
	chk := run.Job{Key: "203.0.113.5", Input: mustAddr("203.0.113.5")}
	if obs, err := st.Run(context.Background(), chk, clients(t, d)); err != nil || len(obs) != 0 {
		t.Errorf("unknown address (NXDOMAIN): %+v %v", obs, err)
	}
	d.RcodeSuffix("asn.cymru.com", 2) // SERVFAIL
	if _, err := st.Run(context.Background(), chk, clients(t, d)); err == nil {
		t.Error("a SERVFAIL must be a transient failure")
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// Netblock ownership queries one first address per routing unit and keys the result by prefix.
func TestNetblockOwnerRun(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		unit, first string
		txt         string
		wantASN     int
		wantPrefix  string
	}{
		{"203.0.113.0/24", "203.0.113.0", "64500 | 203.0.113.0/24 | US | arin | 2000-01-01", 64500, "203.0.113.0/24"},
		{"198.51.100.16/28", "198.51.100.16", "64501 64502 | 198.51.100.0/22 | US | arin | 2000-01-01", 64501, "198.51.100.0/22"}, // the first of several origins
		{"2001:db8:1::/48", "2001:db8:1::", "64503 | 2001:db8::/32 | US | arin | 2000-01-01", 64503, "2001:db8::/32"},
	} {
		d := egresstest.NewDNS(t)
		d.TXT(dnsname.CymruOrigin(mustAddr(tc.first)), tc.txt)
		unit := netip.MustParsePrefix(tc.unit)
		obs, err := dns.NewNetblockOwner().Run(context.Background(), run.Job{Key: tc.unit, Input: unit}, clients(t, d))
		if err != nil || len(obs) != 1 {
			t.Fatalf("%s: %+v %v", tc.unit, obs, err)
		}
		if obs[0].Kind != "netblock_owner" || obs[0].Key != tc.unit {
			t.Errorf("%s: observation %s %q", tc.unit, obs[0].Kind, obs[0].Key)
		}
		a := kinds.NetblockOwner.Attrs(store.Record{Key: obs[0].Key, Attrs: obs[0].Attrs})
		if a.ASN != tc.wantASN || a.Prefix != tc.wantPrefix {
			t.Errorf("%s: attrs = %+v, want AS%d %s", tc.unit, a, tc.wantASN, tc.wantPrefix)
		}
		if got := d.Queried("TXT"); len(got) != 1 || got[0] != dnsname.CymruOrigin(mustAddr(tc.first)) {
			t.Errorf("%s: queried %v, want only the origin of %s", tc.unit, got, tc.first)
		}
	}
}

// A unit Team Cymru knows nothing of is a completed job with no record; a failure is transient.
func TestNetblockOwnerFailureModes(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	st := dns.NewNetblockOwner()
	chk := run.Job{Key: "203.0.113.0/24", Input: netip.MustParsePrefix("203.0.113.0/24")}
	if obs, err := st.Run(context.Background(), chk, clients(t, d)); err != nil || len(obs) != 0 {
		t.Errorf("unknown unit (NXDOMAIN): %+v %v", obs, err)
	}
	d.TXT(dnsname.CymruOrigin(mustAddr("203.0.113.0")), "0 | 203.0.113.0/24 | US | arin | 2000-01-01")
	if obs, err := st.Run(context.Background(), chk, clients(t, d)); err != nil || len(obs) != 0 {
		t.Errorf("AS0: %+v %v", obs, err)
	}
	d.RcodeSuffix("asn.cymru.com", 2) // SERVFAIL
	if _, err := st.Run(context.Background(), chk, clients(t, d)); err == nil {
		t.Error("a SERVFAIL must be a transient failure")
	}
}

// Netblock ownership participates as an ordinary always-enabled third-party DNS procedure.
func TestNetblockOwnerContract(t *testing.T) {
	t.Parallel()
	st := dns.NewNetblockOwner()
	if st.Name() != "netblockowner" || st.Contact() != run.ThirdParty || len(st.Sources()) != 0 {
		t.Errorf("%s contact %v sources %v", st.Name(), st.Contact(), st.Sources())
	}
	if ok, _ := st.Configured(run.Env{}); !ok {
		t.Error("the stage is not always configured")
	}
}
