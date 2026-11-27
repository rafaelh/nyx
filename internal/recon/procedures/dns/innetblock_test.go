package dns

import (
	"context"
	"encoding/json"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/egress/egresstest"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/scope"
)

// inNetblockClients are clients whose DNS goes to the fake server, with a short timeout so a
// dropped query fails quickly.
func inNetblockClients(t *testing.T, d *egresstest.DNS) egress.Clients {
	t.Helper()
	eg := egress.New(egress.Options{ResolverAddrs: []string{d.Addr}, DNSTimeout: 300 * time.Millisecond, RateDNS: 100000})
	eg.SetPolicy(&egress.Policy{Scope: scope.New(scope.Config{})})
	return eg.Clients(false, nil)
}

// inNetblockScope is a scope with the root example.com and the netblock 203.0.113.0/24, in which
// the names given were looked up at the addresses given.
func inNetblockScope(lookups map[string][]string) *scope.Scope {
	l := map[string][]netip.Addr{}
	for name, addrs := range lookups {
		for _, a := range addrs {
			l[name] = append(l[name], netip.MustParseAddr(a))
		}
	}
	return scope.New(scope.Config{
		Roots:              []string{"example.com"},
		Netblocks:          []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Lookups:            l,
		MaxNamesPerAddress: 100,
	})
}

// canonicalObs renders observations as sorted "kind key attrs" lines, so that two sets of
// observations compare whatever their order. Empty attributes are written as {}.
func canonicalObs(t *testing.T, obs []run.Observation) []string {
	t.Helper()
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		attrs := "{}"
		if len(o.Attrs) > 0 {
			b, err := json.Marshal(o.Attrs)
			if err != nil {
				t.Fatal(err)
			}
			attrs = string(b)
		}
		out = append(out, o.Kind+" "+o.Key+" "+attrs)
	}
	slices.Sort(out)
	return out
}

// lookupAttrs decodes a candidate_lookup observation's attributes.
func lookupAttrs(o run.Observation) kinds.CandidateLookupAttrs {
	return kinds.CandidateLookup.Attrs(store.Record{Kind: o.Kind, Key: o.Key, Attrs: o.Attrs, Current: true})
}

// The rows job asks nothing and returns exactly the observations resolve gives for the same
// answer, plus the name as a hostname and, when the name is not its own registrable domain, the
// registrable domain as a root.
func TestInNetblock_RowsJobIsResolvesObservationsPlusHostnameAndRoot(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		desc   string
		name   string
		dns    func(d *egresstest.DNS)
		lookup kinds.CandidateLookupAttrs
		// root is the registrable domain observed as a root; empty when there is none.
		root string
		// cnameHost is a CNAME target resolve itself observes as a hostname, showing the case
		// exercises cnameHost's rule; empty when there is none.
		cnameHost string
	}{
		{
			desc: "addresses only",
			name: "shop.other.net",
			dns: func(d *egresstest.DNS) {
				d.A("shop.other.net", "203.0.113.7", "203.0.113.5", "2001:db8::5")
			},
			lookup: kinds.CandidateLookupAttrs{Addrs: []string{"2001:db8::5", "203.0.113.5", "203.0.113.7"}},
			root:   "other.net",
		},
		{
			desc: "a CNAME chain whose in-scope alias points at a name under a root",
			name: "www.other.net",
			dns: func(d *egresstest.DNS) {
				d.CNAME("www.other.net", "edge.example.com")
				d.CNAME("edge.example.com", "lb.example.com")
				d.A("lb.example.com", "203.0.113.9")
			},
			lookup: kinds.CandidateLookupAttrs{
				Addrs: []string{"203.0.113.9"},
				CNAMEs: []kinds.CNAMELink{
					{Name: "www.other.net", Target: "edge.example.com"},
					{Name: "edge.example.com", Target: "lb.example.com"},
				},
			},
			root:      "other.net",
			cnameHost: "lb.example.com",
		},
		{
			desc: "the name is its own registrable domain",
			name: "other.net",
			dns: func(d *egresstest.DNS) {
				d.A("other.net", "203.0.113.5")
			},
			lookup: kinds.CandidateLookupAttrs{Addrs: []string{"203.0.113.5"}},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			sc := inNetblockScope(map[string][]string{tc.name: tc.lookup.Addrs})

			d := egresstest.NewDNS(t)
			tc.dns(d)
			resolved, _, err := resolve(context.Background(), inNetblockClients(t, d), tc.name, sc)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if tc.cnameHost != "" && !slices.Contains(canonicalObs(t, resolved), "hostname "+tc.cnameHost+" {}") {
				t.Fatalf("resolve does not observe %s as a hostname, so the case does not test cnameHost's rule: %q",
					tc.cnameHost, canonicalObs(t, resolved))
			}
			want := append(slices.Clone(resolved), kinds.Hostname.Obs(tc.name, kinds.HostnameAttrs{}))
			if tc.root != "" {
				want = append(want, kinds.Root.Obs(tc.root))
			}

			quiet := egresstest.NewDNS(t)
			job := run.Job{Key: rowsKey(tc.name, tc.lookup), Input: rowsInput{lookup: tc.lookup, sc: sc}}
			got, err := NewInNetblock().Run(context.Background(), job, inNetblockClients(t, quiet))
			if err != nil {
				t.Fatalf("rows job: %v", err)
			}
			if g, w := canonicalObs(t, got), canonicalObs(t, want); !slices.Equal(g, w) {
				t.Errorf("rows job observations =\n%q,\nwant resolve's plus the hostname and root\n%q", g, w)
			}
			if n := quiet.Total(); n != 0 {
				t.Errorf("the rows job sent %d DNS queries, want none", n)
			}
		})
	}
}

// The rows job of a name that is its own registrable domain observes no root.
func TestInNetblock_RowsJobOfARegistrableDomainObservesNoRoot(t *testing.T) {
	t.Parallel()
	lookup := kinds.CandidateLookupAttrs{Addrs: []string{"203.0.113.5"}}
	sc := inNetblockScope(map[string][]string{"other.net": lookup.Addrs})
	job := run.Job{Key: rowsKey("other.net", lookup), Input: rowsInput{lookup: lookup, sc: sc}}
	got, err := NewInNetblock().Run(context.Background(), job, inNetblockClients(t, egresstest.NewDNS(t)))
	if err != nil {
		t.Fatal(err)
	}
	host := false
	for _, o := range got {
		switch {
		case o.Kind == kinds.Root.Name():
			t.Errorf("root %s observed for a name that is its own registrable domain", o.Key)
		case o.Kind == kinds.Hostname.Name() && o.Key == "other.net":
			host = true
		}
	}
	if !host {
		t.Errorf("other.net is not observed as a hostname: %+v", got)
	}
}

// The rows key is "in|<name>|<hash>", the same for the same answer and different when the
// addresses or the CNAME links differ.
func TestInNetblock_RowsKeyChangesWithTheAnswer(t *testing.T) {
	t.Parallel()
	base := kinds.CandidateLookupAttrs{Addrs: []string{"203.0.113.5"}}
	sameAgain := kinds.CandidateLookupAttrs{Addrs: []string{"203.0.113.5"}}
	otherAddr := kinds.CandidateLookupAttrs{Addrs: []string{"203.0.113.6"}}
	moreAddrs := kinds.CandidateLookupAttrs{Addrs: []string{"203.0.113.5", "203.0.113.6"}}
	withCNAME := kinds.CandidateLookupAttrs{Addrs: []string{"203.0.113.5"},
		CNAMEs: []kinds.CNAMELink{{Name: "shop.other.net", Target: "lb.other.net"}}}
	otherCNAME := kinds.CandidateLookupAttrs{Addrs: []string{"203.0.113.5"},
		CNAMEs: []kinds.CNAMELink{{Name: "shop.other.net", Target: "edge.other.net"}}}

	k := rowsKey("shop.other.net", base)
	hash, ok := strings.CutPrefix(k, "in|shop.other.net|")
	if !ok || hash == "" {
		t.Fatalf("rows key = %q, want in|shop.other.net|<hash>", k)
	}
	if again := rowsKey("shop.other.net", sameAgain); again != k {
		t.Errorf("the same answer gives %q, then %q", k, again)
	}
	keys := map[string]string{"base": k}
	for desc, a := range map[string]kinds.CandidateLookupAttrs{
		"another address": otherAddr, "an added address": moreAddrs,
		"a CNAME link": withCNAME, "another CNAME target": otherCNAME,
	} {
		keys[desc] = rowsKey("shop.other.net", a)
	}
	seen := map[string]string{}
	for _, desc := range slices.Sorted(maps.Keys(keys)) {
		if prev, dup := seen[keys[desc]]; dup {
			t.Errorf("%s and %s give the same rows key %q", prev, desc, keys[desc])
		}
		seen[keys[desc]] = desc
	}
}

// A rows key's evidence is (in-netblock, <name>); a lookup key gives nothing that is a candidate.
func TestInNetblock_Evidence(t *testing.T) {
	t.Parallel()
	p := NewInNetblock()
	lookup := kinds.CandidateLookupAttrs{Addrs: []string{"203.0.113.5"}}
	for _, key := range []string{rowsKey("shop.other.net", lookup), "in|shop.other.net|0123abcd"} {
		if src, item := p.Evidence(key); src != "in-netblock" || item != "shop.other.net" {
			t.Errorf("Evidence(%q) = (%q, %q), want (in-netblock, shop.other.net)", key, src, item)
		}
	}
	if src, item := p.Evidence("shop.other.net"); src != "" {
		t.Errorf("Evidence of a lookup key = (%q, %q), want an empty source", src, item)
	}
}

// A lookup job asks A and AAAA once each and completes with one candidate_lookup observation,
// keyed by the name, holding the addresses sorted and the CNAME links in answer order.
func TestInNetblock_LookupJobRecordsTheAnswer(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	d.CNAME("www.other.net", "edge.example.com")
	d.CNAME("edge.example.com", "lb.example.com")
	d.A("lb.example.com", "203.0.113.7", "203.0.113.5", "2001:db8::5")

	obs, err := NewInNetblock().Run(context.Background(), run.Job{Key: "www.other.net", Cost: 1}, inNetblockClients(t, d))
	if err != nil {
		t.Fatal(err)
	}
	if a, aaaa := d.Count("www.other.net", "A"), d.Count("www.other.net", "AAAA"); a != 1 || aaaa != 1 {
		t.Errorf("asked A %d and AAAA %d times, want once each", a, aaaa)
	}
	if len(obs) != 1 || obs[0].Kind != kinds.CandidateLookup.Name() || obs[0].Key != "www.other.net" {
		t.Fatalf("observations = %+v, want one candidate_lookup of www.other.net", obs)
	}
	got := lookupAttrs(obs[0])
	if want := []string{"203.0.113.5", "203.0.113.7", "2001:db8::5"}; !sameStrings(got.Addrs, want) {
		t.Errorf("addrs = %q, want the set %q", got.Addrs, want)
	}
	if i, j := slices.Index(got.Addrs, "203.0.113.5"), slices.Index(got.Addrs, "203.0.113.7"); i > j {
		t.Errorf("addrs = %q, not sorted", got.Addrs)
	}
	wantLinks := []kinds.CNAMELink{
		{Name: "www.other.net", Target: "edge.example.com"},
		{Name: "edge.example.com", Target: "lb.example.com"},
	}
	if !slices.Equal(got.CNAMEs, wantLinks) {
		t.Errorf("cnames = %+v, want %+v", got.CNAMEs, wantLinks)
	}
}

// A lookup job of a name with addresses and no CNAME records them with no links.
func TestInNetblock_LookupJobWithoutCNAME(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	d.A("shop.other.net", "203.0.113.5")
	obs, err := NewInNetblock().Run(context.Background(), run.Job{Key: "shop.other.net", Cost: 1}, inNetblockClients(t, d))
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].Kind != kinds.CandidateLookup.Name() || obs[0].Key != "shop.other.net" {
		t.Fatalf("observations = %+v, want one candidate_lookup of shop.other.net", obs)
	}
	if got := lookupAttrs(obs[0]); !slices.Equal(got.Addrs, []string{"203.0.113.5"}) || len(got.CNAMEs) != 0 {
		t.Errorf("attrs = %+v, want addrs [203.0.113.5] and no cnames", got)
	}
}

// An answer with no address completes the lookup job with no observation: SERVFAIL, NXDOMAIN,
// an empty answer and a CNAME that leads nowhere.
func TestInNetblock_LookupJobWithNoAddressRecordsNothing(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		desc string
		dns  func(d *egresstest.DNS)
	}{
		{"SERVFAIL", func(d *egresstest.DNS) { d.Rcode("shop.other.net", 2) }},
		{"NXDOMAIN", func(*egresstest.DNS) {}},
		{"an empty answer", func(d *egresstest.DNS) { d.NoDataSuffix("other.net") }},
		{"a dangling CNAME", func(d *egresstest.DNS) { d.CNAME("shop.other.net", "gone.example.org") }},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			t.Parallel()
			d := egresstest.NewDNS(t)
			tc.dns(d)
			obs, err := NewInNetblock().Run(context.Background(), run.Job{Key: "shop.other.net", Cost: 1}, inNetblockClients(t, d))
			if err != nil {
				t.Errorf("the job failed (%v), want it completed", err)
			}
			if len(obs) != 0 {
				t.Errorf("observations = %+v, want none", obs)
			}
			if a, aaaa := d.Count("shop.other.net", "A"), d.Count("shop.other.net", "AAAA"); a != 1 || aaaa != 1 {
				t.Errorf("asked A %d and AAAA %d times, want once each", a, aaaa)
			}
		})
	}
}

// A timeout fails the lookup job, so it is retried on the next run.
func TestInNetblock_LookupJobTimeoutIsAnError(t *testing.T) {
	t.Parallel()
	d := egresstest.NewDNS(t)
	d.Drop("shop.other.net")
	obs, err := NewInNetblock().Run(context.Background(), run.Job{Key: "shop.other.net", Cost: 1}, inNetblockClients(t, d))
	if err == nil {
		t.Errorf("a timeout completed the job with %+v, want an error", obs)
	}
	if d.Count("shop.other.net", "A") == 0 {
		t.Error("the name was not asked")
	}
}

// in-netblock is a third-party procedure with no sources, always configured, budgeted by
// in_netblock.max_lookups, and its own candidate family.
func TestInNetblock_Contract(t *testing.T) {
	t.Parallel()
	p := NewInNetblock()
	if p.Name() != "in-netblock" || p.Contact() != run.ThirdParty || len(p.Sources()) != 0 {
		t.Errorf("%s contact %v sources %v", p.Name(), p.Contact(), p.Sources())
	}
	if ok, _ := p.Configured(run.Env{}); !ok {
		t.Error("the procedure is not always configured")
	}
	var s config.Settings
	s.InNetblock.MaxLookups = 7
	if got := p.Budget(s); got != 7 {
		t.Errorf("Budget = %d, want in_netblock.max_lookups (7)", got)
	}
	if got, want := p.CandidateSources(), map[string]string{"in-netblock": "in-netblock"}; !maps.Equal(got, want) {
		t.Errorf("CandidateSources = %v, want %v", got, want)
	}
	var proc run.Procedure = p
	if _, ok := proc.(run.Retiring); !ok {
		t.Error("in-netblock is not Retiring")
	}
	if _, ok := proc.(run.Evidencer); !ok {
		t.Error("in-netblock is not an Evidencer")
	}
}
