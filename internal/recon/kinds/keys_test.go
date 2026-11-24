package kinds_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/store"
)

// keyed pairs identifying attributes with exact stored keys and fields recoverable after
// retirement.
type keyed struct {
	name    string
	obs     store.Obs
	key     string
	rebuilt func(store.Record) any
	want    any
}

// attrsOf reads a record's attributes with the handle k.
func attrsOf[A any](k kinds.Keyed[A]) func(store.Record) any {
	return func(r store.Record) any { return k.Attrs(r) }
}

// Preserve key bytes for existing state and recover identifying attributes from non-current
// records.
func TestKeyedKinds_KeyAndRebuild(t *testing.T) {
	t.Parallel()
	for _, c := range []keyed{
		{"resolution", kinds.Resolution.Obs(kinds.ResolutionAttrs{Name: "example.com", Type: "TXT", Value: "a|b"}),
			"example.com|TXT|a|b", attrsOf(kinds.Resolution),
			kinds.ResolutionAttrs{Name: "example.com", Type: "TXT", Value: "a|b"}},
		{"dns_claim", kinds.DNSClaim.Obs(kinds.DNSClaimAttrs{Name: "www.example.com", Type: "CNAME", Value: "x.test", Source: "shodan"}),
			"www.example.com|CNAME|x.test", attrsOf(kinds.DNSClaim),
			kinds.DNSClaimAttrs{Name: "www.example.com", Type: "CNAME", Value: "x.test"}},
		{"historical_address", kinds.HistoricalAddress.Obs(kinds.HistoricalAddressAttrs{Host: "www.example.com", Type: "AAAA", Addr: "2001:db8::1", FirstSeen: "2025-01-01"}),
			"www.example.com|AAAA|2001:db8::1", attrsOf(kinds.HistoricalAddress),
			kinds.HistoricalAddressAttrs{Host: "www.example.com", Type: "AAAA", Addr: "2001:db8::1"}},
		{"ip_hostname", kinds.IPHostname.Obs(kinds.IPHostnameAttrs{IP: "192.0.2.1", Hostname: "a.example.com", Source: "rdns"}),
			"192.0.2.1|a.example.com", attrsOf(kinds.IPHostname),
			kinds.IPHostnameAttrs{IP: "192.0.2.1", Hostname: "a.example.com"}},
		{"server_address", kinds.ServerAddress.Obs(kinds.ServerAddressAttrs{Host: "ns1.example.net", Addr: "192.0.2.53"}),
			"ns1.example.net|192.0.2.53", attrsOf(kinds.ServerAddress),
			kinds.ServerAddressAttrs{Host: "ns1.example.net", Addr: "192.0.2.53"}},
		{"registration", kinds.Registration.Obs(kinds.RegistrationAttrs{Registry: "arin", Handle: "NET-192-0-2-0-1", Start: "192.0.2.0"}),
			"arin|NET-192-0-2-0-1", attrsOf(kinds.Registration),
			kinds.RegistrationAttrs{Registry: "arin", Handle: "NET-192-0-2-0-1"}},
		{"candidate_rank", kinds.CandidateRank.Obs(kinds.CandidateRankAttrs{Type: "organisation", Value: "Globex | Ltd", Confidence: "low"}),
			"organisation|Globex | Ltd", attrsOf(kinds.CandidateRank),
			kinds.CandidateRankAttrs{Type: "organisation", Value: "Globex | Ltd"}},
		{"origin_check", kinds.OriginCheck.Obs(kinds.OriginCheckAttrs{Host: "www.example.com", Addr: "192.0.2.80", Status: 200}),
			"www.example.com|192.0.2.80", attrsOf(kinds.OriginCheck),
			kinds.OriginCheckAttrs{Host: "www.example.com", Addr: "192.0.2.80"}},
		{"web_identifier", kinds.WebIdentifier.Obs(kinds.WebIdentifierAttrs{Service: "https://www.example.com", Host: "www.example.com", Type: kinds.IdentifierCopyright, Value: "© Acme | All rights"}),
			"https://www.example.com|copyright|© Acme | All rights", attrsOf(kinds.WebIdentifier),
			kinds.WebIdentifierAttrs{Service: "https://www.example.com", Type: kinds.IdentifierCopyright, Value: "© Acme | All rights"}},
		{"open_port v4", kinds.OpenPort.Obs(kinds.OpenPortAttrs{IP: "192.0.2.1", Port: 22, Banner: "SSH-2.0"}),
			"192.0.2.1:22", attrsOf(kinds.OpenPort),
			kinds.OpenPortAttrs{IP: "192.0.2.1", Port: 22}},
		{"open_port v6", kinds.OpenPort.Obs(kinds.OpenPortAttrs{IP: "2001:db8::1", Port: 443}),
			"[2001:db8::1]:443", attrsOf(kinds.OpenPort),
			kinds.OpenPortAttrs{IP: "2001:db8::1", Port: 443}},
		{"reported_port", kinds.ReportedPort.Obs(kinds.ReportedPortAttrs{IP: "192.0.2.1", Port: 8080, LastSeen: "2026-10-01"}),
			"192.0.2.1:8080", attrsOf(kinds.ReportedPort),
			kinds.ReportedPortAttrs{IP: "192.0.2.1", Port: 8080}},
		{"third_party verification", kinds.ThirdParty.Obs(kinds.ThirdPartyAttrs{Root: "example.com", Mechanism: kinds.MechanismTXTVerification, Provider: "Atlassian"}),
			"example.com|txt-verification|Atlassian", attrsOf(kinds.ThirdParty),
			kinds.ThirdPartyAttrs{Root: "example.com", Mechanism: kinds.MechanismTXTVerification, Provider: "Atlassian"}},
		{"third_party domain", kinds.ThirdPartyObs("example.com", kinds.MechanismNS, "cloudflare.com", 1),
			"example.com|ns|cloudflare.com", attrsOf(kinds.ThirdParty),
			kinds.ThirdPartyAttrs{Root: "example.com", Mechanism: kinds.MechanismNS, Domain: "cloudflare.com", Provider: "Cloudflare"}},
	} {
		if c.obs.Key != c.key {
			t.Errorf("%s: key = %q, want %q", c.name, c.obs.Key, c.key)
		}
		if got := c.rebuilt(store.Record{Kind: c.obs.Kind, Key: c.obs.Key}); got != c.want {
			t.Errorf("%s: attributes from the key = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// Key recovery fills missing fields without overwriting stored attributes.
func TestKeyedKinds_StoredAttributesWin(t *testing.T) {
	t.Parallel()
	r := store.Record{Key: "a.example.com|A|192.0.2.1", Attrs: map[string]any{"name": "b.example.com"}}
	if a := kinds.Resolution.Attrs(r); a != (kinds.ResolutionAttrs{Name: "b.example.com", Type: "A", Value: "192.0.2.1"}) {
		t.Errorf("attrs = %+v", a)
	}
	// A key without the parts it should have fills in nothing.
	if a := kinds.Resolution.Attrs(store.Record{Key: "a.example.com"}); a != (kinds.ResolutionAttrs{}) {
		t.Errorf("attrs from a short key = %+v", a)
	}
}
