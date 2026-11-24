package provider_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/knowledge/provider"
)

// CDN ASN evidence overrides dedicated-hosting ranges so CDN edges cannot become candidate
// origins.
func TestClassify_CDNASNStaysSharedInsideADedicatedRange(t *testing.T) {
	t.Parallel()
	db := provider.Default()
	idx := provider.NewRanges([]provider.Range{
		rng("104.64.0.0/10", "linode", "", "US-TX"),
		rng("143.198.0.0/16", "digitalocean", "", "US-NJ"),
		rng("45.79.0.0/16", "linode", "", "US-TX"),
	})
	cases := []struct {
		name, addr string
		owner      provider.Owner
		want       provider.Result
	}{
		{"akamai edge inside linode's list", "104.64.1.1", provider.Owner{ASN: 20940, Holder: "AKAMAI-ASN1", Known: true},
			provider.Result{Known: true, Shared: true, Provider: "akamai", Evidence: "asn", Class: provider.ClassCDN}},
		{"another cdn's asn inside a dedicated range", "143.198.1.1", provider.Owner{ASN: 13335, Known: true},
			provider.Result{Known: true, Shared: true, Provider: "cloudflare", Evidence: "asn", Class: provider.ClassCDN}},
		{"a customer's own asn inside linode's list stays dedicated", "45.79.1.1", provider.Owner{ASN: 64500, Known: true},
			provider.Result{Known: true, Provider: "linode", Region: "US-TX", Evidence: "range"}},
		{"an unknown owner inside linode's list stays dedicated", "45.79.1.2", provider.Owner{},
			provider.Result{Known: true, Provider: "linode", Region: "US-TX", Evidence: "range"}},
	}
	for _, c := range cases {
		if got := db.Classify(ip(c.addr), c.owner, idx); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// Only fronting providers gain cdn/waf CNAME classes; other classifications remain intact.
func TestCNAMEClasses_CDNAndWAF(t *testing.T) {
	t.Parallel()
	db := provider.Default()
	for target, want := range map[string]string{
		"d111111abcdef8.cloudfront.net": provider.ClassCDN,
		"acme.azurefd.net":              provider.ClassCDN,
		"acme.azureedge.net":            provider.ClassCDN,
		"acme.cdn.cloudflare.net":       provider.ClassCDN,
		"acme.global.prod.fastly.net":   provider.ClassCDN,
		"www.acme.com.edgekey.net":      provider.ClassCDN,
		"acme.edgesuite.net":            provider.ClassCDN,
		"e1234.a.akamaiedge.net":        provider.ClassCDN,
		"abc.x.incapdns.net":            provider.ClassWAF,
		"acme.sucuri.net":               provider.ClassWAF,
		// Unchanged.
		"acme.github.io":      provider.ClassSaaS,
		"acme.herokuapp.com":  "",
		"x.elb.amazonaws.com": "",
	} {
		e, ok := db.CNAMEEntry(target)
		if !ok || e.Class != want {
			t.Errorf("CNAMEEntry(%s) = class %q, ok=%v; want class %q", target, e.Class, ok, want)
		}
	}
}
