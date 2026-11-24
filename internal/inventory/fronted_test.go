package inventory_test

import (
	"net/netip"
	"testing"

	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/provider"
)

func cname(d *inventory.Data, name, target string) {
	d.Resolutions = append(d.Resolutions, inventory.Resolution{Name: name, Type: "CNAME", Value: target})
}

// Fronting requires CDN/WAF CNAME or CDN address evidence, excluding ordinary SaaS/PaaS/cloud
// hosting.
func TestFronted(t *testing.T) {
	t.Parallel()
	var d inventory.Data
	for name, v := range map[string]struct {
		cname string
		addrs []string
	}{
		"cf-cname.example.com":      {"acme.cdn.cloudflare.net", []string{"203.0.113.1"}},
		"cloudfront.example.com":    {"d1.cloudfront.net", []string{"203.0.113.2"}},
		"chain.example.com":         {"lb.example.net", []string{"203.0.113.3"}},
		"waf.example.com":           {"abc.x.incapdns.net", []string{"203.0.113.4"}},
		"range.example.com":         {"", []string{"104.16.0.5"}},
		"asn.example.com":           {"", []string{"203.0.113.5"}},
		"akamai-linode.example.com": {"", []string{"104.64.1.1"}},
		"saas.example.com":          {"acme.github.io", []string{"203.0.113.6"}},
		"heroku.example.com":        {"acme.herokuapp.com", []string{"203.0.113.7"}},
		"aws.example.com":           {"", []string{"203.0.113.8"}},
		"cf-alias.example.com":      {"", []string{"13.32.0.9"}},
		"plain.example.com":         {"", []string{"203.0.113.9"}},
		"nxdomain.example.com":      {"acme.cdn.cloudflare.net", nil},
	} {
		if v.cname != "" {
			cname(&d, name, v.cname)
		}
		resolve(&d, name, v.addrs...)
	}
	cname(&d, "lb.example.net", "x.global.fastly.net")
	d.Owners = map[netip.Addr]provider.Owner{
		ip("203.0.113.5"): {ASN: 54113, Holder: "FASTLY", Known: true},
		ip("104.64.1.1"):  {ASN: 20940, Holder: "AKAMAI-ASN1", Known: true},
		ip("203.0.113.8"): {ASN: 16509, Holder: "AMAZON-02", Known: true},
		ip("203.0.113.9"): {ASN: 64500, Holder: "ACME-NET", Known: true},
	}
	d.Ranges = provider.NewRanges([]provider.Range{
		{Prefix: netip.MustParsePrefix("104.16.0.0/13"), Provider: "cloudflare"},
		{Prefix: netip.MustParsePrefix("104.64.0.0/10"), Provider: "linode", Region: "US-TX"},
		{Prefix: netip.MustParsePrefix("13.32.0.0/15"), Provider: "aws", Service: "AMAZON", Region: "GLOBAL"},
		{Prefix: netip.MustParsePrefix("13.32.0.0/15"), Provider: "aws", Service: "CLOUDFRONT", Region: "GLOBAL"},
	})
	inv := inventory.New(d, provider.Default())
	for host, want := range map[string]string{
		"cf-cname.example.com":      "cloudflare",
		"cloudfront.example.com":    "aws",
		"chain.example.com":         "fastly",
		"waf.example.com":           "incapsula",
		"range.example.com":         "cloudflare",
		"asn.example.com":           "fastly",
		"akamai-linode.example.com": "akamai",
		"nxdomain.example.com":      "cloudflare", // a chain that dangles into a CDN is still behind it
		"saas.example.com":          "",
		"heroku.example.com":        "",
		"aws.example.com":           "",
		"cf-alias.example.com":      "aws", // an apex aliased to CloudFront: its address is in a CloudFront range
		"plain.example.com":         "",
		"unknown.example.com":       "",
	} {
		got, ok := inv.Fronted(host)
		if got != want || ok != (want != "") {
			t.Errorf("Fronted(%s) = %q, %v; want %q", host, got, ok, want)
		}
	}
}
