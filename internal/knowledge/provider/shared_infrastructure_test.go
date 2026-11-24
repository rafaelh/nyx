package provider_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/knowledge/provider"
)

func TestResult_SharedInfrastructure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		r    provider.Result
		want bool
	}{
		{"zero", provider.Result{}, false},
		{"unshared", provider.Result{Known: true, Class: provider.ClassCDN}, false},
		{"cdn", provider.Result{Known: true, Shared: true, Class: provider.ClassCDN}, true},
		{"saas", provider.Result{Known: true, Shared: true, Class: provider.ClassSaaS}, true},
		{"waf", provider.Result{Known: true, Shared: true, Class: provider.ClassWAF}, true},
		{"shared hosting", provider.Result{Known: true, Shared: true, Class: provider.ClassSharedHosting}, true},
		{"a range with no class", provider.Result{Known: true, Shared: true, Evidence: "range"}, true},
		{"hyperscaler", provider.Result{Known: true, Shared: true, Class: provider.ClassHyperscaler}, false},
		{"hyperscaler, not shared", provider.Result{Known: true, Class: provider.ClassHyperscaler}, false},
	} {
		if got := tc.r.SharedInfrastructure(); got != tc.want {
			t.Errorf("%s: SharedInfrastructure() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestClassConstants(t *testing.T) {
	t.Parallel()
	if provider.ClassHyperscaler != "hyperscaler" || provider.ClassSharedHosting != "shared-hosting" {
		t.Errorf("classes = %q, %q", provider.ClassHyperscaler, provider.ClassSharedHosting)
	}
}

// Customer-dedicated cloud ASNs can be conservatively Shared without being
// SharedInfrastructure.
func TestClassify_DigitalOceanAndSoftLayerAreHyperscalers(t *testing.T) {
	t.Parallel()
	db := provider.Default()
	for _, c := range []struct {
		asn      int
		provider string
	}{{14061, "digitalocean"}, {36351, "softlayer"}} {
		got := db.Classify(ip("100.64.0.1"), provider.Owner{ASN: c.asn, Known: true}, nil)
		if got.Provider != c.provider || got.Class != provider.ClassHyperscaler || !got.Shared || got.Evidence != "asn" {
			t.Errorf("AS%d: %+v, want %s, hyperscaler, shared by asn", c.asn, got, c.provider)
		}
		if got.SharedInfrastructure() {
			t.Errorf("AS%d is counted as shared infrastructure", c.asn)
		}
	}
}

// Providers that serve other companies' content stay shared infrastructure.
func TestClassify_SharedHostingAndCDNAreSharedInfrastructure(t *testing.T) {
	t.Parallel()
	db := provider.Default()
	for _, asn := range []int{13335, 20940, 46606, 26496, 53831} {
		got := db.Classify(ip("100.64.0.1"), provider.Owner{ASN: asn, Known: true}, nil)
		if !got.SharedInfrastructure() {
			t.Errorf("AS%d: %+v is not shared infrastructure", asn, got)
		}
	}
	if got := db.Classify(ip("100.64.0.1"), provider.Owner{ASN: 16509, Known: true}, nil); got.SharedInfrastructure() {
		t.Errorf("AWS: %+v is shared infrastructure", got)
	}
}
