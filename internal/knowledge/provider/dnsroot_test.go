package provider_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/knowledge/provider"
)

// A TXT value that starts with a listed prefix, in any case, names its platform.
func TestVerification(t *testing.T) {
	t.Parallel()
	db := provider.Default()
	for value, want := range map[string]string{
		"google-site-verification=abc":        "Google",
		"GOOGLE-SITE-VERIFICATION=abc":        "Google",
		"MS=ms123":                            "Microsoft 365",
		"ms=ms123":                            "Microsoft 365",
		"atlassian-domain-verification=x":     "Atlassian",
		"docusign=x":                          "DocuSign",
		"facebook-domain-verification=x":      "Facebook",
		"apple-domain-verification=x":         "Apple",
		"stripe-verification=x":               "Stripe",
		"adobe-idp-site-verification=x":       "Adobe",
		"hubspot-developer-verification=x":    "HubSpot",
		"zoom-domain-verification=x":          "Zoom",
		"dropbox-domain-verification=x":       "Dropbox",
		"salesforce-domain-verification=x":    "Salesforce",
		"have-i-been-pwned-verification=x":    "Have I Been Pwned",
		"webexdomainverification.ABC=x":       "Cisco Webex",
		"  google-site-verification=padded  ": "Google",
	} {
		if got, ok := db.Verification(value); !ok || got != want {
			t.Errorf("Verification(%q) = %q, %v, want %q", value, got, ok, want)
		}
	}
	for _, value := range []string{"", "v=spf1 -all", "xdocusign=abc", "a google-site-verification=abc", "MSFT=1", "some text"} {
		if got, ok := db.Verification(value); ok {
			t.Errorf("Verification(%q) = %q; only a prefix matches", value, got)
		}
	}
}

// A TXT value no prefix lists but that is shaped as a vendor's verification record names the
// vendor as written, its words capitalised; a listed prefix still wins, and a value that only
// mentions verification names nobody.
func TestVerification_UnlistedVendor(t *testing.T) {
	t.Parallel()
	db := provider.Default()
	for value, want := range map[string]string{
		"linear-domain-verification=s2pgvu2774jk":              "Linear",
		"wrike-verification=Njk3NzM1OTo5MTBk":                  "Wrike",
		"neat-pulse-domain-verification-rvqZKlX=fb2b2f5a-914e": "Neat Pulse",
		"acme_site_verification=1":                             "Acme",
		"Example-Corp-SSO-Verification=abc":                    "Example Corp",
		// Listed prefixes keep their own names.
		"openai-domain-verification=dv-1":               "OpenAI",
		"anthropic-domain-verification-zp17ge=Txm3":     "Anthropic",
		"status-page-domain-verification=nt1cvfk4yj3q":  "Atlassian Statuspage",
		"cloudflare_dashboard_sso=8b09317ea83801289b84": "Cloudflare",
		"jamf-site-verification=WhwM9n6xAPJkb":          "Jamf",
	} {
		if got, ok := db.Verification(value); !ok || got != want {
			t.Errorf("Verification(%q) = %q, %v, want %q", value, got, ok, want)
		}
	}
	for _, value := range []string{"verification=abc", "domain-verification=abc", "-domain-verification=abc",
		"please complete verification of example.com", "acme-verification", "acme verification=1", "v=DMARC1; p=none"} {
		if got, ok := db.Verification(value); ok {
			t.Errorf("Verification(%q) = %q; it names no vendor", value, got)
		}
	}
}

// A provider that uses many registrable domains is named by a pattern: Route 53's numbered
// name-server domains are one family, whatever their number or suffix.
func TestFamily(t *testing.T) {
	t.Parallel()
	db := provider.Default()
	for _, name := range []string{"ns-1340.awsdns-39.org", "ns-1852.awsdns-39.co.uk", "ns-328.awsdns-41.com", "NS-737.awsdns-28.net.", "awsdns-01.com"} {
		if got, ok := db.Family(name); !ok || got != "Amazon Route 53" {
			t.Errorf("Family(%q) = %q, %v, want Amazon Route 53", name, got, ok)
		}
		if got, ok := db.DomainOwner(name); !ok || got != "Amazon Route 53" {
			t.Errorf("DomainOwner(%q) = %q, %v, want Amazon Route 53", name, got, ok)
		}
	}
	for _, name := range []string{"awsdns.com", "awsdns-x.com", "ns-1.awsdns-39.org.evil.test", "notawsdns-39.org", "cloudflare.com", ""} {
		if got, ok := db.Family(name); ok {
			t.Errorf("Family(%q) = %q; the pattern is of the whole registrable domain", name, got)
		}
	}
	if !db.IsFamily("Amazon Route 53") || db.IsFamily("Cloudflare") || db.IsFamily("") {
		t.Error("IsFamily: only a provider a pattern names is a family")
	}
}

// An alias target no entry lists is a third party's platform, named by its registrable domain.
func TestThirdParty(t *testing.T) {
	t.Parallel()
	for target, want := range map[string]string{
		"cl2.myabsorb.eu":           "myabsorb.eu",
		"Proxy-SSL.Webflow.com.":    "webflow.com",
		"tenant.vendor.co.uk":       "vendor.co.uk",
		"starrez.screenconnect.com": "screenconnect.com",
	} {
		e := provider.ThirdParty(target)
		if e.Provider != want || e.Suffix != want || e.Class != provider.ClassSaaS || e.NXDomain || e.Body != "" {
			t.Errorf("ThirdParty(%q) = %+v, want the SaaS platform %s with no fingerprint", target, e, want)
		}
	}
}

// Provider suffix matching respects label boundaries and works across dependency hostname
// depths.
func TestDomainOwner(t *testing.T) {
	t.Parallel()
	db := provider.Default()
	for name, want := range map[string]string{
		"ns1.cloudflare.com":            "Cloudflare",
		"NS1.Cloudflare.com.":           "Cloudflare",
		"cloudflare.com":                "Cloudflare",
		"ns51.domaincontrol.com":        "GoDaddy",
		"ns1-01.azure-dns.com":          "Microsoft Azure DNS",
		"ns-cloud-a1.googledomains.com": "Google Cloud DNS",
		// Mail and SaaS.
		"_spf.google.com":                         "Google",
		"aspmx.l.google.com":                      "Google",
		"example-com.mail.protection.outlook.com": "Microsoft 365",
		"spf.protection.outlook.com":              "Microsoft 365",
		"mailgun.org":                             "Mailgun",
		"sendgrid.net":                            "SendGrid",
		"amazonses.com":                           "Amazon SES",
		"github.io":                               "GitHub",
		"myshopify.com":                           "Shopify",
		"zendesk.com":                             "Zendesk",
		"readme.io":                               "ReadMe",
		"squarespace.com":                         "Squarespace",
		"wixdns.net":                              "Wix",
		"statuspage.io":                           "Atlassian",
		"unbouncepages.com":                       "Unbounce",
		"ghost.io":                                "Ghost",
	} {
		if got, ok := db.DomainOwner(name); !ok || got != want {
			t.Errorf("DomainOwner(%q) = %q, %v, want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"ns1.example.net", "notcloudflare.com", "cloudflare.com.evil.test", "notgoogle.com", "google.com.evil.test", ""} {
		if got, ok := db.DomainOwner(name); ok {
			t.Errorf("DomainOwner(%q) = %q; suffixes match on label boundaries only", name, got)
		}
	}
}

func TestParseTXTAndDomains(t *testing.T) {
	t.Parallel()
	db, err := provider.Parse([]byte("txt:\n  - {prefix: 'X-Verify=', platform: Example}\ndomains:\n  - {suffix: Dns.Example.Test, provider: ExampleDNS}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := db.Verification("x-verify=1"); !ok || p != "Example" {
		t.Errorf("Verification = %q, %v", p, ok)
	}
	if p, ok := db.DomainOwner("a.dns.example.test"); !ok || p != "ExampleDNS" {
		t.Errorf("DomainOwner = %q, %v", p, ok)
	}
}
