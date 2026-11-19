package input_test

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/input"
)

// Domain forms.
func TestParseDomain(t *testing.T) {
	t.Parallel()
	ok := map[string]string{
		"Example.COM":       "example.com",
		"example.com.":      "example.com",
		"sub.example.co.uk": "sub.example.co.uk",
		"bücher.de":         "xn--bcher-kva.de",
	}
	for in, want := range ok {
		got, err := input.ParseDomain(in)
		if err != nil || got != want {
			t.Errorf("ParseDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "co.uk", "com", "localhost", "exa mple.com", "-a.example.com", "a..example.com", "1.2.3.4", "foo_bar.example.com", "https://example.com", "example.com/path"} {
		_, err := input.ParseDomain(bad)
		if err == nil {
			t.Errorf("ParseDomain(%q) should fail", bad)
		} else if !strings.Contains(err.Error(), bad) && bad != "" {
			t.Errorf("error %q should name %q", err, bad)
		}
	}
}

func TestParseASN(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"AS123": "AS123", "as123": "AS123", "123": "AS123", "4294967295": "AS4294967295"} {
		got, err := input.ParseASN(in)
		if err != nil || got != want {
			t.Errorf("ParseASN(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "AS", "ASx", "0", "4294967296", "-5", "AS 12"} {
		if _, err := input.ParseASN(bad); err == nil {
			t.Errorf("ParseASN(%q) should fail", bad)
		}
	}
}

func TestParseCIDR(t *testing.T) {
	t.Parallel()
	got, err := input.ParseCIDR("10.0.0.77/24")
	if err != nil || got != netip.MustParsePrefix("10.0.0.0/24") {
		t.Errorf("got %v %v", got, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "10.0.0.0", "nope", "2001:db8::/129"} {
		if _, err := input.ParseCIDR(bad); err == nil || !strings.Contains(err.Error(), bad) {
			t.Errorf("ParseCIDR(%q): %v", bad, err)
		}
	}
}

func TestParseOrg(t *testing.T) {
	t.Parallel()
	if got, err := input.ParseOrg("  Acme Corp "); err != nil || got != "Acme Corp" {
		t.Errorf("got %q %v", got, err)
	}
	if _, err := input.ParseOrg("   "); err == nil {
		t.Error("blank org should fail")
	}
}

// Exclusion matching table (also pinned at scope level).
func TestExclusions(t *testing.T) {
	t.Parallel()
	type tc struct {
		entry, host string
		want        bool
	}
	for _, c := range []tc{
		{"host.example.com", "host.example.com", true},
		{"host.example.com", "HOST.example.com", true},
		{"host.example.com", "a.host.example.com", false},
		{"*.dev.example.com", "a.dev.example.com", true},
		{"*.dev.example.com", "a.b.dev.example.com", true},
		{"*.dev.example.com", "dev.example.com", false},
		{"*.dev.example.com", "xdev.example.com", false},
		{"10.0.0.0/8", "anything.example.com", false},
	} {
		e, err := input.ParseExclusion(c.entry)
		if err != nil {
			t.Fatalf("%s: %v", c.entry, err)
		}
		if got := e.MatchesHost(c.host); got != c.want {
			t.Errorf("%s vs %s = %v, want %v", c.entry, c.host, got, c.want)
		}
	}
	e, _ := input.ParseExclusion("10.0.0.0/8")
	p, ok := e.Prefix()
	if !ok || !p.Contains(netip.MustParseAddr("10.9.9.9")) || p.Contains(netip.MustParseAddr("11.0.0.1")) {
		t.Errorf("cidr exclusion broken: %v %v", p, ok)
	}
	for _, bad := range []string{"", "*.", "bad host", "10.0.0.0/40", "*.*.example.com", "a.*.example.com", "*example.com"} {
		if _, err := input.ParseExclusion(bad); err == nil {
			t.Errorf("ParseExclusion(%q) should fail", bad)
		}
	}
}

// Engagement name precedence and sanitisation.
func TestEngagementName(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"example.com":      "example.com",
		"Acme Corp, Inc.":  "acme-corp-inc",
		"10.0.0.0/8":       "10.0.0.0_8",
		"  Weird///Name  ": "weird___name",
		"a--b":             "a-b",
		"UPPER.Case":       "upper.case",
		"bücher.de":        "b-cher.de",
		"../x":             "x",
		".hidden":          "hidden",
	} {
		got, err := input.EngagementName(in)
		if err != nil || got != want {
			t.Errorf("EngagementName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "---", "..", "/", " . "} {
		if got, err := input.EngagementName(bad); err == nil {
			t.Errorf("EngagementName(%q) = %q, want an error", bad, got)
		}
	}
}

func writeList(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Each input form; files ignore comments and blank lines.
func TestParse(t *testing.T) {
	t.Parallel()
	df := writeList(t, "# targets\n\nfile.example.org\n  other.example.net  # trailing\n")
	xf := writeList(t, "# skip\n*.dev.example.com\n\n192.0.2.0/24\n")
	p, err := input.Parse(input.Raw{
		Domains:     []string{"Example.com"},
		DomainsFile: df,
		Orgs:        []string{"Acme Corp"},
		ASNs:        []string{"13335", "AS15169"},
		CIDRs:       []string{"203.0.113.9/24"},
		Exclude:     []string{"admin.example.com"},
		ExcludeFile: xf,
	})
	if err != nil {
		t.Fatal(err)
	}
	eq := func(name string, got, want []string) {
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	eq("roots", p.Roots, []string{"example.com", "file.example.org", "other.example.net"})
	eq("orgs", p.Orgs, []string{"Acme Corp"})
	eq("asns", p.ASNs, []string{"AS13335", "AS15169"})
	eq("cidrs", p.CIDRs, []string{"203.0.113.0/24"})
	eq("exclusions", p.Exclusions, []string{"*.dev.example.com", "192.0.2.0/24", "admin.example.com"})
	if p.First != "Example.com" {
		t.Errorf("First = %q", p.First)
	}
}

func TestParseFirstPrecedence(t *testing.T) {
	t.Parallel()
	df := writeList(t, "# c\nfile.example.org\n")
	for _, c := range []struct {
		raw  input.Raw
		want string
	}{
		{input.Raw{Domains: []string{"a.example.com"}, DomainsFile: df, Orgs: []string{"Org"}}, "a.example.com"},
		{input.Raw{DomainsFile: df, Orgs: []string{"Org"}}, "file.example.org"},
		{input.Raw{Orgs: []string{"Org"}, ASNs: []string{"1"}}, "Org"},
		{input.Raw{ASNs: []string{"7"}, CIDRs: []string{"10.0.0.0/8"}}, "AS7"},
		{input.Raw{CIDRs: []string{"10.0.0.0/8"}}, "10.0.0.0/8"},
	} {
		p, err := input.Parse(c.raw)
		if err != nil || p.First != c.want {
			t.Errorf("First = %q, %v; want %q", p.First, err, c.want)
		}
	}
}

// Every invalid form names the bad value.
func TestParseRejects(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		raw  input.Raw
		want string
	}{
		"domain":    {input.Raw{Domains: []string{"bad domain.com"}}, "bad domain.com"},
		"suffix":    {input.Raw{Domains: []string{"co.uk"}}, "co.uk"},
		"asn":       {input.Raw{ASNs: []string{"ASxyz"}}, "ASxyz"},
		"cidr":      {input.Raw{CIDRs: []string{"1.2.3.4/99"}}, "1.2.3.4/99"},
		"exclusion": {input.Raw{Domains: []string{"example.com"}, Exclude: []string{"a b"}}, "a b"},
		"file":      {input.Raw{DomainsFile: "/no/such/file"}, "/no/such/file"},
		"filedom":   {input.Raw{DomainsFile: writeList(t, "ok.example.com\nco.uk\n")}, "co.uk"},
	} {
		_, err := input.Parse(c.raw)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v should name %q", name, err, c.want)
		}
	}
}

// A registry's range is split into the fewest CIDRs that cover it exactly.
func TestRangeCIDRs(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		start, end string
		want       []string
	}{
		{"203.0.113.0", "203.0.113.255", []string{"203.0.113.0/24"}},
		{"198.51.100.0", "198.51.100.191", []string{"198.51.100.0/25", "198.51.100.128/26"}},
		{"198.51.100.5", "198.51.100.5", []string{"198.51.100.5/32"}},
		{"198.51.100.5", "198.51.100.20", []string{"198.51.100.5/32", "198.51.100.6/31", "198.51.100.8/29", "198.51.100.16/30", "198.51.100.20/32"}},
		{"0.0.0.0", "255.255.255.255", []string{"0.0.0.0/0"}},
		{"255.255.255.254", "255.255.255.255", []string{"255.255.255.254/31"}},
		{"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", []string{"2001:db8::/32"}},
		{"203.0.113.9", "203.0.113.8", nil},
		{"203.0.113.9", "2001:db8::1", nil},
	} {
		var got []string
		for _, p := range input.RangeCIDRs(netip.MustParseAddr(c.start), netip.MustParseAddr(c.end)) {
			got = append(got, p.String())
		}
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("RangeCIDRs(%s, %s) = %v, want %v", c.start, c.end, got, c.want)
		}
	}
}

// Every problem is reported, each under the name of the argument it came from
// with the value as given.
func TestParseProblemsNameTheirArgument(t *testing.T) {
	t.Parallel()
	_, err := input.Parse(input.Raw{
		Domains: []string{"co.uk", "ok.example.com"}, DomainsFile: writeList(t, "bad domain.org\n"),
		Orgs: []string{" "}, ASNs: []string{"ASxyz"}, CIDRs: []string{"1.2.3.4/99"},
		Exclude: []string{"a b"}, ExcludeFile: "/no/such/exclusions",
	})
	var probs clierr.Problems
	if !errors.As(err, &probs) {
		t.Fatalf("err = %v, want Problems", err)
	}
	got := map[string]string{}
	for _, p := range probs {
		got[p.Name] = p.Value
	}
	want := map[string]string{"domain": "co.uk", "domains-file": "bad domain.org", "org": " ", "asn": "ASxyz",
		"cidr": "1.2.3.4/99", "exclude": "a b", "exclude-file": "/no/such/exclusions"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("problems by name = %v, want %v", got, want)
	}
	_, err = input.Parse(input.Raw{DomainsFile: "/no/such/domains"})
	if !errors.As(err, &probs) || len(probs) != 1 || probs[0].Name != "domains-file" || probs[0].Value != "/no/such/domains" {
		t.Errorf("an unreadable domains file: %+v", probs)
	}
}
