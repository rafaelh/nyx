package ipsource_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/ipsource"
)

const (
	boot4 = "https://data.iana.org/rdap/ipv4.json"
	boot6 = "https://data.iana.org/rdap/ipv6.json"
)

const bootstrapV4 = `{"services":[
 [["8.0.0.0/8"],["http://rdap.arin.net/registry/","https://rdap.arin.net/registry/"]],
 [["8.8.0.0/16"],["https://rdap.db.ripe.net/"]],
 [["1.0.0.0/8"],["https://rdap.apnic.net/"]],
 [["9.0.0.0/8"],["http://insecure.example/"]]]}`

const arinAnswer = `{"handle":"NET-8-8-8-0-2","startAddress":"8.8.8.0","endAddress":"8.8.8.255",
 "entities":[
  {"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse Desk"]]]},
  {"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","  Google LLC\u001b[31m "]]]}]}`

func newRDAPStub() *httpStub {
	return &httpStub{replies: map[string]egress.ThirdPartyResponse{
		boot4:                                 ok(bootstrapV4),
		"https://rdap.db.ripe.net/ip/8.8.8.8": ok(arinAnswer),
		"https://rdap.arin.net/registry/ip/8.1.1.1": ok(`{"handle":"NET-8","startAddress":"8.1.0.0","endAddress":"8.1.255.255"}`),
	}}
}

func TestLookup_FindsTheRegistration(t *testing.T) {
	t.Parallel()
	stub := newRDAPStub()
	var warns []string
	reg, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, netip.MustParseAddr("8.8.8.8"), func(s string) { warns = append(warns, s) })
	want := ipsource.Registration{
		Start: netip.MustParseAddr("8.8.8.0"), End: netip.MustParseAddr("8.8.8.255"),
		Registrant: "Google LLC", Registry: "ripe", Handle: "NET-8-8-8-0-2",
	}
	if err != nil || !found || reg != want || len(warns) != 0 {
		t.Errorf("Lookup = %+v, %v, %v, warnings %v; want %+v", reg, found, err, warns, want)
	}
}

func TestLookup_LongestPrefixPicksTheRegistry(t *testing.T) {
	t.Parallel()
	stub := newRDAPStub()
	reg, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, netip.MustParseAddr("8.1.1.1"), nil)
	if err != nil || !found || reg.Registry != "arin" {
		t.Errorf("Lookup = %+v, %v, %v; want the arin answer", reg, found, err)
	}
}

func TestLookup_NothingToRecord(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		addr string
	}{
		{"no registry holds the address", "203.0.113.1"},
		{"only an http service holds it", "9.9.9.9"},
		{"the registry answers 404", "1.1.1.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			reg, found, err := ipsource.Lookup(context.Background(), newRDAPStub(), &ipsource.Bootstrap{}, netip.MustParseAddr(c.addr), nil)
			if err != nil || found || reg != (ipsource.Registration{}) {
				t.Errorf("Lookup = %+v, %v, %v", reg, found, err)
			}
		})
	}
}

func TestLookup_HandleDefaultsToTheRange(t *testing.T) {
	t.Parallel()
	stub := newRDAPStub()
	stub.replies["https://rdap.db.ripe.net/ip/8.8.8.8"] = ok(`{"startAddress":"8.8.8.0","endAddress":"8.8.8.255"}`)
	reg, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, netip.MustParseAddr("8.8.8.8"), nil)
	if err != nil || !found || reg.Handle != "8.8.8.0-8.8.8.255" || reg.Registrant != "" {
		t.Errorf("Lookup = %+v, %v, %v", reg, found, err)
	}
}

func TestLookup_UnusableRanges(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"a range that leaves the address out": `{"startAddress":"8.8.9.0","endAddress":"8.8.9.255"}`,
		"a range of mixed families":           `{"startAddress":"8.8.8.0","endAddress":"::ffff"}`,
		"no range":                            `{"handle":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stub := newRDAPStub()
			stub.replies["https://rdap.db.ripe.net/ip/8.8.8.8"] = ok(body)
			var warns []string
			_, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, netip.MustParseAddr("8.8.8.8"), func(s string) { warns = append(warns, s) })
			want := "rdap: ripe (rdap.db.ripe.net) gave no address range for 8.8.8.8"
			if err != nil || found || !slices.Equal(warns, []string{want}) {
				t.Errorf("found=%v err=%v warnings=%q; want the warning %q", found, err, warns, want)
			}
		})
	}
}

func TestLookup_Referrals(t *testing.T) {
	t.Parallel()
	redirect := func(to string) egress.ThirdPartyResponse {
		return egress.ThirdPartyResponse{Status: 302, Header: map[string][]string{"Location": {to}}}
	}
	t.Run("followed to another registry", func(t *testing.T) {
		t.Parallel()
		stub := newRDAPStub()
		stub.replies["https://rdap.db.ripe.net/ip/8.8.8.8"] = redirect("https://rdap.arin.net/registry/ip/8.8.8.8")
		stub.replies["https://rdap.arin.net/registry/ip/8.8.8.8"] = ok(arinAnswer)
		reg, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, netip.MustParseAddr("8.8.8.8"), nil)
		if err != nil || !found || reg.Registry != "arin" {
			t.Errorf("Lookup = %+v, %v, %v", reg, found, err)
		}
	})
	t.Run("a relative referral resolves against the request", func(t *testing.T) {
		t.Parallel()
		stub := newRDAPStub()
		stub.replies["https://rdap.db.ripe.net/ip/8.8.8.8"] = redirect("/other/8.8.8.8")
		stub.replies["https://rdap.db.ripe.net/other/8.8.8.8"] = ok(arinAnswer)
		_, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, netip.MustParseAddr("8.8.8.8"), nil)
		if err != nil || !found {
			t.Errorf("found=%v err=%v", found, err)
		}
	})
	t.Run("a host that is not a registry is warned about and not asked", func(t *testing.T) {
		t.Parallel()
		stub := newRDAPStub()
		stub.replies["https://rdap.db.ripe.net/ip/8.8.8.8"] = redirect("https://evil.example/ip/8.8.8.8")
		var warns []string
		_, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, netip.MustParseAddr("8.8.8.8"), func(s string) { warns = append(warns, s) })
		want := "rdap: 8.8.8.8 is held by evil.example, which is not one of the registries; no registration is recorded"
		if err != nil || found || !slices.Equal(warns, []string{want}) || stub.count("https://evil.example/ip/8.8.8.8") != 0 {
			t.Errorf("found=%v err=%v warnings=%q", found, err, warns)
		}
	})
	t.Run("a referral that cannot be followed", func(t *testing.T) {
		t.Parallel()
		stub := newRDAPStub()
		stub.replies["https://rdap.db.ripe.net/ip/8.8.8.8"] = redirect("http://rdap.arin.net/registry/ip/8.8.8.8")
		var warns []string
		_, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, netip.MustParseAddr("8.8.8.8"), func(s string) { warns = append(warns, s) })
		want := `rdap: rdap.db.ripe.net referred the lookup of 8.8.8.8 to "http://rdap.arin.net/registry/ip/8.8.8.8", which cannot be followed; no registration is recorded`
		if err != nil || found || !slices.Equal(warns, []string{want}) {
			t.Errorf("found=%v err=%v warnings=%q", found, err, warns)
		}
	})
	t.Run("more than three referrals", func(t *testing.T) {
		t.Parallel()
		stub := newRDAPStub()
		stub.replies["https://rdap.db.ripe.net/ip/8.8.8.8"] = redirect("https://rdap.arin.net/registry/ip/8.8.8.8")
		stub.replies["https://rdap.arin.net/registry/ip/8.8.8.8"] = redirect("https://rdap.db.ripe.net/ip/8.8.8.8")
		var warns []string
		_, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, netip.MustParseAddr("8.8.8.8"), func(s string) { warns = append(warns, s) })
		want := "rdap: the lookup of 8.8.8.8 was referred more than 3 times; no registration is recorded"
		if err != nil || found || !slices.Equal(warns, []string{want}) {
			t.Errorf("found=%v err=%v warnings=%q", found, err, warns)
		}
		if n := stub.count("https://rdap.db.ripe.net/ip/8.8.8.8") + stub.count("https://rdap.arin.net/registry/ip/8.8.8.8"); n != 4 {
			t.Errorf("%d requests, want the first and three referrals", n)
		}
	})
}

func TestLookup_Failures(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("8.8.8.8")
	t.Run("a 429 from a registry names it", func(t *testing.T) {
		t.Parallel()
		stub := newRDAPStub()
		stub.replies["https://rdap.db.ripe.net/ip/8.8.8.8"] = egress.ThirdPartyResponse{Status: 429}
		_, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, addr, nil)
		var rl *ipsource.RateLimitedError
		if found || !errors.Is(err, ipsource.ErrQuota) || !errors.As(err, &rl) || rl.Host != "rdap.db.ripe.net" {
			t.Errorf("found=%v err=%v", found, err)
		}
	})
	t.Run("a 429 from the bootstrap names IANA", func(t *testing.T) {
		t.Parallel()
		stub := &httpStub{replies: map[string]egress.ThirdPartyResponse{boot4: {Status: 429}}}
		_, _, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, addr, nil)
		var rl *ipsource.RateLimitedError
		if !errors.Is(err, ipsource.ErrQuota) || !errors.As(err, &rl) || rl.Host != "data.iana.org" || err.Error() != "bootstrap ipv4.json: HTTP 429" {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("other failures are errors", func(t *testing.T) {
		t.Parallel()
		for name, c := range map[string]struct {
			url  string
			resp egress.ThirdPartyResponse
			want string
		}{
			"bootstrap 404":       {boot4, egress.ThirdPartyResponse{Status: 404}, "bootstrap ipv4.json: HTTP 404"},
			"bootstrap 500":       {boot4, egress.ThirdPartyResponse{Status: 500}, "bootstrap ipv4.json: HTTP 500"},
			"bootstrap truncated": {boot4, egress.ThirdPartyResponse{Status: 200, Truncated: true}, "bootstrap ipv4.json: response was larger than the 10 MiB limit"},
			"registry 500":        {"https://rdap.db.ripe.net/ip/8.8.8.8", egress.ThirdPartyResponse{Status: 500}, "HTTP 500"},
			"registry truncated":  {"https://rdap.db.ripe.net/ip/8.8.8.8", egress.ThirdPartyResponse{Status: 200, Truncated: true}, "response was larger than the 10 MiB limit"},
		} {
			stub := newRDAPStub()
			stub.replies[c.url] = c.resp
			_, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, addr, nil)
			if found || err == nil || err.Error() != c.want || errors.Is(err, ipsource.ErrQuota) {
				t.Errorf("%s: found=%v err=%v; want %q", name, found, err, c.want)
			}
		}
	})
	t.Run("unreadable bodies", func(t *testing.T) {
		t.Parallel()
		stub := newRDAPStub()
		stub.replies["https://rdap.db.ripe.net/ip/8.8.8.8"] = ok("<html>")
		if _, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, addr, nil); found || err == nil {
			t.Errorf("an unreadable answer: found=%v err=%v", found, err)
		}
		stub = newRDAPStub()
		stub.replies[boot4] = ok("{")
		if _, found, err := ipsource.Lookup(context.Background(), stub, &ipsource.Bootstrap{}, addr, nil); found || err == nil {
			t.Errorf("an unreadable bootstrap: found=%v err=%v", found, err)
		}
	})
}

func TestBootstrap_FetchedOncePerFamily(t *testing.T) {
	t.Parallel()
	stub := newRDAPStub()
	stub.replies[boot6] = ok(`{"services":[[["2001:4860::/32"],["https://rdap.arin.net/registry/"]]]}`)
	b := &ipsource.Bootstrap{}
	addrs := []string{"8.8.8.8", "8.1.1.1", "8.8.8.8", "2001:4860::1", "2001:4860::2"}
	var wg sync.WaitGroup
	for _, a := range addrs {
		wg.Go(func() {
			if _, _, err := ipsource.Lookup(context.Background(), stub, b, netip.MustParseAddr(a), nil); err != nil {
				t.Errorf("%s: %v", a, err)
			}
		})
	}
	wg.Wait()
	if stub.count(boot4) != 1 || stub.count(boot6) != 1 {
		t.Errorf("the bootstrap files were fetched %d and %d times, want once each", stub.count(boot4), stub.count(boot6))
	}
}

func TestBootstrap_AFailedFetchIsRemembered(t *testing.T) {
	t.Parallel()
	stub := &httpStub{replies: map[string]egress.ThirdPartyResponse{boot4: {Status: 500}}}
	b := &ipsource.Bootstrap{}
	for range 2 {
		if _, _, err := ipsource.Lookup(context.Background(), stub, b, netip.MustParseAddr("8.8.8.8"), nil); err == nil {
			t.Fatal("want an error")
		}
	}
	if n := stub.count(boot4); n != 1 {
		t.Errorf("%d fetches, want 1", n)
	}
}

func TestRegistries(t *testing.T) {
	t.Parallel()
	hosts := ipsource.RDAPHosts()
	want := []string{"data.iana.org", "rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net", "rdap.lacnic.net", "rdap.afrinic.net"}
	if !slices.Equal(hosts, want) {
		t.Errorf("RDAPHosts = %v", hosts)
	}
	if r, ok := ipsource.RegistryByHost("rdap.apnic.net"); !ok || r.Name != "apnic" || !r.Search || r.Base != "https://rdap.apnic.net/" {
		t.Errorf("RegistryByHost(apnic) = %+v, %v", r, ok)
	}
	if _, ok := ipsource.RegistryByHost("evil.example"); ok {
		t.Error("an unknown host is no registry")
	}
	rs := ipsource.Registries()
	rs[0].Name = "changed"
	if ipsource.Registries()[0].Name != "arin" {
		t.Error("Registries returns a copy")
	}
}

func TestVCardName(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		`["vcard",[["fn",{},"text","Example Pty Ltd"]]]`: "Example Pty Ltd",
		`["vcard",[["org",{},"text","x"]]]`:              "",
		`["vcard"]`:                                      "",
		`null`:                                           "",
		`"x"`:                                            "",
	} {
		if got := ipsource.VCardName([]byte(in)); got != want {
			t.Errorf("VCardName(%s) = %q, want %q", in, got, want)
		}
	}
}
