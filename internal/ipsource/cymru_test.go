package ipsource_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/ipsource"
)

func TestOrigin_Answers(t *testing.T) {
	t.Parallel()
	const name = "1.1.1.1.origin.asn.cymru.com"
	cases := []struct {
		name  string
		reply egress.DNSResult
		want  ipsource.Owner
		found bool
	}{
		{"an origin", txt("13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"), ipsource.Owner{ASN: 13335, Prefix: "1.1.1.0/24"}, true},
		{"several origins take the first", txt("13335 64512 | 1.1.1.0/24 | AU | apnic | 2011-08-11"), ipsource.Owner{ASN: 13335, Prefix: "1.1.1.0/24"}, true},
		{"nxdomain", egress.DNSResult{RCode: egress.RCodeNXDomain}, ipsource.Owner{}, false},
		{"no answers", egress.DNSResult{RCode: egress.RCodeSuccess}, ipsource.Owner{}, false},
		{"an answer that does not parse", txt("none | x"), ipsource.Owner{}, false},
		{"too few fields", txt("13335"), ipsource.Owner{}, false},
		{"AS0 names no owner", txt("0 | 1.1.1.0/24 | AU | apnic | 2011-08-11"), ipsource.Owner{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := &dnsStub{results: map[string]egress.DNSResult{name: c.reply}}
			got, found, err := ipsource.Origin(context.Background(), r, netip.MustParseAddr("1.1.1.1"))
			if err != nil || found != c.found || got != c.want {
				t.Errorf("Origin = %+v, %v, %v; want %+v, %v, nil", got, found, err, c.want, c.found)
			}
		})
	}
}

func TestOrigin_AskedWithTheCymruName(t *testing.T) {
	t.Parallel()
	r := &dnsStub{}
	if _, _, err := ipsource.Origin(context.Background(), r, netip.MustParseAddr("2606:4700::1")); err != nil {
		t.Fatal(err)
	}
	if len(r.asked) != 1 || r.asked[0] != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.6.0.6.2.origin6.asn.cymru.com" {
		t.Errorf("asked %v", r.asked)
	}
}

func TestOrigin_Failures(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("1.1.1.1")
	boom := errors.New("no response")
	if _, found, err := ipsource.Origin(context.Background(), &dnsStub{err: boom}, addr); !errors.Is(err, boom) || found {
		t.Errorf("a transport failure: found=%v err=%v", found, err)
	}
	servfail := &dnsStub{results: map[string]egress.DNSResult{"1.1.1.1.origin.asn.cymru.com": {RCode: egress.RCodeServFail}}}
	if _, found, err := ipsource.Origin(context.Background(), servfail, addr); err == nil || found || err.Error() != "resolver answered rcode 2" {
		t.Errorf("SERVFAIL: found=%v err=%v", found, err)
	}
}

func TestASName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		reply egress.DNSResult
		want  string
	}{
		{"country suffix trimmed", txt("13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"), "CLOUDFLARENET"},
		{"a comma that is not a suffix stays", txt("1 | US | arin | 2010-07-14 | ACME, INC"), "ACME, INC"},
		{"nxdomain", egress.DNSResult{RCode: egress.RCodeNXDomain}, ""},
		{"short answer", txt("13335 | US"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := &dnsStub{results: map[string]egress.DNSResult{"AS13335.asn.cymru.com": c.reply}}
			got, err := ipsource.ASName(context.Background(), r, 13335)
			if err != nil || got != c.want {
				t.Errorf("ASName = %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

func TestASName_Failures(t *testing.T) {
	t.Parallel()
	if _, err := ipsource.ASName(context.Background(), &dnsStub{err: errors.New("x")}, 1); err == nil {
		t.Error("a transport failure should be an error")
	}
	servfail := &dnsStub{results: map[string]egress.DNSResult{"AS1.asn.cymru.com": {RCode: egress.RCodeServFail}}}
	if _, err := ipsource.ASName(context.Background(), servfail, 1); err == nil || err.Error() != "resolver answered rcode 2 for AS1" {
		t.Errorf("SERVFAIL: %v", err)
	}
}
