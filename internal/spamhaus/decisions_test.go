package spamhaus_test

import (
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/spamhaus"
)

// The parse decisions the main tests leave open: what counts as missing, which control characters
// refuse a list, and which text the parser never reads.
func TestParse_Decisions(t *testing.T) {
	t.Parallel()
	r1 := `{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"arin"}`
	r6 := `{"cidr":"2001:db8::/32","sblid":"SBL6","rir":"apnic"}`
	a1 := `{"asn":64500,"rir":"ripencc","domain":"example.net","cc":"RU","asname":"BAD-AS"}`
	m := func(n int) string { return meta(v4Time, n) }
	for _, tc := range []struct {
		name string
		v6   bool
		asn  bool
		b    []byte
		ok   bool
	}{
		{"an empty SBL ID", false, false, file(r1, `{"cidr":"198.51.100.0/24","sblid":"","rir":"arin"}`, m(2)), false},
		{"an empty CIDR", false, false, file(r1, `{"cidr":"","sblid":"SBL2"}`, m(2)), false},
		{"a null SBL ID", false, false, file(r1, `{"cidr":"198.51.100.0/24","sblid":null}`, m(2)), false},
		{"a null CIDR", false, false, file(r1, `{"cidr":null,"sblid":"SBL2"}`, m(2)), false},
		{"DEL in a RIR", false, false, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","rir":"ar\u007fin"}`, m(2)), false},
		{"DEL in a domain", false, true, file(a1, `{"asn":64501,"domain":"x\u007f.example"}`, m(2)), false},
		{"DEL in the terms", false, false, file(r1, `{"type":"metadata","timestamp":1790000000,"records":1,"terms":"x\u007f"}`), false},
		{"a control character in an unknown field", false, false, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","note":"a\u0007b"}`, m(2)), true},
		{"a control character in an unknown ASN field", false, true, file(a1, `{"asn":64501,"note":"a\u009bb"}`, m(2)), true},
		{"a control character in an unknown metadata field", false, false, file(r1, `{"type":"metadata","timestamp":1790000000,"records":1,"note":"a\u0007"}`), true},
		{"an IPv4-mapped prefix in DROPv6", true, false, file(r6, `{"cidr":"::ffff:192.0.2.0/120","sblid":"SBL7"}`, m(2)), false},
		{"an IPv4-mapped prefix in DROP", false, false, file(r1, `{"cidr":"::ffff:192.0.2.0/120","sblid":"SBL7"}`, m(2)), false},
		{"a prefix with a zone", true, false, file(r6, `{"cidr":"fe80::%eth0/64","sblid":"SBL7"}`, m(2)), false},
		{"no records count", false, false, file(r1, `{"type":"metadata","timestamp":1790000000}`), false},
		{"a records count that is not a number", false, false, file(r1, `{"type":"metadata","timestamp":1790000000,"records":"1"}`), false},
		{"an ASN that is not whole", false, true, file(a1, `{"asn":64501.5}`, m(2)), false},
		{"CRLF line ends", false, false, []byte(r1 + "\r\n" + m(1) + "\r\n"), true},
	} {
		var err error
		if tc.asn {
			_, err = spamhaus.ParseASNDrop(tc.b)
		} else {
			_, err = spamhaus.ParseDrop(tc.b, tc.v6)
		}
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// An ASN list built by hand, with no parse behind it, still matches.
func TestASN_ListMadeByHand(t *testing.T) {
	t.Parallel()
	l := spamhaus.Lists{ASNs: spamhaus.ASNList{
		Meta:    spamhaus.Meta{Timestamp: asnTime},
		Entries: []spamhaus.ASNEntry{{ASN: 64500, ASName: "BAD-AS", Country: "RU"}},
	}}
	want := []spamhaus.ASNMatch{{ASN: 64500, ASName: "BAD-AS", Country: "RU", Updated: asnDate}}
	if got := l.ASN(64500); !slices.Equal(got, want) {
		t.Errorf("ASN(64500) = %+v, want %+v", got, want)
	}
	if got := l.ASN(64501); len(got) != 0 || got == nil {
		t.Errorf("ASN(64501) = %#v, want an empty list that is not nil", got)
	}
	if got := (spamhaus.Lists{}).Networks(addr("192.0.2.1")); len(got) != 0 || got == nil {
		t.Errorf("Networks on empty lists = %#v, want an empty list that is not nil", got)
	}
}

// A bundle's lists are cut at the markers whatever the blank lines around them, and a bundle with no
// final newline reads.
func TestParseBundle_Layout(t *testing.T) {
	t.Parallel()
	v4, v6, asn := withMeta(v4Time, v4Rows...), withMeta(v6Time, v6Rows...), withMeta(asnTime, asnRows...)
	b := append([]byte("\n"), spamhaus.Bundle(v4, v6, asn)...)
	b = b[:len(b)-1] // no final newline
	l, err := spamhaus.ParseBundle(b)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if len(l.V4.Entries) != len(v4Rows) || len(l.ASNs.Entries) != len(asnRows) {
		t.Errorf("entries = %d, %d, %d", len(l.V4.Entries), len(l.V6.Entries), len(l.ASNs.Entries))
	}
}
