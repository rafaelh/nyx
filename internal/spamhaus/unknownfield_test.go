package spamhaus_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/spamhaus"
)

// Reject controls throughout JSON, including unknown nested values and keys, even when
// syntactic JSON remains valid.
func TestParse_ControlCharacterInAnUnknownField(t *testing.T) {
	t.Parallel()
	r1 := `{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"arin"}`
	r6 := `{"cidr":"2001:db8::/32","sblid":"SBL6","rir":"apnic"}`
	a1 := `{"asn":64500,"rir":"ripencc","domain":"example.net","cc":"RU","asname":"BAD-AS"}`
	m := func(n int) string { return meta(v4Time, n) }
	type list int
	const (
		v4 list = iota
		v6
		asn
	)
	for _, tc := range []struct {
		name string
		list list
		b    []byte
	}{
		// An unknown top-level field's text, in each kind of line.
		{"a C0 character in a DROP row", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","rir":"arin","note":"a\u0007b"}`, m(2))},
		{"an escape in a DROP row", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","note":"\u001b[31mred"}`, m(2))},
		{"a tab in a DROP row", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","note":"a\tb"}`, m(2))},
		{"DEL in a DROP row", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","note":"a\u007fb"}`, m(2))},
		{"a C1 character in a DROPv6 row", v6, file(r6, `{"cidr":"2001:db8:1::/48","sblid":"SBL7","note":"a\u0085b"}`, m(2))},
		{"a C1 character in an ASN-DROP row", asn, file(a1, `{"asn":64501,"cc":"US","note":"a\u0085b"}`, m(2))},
		{"a C0 character in an ASN-DROP row", asn, file(a1, `{"asn":64501,"note":"\u0000"}`, m(2))},
		{"a C0 character in the metadata", v4, file(r1, `{"type":"metadata","timestamp":1790000000,"records":1,"note":"a\u0007"}`)},
		{"a C1 character in the metadata", asn, file(a1, `{"type":"metadata","timestamp":1790000000,"records":1,"copyright":"(c) Spamhaus","note":"\u009b31m"}`)},
		{"DEL in the metadata", v6, file(r6, `{"type":"metadata","timestamp":1790000000,"records":1,"note":"x\u007f"}`)},

		// Nested in an unknown field's object or array.
		{"in an object in a DROP row", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","extra":{"a":"ok","b":"x\u0085"}}`, m(2))},
		{"in an array in a DROP row", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","tags":["ok","x\u0007"]}`, m(2))},
		{"deep in an ASN-DROP row", asn, file(a1, `{"asn":64501,"extra":[1,{"a":[true,null,"x\u001b"]}]}`, m(2))},
		{"in an array in the metadata", v4, file(r1, `{"type":"metadata","timestamp":1790000000,"records":1,"notes":["ok",{"a":"\u0085"}]}`)},

		// In an unknown field's key.
		{"in a key in a DROP row", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","no\u0007te":"x"}`, m(2))},
		{"in a key in an ASN-DROP row", asn, file(a1, `{"asn":64501,"no\u0085te":1}`, m(2))},
		{"in a key in the metadata", v4, file(r1, `{"type":"metadata","timestamp":1790000000,"records":1,"\u001bnote":"x"}`)},
		{"in a nested key in a DROP row", v4, file(r1, `{"cidr":"198.51.100.0/24","sblid":"SBL2","extra":{"k\u007f":"x"}}`, m(2))},
	} {
		var err error
		switch tc.list {
		case v4, v6:
			_, err = spamhaus.ParseDrop(tc.b, tc.list == v6)
		case asn:
			_, err = spamhaus.ParseASNDrop(tc.b)
		}
		if err == nil {
			t.Errorf("%s: accepted, want refused\n%s", tc.name, tc.b)
		}
	}
}

// A bundle fails as a whole when one of its lists holds a control character in an unknown field.
func TestParseBundle_ControlCharacterInAnUnknownField(t *testing.T) {
	t.Parallel()
	v4, v6 := withMeta(v4Time, v4Rows...), withMeta(v6Time, v6Rows...)
	asn := withMeta(asnTime, append(slices.Clone(asnRows), `{"asn":64999,"cc":"US","note":"a\u0085b"}`)...)
	if _, err := spamhaus.ParseBundle(spamhaus.Bundle(v4, v6, asn)); err == nil {
		t.Error("ParseBundle accepted a bundle whose ASN-DROP holds a control character in an unknown field")
	}
}

// Ignore clean unknown fields regardless of type or nesting without changing recognised data.
func TestParse_CleanUnknownFieldsPass(t *testing.T) {
	t.Parallel()
	l := mustDrop(t, withMeta(v4Time,
		`{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"arin","note":"added 2026-09-01"}`,
		`{"cidr":"198.51.100.0/24","sblid":"SBL2","size":256,"listed":true,"gone":null}`,
		`{"cidr":"203.0.113.0/24","sblid":"SBL3","extra":{"a":"b","n":[1,"two",{"c":"Ünïcode – ok"}]},"kéy":"v"}`), false)
	want := []spamhaus.NetworkEntry{
		{CIDR: netip.MustParsePrefix("192.0.2.0/24"), SBLID: "SBL1", RIR: "arin"},
		{CIDR: netip.MustParsePrefix("198.51.100.0/24"), SBLID: "SBL2"},
		{CIDR: netip.MustParsePrefix("203.0.113.0/24"), SBLID: "SBL3"},
	}
	if !slices.Equal(l.Entries, want) {
		t.Errorf("DROP entries = %+v, want %+v", l.Entries, want)
	}

	l6 := mustDrop(t, withMeta(v6Time, `{"cidr":"2001:db8::/32","sblid":"SBL6","tags":["a","b"]}`), true)
	if len(l6.Entries) != 1 || l6.Entries[0].SBLID != "SBL6" {
		t.Errorf("DROPv6 entries = %+v, want SBL6 alone", l6.Entries)
	}

	a := mustASNDrop(t, withMeta(asnTime,
		`{"asn":64500,"asname":"BAD-AS","cc":"RU","note":"Serviços Ltd"}`,
		`{"asn":64501,"weight":1.5,"extra":{"since":"2026","flags":[false,null]}}`))
	wantASN := []spamhaus.ASNEntry{{ASN: 64500, ASName: "BAD-AS", Country: "RU"}, {ASN: 64501}}
	if !slices.Equal(a.Entries, wantASN) {
		t.Errorf("ASN-DROP entries = %+v, want %+v", a.Entries, wantASN)
	}

	md := mustDrop(t, file(`{"cidr":"192.0.2.0/24","sblid":"SBL1"}`,
		`{"type":"metadata","timestamp":1790000000,"records":1,"size":1234,"version":"2","notes":["clean",{"a":"b"}],"copyright":"(c) Spamhaus"}`), false).Meta
	if md.Records != 1 || md.Copyright != "(c) Spamhaus" || md.Terms != "" || md.Timestamp.Unix() != 1790000000 {
		t.Errorf("metadata = %+v", md)
	}
}
