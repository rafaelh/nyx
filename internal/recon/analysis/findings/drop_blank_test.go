package findings_test

import (
	"slices"
	"testing"

	tdt "github.com/rafaelh/nyx/internal/threatdata/threatdatatest"
)

// Optional missing fields must not leave empty parentheses or doubled spaces in finding text.
func TestDrop_BlankFieldsLeaveNoGaps(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.drop = dropListsOf(t,
		[]string{`{"cidr":"203.0.113.0/24","sblid":"SBL5"}`}, nil,
		[]string{`{"asn":64500}`})
	w.host("app.example.com", "203.0.113.17", "192.0.2.9")
	w.owner("203.0.113.17", 64501)
	w.owner("192.0.2.9", 64500)

	net := w.derive(t)["203.0.113.17"]
	if got, want := strs(net.Attrs["drop_networks"]), []string{"203.0.113.0/24 SBL5"}; !slices.Equal(got, want) {
		t.Errorf("drop_networks = %q, want %q", got, want)
	}
	if got, want := net.FoundText(), "address 203.0.113.17 in Spamhaus DROP network 203.0.113.0/24 (SBL5)"; got != want {
		t.Errorf("found = %q, want %q", got, want)
	}
	if want := "address 203.0.113.17 is in Spamhaus DROP network 203.0.113.0/24 (SBL5, list of " + dropV4Date + ")"; net.Detail != want {
		t.Errorf("detail = %q, want %q", net.Detail, want)
	}

	as := w.derive(t)["192.0.2.9"]
	if got, want := strs(as.Attrs["drop_asn"]), []string{"AS64500"}; !slices.Equal(got, want) {
		t.Errorf("drop_asn = %q, want %q", got, want)
	}
	if got, want := as.FoundText(), "address 192.0.2.9 in Spamhaus ASN-DROP AS64500"; got != want {
		t.Errorf("found = %q, want %q", got, want)
	}
	if want := "address 192.0.2.9 is in Spamhaus ASN-DROP AS64500 (list of " + dropASNDate + ")"; as.Detail != want {
		t.Errorf("detail = %q, want %q", as.Detail, want)
	}
}

// The found line of a drop-asn finding names the AS and its name.
func TestDrop_ASNFoundLine(t *testing.T) {
	t.Parallel()
	w := newAbusiveWorld()
	w.drop = dropListsOf(t, nil, nil, []string{tdt.ASNRow(64500, "BAD-AS", "RU", "example.net", "ripencc")})
	w.host("app.example.com", "203.0.113.17")
	w.owner("203.0.113.17", 64500)
	f := w.derive(t)["203.0.113.17"]
	if got, want := f.FoundText(), "address 203.0.113.17 in Spamhaus ASN-DROP AS64500 (BAD-AS)"; got != want {
		t.Errorf("found = %q, want %q", got, want)
	}
}
