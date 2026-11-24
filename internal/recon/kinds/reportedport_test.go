package kinds_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/scope"
)

// portWorld is example.com with 198.51.100.0/24 in scope, 203.0.113.5 a
// dedicated address and the given ports found closed.
func portWorld(closed ...string) *kinds.Visibility {
	var ap []netip.AddrPort
	for _, c := range closed {
		ap = append(ap, netip.MustParseAddrPort(c))
	}
	inv := inventory.New(inventory.Data{
		Resolutions: []inventory.Resolution{{Name: "www.example.com", Type: "A", Value: "203.0.113.5"}},
		Owners:      map[netip.Addr]provider.Owner{netip.MustParseAddr("203.0.113.5"): {ASN: 64500, Holder: "ACME-NET", Known: true}},
		ClosedPorts: ap,
	}, provider.Default())
	sc := scope.New(scope.Config{Roots: []string{"example.com"}, Netblocks: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Resolutions: inv.Addrs(), WildcardOnly: inv.WildcardOnly(), Exclusions: []input.Exclusion{}})
	return kinds.NewVisibility(sc, inv)
}

// Port reports obey eligibility and confirmed-closed evidence; confirmed open records remain
// authoritative.
func TestReportedPortShown(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, key string
		closed    []string
		want      bool
	}{
		{"dedicated address", "203.0.113.5:8080", nil, true},
		{"netblock address", "198.51.100.7:22", nil, true},
		{"address nothing is known about", "192.0.2.9:80", nil, false},
		{"found closed", "203.0.113.5:8080", []string{"203.0.113.5:8080"}, false},
		{"another port closed", "203.0.113.5:8080", []string{"203.0.113.5:8081"}, true},
		{"key that is not an address and port", "203.0.113.5", nil, false},
	} {
		if got := portWorld(c.closed...).Shown(kinds.ReportedPort, rec(c.key)); got != c.want {
			t.Errorf("%s: Shown(reported_port %s) = %v, want %v", c.name, c.key, got, c.want)
		}
	}
	if !portWorld("203.0.113.5:8080").Shown(kinds.OpenPort, rec("203.0.113.5:8080")) {
		t.Error("a closed report must not hide an open_port record")
	}
}

// The open-port count is split: nyx's own handshakes, and the ports others
// reported that nyx has neither confirmed nor found closed.
func TestTotalsSplitOpenPorts(t *testing.T) {
	t.Parallel()
	gone := rec("203.0.113.5:9999")
	gone.Current = false
	got := portWorld("203.0.113.5:8082").Totals(map[string][]store.Record{
		"open_port": {rec("203.0.113.5:8080"), rec("198.51.100.7:22")},
		"reported_port": {
			rec("203.0.113.5:8080"), // confirmed: counted once, as confirmed
			rec("203.0.113.5:8081"), // reported only
			rec("203.0.113.5:8082"), // found closed
			rec("192.0.2.9:80"),     // not port-eligible
			gone,
		},
	})
	if got["open ports (confirmed)"] != 2 || got["open ports (third-party reported)"] != 1 {
		t.Errorf("totals = %v, want 2 confirmed and 1 reported", got)
	}
	if _, ok := got["open ports"]; ok {
		t.Errorf("the old category is still listed: %v", got)
	}
	// Both categories are listed when empty.
	empty := portWorld().Totals(nil)
	if v, ok := empty["open ports (third-party reported)"]; !ok || v != 0 {
		t.Errorf("empty totals = %v", empty)
	}
}

func TestEncodeBanner(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"SSH-2.0-x":      "SSH-2.0-x",
		"a\x1b[31mb\r\n": `a\x1b[31mb\r\n`,
		"caf\xe9":        `caf\xe9`,
		"\"q\"":          `\"q\"`,
	} {
		if got := kinds.EncodeBanner(in); got != want {
			t.Errorf("EncodeBanner(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirstLine(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 300)
	for _, c := range []struct{ in, want string }{
		{"HTTP/1.1 200 OK\r\nServer: x", "HTTP/1.1 200 OK"},
		{"one\ntwo", "one"},
		{"one\rtwo", "one"},
		{"", ""},
		{long, long[:256]},
		{"é" + long, "é" + long[:255]},
	} {
		if got := kinds.ShodanBanner(c.in); got != kinds.EncodeBanner(c.want) {
			t.Errorf("ShodanBanner(%.20q) = %q, want %q", c.in, got, kinds.EncodeBanner(c.want))
		}
	}
}
