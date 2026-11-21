package iplookup

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/rafaelh/nyx/internal/addrkind"
	"github.com/rafaelh/nyx/internal/clierr"
)

func TestNewRecord(t *testing.T) {
	t.Parallel()
	hosts := []string{"a.example.com"}
	r := NewRecord(Address{Addr: netip.MustParseAddr("2001:DB8:0:0::1"), Hostnames: hosts})
	if r.Address != "2001:db8::1" {
		t.Errorf("address %q, want the canonical form", r.Address)
	}
	if r.Kind != addrkind.Of(netip.MustParseAddr("2001:db8::1")) || r.Kind != "documentation" {
		t.Errorf("kind %q, want documentation", r.Kind)
	}
	hosts[0] = "changed"
	if !slices.Equal(r.Hostnames, []string{"a.example.com"}) {
		t.Errorf("hostnames %q share the caller's slice", r.Hostnames)
	}
	if r.Hostnames == nil || r.Failures == nil {
		t.Errorf("hostnames and failures are nil, want empty lists: %#v", r)
	}
	if r.ASN != nil || r.PTR != nil || r.ReverseIP != nil || r.Ports != nil {
		t.Errorf("the other keys must start unknown (null): %#v", r)
	}
	pub := NewRecord(Address{Addr: netip.MustParseAddr("1.1.1.1")})
	if pub.Kind != addrkind.Public || pub.Address != "1.1.1.1" || len(pub.Hostnames) != 0 {
		t.Errorf("public record %#v", pub)
	}
}

func TestRecord_Failures(t *testing.T) {
	t.Parallel()
	r := NewRecord(Address{Addr: netip.MustParseAddr("1.1.1.1")})
	if r.Failed(SourceCymru) {
		t.Error("a new record has a failure")
	}
	r.AddFailure(Failure{Source: SourceCymru, Code: clierr.Timeout, Message: "late", Transient: true})
	r.AddFailure(Failure{Source: SourceHackerTarget, Code: clierr.RateLimited, Quota: true})
	if !r.Failed(SourceCymru) || !r.Failed(SourceHackerTarget) {
		t.Error("a failure added is not found, a quota failure included")
	}
	if r.Failed(SourceRDAP) || r.Failed(SourceProbe) {
		t.Error("a source with no failure is reported failed")
	}
	if len(r.Failures) != 2 || r.Failures[0].Source != SourceCymru {
		t.Errorf("failures %#v, want both in the order added", r.Failures)
	}
}

func TestSources_Order(t *testing.T) {
	t.Parallel()
	got := Sources()
	want := []Source{"cymru", "rdap", "ptr", "ripestat", "internetdb", "hackertarget", "probe"}
	if !slices.Equal(got, want) {
		t.Errorf("sources %v, want %v", got, want)
	}
	got[0] = "changed"
	if Sources()[0] != SourceCymru {
		t.Error("Sources returns a shared slice")
	}
}

func TestNetblock(t *testing.T) {
	t.Parallel()
	a := netip.MustParseAddr
	for _, c := range []struct {
		start, end, want string
	}{
		{"1.1.1.0", "1.1.1.255", "1.1.1.0/24"},
		{"8.8.8.8", "8.8.8.8", "8.8.8.8/32"},
		{"10.0.0.0", "10.0.0.2", "10.0.0.0-10.0.0.2"},
		{"10.0.0.1", "10.0.0.2", "10.0.0.1-10.0.0.2"},
		{"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::/32"},
		{"2001:db8::", "2001:db9::1", "2001:db8::-2001:db9::1"},
		{"::ffff:1.1.1.0", "::ffff:1.1.1.255", "1.1.1.0/24"},
	} {
		if got := Netblock(a(c.start), a(c.end)); got != c.want {
			t.Errorf("Netblock(%s, %s) = %q, want %q", c.start, c.end, got, c.want)
		}
	}
	if got := Netblock(netip.Addr{}, netip.Addr{}); got != "" {
		t.Errorf("an invalid range gave %q", got)
	}
}

func TestExpiry(t *testing.T) {
	t.Parallel()
	zone := time.FixedZone("AEDT", 11*3600)
	got := Expiry(time.Date(2027, 1, 1, 5, 0, 0, 0, zone)) // 2026-12-31 18:00 UTC
	if got != "2026-12-31" {
		t.Errorf("Expiry = %q, want the UTC date 2026-12-31", got)
	}
}

func TestBannerText(t *testing.T) {
	t.Parallel()
	if got := BannerText([]byte("SSH-2.0-OpenSSH_9.6\r\n")); got != "SSH-2.0-OpenSSH_9.6\r\n" {
		t.Errorf("trailing line end kept: %q", got)
	}
	if got := BannerText([]byte("a\xffb")); got != "a�b" {
		t.Errorf("invalid UTF-8: %q", got)
	}
	if got := BannerText(nil); got != "" {
		t.Errorf("no banner: %q", got)
	}
	long := BannerText([]byte(strings.Repeat("x", 3000)))
	if len(long) != MaxBanner {
		t.Errorf("a long banner is %d bytes, want %d", len(long), MaxBanner)
	}
	// A cut through the middle of a character drops the character, not half of it.
	split := BannerText([]byte(strings.Repeat("x", MaxBanner-1) + "é" + "tail"))
	if !utf8.ValidString(split) || strings.ContainsRune(split, utf8.RuneError) {
		t.Errorf("a split character reached the text: %q", split[len(split)-4:])
	}
	if len(split) != MaxBanner-1 {
		t.Errorf("split banner is %d bytes, want %d", len(split), MaxBanner-1)
	}
	whole := BannerText([]byte(strings.Repeat("x", MaxBanner-2) + "é"))
	if !strings.HasSuffix(whole, "é") || len(whole) != MaxBanner {
		t.Errorf("a character that fits was dropped: %d bytes", len(whole))
	}
}
