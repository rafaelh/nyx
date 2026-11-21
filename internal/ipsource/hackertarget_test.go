package ipsource_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/ipsource"
)

func TestHackerTargetLines(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, body string
		want       []string
		quota      bool
	}{
		{"empty", "", nil, false},
		{"no records", "No records found\n", nil, false},
		{"bad parameter", "error check your search parameter", nil, false},
		{"no dns a records", "No DNS A records found for 1.2.3.4", nil, false},
		{"quota", "API count exceeded - Increase Quota with Membership", nil, true},
		{"quota in any case", "  api COUNT exceeded", nil, true},
		{"lines trimmed, blanks dropped", " a.example.com \n\nb.example.com\r\n", []string{"a.example.com", "b.example.com"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, quota := ipsource.HackerTargetLines([]byte(c.body))
			if !slices.Equal(got, c.want) || quota != c.quota {
				t.Errorf("HackerTargetLines = %q, %v; want %q, %v", got, quota, c.want, c.quota)
			}
		})
	}
}

func TestReverseNames(t *testing.T) {
	t.Parallel()
	body := "B.example.com.\n*.a.example.com\na.example.com\nb.example.com\n1.2.3.4\nxn--bcher-kva.example\nbücher.example\n"
	names, quota, err := ipsource.ReverseNames([]byte(body))
	want := []string{"a.example.com", "b.example.com", "xn--bcher-kva.example"}
	if err != nil || quota || !slices.Equal(names, want) {
		t.Errorf("ReverseNames = %q, %v, %v; want %q", names, quota, err, want)
	}
}

func TestReverseNames_NotAList(t *testing.T) {
	t.Parallel()
	for _, line := range []string{"a b", "a\tb", "a,b", "<html>", "a>b"} {
		if _, _, err := ipsource.ReverseNames([]byte("ok.example.com\n" + line)); err == nil {
			t.Errorf("a reply with the line %q should be unreadable", line)
		}
	}
	if _, quota, err := ipsource.ReverseNames([]byte("API count exceeded")); !quota || err != nil {
		t.Errorf("quota reply: quota=%v err=%v", quota, err)
	}
	if names, quota, err := ipsource.ReverseNames([]byte("No records found")); names != nil || quota || err != nil {
		t.Errorf("no records: %v %v %v", names, quota, err)
	}
}

const reverseURL = "https://api.hackertarget.com/reverseiplookup/?q=203.0.113.9"

func TestHackerTargetReverse(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("203.0.113.9")
	stub := &httpStub{replies: map[string]egress.ThirdPartyResponse{reverseURL: ok("b.example.com\na.example.com\n")}}
	names, err := ipsource.HackerTargetReverse(context.Background(), stub, addr)
	if err != nil || !slices.Equal(names, []string{"a.example.com", "b.example.com"}) {
		t.Errorf("names = %q, err = %v", names, err)
	}
}

func TestHackerTargetReverse_Statuses(t *testing.T) {
	t.Parallel()
	addr := netip.MustParseAddr("203.0.113.9")
	cases := []struct {
		name  string
		resp  egress.ThirdPartyResponse
		err   error
		quota bool
		fail  bool
	}{
		{"429 is the quota", egress.ThirdPartyResponse{Status: 429}, nil, true, true},
		{"quota text in a 200", ok("API count exceeded"), nil, true, true},
		{"404 is no names", egress.ThirdPartyResponse{Status: 404}, nil, false, false},
		{"500 is an error", egress.ThirdPartyResponse{Status: 500}, nil, false, true},
		{"truncated is an error", egress.ThirdPartyResponse{Status: 200, Truncated: true, Body: []byte("a.example.com")}, nil, false, true},
		{"not a list is an error", ok("<html>oops</html>"), nil, false, true},
		{"transport error", egress.ThirdPartyResponse{}, errors.New("boom"), false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			stub := &httpStub{replies: map[string]egress.ThirdPartyResponse{reverseURL: c.resp}}
			if c.err != nil {
				stub.errs = map[string]error{reverseURL: c.err}
			}
			names, err := ipsource.HackerTargetReverse(context.Background(), stub, addr)
			if (err != nil) != c.fail || errors.Is(err, ipsource.ErrQuota) != c.quota || names != nil {
				t.Errorf("names = %q, err = %v; want fail=%v quota=%v", names, err, c.fail, c.quota)
			}
		})
	}
}

func TestHackerTargetReverse_RateLimitNamesTheHost(t *testing.T) {
	t.Parallel()
	stub := &httpStub{replies: map[string]egress.ThirdPartyResponse{reverseURL: {Status: 429}}}
	_, err := ipsource.HackerTargetReverse(context.Background(), stub, netip.MustParseAddr("203.0.113.9"))
	var rl *ipsource.RateLimitedError
	if !errors.As(err, &rl) || rl.Host != "api.hackertarget.com" || !strings.Contains(err.Error(), "429") {
		t.Errorf("err = %v", err)
	}
}
