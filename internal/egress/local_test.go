package egress_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/egress/egresstest"
)

// localFixture is an Egress whose "this machine's resolver" is the fake server.
func localFixture(t *testing.T, opts egress.Options) (egress.LocalResolver, *egresstest.DNS) {
	t.Helper()
	d := egresstest.NewDNS(t)
	opts.LocalResolverAddr = d.Addr
	if opts.DNSTimeout == 0 {
		opts.DNSTimeout = 2 * time.Second
	}
	return egress.New(opts).Local(), d
}

func TestLocalAddrsReturnsBothFamilies(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{})
	d.A("nas.corp.example", "192.0.2.10", "2001:db8::10")
	got, err := l.Addrs(context.Background(), "nas.corp.example")
	if err != nil {
		t.Fatalf("Addrs: %v %v", got, err)
	}
	slices.SortFunc(got, netip.Addr.Compare)
	want := []netip.Addr{addr("192.0.2.10"), addr("2001:db8::10")}
	if !slices.Equal(got, want) {
		t.Errorf("Addrs = %v, want %v", got, want)
	}
	for _, a := range got {
		if a != a.Unmap() {
			t.Errorf("%v is not unmapped", a)
		}
	}
	if d.Count("nas.corp.example", "A") == 0 || d.Count("nas.corp.example", "AAAA") == 0 {
		t.Errorf("want an A and an AAAA query at the local resolver, got A=%d AAAA=%d",
			d.Count("nas.corp.example", "A"), d.Count("nas.corp.example", "AAAA"))
	}
}

func TestLocalAddrsSingleLabel(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{})
	d.A("intranet", "192.0.2.20")
	got, err := l.Addrs(context.Background(), "intranet")
	if err != nil || !slices.Equal(got, []netip.Addr{addr("192.0.2.20")}) {
		t.Fatalf("Addrs: %v %v", got, err)
	}
}

func TestLocalAddrsNXDomainIsNotFound(t *testing.T) {
	t.Parallel()
	l, _ := localFixture(t, egress.Options{})
	got, err := l.Addrs(context.Background(), "nothing.corp.example")
	if err != nil {
		t.Fatalf("NXDOMAIN must not be an error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Addrs = %v, want no addresses", got)
	}
}

func TestLocalAddrsNoAddressesIsNotFound(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{})
	d.TXT("txtonly.corp.example", "hello") // the name exists, with neither A nor AAAA
	got, err := l.Addrs(context.Background(), "txtonly.corp.example")
	if err != nil || len(got) != 0 {
		t.Errorf("Addrs = %v %v, want no addresses and no error", got, err)
	}
}

func TestLocalAddrsTimeout(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{DNSTimeout: 150 * time.Millisecond})
	d.A("slow.corp.example", "192.0.2.30")
	d.Drop("slow.corp.example")
	start := time.Now()
	_, err := l.Addrs(context.Background(), "slow.corp.example")
	if !errors.Is(err, egress.ErrLocalTimeout) {
		t.Fatalf("err = %v, want ErrLocalTimeout", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("took %v; the DNS timeout is 150ms", el)
	}
}

func TestLocalAddrsServFailIsAnErrorNotATimeout(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{})
	d.Rcode("broken.corp.example", egress.RCodeServFail)
	got, err := l.Addrs(context.Background(), "broken.corp.example")
	if err == nil {
		t.Fatalf("SERVFAIL must be an error, got %v", got)
	}
	if errors.Is(err, egress.ErrLocalTimeout) {
		t.Errorf("SERVFAIL = %v; want a plain error", err)
	}
}

func TestLocalAddrsCancelledIsNotATimeout(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{DNSTimeout: 5 * time.Second})
	d.A("slow.corp.example", "192.0.2.30")
	d.Drop("slow.corp.example")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err := l.Addrs(ctx, "slow.corp.example")
	if !errors.Is(err, context.Canceled) || errors.Is(err, egress.ErrLocalTimeout) {
		t.Errorf("err = %v, want the cancellation", err)
	}
}

func TestLocalPTR(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{})
	d.PTR("192.0.2.40", "nas.corp.example")
	d.PTR("192.0.2.40", "storage.corp.example")
	names, err := l.PTR(context.Background(), addr("192.0.2.40"))
	if err != nil {
		t.Fatalf("PTR: %v %v", names, err)
	}
	slices.Sort(names)
	if want := []string{"nas.corp.example", "storage.corp.example"}; !slices.Equal(names, want) {
		t.Errorf("names = %v, want %v (lower case, no trailing dot)", names, want)
	}
	if len(d.Queried("PTR")) == 0 {
		t.Error("no PTR query reached the local resolver")
	}
}

func TestLocalPTRIPv6(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{})
	d.PTR("2001:db8::40", "v6.corp.example")
	names, err := l.PTR(context.Background(), addr("2001:db8::40"))
	if err != nil || !slices.Equal(names, []string{"v6.corp.example"}) {
		t.Errorf("PTR: %v %v", names, err)
	}
}

// A name that is not a valid hostname is left out, and the valid names beside it are the answer.
func TestLocalPTRKeepsTheValidNames(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{})
	d.PTR("192.0.2.44", "nas.corp.example")
	d.PTR("192.0.2.44", "bad\\032name.corp.example")
	names, err := l.PTR(context.Background(), addr("192.0.2.44"))
	if err != nil || !slices.Equal(names, []string{"nas.corp.example"}) {
		t.Errorf("PTR: %v %v, want the valid name and no error", names, err)
	}
}

func TestLocalPTRNotFound(t *testing.T) {
	t.Parallel()
	l, _ := localFixture(t, egress.Options{})
	names, err := l.PTR(context.Background(), addr("192.0.2.41"))
	if err != nil || len(names) != 0 {
		t.Errorf("PTR: %v %v, want no names and no error", names, err)
	}
}

func TestLocalPTRTimeout(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{DNSTimeout: 150 * time.Millisecond})
	d.PTR("192.0.2.42", "x.corp.example")
	d.Drop("42.2.0.192.in-addr.arpa")
	if _, err := l.PTR(context.Background(), addr("192.0.2.42")); !errors.Is(err, egress.ErrLocalTimeout) {
		t.Errorf("err = %v, want ErrLocalTimeout", err)
	}
}

func TestLocalPTRServFailIsAnError(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{})
	d.Rcode("43.2.0.192.in-addr.arpa", egress.RCodeServFail)
	_, err := l.PTR(context.Background(), addr("192.0.2.43"))
	if err == nil || errors.Is(err, egress.ErrLocalTimeout) {
		t.Errorf("PTR err=%v, want a plain error", err)
	}
}

// Lookups share the DNS rate limiter.
func TestLocalLookupsAreRateLimited(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{RateDNS: 10})
	d.A("a.corp.example", "192.0.2.50")
	start := time.Now()
	for range 13 { // the first ten use the burst; each of the rest waits 100ms
		if _, err := l.Addrs(context.Background(), "a.corp.example"); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 250*time.Millisecond {
		t.Errorf("13 lookups at 10/s took %v; want >= 300ms", el)
	}
}

func TestLocalLookupHonoursCancelWhileWaitingForTheLimiter(t *testing.T) {
	t.Parallel()
	l, d := localFixture(t, egress.Options{RateDNS: 1})
	d.A("a.corp.example", "192.0.2.50")
	if _, err := l.Addrs(context.Background(), "a.corp.example"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.Addrs(ctx, "a.corp.example"); err == nil {
		t.Error("a lookup that cannot get a token before its deadline must fail")
	}
}
