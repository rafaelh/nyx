package egress_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/rafaelh/nyx/internal/egress"
)

// cancelBudget is how long a cancelled read may take to return. The reads under
// test would otherwise block for five seconds.
const cancelBudget = 500 * time.Millisecond

// cancelAfterSignal waits until the server has a request before cancelling a client blocked in
// response reading.
func cancelAfterSignal(t *testing.T, ready <-chan struct{}, cancel context.CancelFunc) <-chan time.Time {
	t.Helper()
	at := make(chan time.Time, 1)
	go func() {
		select {
		case <-ready:
		case <-time.After(3 * time.Second):
			t.Error("the server never received the request")
		}
		time.Sleep(50 * time.Millisecond)
		at <- time.Now()
		cancel()
	}()
	return at
}

func assertPromptCancel(t *testing.T, err error, at <-chan time.Time) {
	t.Helper()
	returned := time.Now()
	cancelled := <-at
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want the context's error", err)
	}
	if d := returned.Sub(cancelled); d > cancelBudget {
		t.Errorf("returned %v after the cancel, want under %v", d, cancelBudget)
	}
}

// signal closes a channel once, however many times it is called.
type signal struct {
	once sync.Once
	ch   chan struct{}
}

func newSignal() *signal { return &signal{ch: make(chan struct{})} }
func (s *signal) fire()  { s.once.Do(func() { close(s.ch) }) }

// A lookup against a server that never answers ends when the context is cancelled.
func TestDNSCancelEndsSilentUDPRead(t *testing.T) {
	t.Parallel()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	got := newSignal()
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			got.fire()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	at := cancelAfterSignal(t, got.ch, cancel)
	_, err = resolver(pc.LocalAddr().String(), 5*time.Second).Query(ctx, "x.example.com", mdns.TypeA)
	assertPromptCancel(t, err, at)
}

// truncatingServer forces UDP-to-TCP fallback, then holds TCP silent and signals when
// connected.
func truncatingServer(t *testing.T) (string, *signal) {
	t.Helper()
	var pc net.PacketConn
	var ln net.Listener
	for range 20 {
		p, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", p.LocalAddr().String())
		if err == nil {
			pc, ln = p, l
			break
		}
		_ = p.Close()
	}
	if pc == nil {
		t.Skip("no port free for both UDP and TCP")
	}
	t.Cleanup(func() { _ = pc.Close(); _ = ln.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := new(mdns.Msg)
			if q.Unpack(buf[:n]) != nil {
				continue
			}
			r := new(mdns.Msg).SetReply(q)
			r.Truncated = true
			if b, err := r.Pack(); err == nil {
				_, _ = pc.WriteTo(b, from)
			}
		}
	}()
	tcpSeen := newSignal()
	go func() {
		var held []net.Conn
		defer func() {
			for _, c := range held {
				_ = c.Close()
			}
		}()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			held = append(held, c)
			tcpSeen.fire()
		}
	}()
	return pc.LocalAddr().String(), tcpSeen
}

// Cancellation must interrupt a silent TCP retry after truncated UDP DNS.
func TestDNSCancelEndsSilentTCPRetry(t *testing.T) {
	t.Parallel()
	addr, tcpSeen := truncatingServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	at := cancelAfterSignal(t, tcpSeen.ch, cancel)
	_, err := resolver(addr, 5*time.Second).Query(ctx, "x.example.com", mdns.TypeA)
	assertPromptCancel(t, err, at)
}

// serveTCP supplies test-lifetime loopback connections to a handler, then closes them.
func serveTCP(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if handle != nil {
					handle(c)
				}
				_ = c.Close()
			}()
		}
	}()
	return portOf(t, ln.Addr().String())
}

// sshBanner sends an SSH banner unprompted.
func sshBanner(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0-test\r\n")) }

// silentListener accepts connections and sends nothing until the client leaves.
func silentListener(t *testing.T) (int, *signal) {
	t.Helper()
	seen := newSignal()
	return serveTCP(t, func(c net.Conn) { seen.fire(); _, _ = c.Read(make([]byte, 1)) }), seen
}

// A banner read against a listener that sends nothing ends when the context is
// cancelled.
func TestTCPCancelEndsSilentBannerRead(t *testing.T) {
	t.Parallel()
	port, seen := silentListener(t)
	eg := egress.New(egress.Options{ConnectTimeout: time.Second, BannerWait: 5 * time.Second, RatePerHost: 1000})
	eg.SetPolicy(tcpPolicy(port))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	at := cancelAfterSignal(t, seen.ch, cancel)
	res, err := eg.Clients(true, nil).TCP.Connect(ctx, addr("127.0.0.1"), port)
	assertPromptCancel(t, err, at)
	if res != nil {
		t.Errorf("result = %#v, want none for a cancelled check", res)
	}
}

// Without cancellation, banners are retained and silent open services finish after BannerWait.
func TestTCPBannerUnchangedWithoutCancel(t *testing.T) {
	t.Parallel()
	bannerPort := serveTCP(t, sshBanner)
	quietPort, _ := silentListener(t)

	eg := egress.New(egress.Options{ConnectTimeout: time.Second, BannerWait: 300 * time.Millisecond, RatePerHost: 1000})
	eg.SetPolicy(tcpPolicy(bannerPort, quietPort))
	tcp := eg.Clients(true, nil).TCP

	res, err := tcp.Connect(context.Background(), addr("127.0.0.1"), bannerPort)
	if o, ok := res.(egress.Open); err != nil || !ok || !strings.HasPrefix(string(o.Banner), "SSH-2.0") {
		t.Errorf("banner: %#v %v", res, err)
	}
	start := time.Now()
	res, err = tcp.Connect(context.Background(), addr("127.0.0.1"), quietPort)
	if o, ok := res.(egress.Open); err != nil || !ok || len(o.Banner) != 0 {
		t.Errorf("silent: %#v %v", res, err)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Error("a silent listener must be waited on for BannerWait")
	}
}
