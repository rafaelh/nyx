package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

// TCPResult is the outcome of a TCP connect. No connection is ever returned.
type TCPResult interface{ tcpResult() }

// Open means the handshake completed; Banner is whatever the service sent unprompted.
type Open struct{ Banner []byte }

// Closed means the port actively refused the connection.
type Closed struct{}

// Filtered means there was no answer (timeout or unreachable).
type Filtered struct{}

// Refused means policy refused the request; nothing was sent. It is a
// completed job, not a failure.
type Refused struct{ Reason string }

func (Open) tcpResult()     {}
func (Closed) tcpResult()   {}
func (Filtered) tcpResult() {}
func (Refused) tcpResult()  {}

// TargetTCP completes TCP handshakes to target-owned addresses and reads the banner.
type TargetTCP interface {
	Connect(ctx context.Context, addr netip.Addr, port int) (TCPResult, error)
}

type targetTCP struct{ e *Egress }

func (t *targetTCP) Connect(ctx context.Context, addr netip.Addr, port int) (TCPResult, error) {
	p := t.e.policy()
	if r, ok := p.targetRefusal(); ok {
		return r, nil
	}
	if !p.portAllowed(port, false) {
		return Refused{"port " + strconv.Itoa(port) + " not in the configured list"}, nil
	}
	addr = addr.Unmap()
	if r, refused := p.portIneligible(addr); refused {
		return r, nil
	}
	if err := wait(ctx, t.e.hostLimiter(addr)); err != nil {
		return nil, err
	}
	return t.e.dialAndRead(ctx, addr, port)
}

func (e *Egress) dialAddr(addr netip.Addr, port int) string {
	hp := net.JoinHostPort(addr.String(), strconv.Itoa(port))
	if m, ok := e.opts.DialMap[hp]; ok {
		return m
	}
	return hp
}

func (e *Egress) dialAndRead(ctx context.Context, addr netip.Addr, port int) (TCPResult, error) {
	d := net.Dialer{Timeout: e.opts.ConnectTimeout}
	conn, err := d.DialContext(ctx, "tcp", e.dialAddr(addr, port))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return classifyDial(err, addr, udpRoute)
	}
	defer conn.Close()
	buf := make([]byte, 1024)
	if err := conn.SetReadDeadline(time.Now().Add(e.opts.BannerWait)); err != nil {
		return Open{}, nil // the port is open; without a deadline the read could block forever
	}
	// Cancelling ctx closes the connection, which ends the read at once.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	n, _ := conn.Read(buf)
	stop()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return Open{Banner: append([]byte(nil), buf[:n]...)}, nil
}

// classifyDial maps refusals to Closed and unanswered dials to Filtered. Local failures remain
// retryable errors, including routing errors reproduced by a local route lookup.
func classifyDial(err error, addr netip.Addr, route func(netip.Addr) error) (TCPResult, error) {
	err = localRoute(err, addr, route)
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return Closed{}, nil
	case localFailure(err):
		return nil, err
	}
	return Filtered{}, nil
}

// errLocalRoute marks a dial error that this machine's routing table produced.
var errLocalRoute = errors.New("no route on this machine")

// routeErrnos can originate locally or from a remote router: ENETUNREACH, EHOSTUNREACH and
// EACCES. A route lookup distinguishes local route failures from ICMP responses.
var routeErrnos = []syscall.Errno{syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.EACCES}

// localRoute marks a routing error local only when a lookup for the same address reproduces its
// errno. Otherwise it remains a network response.
func localRoute(err error, addr netip.Addr, route func(netip.Addr) error) error {
	for _, e := range routeErrnos {
		if errors.Is(err, e) {
			if errors.Is(route(addr), e) {
				return fmt.Errorf("%w: %w", errLocalRoute, err)
			}
			return err
		}
	}
	return err
}

// udpRoute queries kernel routing through a UDP connect without sending a datagram.
func udpRoute(addr netip.Addr) error {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 9)))
	if err != nil {
		return err
	}
	return c.Close()
}

// localFailure identifies host-side resource, network, firewall or routing errors. These are
// retryable failures rather than evidence about a target port.
func localFailure(err error) bool {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.EADDRNOTAVAIL, syscall.EADDRINUSE, syscall.ENETDOWN, syscall.EPERM, errLocalRoute} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
