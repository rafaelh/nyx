package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"

	"github.com/rafaelh/nyx/internal/dnsname"
)

// ErrLocalTimeout is the error of a lookup that this machine's resolver did not answer in time.
var ErrLocalTimeout = errors.New("this machine's resolver did not answer in time")

// LocalResolver uses the machine's resolver for names public DNS may not know. NXDOMAIN and
// names without A/AAAA return empty results without error.
type LocalResolver interface {
	Addrs(ctx context.Context, name string) ([]netip.Addr, error)
	PTR(ctx context.Context, addr netip.Addr) ([]string, error)
}

type localResolver struct{ e *Egress }

// Local returns the client for this machine's resolver.
func (e *Egress) Local() LocalResolver { return &localResolver{e: e} }

// localNet is the resolver to ask: this machine's own, or the fake the LocalResolverAddr test
// hook names.
func (e *Egress) localNet() *net.Resolver {
	addr := e.opts.LocalResolverAddr
	if addr == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
}

// lookup applies DNS pacing and timeout, preserving cancellation, mapping timeouts to
// ErrLocalTimeout and treating nonexistent names as empty successful answers.
func lookup[T any](ctx context.Context, e *Egress, fn func(context.Context, *net.Resolver) (T, error)) (T, error) {
	var zero T
	if err := wait(ctx, e.dnsLim); err != nil {
		return zero, err
	}
	lctx, cancel := context.WithTimeout(ctx, e.opts.DNSTimeout)
	defer cancel()
	out, err := fn(lctx, e.localNet())
	if err == nil {
		return out, nil
	}
	var de *net.DNSError
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return zero, ctx.Err()
	case lctx.Err() != nil || errors.As(err, &de) && de.IsTimeout:
		return zero, fmt.Errorf("%w: %w", ErrLocalTimeout, err)
	case errors.As(err, &de) && de.IsNotFound:
		return zero, nil
	}
	return zero, err
}

func (l *localResolver) Addrs(ctx context.Context, name string) ([]netip.Addr, error) {
	addrs, err := lookup(ctx, l.e, func(ctx context.Context, r *net.Resolver) ([]netip.Addr, error) {
		return r.LookupNetIP(ctx, "ip", name)
	})
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range addrs {
		if a = a.Unmap(); !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out, nil
}

func (l *localResolver) PTR(ctx context.Context, addr netip.Addr) ([]string, error) {
	names, err := lookup(ctx, l.e, func(ctx context.Context, r *net.Resolver) ([]string, error) {
		names, err := r.LookupAddr(ctx, addr.Unmap().String())
		// LookupAddr keeps valid hostnames even if others are invalid, returning
		// validation errors alongside usable results.
		var de *net.DNSError
		if err != nil && len(names) > 0 && errors.As(err, &de) && !de.IsTimeout && !de.IsNotFound {
			return names, nil
		}
		return names, err
	})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		if n = dnsname.Normalise(n); n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, nil
}
