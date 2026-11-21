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

// LocalResolver asks this machine's own resolver, which may know private names the public
// resolvers do not. A name or address it answers has none of (NXDOMAIN, or a name with neither
// A nor AAAA) is an empty answer and no error.
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

// lookup runs fn under the DNS timeout, after the DNS rate limiter, and classifies its failure:
// a cancelled ctx is its own error, a timeout is ErrLocalTimeout, and a name that does not exist
// is the zero answer with no error.
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
		// LookupAddr drops the names that are not valid hostnames and returns an error beside the
		// rest: the valid ones are the answer, not a failure.
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
