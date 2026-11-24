package dns

import (
	"context"
	"fmt"
	"iter"
	"net/netip"
	"sync"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/ipsource"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
)

// IPOwner finds the origin AS of each address outside the in-scope netblocks
// using Team Cymru's DNS service through the public resolvers.
type IPOwner struct {
	base
	mu      sync.Mutex
	holders map[int]string // cached per ASN for the life of the process
}

// NewIPOwner returns the ipowner procedure.
func NewIPOwner() *IPOwner { return &IPOwner{base: base{"ipowner"}, holders: map[int]string{}} }

// Jobs yields one job per ip record outside the in-scope netblocks.
func (*IPOwner) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		sc := v.Scope()
		for _, a := range v.IPs(func(a netip.Addr) bool { return !sc.InScopeIP(a) }) {
			if !yield(run.Job{Key: a.String(), Input: a}, nil) {
				return
			}
		}
	}
}

// Run resolves the announcing AS and holder. Unknown Cymru addresses complete without
// ownership; other failures remain retryable and leave ownership unknown.
func (o *IPOwner) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	addr := c.Input.(netip.Addr)
	owner, found, err := ipsource.Origin(ctx, e.DNS, addr)
	if err != nil {
		return nil, fmt.Errorf("owner of %s: %w", addr, err)
	}
	if !found {
		return nil, nil
	}
	holder, err := o.holder(ctx, owner.ASN, e)
	if err != nil {
		return nil, fmt.Errorf("owner of %s: %w", addr, err)
	}
	return []run.Observation{kinds.IPOwner.Obs(addr.String(), kinds.IPOwnerAttrs{ASN: owner.ASN, Prefix: owner.Prefix, Holder: holder})}, nil
}

func (o *IPOwner) holder(ctx context.Context, asn int, e egress.Clients) (string, error) {
	o.mu.Lock()
	h, ok := o.holders[asn]
	o.mu.Unlock()
	if ok {
		return h, nil
	}
	h, err := ipsource.ASName(ctx, e.DNS, asn)
	if err != nil {
		return "", err
	}
	o.mu.Lock()
	o.holders[asn] = h
	o.mu.Unlock()
	return h, nil
}
