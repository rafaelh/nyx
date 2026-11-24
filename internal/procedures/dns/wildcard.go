package dns

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"slices"

	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
)

// Wildcard records responses to two random names per zone. inventory later determines which
// real names are wildcard-only.
type Wildcard struct {
	base
	label func() string
}

// NewWildcard returns the wildcard procedure. label supplies the probe labels
// (default: 16 random hex characters), injectable for tests.
func NewWildcard(label func() string) *Wildcard {
	if label == nil {
		label = randomLabel
	}
	return &Wildcard{base{"wildcard"}, label}
}

func randomLabel() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Jobs yields one job per zone: every input root and every parent of a
// resolved in-scope name, down to its registrable domain.
func (*Wildcard) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		zones := map[string]bool{}
		for _, r := range v.Inputs().Roots {
			zones[dnsname.Normalise(r)] = true
		}
		for _, rec := range v.Records(kinds.Resolution) {
			a := kinds.Resolution.Attrs(rec)
			// Only host-resolution types introduce wildcard zones. Root records and
			// SRV names already belong to known zones.
			if a.Type != "A" && a.Type != "AAAA" && a.Type != "CNAME" {
				continue
			}
			name := dnsname.Normalise(a.Name)
			if !v.Scope().HostInScope(name) {
				continue
			}
			for _, p := range dnsname.Parents(name) {
				zones[p] = true
			}
		}
		// A sub-root's parents are not ours to probe.
		maps.DeleteFunc(zones, func(z string, _ bool) bool { return !v.Scope().HostInScope(z) })
		for _, z := range slices.Sorted(maps.Keys(zones)) {
			if !yield(run.Job{Key: z, Input: z}, nil) {
				return
			}
		}
	}
}

// Run probes random A/AAAA names and records any wildcard addresses plus the first CNAME
// target.
func (w *Wildcard) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	zone := c.Key
	var addrs []netip.Addr
	cname := ""
	answered := false
	var servfail error
	l1, l2 := w.label(), w.label()
	for l2 == l1 {
		l2 = w.label()
	}
	for _, label := range []string{l1, l2} {
		for _, qt := range []uint16{egress.TypeA, egress.TypeAAAA} {
			res, err := lookup(ctx, e, label+"."+zone, qt)
			if err != nil {
				return nil, err
			}
			if res.RCode == egress.RCodeServFail && servfail == nil {
				servfail = fmt.Errorf("%s.%s: resolver answered SERVFAIL", label, zone)
			}
			if len(res.CNAMEs) > 0 || len(res.Answers) > 0 {
				answered = true
			}
			if len(res.CNAMEs) > 0 && cname == "" {
				cname = res.CNAMEs[0].Target
			}
			addrs = append(addrs, res.Addrs()...)
		}
	}
	// A failed probe cannot establish the absence of a wildcard. Without another successful
	// answer, retry rather than allowing arbitrary wildcard names through.
	if !answered {
		return nil, servfail
	}
	return []run.Observation{kinds.Wildcard.Obs(zone, kinds.WildcardAttrs{Addrs: sortedStrings(addrs), CNAME: cname})}, nil
}
