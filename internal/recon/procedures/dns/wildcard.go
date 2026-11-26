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

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
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
	return &Wildcard{base{wildcardName}, label}
}

const wildcardName = "wildcard"

// wildcardChecked reports whether the zone's wildcard job has completed; its key is the zone.
func wildcardChecked(v run.View, zone string) bool { return v.DoneBy(wildcardName, zone) }

// Required: wildcard answers decide which names are real, so it cannot be skipped.
func (*Wildcard) Required() {}

func randomLabel() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Jobs yields one job per zone that wildcardZones gives.
func (*Wildcard) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return run.JobsOf(slices.Sorted(maps.Keys(wildcardZones(v))), func(z string) run.Job { return run.Job{Key: z, Input: z} })
}

// wildcardZones are the zones the wildcard procedure checks: every input root and every parent
// of a resolved in-scope name, down to its registrable domain, that is in scope.
func wildcardZones(v run.View) map[string]bool {
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
	return zones
}

// wildcardPending reports whether a zone's wildcard check is due and has not completed: the zone
// is one of zones (wildcardZones) and its job is not done. A name guessed or resolved as a parent
// in such a zone waits for the check, so that a wildcard's answers are known first; a zone the
// procedure does not check holds nothing back.
func wildcardPending(v run.View, zones map[string]bool, zone string) bool {
	return zones[zone] && !wildcardChecked(v, zone)
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
