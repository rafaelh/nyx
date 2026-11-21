package run

import (
	"crypto/sha256"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/candidates"
	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/store"
	"github.com/rafaelh/nyx/internal/thirdparty"
)

// deriveInput is what a deriver reads: the current Scope, Inventory and their
// Visibility, the engagement's inputs, the date, and the store through the
// records of a kind (current or not) and the completed checks observing them.
type deriveInput struct {
	Scope     *scope.Scope
	Inv       *inventory.Inventory
	Vis       *kinds.Visibility
	Inputs    input.Parsed
	Today     string // YYYY-MM-DD
	Records   func(kinds.Named) []store.Record
	Observers func(kinds.Named) map[string][]store.Observer
}

// deriver computes records from other records and stores them as the
// observations of a single check "derived" of the pseudo-stage name. A record
// it no longer emits loses its only observation, so it stops being current. It
// runs after every stage that did work and before every render, and is skipped
// while the version of each kind in reads and the date are unchanged. A deriver
// reads nothing else but its own earlier records, and writes only records of
// its kind writes, which no deriver reads.
//
// derive returns the records and, if it needs one, a hook run once they are
// stored (stored is false when they were the same as last stored, so nothing
// changed). The hook is not run when a read failed, and the deriver then runs
// again next time.
type deriver struct {
	name   string
	reads  []kinds.Named
	writes kinds.Named
	derive func(deriveInput) (obs []store.Obs, after func(stored bool))

	sig    string            // what it was last derived from
	stored [sha256.Size]byte // the date and records last stored (see storeDerived)
}

// newDerivers lists the derivers in the order they run. The findings come
// first and read every kind but the derived ones, so that storing a derived
// record never derives the findings again.
func (r *Runner) newDerivers() []*deriver {
	others := []*deriver{
		{name: "candidate-rank", reads: append(slices.Clone(scopeKinds), kinds.CandidateKinds...), writes: kinds.CandidateRank, derive: plain(r.rankCandidates)},
		{name: "thirdparty-cname", reads: []kinds.Named{kinds.Hostname, kinds.Resolution, kinds.Wildcard}, writes: kinds.ThirdParty, derive: plain(thirdPartyCNAME)},
	}
	derived := map[string]bool{kinds.Finding.Name(): true}
	for _, d := range others {
		derived[d.writes.Name()] = true
	}
	var evidence []kinds.Named
	for _, k := range kinds.All() {
		if !derived[k.Name] {
			named, _ := kinds.Lookup(k.Name)
			evidence = append(evidence, named)
		}
	}
	return append([]*deriver{{name: "findings", reads: evidence, writes: kinds.Finding, derive: r.deriveFindings}}, others...)
}

// plain adapts a derivation that needs no hook.
func plain(f func(deriveInput) []store.Obs) func(deriveInput) ([]store.Obs, func(bool)) {
	return func(in deriveInput) ([]store.Obs, func(bool)) { return f(in), nil }
}

// deriveFindings derives the findings from the evidence. A new finding is
// printed once by the store's OnNew callback; its hook prints again a finding
// whose severity has risen (an unconfirmed port a handshake then confirmed),
// but not one that has fallen, and keeps the storage attribution the render
// needs, computed from the same evidence.
func (r *Runner) deriveFindings(in deriveInput) ([]store.Obs, func(bool)) {
	fs, attribution := findings.DeriveAll(findings.Input{Scope: in.Scope, Inv: in.Inv, Settings: r.cfg.Settings,
		Today: in.Today, Records: in.Records, Roots: in.Inputs.Roots, Orgs: in.Inputs.Orgs, Vis: in.Vis})
	was := map[string]string{} // the severity of each current finding, by key
	for _, rec := range in.Records(kinds.Finding) {
		if rec.Current {
			was[rec.Key] = rec.Str("severity")
		}
	}
	obs := make([]store.Obs, len(fs))
	var risen []findings.Finding
	for i, f := range fs {
		obs[i] = kinds.Finding.Obs(f.Key(), f.Attrs)
		if old, ok := was[f.Key()]; ok && findings.Higher(f.Severity, old) {
			risen = append(risen, f)
		}
	}
	return obs, func(stored bool) {
		if stored {
			for _, f := range risen {
				r.emit("found", foundFields(kinds.Finding.Name(), f.Key(), f.Attrs))
			}
		}
		r.attribution = attribution
	}
}

// thirdPartyCNAME derives the SaaS platforms in-scope names are served by. Its
// deriver reads the kinds the inventory's provider hosts come from, and not
// third_party, which it and the stages write.
func thirdPartyCNAME(in deriveInput) []store.Obs {
	return thirdparty.CNAME(in.Scope, in.Inv)
}

// derive runs the derivers whose inputs have changed. Every place that derives
// calls it, so that a new derivation cannot be missed at one of them.
func (r *Runner) derive() error {
	sc, inv, vis := r.sc.Load(), r.inv.Load(), r.vis.Load()
	if sc == nil || inv == nil {
		return nil
	}
	today := r.today()
	for _, d := range r.derivers {
		sig := r.kindSig(d.reads) + today
		if sig == d.sig {
			continue
		}
		var readErr error
		obs, after := d.derive(deriveInput{Scope: sc, Inv: inv, Vis: vis, Inputs: r.inputs, Today: today,
			Records: keepFirstErr(&readErr, r.records), Observers: keepFirstErr(&readErr, r.observers)})
		if readErr != nil {
			return readErr
		}
		stored, err := r.storeDerived(d.name, obs, &d.stored)
		if err != nil {
			return err
		}
		if after != nil {
			after(stored)
		}
		d.sig = sig
	}
	return nil
}

// evidence is what one completed check contributes to a candidate it observes:
// the stage's own account of its source and item if it gives one (Evidencer),
// else the stage and the check key.
func (r *Runner) evidence(stage, check string) candidates.Evidence {
	if e, ok := r.evidencers[stage]; ok {
		source, item := e.Evidence(check)
		return candidates.Evidence{Source: source, Item: item}
	}
	return candidates.Evidence{Source: stage, Item: check}
}

// rankCandidates ranks every candidate from the completed checks that observe
// it. A candidate root also counts the evidence of the candidate hostnames
// under it, so that stages that report roots and stages that report hostnames
// can corroborate each other; the hostnames keep their own rank. A candidate
// that is no longer current, or whose only support awaits a redo, keeps the
// rank it last had.
func (r *Runner) rankCandidates(in deriveInput) []store.Obs {
	last := map[string]kinds.CandidateRankAttrs{} // by rank key
	for _, rec := range in.Records(kinds.CandidateRank) {
		if rec.Current {
			last[rec.Key] = kinds.CandidateRank.Attrs(rec)
		}
	}
	all := r.gatherCandidates(in)
	var obs []store.Obs
	for _, c := range all {
		key := kinds.CandidateRank.Key(kinds.CandidateRankAttrs{Type: c.typ, Value: c.value})
		attrs, ok := last[key]
		// A current candidate with no evidence of its own is observed only by
		// checks a redo has forgotten and that have not run again (evidence
		// rolled up from hostnames does not make a root current): it keeps its
		// last rank until they do, so that a candidate they no longer find
		// shows the rank it had while supported.
		if c.current && (c.own > 0 || !ok) {
			rank := candidates.Score(c.evidence, in.Inputs.Orgs)
			attrs = kinds.CandidateRankAttrs{Type: c.typ, Value: c.value, Sources: strings.Join(rank.Sources, ";"),
				EvidenceCount: rank.Count, Confidence: string(rank.Confidence), Current: true}
		} else if !ok {
			continue // never ranked, and there is nothing to keep
		}
		attrs.Current = c.current
		obs = append(obs, kinds.CandidateRank.Obs(attrs))
	}
	return obs
}

// rankedCandidate is a candidate record and the evidence it is ranked on.
type rankedCandidate struct {
	typ, value string
	current    bool
	evidence   []candidates.Evidence
	own        int // the evidence of its own completed checks, before any roll-up
}

// gatherCandidates lists the candidate records of every candidate kind, each
// with the evidence of the checks that observe it, and rolls the evidence of
// each current candidate hostname up into the current candidate roots above
// it (or equal to it).
func (r *Runner) gatherCandidates(in deriveInput) []*rankedCandidate {
	var all []*rankedCandidate
	roots := map[string]*rankedCandidate{} // current candidate roots, by value
	var hostnames []*rankedCandidate
	for _, kind := range kinds.CandidateKinds {
		observers := in.Observers(kind)
		for _, rec := range in.Records(kind) {
			if in.Vis.Category(kind, rec) != kinds.Candidates {
				continue
			}
			c := &rankedCandidate{typ: kind.Name(), value: rec.Key, current: rec.Current}
			for _, o := range observers[rec.Key] {
				c.evidence = append(c.evidence, r.evidence(o.Stage, o.CheckKey))
			}
			c.own = len(c.evidence)
			all = append(all, c)
			switch {
			case !c.current:
			case kind.Name() == kinds.Root.Name():
				roots[rec.Key] = c
			case kind.Name() == kinds.Hostname.Name():
				hostnames = append(hostnames, c)
			}
		}
	}
	for _, h := range hostnames {
		rollUp(h, roots)
	}
	return all
}

// rollUp adds a hostname's evidence to every root in roots above it, or equal
// to it.
func rollUp(h *rankedCandidate, roots map[string]*rankedCandidate) {
	for name := h.value; ; {
		if c, ok := roots[name]; ok {
			c.evidence = append(c.evidence, h.evidence...)
		}
		_, rest, found := strings.Cut(name, ".")
		if !found {
			return
		}
		name = rest
	}
}
