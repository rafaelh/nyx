package run

import (
	"crypto/sha256"
	"net/netip"
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
		Today: in.Today, Records: in.Records, Roots: in.Inputs.Roots, Orgs: in.Inputs.Orgs, Vis: in.Vis,
		Abusive: r.cfg.Abusive, Drop: r.cfg.Drop, HistoryOnly: r.historyOnly(in.Records)})
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
// else the stage and the check key, with the family the stages name for the
// source.
func (r *Runner) evidence(stage, check string) candidates.Evidence {
	source, item := stage, check
	if e, ok := r.evidencers[stage]; ok {
		source, item = e.Evidence(check)
	}
	return candidates.Evidence{Source: source, Item: item, Family: r.families.Of(source)}
}

// rankCandidates ranks every candidate from the completed checks that observe
// it, by the rules of candidates.RankAll.
func (r *Runner) rankCandidates(in deriveInput) []store.Obs {
	last := map[candidates.Key]candidates.Rank{}
	for _, rec := range in.Records(kinds.CandidateRank) {
		if rec.Current {
			a := kinds.CandidateRank.Attrs(rec)
			last[candidates.Key{Type: a.Type, Value: a.Value}] = rankOf(a)
		}
	}
	var cs []candidates.Candidate
	for _, kind := range kinds.CandidateKinds {
		observers := in.Observers(kind)
		for _, rec := range in.Records(kind) {
			if in.Vis.Category(kind, rec) != kinds.Candidates {
				continue
			}
			c := candidates.Candidate{Type: kind.Name(), Value: rec.Key, Current: rec.Current}
			for _, o := range observers[rec.Key] {
				c.Evidence = append(c.Evidence, r.evidence(o.Stage, o.CheckKey))
			}
			cs = append(cs, c)
		}
	}
	ranked := candidates.RankAll(cs, last, in.Inputs.Orgs)
	obs := make([]store.Obs, len(ranked))
	for i, c := range ranked {
		obs[i] = kinds.CandidateRank.Obs(kinds.CandidateRankAttrs{Type: c.Type, Value: c.Value, Sources: strings.Join(c.Sources, ";"),
			EvidenceCount: c.Count, Confidence: string(c.Confidence), Current: c.Current})
	}
	return obs
}

// rankOf is the rank a candidate_rank record stores.
func rankOf(a kinds.CandidateRankAttrs) candidates.Rank {
	var sources []string
	if a.Sources != "" {
		sources = strings.Split(a.Sources, ";")
	}
	return candidates.Rank{Sources: sources, Count: a.EvidenceCount, Confidence: candidates.Confidence(a.Confidence)}
}

// historyOnly says whether DNS history alone names an address: its current ip record is observed
// only by stages that are Historical. Code outside a stage never names one, so the stages say it
// through that marker. It is nil when no stage is historical.
func (r *Runner) historyOnly(records func(kinds.Named) []store.Record) func(netip.Addr) bool {
	if len(r.historical) == 0 {
		return nil
	}
	only := map[netip.Addr]bool{}
	for _, rec := range records(kinds.IP) {
		a, err := netip.ParseAddr(rec.Key)
		if err != nil || !rec.Current || len(rec.Stages) == 0 {
			continue
		}
		if slices.ContainsFunc(rec.Stages, func(s string) bool { return !r.historical[s] }) {
			continue
		}
		only[a.Unmap()] = true
	}
	return func(a netip.Addr) bool { return only[a.Unmap()] }
}
