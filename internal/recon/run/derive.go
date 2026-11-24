package run

import (
	"crypto/sha256"
	"net/netip"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/recon/analysis/candidates"
	"github.com/rafaelh/nyx/internal/recon/analysis/findings"
	"github.com/rafaelh/nyx/internal/recon/analysis/thirdparty"
	"github.com/rafaelh/nyx/internal/recon/inventory"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/store"
	"github.com/rafaelh/nyx/internal/scope"
)

// analysisInput provides the scope, inventory, visibility, inputs, date and record readers used
// to calculate derived records.
type analysisInput struct {
	Scope     *scope.Scope
	Inv       *inventory.Inventory
	Vis       *kinds.Visibility
	Inputs    input.Parsed
	Today     string // YYYY-MM-DD
	Records   func(kinds.Named) []store.Record
	Observers func(kinds.Named) map[string][]store.Observer
}

// analysis calculates records and stores them under its own name, with Store.Put and no job.
// Records it stops producing become non-current. It runs after procedure work and before rendering
// when its input versions or the date change. Each analysis writes one kind; other analyses do not
// read that output.
//
// The optional hook runs after storage, with stored=false if the records were unchanged. Read
// failures skip the hook and leave the derivation due for retry.
type analysis struct {
	name   string
	reads  []kinds.Named
	writes kinds.Named
	derive func(analysisInput) (obs []store.Obs, after func(stored bool))

	sig    string            // signature of the inputs used for the last derivation
	stored [sha256.Size]byte // hash of the last stored date and records
}

// newAnalyses orders the calculations. Findings read all non-derived kinds so writing derived
// records cannot trigger another findings calculation.
func (r *Runner) newAnalyses() []*analysis {
	others := []*analysis{
		{name: AnalysisCandidateRank, reads: append(slices.Clone(scopeKinds), kinds.CandidateKinds...), writes: kinds.CandidateRank, derive: plain(r.rankCandidates)},
		{name: AnalysisThirdPartyCNAME, reads: []kinds.Named{kinds.Hostname, kinds.Resolution, kinds.Wildcard}, writes: kinds.ThirdParty, derive: plain(thirdPartyCNAME)},
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
	return append([]*analysis{{name: AnalysisFindings, reads: evidence, writes: kinds.Finding, derive: r.deriveFindings}}, others...)
}

func plain(f func(analysisInput) []store.Obs) func(analysisInput) ([]store.Obs, func(bool)) {
	return func(in analysisInput) ([]store.Obs, func(bool)) { return f(in), nil }
}

// deriveFindings calculates findings and storage attribution from the same evidence. The store
// announces new findings. The returned hook also announces severity increases, such as a port
// confirmed by a handshake, and saves attribution for rendering.
func (r *Runner) deriveFindings(in analysisInput) ([]store.Obs, func(bool)) {
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

// thirdPartyCNAME identifies SaaS platforms serving in-scope names. It reads the inventory's
// source kinds rather than third_party, which both this analysis and procedures write.
func thirdPartyCNAME(in analysisInput) []store.Obs {
	return thirdparty.CNAME(in.Scope, in.Inv)
}

// derive is the shared entry point for recalculating derived records whose inputs changed.
func (r *Runner) derive() error {
	sc, inv, vis := r.sc.Load(), r.inv.Load(), r.vis.Load()
	if sc == nil || inv == nil {
		return nil
	}
	today := r.today()
	for _, d := range r.analyses {
		sig := r.kindSig(d.reads) + today
		if sig == d.sig {
			continue
		}
		var readErr error
		obs, after := d.derive(analysisInput{Scope: sc, Inv: inv, Vis: vis, Inputs: r.inputs, Today: today,
			Records: keepFirstErr(&readErr, r.records), Observers: keepFirstErr(&readErr, r.observers)})
		if readErr != nil {
			return readErr
		}
		stored, err := r.storeAnalysis(d.name, obs, &d.stored)
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

// evidence describes a job's support for a candidate. Procedures implementing Evidencer supply
// the source and item; others use the procedure name and job key. The source determines the
// family.
func (r *Runner) evidence(procedure, job string) candidates.Evidence {
	source, item := procedure, job
	if e, ok := r.evidencers[procedure]; ok {
		source, item = e.Evidence(job)
	}
	return candidates.Evidence{Source: source, Item: item, Family: r.families.Of(source)}
}

// rankCandidates calculates candidate ranks from the completed jobs supporting each
// candidate.
func (r *Runner) rankCandidates(in analysisInput) []store.Obs {
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
				c.Evidence = append(c.Evidence, r.evidence(o.Procedure, o.JobKey))
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

func rankOf(a kinds.CandidateRankAttrs) candidates.Rank {
	var sources []string
	if a.Sources != "" {
		sources = strings.Split(a.Sources, ";")
	}
	return candidates.Rank{Sources: sources, Count: a.EvidenceCount, Confidence: candidates.Confidence(a.Confidence)}
}

// historyOnly returns a predicate for addresses observed exclusively by Historical procedures. Such
// addresses may no longer belong to the engagement. It returns nil if no procedures provide
// historical data.
func (r *Runner) historyOnly(records func(kinds.Named) []store.Record) func(netip.Addr) bool {
	if len(r.historical) == 0 {
		return nil
	}
	only := map[netip.Addr]bool{}
	for _, rec := range records(kinds.IP) {
		a, err := netip.ParseAddr(rec.Key)
		if err != nil || !rec.Current || len(rec.Producers) == 0 {
			continue
		}
		if slices.ContainsFunc(rec.Producers, func(s string) bool { return !r.historical[s] }) {
			continue
		}
		only[a.Unmap()] = true
	}
	return func(a netip.Addr) bool { return only[a.Unmap()] }
}
