package dns

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"iter"
	"net/netip"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/scope"
)

// InNetblock looks up the A and AAAA records of candidate hostnames and roots through the public
// resolvers, and lists the rows of each name the scope brings in by an address inside an in-scope
// netblock. Scope decides which names come in (scope.Scope.ByAddress) from the lookups this
// procedure stores; a candidate itself is never contacted.
//
// It has two kinds of job. A lookup job, keyed by the name, asks A and AAAA and stores the answer
// as a candidate_lookup record. A rows job, keyed "in|<name>|<hash of the answer>", asks nothing:
// it turns the stored answer of a name in scope by address into the rows resolve would give it,
// plus the name as a hostname and its registrable domain as a root, so one answer decides the
// name's membership, its listed rows and where it is dialled. Both kinds are retired once no
// longer listed, so a name that leaves scope loses its rows.
type InNetblock struct{ base }

// NewInNetblock returns the in-netblock procedure.
func NewInNetblock() *InNetblock { return &InNetblock{base{"in-netblock"}} }

// rowsPrefix marks the key of a rows job.
const rowsPrefix = "in|"

// Budget caps the candidate lookups per run; rows jobs are not charged.
func (*InNetblock) Budget(s config.Settings) int { return s.InNetblock.MaxLookups }

// RetiresUnlistedJobs: a lookup of a name that is no longer a candidate, and the rows of a name
// that is no longer in scope by address or whose lookup changed, stop being current.
func (*InNetblock) RetiresUnlistedJobs() {}

// Evidence gives a rows job's name as its supporting item. A lookup job supports no candidate.
func (*InNetblock) Evidence(jobKey string) (source, item string) {
	rest, ok := strings.CutPrefix(jobKey, rowsPrefix)
	if !ok {
		return "", ""
	}
	name, _, _ := strings.Cut(rest, "|")
	return "in-netblock", name
}

// CandidateSources: in-netblock is a family of its own.
func (*InNetblock) CandidateSources() map[string]string {
	return map[string]string{"in-netblock": "in-netblock"}
}

// rowsInput is a rows job's input: the answer of the name's current candidate lookup, and the
// scope snapshot the targets of its CNAME links are judged against.
type rowsInput struct {
	lookup kinds.CandidateLookupAttrs
	sc     *scope.Scope
}

// rowsKey is the key of the rows job of name for the lookup answer a: "in|<name>|<hash>", where
// the hash changes with the answer.
func rowsKey(name string, a kinds.CandidateLookupAttrs) string {
	b, _ := json.Marshal(a) // a struct of strings always marshals
	sum := sha256.Sum256(b)
	return rowsPrefix + name + "|" + hex.EncodeToString(sum[:6])
}

// Jobs yields, in order, the rows jobs of the names in scope by address, sorted; the lookup jobs
// of those names, sorted, so a redo refreshes them first; then the lookup jobs of the current
// candidate hostnames and roots in candidates.csv's order. A name is looked up only while a
// producer other than this procedure observes its hostname or root record, it is under no root
// and its name alone makes it a candidate.
//
// With promotion off, or no in-scope netblock, nothing is asked and no rows are listed: only the
// lookups already made are yielded, so they are kept while every rows job is retired.
func (p *InNetblock) Jobs(_ context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		sc := v.Scope()
		on := sc.PromotesByAddress()
		for _, a := range sc.SharedHosting() {
			v.Warn("in-netblock: %s is served by more names than in_netblock.max_names_per_address allows, so none of them enters scope by its address", a)
		}
		rows, inScope := rowsJobs(v, sc)
		if on {
			for _, j := range rows {
				if !yield(j, nil) {
					return
				}
			}
		}
		for _, name := range p.lookupNames(v, sc, inScope) {
			if (on || v.Done(name)) && !yield(run.Job{Key: name, Cost: 1}, nil) {
				return
			}
		}
	}
}

// rowsJobs returns the rows jobs of the names in scope by address, sorted by key, and those names,
// sorted.
func rowsJobs(v run.View, sc *scope.Scope) ([]run.Job, []string) {
	var jobs []run.Job
	var names []string
	for _, r := range v.Records(kinds.CandidateLookup) {
		name := dnsname.Normalise(r.Key)
		if sc.InScopeByAddress(name) {
			lookup := kinds.CandidateLookup.Attrs(r)
			names = append(names, name)
			jobs = append(jobs, run.Job{Key: rowsKey(name, lookup), Input: rowsInput{lookup, sc}, Unbudgeted: true})
		}
	}
	slices.SortFunc(jobs, func(a, b run.Job) int { return strings.Compare(a.Key, b.Key) })
	slices.Sort(names)
	return jobs, names
}

// lookupNames returns, once each, the names in scope by address and then the current candidates in
// candidates.csv's order, keeping those another source found independently, under no root and
// candidates by their name alone.
func (p *InNetblock) lookupNames(v run.View, sc *scope.Scope, inScope []string) []string {
	found := p.foundByOther(v, sc)
	names := slices.Clone(inScope)
	for _, c := range v.Candidates() {
		names = append(names, dnsname.Normalise(c))
	}
	var out []string
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] || !found[name] || sc.RootOf(name) != "" || sc.ClassifyName(name).Class != scope.Candidate {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// foundByOther gives the names whose hostname or root record a job of another procedure supports.
// A root only this procedure found is not looked up on that alone, nor is a name only a job
// about a hostname under no input root found: a target procedure contacts such a name only
// because its address brought it into scope, so two names that name each other (in a shared
// certificate, say) cannot keep each other in.
func (p *InNetblock) foundByOther(v run.View, sc *scope.Scope) map[string]bool {
	found := map[string]bool{}
	for _, k := range []kinds.Named{kinds.Hostname, kinds.Root} {
		for key, obs := range v.Observers(k) {
			if slices.ContainsFunc(obs, func(o run.Observer) bool {
				return o.Procedure != p.Name() && (!o.Target || !rootlessName(sc, o.JobKey))
			}) {
				found[dnsname.Normalise(key)] = true
			}
		}
	}
	return found
}

// rootlessName reports whether a target job's key ("<host>:<port>", a URL, either followed by
// "|" and settings) names a hostname under no input root rather than an address or a name
// under one.
func rootlessName(sc *scope.Scope, jobKey string) bool {
	host, _, _ := strings.Cut(jobKey, "|")
	if _, rest, ok := strings.Cut(host, "://"); ok {
		host, _, _ = strings.Cut(rest, "/")
	}
	if _, err := netip.ParseAddrPort(host); err == nil || strings.HasPrefix(host, "[") {
		return false // an address and port
	}
	if h, _, ok := strings.Cut(host, ":"); ok && strings.Count(host, ":") == 1 {
		host = h
	}
	if _, err := netip.ParseAddr(host); err == nil || host == "" {
		return false
	}
	return sc.RootOf(host) == ""
}

// Run performs a lookup job or a rows job. A lookup's timeout is an error, retried on a later
// run; any other answer completes the job, with a candidate_lookup record when it has an address.
func (*InNetblock) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	if rest, ok := strings.CutPrefix(c.Key, rowsPrefix); ok {
		name, _, _ := strings.Cut(rest, "|")
		return rows(name, c.Input.(rowsInput)), nil
	}
	ans, err := ask(ctx, e, c.Key)
	if err != nil || len(ans.addrs) == 0 {
		return nil, err
	}
	slices.SortFunc(ans.addrs, netip.Addr.Compare)
	a := kinds.CandidateLookupAttrs{Addrs: make([]string, len(ans.addrs)), CNAMEs: []kinds.CNAMELink{}}
	for i, addr := range ans.addrs {
		a.Addrs[i] = addr.String()
	}
	for _, l := range ans.links {
		a.CNAMEs = append(a.CNAMEs, kinds.CNAMELink{Name: l.Name, Target: l.Target})
	}
	return []run.Observation{kinds.CandidateLookup.Obs(c.Key, a)}, nil
}

// rows gives the observations resolve would give for the stored answer, plus the name as a
// hostname and its registrable domain, when that is not the name itself, as a root.
func rows(name string, in rowsInput) []run.Observation {
	ans := answer{name: name, addrs: in.lookup.Addresses()}
	for _, l := range in.lookup.CNAMEs {
		ans.links = append(ans.links, egress.CNAME{Name: l.Name, Target: l.Target})
	}
	obs := append(ans.observations(in.sc), kinds.Hostname.Obs(name, kinds.HostnameAttrs{}))
	if root, _ := dnsname.ETLDPlusOne(name); root != "" && root != name {
		obs = append(obs, kinds.Root.Obs(root))
	}
	return obs
}
