package dns

import (
	"cmp"
	"context"
	"iter"
	"maps"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// LearnedNames tries the labels of found names under the other zones that have names: with
// staging.a.example.com and api.b.example.com found, it tries staging.b.example.com and
// api.a.example.com. Each tried name is one job, so a name is asked once per engagement until it
// is redone, and the runner's budget defers what is over learned_names.max_names.
type LearnedNames struct{ base }

// NewLearnedNames returns the learned-names procedure.
func NewLearnedNames() *LearnedNames { return &LearnedNames{base{"learned-names"}} }

// Configured is permutations' answer: turning permutations off turns learning off too.
func (*LearnedNames) Configured(e run.Env) (bool, string) { return NewPermutations().Configured(e) }

// Budget is the most names the procedure tries in one run.
func (*LearnedNames) Budget(s config.Settings) int { return s.LearnedNames.MaxNames }

// Jobs plans the names to try from the view on every pass, so names found meanwhile are learned
// from in the same run. A hostname is learned from only once its zone's wildcard check has
// completed, and nothing is tried under a zone until its check has completed and found no
// wildcard. Names another path owns are left out: known names, parent names (resolve asks them)
// and, while permutations runs, wordlist words directly under a root (its root jobs ask them).
// The whole backlog is yielded; the runner defers what is over the budget.
func (l *LearnedNames) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	sc := v.Scope()
	var hosts []learnHost
	for _, h := range v.Learnable() {
		_, zone, _ := strings.Cut(h, ".")
		if wildcardChecked(v, zone) {
			hosts = append(hosts, learnHost{Name: h, Root: sc.RootOf(h)})
		}
	}
	// Known names: those another procedure found (and the input roots), which resolve asks.
	known := map[string]bool{}
	for _, n := range v.ResolvableHostnames(l.Name()) {
		known[n] = true
	}
	for _, p := range v.ParentNames(NewResolve().Name()) {
		known[p] = true
	}
	roots := map[string]bool{}
	for _, r := range v.Inputs().Roots {
		roots[dnsname.Normalise(r)] = true
	}
	var words map[string]bool
	if s := v.Settings(); !slices.Contains(s.Skip, NewPermutations().Name()) {
		words = map[string]bool{}
		for _, w := range rootWords(lowerWords(s)) {
			words[w] = true
		}
	}
	zoneOK := func(zone string) bool {
		return sc.HostInScope(zone) && wildcardChecked(v, zone) && !v.WildcardZone(zone)
	}
	skip := func(name string) bool {
		if known[name] || !sc.HostInScope(name) {
			return true
		}
		label, zone, _ := strings.Cut(name, ".")
		return roots[zone] && words[label]
	}
	names := learnNames(hosts, slices.Collect(maps.Keys(roots)), zoneOK, skip)
	return run.JobsOf(names, func(n string) run.Job { return run.Job{Key: n, Input: n, Cost: 1} })
}

// Run asks A for the tried name and records it as a hostname when it exists. A timeout fails the
// job, so the name is asked again on the next run.
func (*LearnedNames) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	name := c.Input.(string)
	res, err := lookup(ctx, e, name, egress.TypeA)
	if err != nil {
		return nil, err
	}
	if !guessExists(res) {
		return nil, nil
	}
	return []run.Observation{kinds.Hostname.Obs(name, kinds.HostnameAttrs{})}, nil
}

// learnHost is a hostname that learning learns from, with its most specific input root.
type learnHost struct{ Name, Root string }

// learnNames plans the names learning tries: the learnable forms of every label of each host
// below its root, under every populated zone (the roots and the names between a host and its
// root) that zoneOK accepts. Labels are ranked by the number of zones that have a host whose
// first label it is, most first, then alphabetically; each label's names follow in alphabetical
// order of zone. Names skip accepts and names too long for DNS are left out.
func learnNames(hosts []learnHost, roots []string, zoneOK func(zone string) bool, skip func(name string) bool) []string {
	zones := map[string]bool{}
	for _, r := range roots {
		zones[r] = true
	}
	labels := map[string]bool{}
	firsts := map[string]map[string]bool{} // first label -> zones holding a host that starts with it
	for _, h := range hosts {
		if h.Name == h.Root || !dnsname.Under(h.Name, h.Root) {
			continue
		}
		below := strings.Split(strings.TrimSuffix(h.Name, "."+h.Root), ".")
		for _, l := range below {
			for _, f := range dnsname.LearnableForms(l) {
				labels[f] = true
			}
		}
		_, parent, _ := strings.Cut(h.Name, ".")
		if firsts[below[0]] == nil {
			firsts[below[0]] = map[string]bool{}
		}
		firsts[below[0]][parent] = true
		// The names between the host and its root, each one label shorter.
		for zone, i := parent, 1; i < len(below); i++ {
			zones[zone] = true
			_, zone, _ = strings.Cut(zone, ".")
		}
	}
	rank := map[string]int{}
	for l, fz := range firsts {
		for z := range fz {
			if zones[z] {
				rank[l]++
			}
		}
	}
	ranked := slices.SortedFunc(maps.Keys(labels), func(a, b string) int {
		return cmp.Or(cmp.Compare(rank[b], rank[a]), strings.Compare(a, b))
	})
	tryable := slices.Sorted(maps.Keys(zones))
	tryable = slices.DeleteFunc(tryable, func(z string) bool { return !zoneOK(z) })
	var out []string
	for _, l := range ranked {
		for _, z := range tryable {
			if n := l + "." + z; len(n) <= dnsname.MaxNameLen && !skip(n) {
				out = append(out, n)
			}
		}
	}
	return out
}
