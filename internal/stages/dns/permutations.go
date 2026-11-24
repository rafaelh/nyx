package dns

import (
	"context"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
)

// wellKnownLabels adds common mail, voice and device-management names to root checks even
// without wordlist entries. Seed permutations do not query them separately.
var wellKnownLabels = []string{"autodiscover", "lyncdiscover", "enterpriseenrollment", "enterpriseregistration", "mta-sts"}

// wellKnownToken identifies wellKnownLabels in the root key, so a changed list
// repeats the root checks.
var wellKnownToken = config.ListHash(wellKnownLabels)

// Permutations generates names from roots and other stages' discoveries, emitting names that
// exist for resolve to query. inventory.Seeds prevents feedback from its own output.
type Permutations struct{ base }

// NewPermutations returns the permutations stage.
func NewPermutations() *Permutations { return &Permutations{base{"permutations"}} }

// Configured is false when permutations are turned off.
func (*Permutations) Configured(e run.Env) (bool, string) {
	if !e.Settings.Permutations.Enabled {
		return false, "disabled"
	}
	return true, ""
}

// Budget is the most names the stage generates in one run.
func (*Permutations) Budget(s config.Settings) int { return s.Permutations.MaxNames }

// Checks lists root checks before seed checks so the budget reaches each root first. Cost
// equals queried names. Keys include the wordlist hash; seed keys also include the cap, and
// root keys version the well-known labels. Changing these inputs reruns only affected checks.
// Known wildcard zones and generated names directly beneath them are omitted because arbitrary
// names already resolve there.
func (p *Permutations) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		s := v.Settings()
		hash := config.ListHash(s.WordlistWords)
		words := make([]string, len(s.WordlistWords))
		for i, w := range s.WordlistWords {
			words[i] = strings.ToLower(w)
		}
		// A word that is not a valid label gives no name under any root.
		valid := slices.DeleteFunc(slices.Clone(words), func(w string) bool { return !dnsname.ValidLabel(w) })
		for _, l := range wellKnownLabels {
			if !slices.Contains(valid, l) {
				valid = append(valid, l)
			}
		}
		for _, root := range slices.Sorted(slices.Values(v.Inputs().Roots)) {
			if v.WildcardZone(dnsname.Normalise(root)) {
				continue
			}
			c := run.Check{Key: fmt.Sprintf("root|%s|wl=%s|wk=%s", root, hash, wellKnownToken)}
			if !v.Done(c.Key) { // the runner skips a done check before reading its names
				names := rootNames(root, valid)
				c.Input, c.Cost = names, len(names)
			}
			if !yield(c, nil) {
				return
			}
		}
		// Seeds are never directly under a wildcard zone: the view leaves them out.
		for _, seed := range v.Seeds(p.Name()) {
			c := run.Check{Key: fmt.Sprintf("seed|%s|wl=%s|max=%d", seed, hash, s.Permutations.MaxPerSeed)}
			if !v.Done(c.Key) {
				names := slices.DeleteFunc(seedNames(seed, words, s.Permutations.MaxPerSeed), func(n string) bool {
					_, parent, _ := strings.Cut(n, ".")
					return v.WildcardZone(parent)
				})
				c.Input, c.Cost = names, len(names)
			}
			if !yield(c, nil) {
				return
			}
		}
	}
}

// Run queries A once per generated name. A CNAME establishes existence even with a dangling
// NXDOMAIN target. SERVFAIL proves nothing; other non-NXDOMAIN results establish existence.
// Timeouts fail the whole check for retry next run.
func (p *Permutations) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	var obs []run.Observation
	for _, n := range c.Input.([]string) {
		res, err := lookup(ctx, e, n, egress.TypeA)
		if err != nil {
			return nil, err
		}
		if len(res.CNAMEs) == 0 && (res.RCode == egress.RCodeNXDomain || res.RCode == egress.RCodeServFail) {
			continue
		}
		obs = append(obs, kinds.Hostname.Obs(n, kinds.HostnameAttrs{}))
	}
	return obs, nil
}

// rootNames are the names a root check queries: each word directly under the root.
func rootNames(root string, words []string) []string {
	out := make([]string, len(words))
	for i, w := range words {
		out[i] = w + "." + root
	}
	return out
}

// seedNames is shared by cost calculation and execution so the budget matches the exact query
// count.
func seedNames(seed string, words []string, max int) []string {
	label, parent, _ := strings.Cut(seed, ".")
	var out []string
	for _, v := range dnsname.Permute(label, words, max) {
		out = append(out, v+"."+parent)
	}
	return out
}
