package web

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/scope"
)

const (
	// maxTextNames is how many distinct names are taken from the responses of one web service
	// over the engagement, and from one origin-check response.
	maxTextNames = 1000
	// maxLeftOut is how many distinct names left out by the cap are counted exactly.
	maxLeftOut = 10000
)

// textNames is a job-local ordered set of the distinct names read from a job's responses,
// bounded at maxTextNames+maxLeftOut names. A new name past the bound sets over, and the job
// stops scanning. Nothing shared is touched until the job commits it, so a job that fails
// part-way reserves nothing.
type textNames struct {
	names []string        // in the order first read
	seen  map[string]bool // the names in names
	over  bool            // a new name came past the bound
}

// add adds a name not yet in the set, and reports whether the caller may go on scanning: false
// once over is set.
func (c *textNames) add(name string) bool {
	if c.over {
		return false
	}
	if c.seen[name] {
		return true
	}
	if len(c.names) == maxTextNames+maxLeftOut {
		c.over = true
		return false
	}
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	c.seen[name] = true
	c.names = append(c.names, name)
	return true
}

// read adds the names in one response that keep lets through: each header value, header keys
// in sorted order (the names of headers are not read), then the body, a name running into the
// end of a truncated body left out.
func (c *textNames) read(resp egress.Response, keep func(string) bool) {
	if c.over {
		return
	}
	for _, k := range slices.Sorted(maps.Keys(resp.Header)) {
		for _, v := range resp.Header[k] {
			if !readText(c, v, false, keep) {
				return
			}
		}
	}
	readText(c, resp.Body, resp.Truncated, keep)
}

// readText adds the names in text that keep lets through, cut saying a size limit cut the text,
// and reports whether the caller may go on scanning.
func readText[T ~string | ~[]byte](c *textNames, text T, cut bool, keep func(string) bool) bool {
	for n := range dnsname.HostnamesIn(text, cut) {
		if !c.seen[n] && keep(n) && !c.add(n) {
			return false
		}
	}
	return true
}

// takeable is the rule for which names are taken from text: a name strictly below an input root,
// excluded or not (the hostname kind's placement shows an excluded one as excluded), other than
// the responding host's own name. A name under no root, and one in scope only by its address, is
// left out. The TXT reader of the dns procedures drops an excluded name instead.
func takeable(sc *scope.Scope, self string) func(string) bool {
	self = dnsname.Normalise(self)
	return func(n string) bool {
		r := sc.RootOf(n)
		return r != "" && r != n && n != self
	}
}

// textBudget is the cap of one unit shared by the jobs of a run, seeded with the names already
// taken from it. It is kept per run, not only in the store, because a procedure runs many jobs of
// one unit at once.
type textBudget struct {
	unit textUnit

	mu    sync.Mutex
	taken map[string]bool
	left  map[string]bool // distinct names left out this run, at most maxLeftOut
	more  bool            // more than maxLeftOut were left out
}

// newTextBudget returns the budget of a web service, with the names already taken from it.
func newTextBudget(service string, seed []string) *textBudget {
	return budgetOf(textUnit{name: service, per: perService, taken: seed})
}

// budgetOf returns the budget of u, seeded with its taken names.
func budgetOf(u textUnit) *textBudget {
	b := &textBudget{unit: u, taken: make(map[string]bool, len(u.taken)), left: map[string]bool{}}
	for _, n := range u.taken {
		b.taken[n] = true
	}
	return b
}

// admit returns the names to take: one already taken, and new ones while fewer than
// maxTextNames are taken. The others are counted as left out; over says the job's collector
// passed its bound.
func (b *textBudget) admit(names []string, over bool) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var kept []string
	for _, n := range names {
		switch {
		case b.taken[n]:
			kept = append(kept, n)
		case len(b.taken) < maxTextNames:
			b.taken[n] = true
			kept = append(kept, n)
		case b.left[n]:
		case len(b.left) < maxLeftOut:
			b.left[n] = true
		default:
			b.more = true
		}
	}
	b.more = b.more || over
	return kept
}

// EndWarning says how many distinct names the cap left out this run, or nothing.
func (b *textBudget) EndWarning() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var n string
	noun, verb := "hostnames", "were"
	switch {
	case b.more:
		n = "more than " + thousands(maxLeftOut)
	case len(b.left) == 0:
		return ""
	case len(b.left) == 1:
		n, noun, verb = "1", "hostname", "was"
	default:
		n = thousands(len(b.left))
	}
	return fmt.Sprintf("%s: %s %s in its responses %s left out: at most %s are taken from %s",
		b.unit.name, n, noun, verb, thousands(maxTextNames), b.unit.per)
}

// thousands writes a count with commas between groups of three digits.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// budgetKey keys a unit's budget in the run state.
type budgetKey struct{ unit string }

// textUnit is what one cap is kept for: a web service, whose taken names are stored, or one
// origin-check response, whose cap is its own and not remembered.
type textUnit struct {
	name   string   // the web service's origin, or the origin check's host and address
	per    string   // what the cap is per, for the warning
	taken  []string // the names already taken from it
	record bool     // store text_hostname records, so later runs count the names
}

// perService is what a web service's cap is per, for the warning.
const perService = "one web service"

// serviceUnit is the unit of a web service, whose cap spans its probe, its crawl and the scripts
// it serves over the engagement.
func serviceUnit(origin string, taken map[string][]string) textUnit {
	return textUnit{name: origin, per: perService, taken: taken[origin], record: true}
}

// commitText admits a finished job's names into its unit's budget for this run and returns the
// observations of the names taken: a hostname for each, and the text_hostname that counts it
// against a web service in later runs.
func commitText(ctx context.Context, c *textNames, u textUnit) []run.Observation {
	if len(c.names) == 0 && !c.over {
		return nil
	}
	b := run.PerRun(ctx, budgetKey{u.name}, func() *textBudget { return budgetOf(u) })
	var out []run.Observation
	for _, n := range b.admit(c.names, c.over) {
		out = append(out, kinds.Hostname.Obs(n, kinds.HostnameAttrs{}))
		if u.record {
			out = append(out, kinds.TextHostname.Obs(kinds.TextHostnameAttrs{Service: u.name, Name: n}))
		}
	}
	return out
}
