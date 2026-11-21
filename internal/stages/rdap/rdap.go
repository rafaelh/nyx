// Package rdap asks the regional internet registries who the netblocks of an
// engagement are registered to, and which netblocks and autonomous systems are
// registered to an input organisation. It contacts only IANA, for the bootstrap
// file that says which registry holds an address, and the five registries.
//
// Everything it finds about an organisation is a candidate: nothing enters scope
// until the user passes the netblock, autonomous system or organisation as an input.
package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/ipsource"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/orgname"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

const (
	// maxResults caps the netblocks and autonomous systems kept for one
	// organisation at one registry. The value is a reasonable guess, not a registry limit.
	maxResults = 50
)

// Stage is the rdap stage. It has two kinds of check, both made once per
// engagement and refreshed only by --redo rdap:
//
//	org|<organisation>|<registry>   the organisation's netblocks and autonomous systems
//	ip|<address>                    who the address's netblock is registered to
//
// A lookup of an address records the whole registered range, so another
// address inside it needs no request, in this run or a later one. The key
// carries no scope: an address that becomes eligible later is looked up then.
type Stage struct{}

// New returns the rdap stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string         { return "rdap" }
func (*Stage) Contact() run.Contact { return run.ThirdParty }

func (*Stage) Sources() []string { return ipsource.RDAPHosts() }

func (*Stage) Configured(run.Env) (bool, string) { return true, "" }

// Workers is 1: the checks run one at a time, so a second address in a range
// waits for the lookup that finds it (one request, not two), the registries'
// request rate stays down, and a 429 stops the stage before the next check sends.
func (*Stage) Workers(config.Settings) int { return 1 }

// Evidence names what a check gives a candidate. An organisation check is
// evidence about the organisation, however many registries returned the result;
// an address check is evidence about the address, so a registrant's count is the
// number of ranges it was found on.
func (*Stage) Evidence(checkKey string) (source, item string) {
	kind, rest, _ := strings.Cut(checkKey, "|")
	if kind == "org" {
		if i := strings.LastIndex(rest, "|"); i >= 0 {
			rest = rest[:i]
		}
	}
	return "rdap", rest
}

type orgInput struct {
	org string
	reg ipsource.Registry
}

type ipInput struct{ addr netip.Addr }

// Checks yields an organisation search for each --org input at each registry,
// then each address no current registration holds. A redo forgets the checks
// but keeps their registrations current until its first pass ends, when the
// runner sweeps them and runs another pass: every address is then yielded again
// and the lookups of a run share what they find, one request for a range.
func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, org := range v.Inputs().Orgs {
			for _, r := range ipsource.Registries() {
				if !yield(run.Check{Key: "org|" + org + "|" + r.Name, Input: orgInput{org, r}}, nil) {
					return
				}
			}
		}
		// An address in an in-scope netblock is the target's already, so it is not
		// asked about. One that may be port-checked is not shared provider
		// infrastructure, which is the other half of the rule.
		sc := v.Scope()
		for _, a := range v.KnownAddrs() {
			if ctx.Err() != nil {
				return
			}
			if v.PortEligible(a) && !sc.InScopeIP(a) && !v.Registered(a) {
				if !yield(run.Check{Key: "ip|" + a.String(), Input: ipInput{a}}, nil) {
					return
				}
			}
		}
	}
}

// Run makes one check.
func (s *Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	var obs []run.Observation
	var err error
	switch in := c.Input.(type) {
	case orgInput:
		obs, err = searchOrg(ctx, e, in)
	case ipInput:
		obs, err = lookup(ctx, e, in.addr)
	default:
		err = errors.New("unknown check")
	}
	if err != nil {
		return nil, fmt.Errorf("rdap %s: %w", c.Key, err)
	}
	return obs, nil
}

// get fetches a URL that answers 200 with a body. A 404 is httpsrc.ErrNotFound,
// and a 429 a spent quota: the registries are unkeyed.
func get(ctx context.Context, e egress.Clients, u string) ([]byte, error) {
	return httpsrc.GetQuota(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: u, Accept: ipsource.RDAPAccept})
}

// --- the entities of a response ---

type entity struct {
	Handle   string          `json:"handle"`
	Roles    []string        `json:"roles"`
	VCard    json.RawMessage `json:"vcardArray"`
	Networks []network       `json:"networks"`
	Autnums  []autnum        `json:"autnums"`
	Entities []entity        `json:"entities"`
}

// has reports whether the answer carried the entity's networks or autonomous
// systems, even if the lists are empty: encoding/json leaves a missing list nil
// and makes an empty one for [].
func (e entity) has() bool { return e.Networks != nil || e.Autnums != nil }

type network struct {
	Handle       string `json:"handle"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
}

type autnum struct {
	Handle      string `json:"handle"`
	StartAutnum uint32 `json:"startAutnum"`
	EndAutnum   uint32 `json:"endAutnum"`
}

// name is the entity's formatted name (the fn of its vCard), cleaned for display.
func (e entity) name() string { return ipsource.VCardName(e.VCard) }

// --- organisation search ---

// result is a netblock or an autonomous system a search returned.
type result struct {
	prefixes []netip.Prefix // a netblock, split into its CIDRs
	asns     []string       // an autonomous system (one system of a range is a result of its own)
}

// searchOrg asks one registry for the organisation's netblocks and autonomous
// systems. The registry's entities are searched by the organisation's first word
// and kept when the word rule matches their name.
func searchOrg(ctx context.Context, e egress.Clients, in orgInput) ([]run.Observation, error) {
	words := orgname.Tokens(in.org)
	if len(words) == 0 {
		return nil, nil
	}
	if !in.reg.Search {
		run.Warnf(ctx, "rdap: %s (%s) does not return an organisation's netblocks, so %q is not searched there", in.reg.Name, in.reg.Host, in.org)
		return nil, nil
	}
	found, err := searchEntities(ctx, e, in, words[0])
	if err != nil {
		return nil, err
	}

	c := &orgResults{in: in, seen: map[string]bool{}}
	for _, ent := range found {
		name := ent.name()
		if !orgname.Matches(in.org, name) {
			continue
		}
		full, ok, err := withNetworks(ctx, e, in, ent)
		if err != nil {
			return nil, err
		}
		if ok && !c.add(full, name) {
			break
		}
	}
	if c.truncated {
		run.Warnf(ctx, "rdap: %s (%s) returned more than %d netblocks and autonomous systems for %q; the first %d are kept",
			in.reg.Name, in.reg.Host, maxResults, in.org, maxResults)
	}
	return c.obs, nil
}

// searchEntities returns the registry's entities whose name starts with word.
// A registry that answers not found has none.
func searchEntities(ctx context.Context, e egress.Clients, in orgInput, word string) ([]entity, error) {
	raw, err := get(ctx, e, in.reg.Base+"entities?fn="+url.QueryEscape(word)+"*")
	if errors.Is(err, httpsrc.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var found struct {
		Results []entity `json:"entitySearchResults"`
	}
	if err := json.Unmarshal(raw, &found); err != nil {
		return nil, fmt.Errorf("unreadable response: %w", err)
	}
	return found.Results, nil
}

// withNetworks returns the entity with its networks and autonomous systems:
// ARIN's search result names the entity, and its own record has its networks.
// ok is false when that record is not found or cannot be read.
func withNetworks(ctx context.Context, e egress.Clients, in orgInput, ent entity) (entity, bool, error) {
	if ent.has() {
		return ent, true, nil
	}
	raw, err := get(ctx, e, in.reg.Base+"entity/"+url.PathEscape(ent.Handle))
	if errors.Is(err, httpsrc.ErrNotFound) {
		return ent, false, nil
	}
	if err != nil {
		return ent, false, err
	}
	if json.Unmarshal(raw, &ent) != nil {
		return ent, false, nil //nolint:nilerr // an unreadable entity record is not found, like a 404, so the lookup completes without its networks
	}
	return ent, true, nil
}

// orgResults collects the netblocks and autonomous systems of an
// organisation's matching entities, at most maxResults of them.
type orgResults struct {
	in        orgInput
	obs       []run.Observation
	seen      map[string]bool
	kept      int
	truncated bool
}

// add records the results of one matching entity, named name. It reports false
// once the cap is reached.
func (c *orgResults) add(ent entity, name string) bool {
	for _, r := range results(ent) {
		// A result another matching entity already gave adds nothing, so it does
		// not count toward the cap.
		if !slices.ContainsFunc(r.prefixes, func(p netip.Prefix) bool { return !c.seen[p.String()] }) &&
			!slices.ContainsFunc(r.asns, func(a string) bool { return !c.seen[a] }) {
			continue
		}
		if c.kept == maxResults {
			c.truncated = true
			return false
		}
		c.kept++
		for _, p := range r.prefixes {
			if !c.seen[p.String()] {
				c.seen[p.String()] = true
				c.obs = append(c.obs, kinds.Netblock.Obs(p.String(), kinds.NetblockAttrs{Org: c.in.org}))
			}
		}
		for _, a := range r.asns {
			if !c.seen[a] {
				c.seen[a] = true
				c.obs = append(c.obs, kinds.ASN.Obs(a, kinds.ASNAttrs{Org: c.in.org, Registrant: name, Registry: c.in.reg.Name}))
			}
		}
	}
	return true
}

// results are the netblocks and autonomous systems of an entity that name something usable.
func results(e entity) []result {
	var out []result
	for _, n := range e.Networks {
		start, e1 := netip.ParseAddr(n.StartAddress)
		end, e2 := netip.ParseAddr(n.EndAddress)
		if e1 == nil && e2 == nil {
			if ps := input.RangeCIDRs(start, end); len(ps) > 0 {
				out = append(out, result{prefixes: ps})
			}
		}
	}
	for _, a := range e.Autnums {
		start, end := a.StartAutnum, max(a.EndAutnum, a.StartAutnum)
		if start == 0 {
			if canon, err := input.ParseASN(a.Handle); err == nil {
				out = append(out, result{asns: []string{canon}})
			}
			continue
		}
		// Each system of a range is a result of its own, so the cap counts it and
		// a cut is warned about. One more than the cap is enough to know of a cut.
		for n := uint64(start); n <= uint64(end) && len(out) <= maxResults; n++ {
			out = append(out, result{asns: []string{fmt.Sprintf("AS%d", n)}})
		}
	}
	return out
}

// --- address lookups ---

// runState is what the checks of one run share: the bootstrap files, fetched
// once, and the ranges already found, so that an address inside one needs no
// request. The stage's one worker is the only one to touch it.
type runState struct {
	boot  ipsource.Bootstrap
	found []inventory.Registration
}

type runStateKey struct{}

// lookup records the registered netblock of an address, unless one already
// found in this run holds it.
func lookup(ctx context.Context, e egress.Clients, addr netip.Addr) ([]run.Observation, error) {
	st := run.PerRun(ctx, runStateKey{}, func() *runState { return &runState{} })
	if slices.ContainsFunc(st.found, func(r inventory.Registration) bool { return r.Contains(addr) }) {
		return nil, nil // answered by the lookup that found the range
	}
	reg, found, err := ipsource.Lookup(ctx, e.ThirdParty, &st.boot, addr, func(s string) { run.Warnf(ctx, "%s", s) })
	if err != nil {
		return nil, httpsrc.QuotaError(err)
	}
	if !found {
		return nil, nil
	}
	st.found = append(st.found, inventory.Registration{Start: reg.Start, End: reg.End})
	obs := []run.Observation{kinds.Registration.Obs(kinds.RegistrationAttrs{
		Start: reg.Start.String(), End: reg.End.String(), Registrant: reg.Registrant, Registry: reg.Registry, Handle: reg.Handle, Asked: addr.String()})}
	if reg.Registrant != "" {
		obs = append(obs, kinds.Organisation.Obs(reg.Registrant))
	}
	return obs, nil
}
