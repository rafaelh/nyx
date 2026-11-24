// Package rdap queries IANA bootstrap and regional registries for address allocations and
// organisation-owned netblocks/ASNs. Organisation discoveries remain candidates until supplied
// as scope inputs.
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

	"github.com/rafaelh/nyx/internal/candidates"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/httpsrc"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/inventory"
	"github.com/rafaelh/nyx/internal/ipsource"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/orgname"
	"github.com/rafaelh/nyx/internal/run"
)

const (
	// maxResults bounds organisation allocations per registry as a local starting limit,
	// not a registry-imposed limit.
	maxResults = 50
)

// Procedure looks up organisation/registry pairs and individual addresses once unless redone.
// Recorded allocations cover later addresses in the same range, avoiding repeat requests across
// runs. Newly eligible addresses are picked up without putting scope into job keys.
type Procedure struct{}

// New returns the rdap procedure.
func New() *Procedure { return &Procedure{} }

func (*Procedure) Name() string         { return "rdap" }
func (*Procedure) Contact() run.Contact { return run.ThirdParty }

func (*Procedure) Sources() []string { return ipsource.RDAPHosts() }

func (*Procedure) Configured(run.Env) (bool, string) { return true, "" }

// Workers serialises lookups so addresses can reuse newly found allocations and a 429 stops
// requests before the next job. This also limits registry traffic.
func (*Procedure) Workers(config.Settings) int { return 1 }

// CandidateSources classifies registry allocation evidence as registrant evidence.
func (*Procedure) CandidateSources() map[string]string {
	return map[string]string{"rdap": candidates.Registrant}
}

// Evidence counts an organisation once across registries, or the looked-up address for address
// jobs, avoiding duplicate support from registry overlap.
func (*Procedure) Evidence(jobKey string) (source, item string) {
	kind, rest, _ := strings.Cut(jobKey, "|")
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

// Jobs searches each input organisation at each registry, then uncovered addresses. During
// redo, old allocations survive until the first sweep; the next pass then lists newly uncovered
// addresses and shares fresh allocations to avoid duplicate range lookups.
func (*Procedure) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		for _, org := range v.Inputs().Orgs {
			for _, r := range ipsource.Registries() {
				if !yield(run.Job{Key: "org|" + org + "|" + r.Name, Input: orgInput{org, r}}, nil) {
					return
				}
			}
		}
		// In-scope netblocks already establish ownership. Other queried addresses need
		// port eligibility to rule out shared infrastructure.
		sc := v.Scope()
		for _, a := range v.KnownAddrs() {
			if ctx.Err() != nil {
				return
			}
			if v.PortEligible(a) && !sc.InScopeIP(a) && !v.Registered(a) {
				if !yield(run.Job{Key: "ip|" + a.String(), Input: ipInput{a}}, nil) {
					return
				}
			}
		}
	}
}

// Run makes one job.
func (s *Procedure) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
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

// get maps 404 to ErrNotFound and unkeyed registry 429 to quota exhaustion. Successful
// responses require a 200 body.
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

// has distinguishes present empty lists from missing fields using JSON's non-nil empty-slice
// decoding.
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

// searchOrg searches by the organisation's first word, then applies the shared word rule to
// registry entity names before accepting their ranges and ASNs.
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
	org := orgname.New(in.org)
	for _, ent := range found {
		name := ent.name()
		if !org.Matches(name) {
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

// withNetworks follows ARIN search entities to their full records, which hold allocations.
// Missing or unreadable records return ok=false.
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
		// Count each ASN in an expanded range against the cap. One extra item is enough
		// to detect truncation and warn.
		for n := uint64(start); n <= uint64(end) && len(out) <= maxResults; n++ {
			out = append(out, result{asns: []string{fmt.Sprintf("AS%d", n)}})
		}
	}
	return out
}

// --- address lookups ---

// runState shares bootstrap data and discovered allocations for this run. The procedure's single
// worker needs no additional locking here.
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
