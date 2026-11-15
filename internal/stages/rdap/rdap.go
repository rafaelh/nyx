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
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/orgname"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/sanitize"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

const (
	bootstrapHost = "data.iana.org"
	// maxResults caps the netblocks and autonomous systems kept for one
	// organisation at one registry. The value is a reasonable guess, not a registry limit.
	maxResults = 50
	// maxHops is how many referrals a lookup follows.
	maxHops = 3
)

// registry is one of the five regional internet registries.
type registry struct {
	name, host string
	// base is the registry's service URL, as the bootstrap file gives it.
	base string
	// search is whether an organisation search returns the organisation's
	// netblocks and autonomous systems. ARIN does, with a second request for the
	// entity, and APNIC does in the search result. RIPE, LACNIC and AFRINIC
	// return the entity alone, so they are not asked.
	search bool
}

var registries = []registry{
	{"arin", "rdap.arin.net", "https://rdap.arin.net/registry/", true},
	{"ripe", "rdap.db.ripe.net", "https://rdap.db.ripe.net/", false},
	{"apnic", "rdap.apnic.net", "https://rdap.apnic.net/", true},
	{"lacnic", "rdap.lacnic.net", "https://rdap.lacnic.net/rdap/", false},
	{"afrinic", "rdap.afrinic.net", "https://rdap.afrinic.net/rdap/", false},
}

func registryByHost(host string) (registry, bool) {
	i := slices.IndexFunc(registries, func(r registry) bool { return r.host == host })
	if i < 0 {
		return registry{}, false
	}
	return registries[i], true
}

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

func (*Stage) Sources() []string {
	out := []string{bootstrapHost}
	for _, r := range registries {
		out = append(out, r.host)
	}
	return out
}

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
	reg registry
}

type ipInput struct{ addr netip.Addr }

// Checks yields an organisation search for each --org input at each registry,
// then each address no current registration holds. After --redo rdap no
// registration is current (a redo forgets the checks, and a record is current
// only while a completed check observes it), so every address is yielded again
// and the lookups of a run share what they find: one request for a range.
func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, org := range v.Inputs().Orgs {
			for _, r := range registries {
				if !yield(run.Check{Key: "org|" + org + "|" + r.name, Input: orgInput{org, r}}, nil) {
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

const accept = "application/rdap+json, application/json"

// get fetches a URL that answers 200 with a body. A 404 is httpsrc.ErrNotFound,
// and a 429 a spent quota: the registries are unkeyed.
func get(ctx context.Context, e egress.Clients, u string) ([]byte, error) {
	return httpsrc.GetQuota(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: u, Accept: accept})
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
func (e entity) name() string {
	var card []json.RawMessage
	if json.Unmarshal(e.VCard, &card) != nil || len(card) < 2 {
		return ""
	}
	var props [][]json.RawMessage
	if json.Unmarshal(card[1], &props) != nil {
		return ""
	}
	for _, p := range props {
		var key, val string
		if len(p) >= 4 && json.Unmarshal(p[0], &key) == nil && key == "fn" && json.Unmarshal(p[3], &val) == nil {
			return strings.TrimSpace(sanitize.Text(val))
		}
	}
	return ""
}

func (e entity) is(role string) bool { return slices.Contains(e.Roles, role) }

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
	if !in.reg.search {
		run.Warnf(ctx, "rdap: %s (%s) does not return an organisation's netblocks, so %q is not searched there", in.reg.name, in.reg.host, in.org)
		return nil, nil
	}
	raw, err := get(ctx, e, in.reg.base+"entities?fn="+url.QueryEscape(words[0])+"*")
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
		return nil, fmt.Errorf("unreadable response: %v", err)
	}

	var obs []run.Observation
	seen := map[string]bool{}
	kept, truncated := 0, false
search:
	for _, ent := range found.Results {
		name := ent.name()
		if !orgname.Matches(in.org, name) {
			continue
		}
		if !ent.has() {
			// ARIN's search result names the entity; its own record has its networks.
			raw, err := get(ctx, e, in.reg.base+"entity/"+url.PathEscape(ent.Handle))
			if errors.Is(err, httpsrc.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if json.Unmarshal(raw, &ent) != nil {
				continue
			}
		}
		for _, r := range results(ent) {
			// A result another matching entity already gave adds nothing, so it does
			// not count toward the cap.
			if !slices.ContainsFunc(r.prefixes, func(p netip.Prefix) bool { return !seen[p.String()] }) &&
				!slices.ContainsFunc(r.asns, func(a string) bool { return !seen[a] }) {
				continue
			}
			if kept == maxResults {
				truncated = true
				break search
			}
			kept++
			for _, p := range r.prefixes {
				if !seen[p.String()] {
					seen[p.String()] = true
					obs = append(obs, kinds.Netblock.Obs(p.String(), kinds.NetblockAttrs{Org: in.org}))
				}
			}
			for _, a := range r.asns {
				if !seen[a] {
					seen[a] = true
					obs = append(obs, kinds.ASN.Obs(a, kinds.ASNAttrs{Org: in.org, Registrant: name, Registry: in.reg.name}))
				}
			}
		}
	}
	if truncated {
		run.Warnf(ctx, "rdap: %s (%s) returned more than %d netblocks and autonomous systems for %q; the first %d are kept",
			in.reg.name, in.reg.host, maxResults, in.org, maxResults)
	}
	return obs, nil
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
	boot  map[bool]*bootstrap // by whether the address is IPv4
	found []inventory.Registration
}

type runStateKey struct{}

// bootstrap is IANA's file for one address family, or the reason it could not be had.
type bootstrap struct {
	entries []bootEntry
	err     error
}

type bootEntry struct {
	prefix netip.Prefix
	url    string
}

// serviceURL is the registry URL that holds the address: the longest matching prefix's.
func (b *bootstrap) serviceURL(a netip.Addr) (string, bool) {
	best, bits := "", -1
	for _, e := range b.entries {
		if e.prefix.Contains(a) && e.prefix.Bits() > bits {
			best, bits = e.url, e.prefix.Bits()
		}
	}
	return best, bits >= 0
}

func (st *runState) bootstrapFor(ctx context.Context, e egress.Clients, a netip.Addr) *bootstrap {
	if b, ok := st.boot[a.Is4()]; ok {
		return b
	}
	b := fetchBootstrap(ctx, e, a.Is4())
	st.boot[a.Is4()] = b
	return b
}

func fetchBootstrap(ctx context.Context, e egress.Clients, v4 bool) *bootstrap {
	name := "ipv6.json"
	if v4 {
		name = "ipv4.json"
	}
	fail := func(err error) *bootstrap { return &bootstrap{err: fmt.Errorf("bootstrap %s: %w", name, err)} }
	raw, err := get(ctx, e, "https://"+bootstrapHost+"/rdap/"+name)
	if err != nil {
		return fail(err)
	}
	var file struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return fail(fmt.Errorf("unreadable: %v", err))
	}
	b := &bootstrap{}
	for _, svc := range file.Services {
		if len(svc) != 2 {
			continue
		}
		u := ""
		for _, c := range svc[1] { // the https URL, which is all the client may use
			if strings.HasPrefix(c, "https://") {
				u = c
				break
			}
		}
		for _, p := range svc[0] {
			if pfx, err := netip.ParsePrefix(p); err == nil && u != "" {
				b.entries = append(b.entries, bootEntry{pfx.Masked(), u})
			}
		}
	}
	return b
}

// lookup records the registered netblock of an address, unless one already
// found in this run holds it.
func lookup(ctx context.Context, e egress.Clients, addr netip.Addr) ([]run.Observation, error) {
	st := run.PerRun(ctx, runStateKey{}, func() *runState { return &runState{boot: map[bool]*bootstrap{}} })
	if slices.ContainsFunc(st.found, func(r inventory.Registration) bool { return r.Contains(addr) }) {
		return nil, nil // answered by the lookup that found the range
	}
	b := st.bootstrapFor(ctx, e, addr)
	if b.err != nil {
		return nil, b.err
	}
	base, ok := b.serviceURL(addr)
	if !ok {
		return nil, nil // no registry holds it: nothing to record
	}
	raw, reg, err := follow(ctx, e, addr, base+"ip/"+addr.String())
	if err != nil || raw == nil {
		return nil, err
	}
	var ans struct {
		Handle       string   `json:"handle"`
		StartAddress string   `json:"startAddress"`
		EndAddress   string   `json:"endAddress"`
		Entities     []entity `json:"entities"`
	}
	if err := json.Unmarshal(raw, &ans); err != nil {
		return nil, fmt.Errorf("unreadable response: %v", err)
	}
	start, e1 := netip.ParseAddr(ans.StartAddress)
	end, e2 := netip.ParseAddr(ans.EndAddress)
	start, end = start.Unmap(), end.Unmap()
	// A range of mixed families, or one that leaves out the address asked about,
	// would answer later addresses it says nothing about, here and on later runs.
	span := inventory.Registration{Start: start, End: end}
	if e1 != nil || e2 != nil || start.Is4() != end.Is4() || !span.Contains(addr.Unmap()) {
		run.Warnf(ctx, "rdap: %s (%s) gave no address range for %s", reg.name, reg.host, addr)
		return nil, nil
	}
	registrant := ""
	for _, ent := range ans.Entities {
		if !ent.is("registrant") {
			continue
		}
		if n := ent.name(); n != "" {
			registrant = n
			break
		}
	}
	handle := strings.TrimSpace(sanitize.Text(ans.Handle))
	if handle == "" {
		handle = start.String() + "-" + end.String()
	}
	st.found = append(st.found, span)
	obs := []run.Observation{kinds.Registration.Obs(kinds.RegistrationKey(reg.name, handle), kinds.RegistrationAttrs{
		Start: start.String(), End: end.String(), Registrant: registrant, Registry: reg.name, Handle: handle, Asked: addr.String()})}
	if registrant != "" {
		obs = append(obs, kinds.Organisation.Obs(registrant))
	}
	return obs, nil
}

// follow requests the URL and follows a referral by hand, up to maxHops times,
// to one of the five registries. It returns the body of the answer and the
// registry that gave it. The body is nil for a lookup that completes with
// nothing: a 404, a referral to another host or too many referrals.
func follow(ctx context.Context, e egress.Clients, addr netip.Addr, u string) ([]byte, registry, error) {
	for hop := 0; ; hop++ {
		host := ""
		parsed, perr := url.Parse(u)
		if perr == nil {
			host = strings.ToLower(parsed.Hostname())
		}
		reg, found := registryByHost(host)
		if !found {
			run.Warnf(ctx, "rdap: %s is held by %s, which is not one of the registries; no registration is recorded", addr, host)
			return nil, reg, nil
		}
		// Not httpsrc.GetQuota: a referral's status and Location are needed.
		resp, err := e.ThirdParty.Do(ctx, egress.ThirdPartyRequest{Method: "GET", URL: u, Accept: accept})
		switch {
		case err != nil:
			return nil, reg, err
		case resp.Status == 429:
			return nil, reg, fmt.Errorf("HTTP 429: %w", run.ErrQuota)
		case resp.Truncated:
			return nil, reg, errors.New("response was larger than the 10 MiB limit")
		}
		switch resp.Status {
		case 200:
			return resp.Body, reg, nil
		case 404:
			return nil, reg, nil
		case 301, 302, 303, 307, 308:
		default:
			return nil, reg, fmt.Errorf("HTTP %d", resp.Status)
		}
		if hop == maxHops {
			run.Warnf(ctx, "rdap: the lookup of %s was referred more than %d times; no registration is recorded", addr, maxHops)
			return nil, reg, nil
		}
		loc := ""
		if l := resp.Header["Location"]; len(l) > 0 {
			loc = l[0]
		}
		next, err := parsed.Parse(loc)
		if err != nil || loc == "" || next.Scheme != "https" {
			run.Warnf(ctx, "rdap: %s referred the lookup of %s to %q, which cannot be followed; no registration is recorded", reg.host, addr, loc)
			return nil, reg, nil
		}
		u = next.String()
	}
}
