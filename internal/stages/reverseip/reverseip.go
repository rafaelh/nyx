// Package reverseip is the reverseip stage: the other hostnames that point at
// each dedicated address nyx has recorded.
package reverseip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

// maxSecurityTrailsPages caps the result pages read for one address (one query
// credit each). An address that needs more is shared hosting for any sensible
// reverseip.max_domains.
const maxSecurityTrailsPages = 10

// Stage asks HackerTarget's reverse IP lookup (unkeyed, IPv4 only) and, when
// keys.securitytrails is set, SecurityTrails' list of domains whose current A or
// AAAA record is the address, for every recorded address that may be port-checked:
// one in an in-scope netblock, or dedicated to the organisation and not excluded.
// It never walks a netblock: only an address some other stage recorded is asked.
//
// An address that returns more distinct registrable domains than
// reverseip.max_domains is unrecognised shared hosting, and nothing is recorded
// for it. The cap is in the check key, so changing it asks again. The key carries
// no scope: a hostname under a root promoted later was recorded only as a
// candidate root until --redo reverseip. It never calls Shodan.
type Stage struct{}

// New returns the reverseip stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string         { return "reverseip" }
func (*Stage) Contact() run.Contact { return run.ThirdParty }
func (*Stage) Sources() []string    { return []string{"api.hackertarget.com", "api.securitytrails.com"} }

// Configured: HackerTarget needs no key, so the stage always runs; a SecurityTrails
// key adds a source.
func (*Stage) Configured(run.Env) (bool, string) { return true, "" }

// input is the Check.Input. The scope travels in it so that Run can tell a
// hostname under an in-scope root from any other name.
type input struct {
	addr  netip.Addr
	sc    *scope.Scope
	max   int
	keyed bool // keys.securitytrails was set when the check was made
}

// Checks yields, in address order, each recorded address that may be port-checked
// (which excludes shared, excluded and unknown-owner addresses). An IPv6 address
// is yielded only with a SecurityTrails key, since HackerTarget cannot answer it;
// it gets its check when a key is added.
func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		set := v.Settings()
		_, keyed := run.Env{Settings: set}.Key("securitytrails")
		sc := v.Scope()
		for _, a := range v.IPs(func(a netip.Addr) bool { return (a.Is4() || keyed) && v.PortEligible(a) }) {
			if ctx.Err() != nil {
				return
			}
			key := fmt.Sprintf("%s|max=%d", a, set.ReverseIP.MaxDomains)
			if !yield(run.Check{Key: key, Input: input{a, sc, set.ReverseIP.MaxDomains, keyed}}, nil) {
				return
			}
		}
	}
}

// Evidence is the address, under the source "reverseip" that the candidate family
// table holds. The item leaves out the cap, so changing it does not count an
// address twice, and a root seen on two addresses has two pairs.
func (*Stage) Evidence(checkKey string) (source, item string) {
	addr, _, _ := strings.Cut(checkKey, "|")
	return "reverseip", addr
}

// Run asks each source and merges the names. A name the scope classifies in scope
// or excluded is a hostname (scope lists it as a subdomain or as excluded); any
// other contributes its registrable domain as a candidate root and the hostname is
// dropped. No names is a completed check.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(input)
	f := found{seen: map[string]bool{}, domains: map[string]bool{}}
	if err := gather(ctx, e, in, &f); err != nil {
		return nil, fmt.Errorf("reverseip %s: %w", in.addr, err)
	}
	if f.over(in.max) {
		run.Warnf(ctx, "reverseip %s: %d registrable domains, more than reverseip.max_domains (%d): treated as shared hosting, nothing recorded",
			in.addr, len(f.domains), in.max)
		return nil, nil
	}
	var obs []run.Observation
	roots := map[string]bool{}
	for _, n := range f.names {
		if class := in.sc.ClassifyHost(n.name).Class; class == scope.InScope || class == scope.Excluded {
			obs = append(obs, kinds.Hostname.Obs(n.name, kinds.HostnameAttrs{}))
		} else if n.root != "" && !roots[n.root] {
			roots[n.root] = true
			obs = append(obs, kinds.Root.Obs(n.root))
		}
	}
	return obs, nil
}

// found is the names an address returned, cleaned and without repeats, each with
// its registrable domain ("" when it has none), and the set of those domains.
type found struct {
	names   []struct{ name, root string }
	seen    map[string]bool
	domains map[string]bool
}

func (f *found) add(names []string) {
	for _, n := range names {
		if n = httpsrc.CleanName(n); n == "" || f.seen[n] {
			continue
		}
		f.seen[n] = true
		root, _ := dnsname.ETLDPlusOne(n)
		if root != "" {
			f.domains[root] = true
		}
		f.names = append(f.names, struct{ name, root string }{n, root})
	}
}

// over reports whether the names span more registrable domains than the cap: the
// address is shared hosting.
func (f *found) over(limit int) bool { return len(f.domains) > limit }

// gather asks HackerTarget (IPv4 only) and then, with a key, SecurityTrails. An
// address HackerTarget already shows to be shared hosting is not asked of
// SecurityTrails, whose pages each spend a credit.
func gather(ctx context.Context, e egress.Clients, in input, f *found) error {
	if in.addr.Is4() {
		names, err := httpsrc.GetNames(ctx, e, "https://api.hackertarget.com/reverseiplookup/?"+url.Values{"q": {in.addr.String()}}.Encode(), reverseLines)
		if err != nil {
			return err
		}
		f.add(names)
	}
	if !in.keyed || f.over(in.max) {
		return nil
	}
	return securityTrails(ctx, e, in, f)
}

// reverseLines reads HackerTarget's reverse lookup reply, one name per line. Its
// quota (a 429, or the text reply it sends with a 200) is run.ErrQuota. A line
// that is not a name means the reply is not a list, which is an error and not "no
// names".
func reverseLines(body []byte) ([]string, error) {
	lines, err := httpsrc.HackerTargetLines(body)
	if err != nil {
		return nil, err
	}
	for _, l := range lines {
		if strings.ContainsAny(l, " \t,<>") {
			return nil, errors.New("unreadable HackerTarget response")
		}
	}
	return lines, nil
}

// securityTrails adds the domains whose current A or AAAA record is the address.
// It reads pages until the cap is passed (the address is then shared hosting and
// more would only spend credits), the pages run out, or maxSecurityTrailsPages.
// A 401, 403 or 429 aborts the stage (httpsrc.Get): HackerTarget lookups included.
func securityTrails(ctx context.Context, e egress.Clients, in input, f *found) error {
	field := "ipv4"
	if in.addr.Is6() {
		field = "ipv6"
	}
	body, err := json.Marshal(map[string]any{"filter": map[string]string{field: in.addr.String()}})
	if err != nil {
		return err
	}
	for page := 1; ; page++ {
		raw, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{
			Method: "POST", URL: "https://api.securitytrails.com/v1/domains/list?include_ips=false&scroll=false&page=" + strconv.Itoa(page),
			Body: body, ContentType: "application/json", KeySource: "securitytrails", KeyHeader: "APIKEY",
		})
		if errors.Is(err, httpsrc.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		// The page count is read from meta.total_pages, where SecurityTrails' domain
		// search reports it, and from a top-level pages, whichever is larger: with
		// neither, only the first page would ever be read and the shared-hosting guard
		// could not be passed.
		var r struct {
			Pages int `json:"pages"`
			Meta  struct {
				TotalPages int `json:"total_pages"`
			} `json:"meta"`
			Records []struct {
				Hostname string `json:"hostname"`
			} `json:"records"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || r.Records == nil {
			return errors.New("unreadable SecurityTrails response")
		}
		names := make([]string, len(r.Records))
		for i, rec := range r.Records {
			names[i] = rec.Hostname
		}
		f.add(names)
		if page >= max(r.Pages, r.Meta.TotalPages) || f.over(in.max) {
			return nil
		}
		if page == maxSecurityTrailsPages {
			run.Warnf(ctx, "reverseip %s: SecurityTrails result truncated after %d pages", in.addr, page)
			return nil
		}
	}
}
