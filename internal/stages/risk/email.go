package risk

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/provider"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/stages/serveraddr"
)

// Email reads MX, SPF, DMARC, MTA-STS and common DKIM selectors for each
// in-scope input root, and from them the third parties the root authorises to
// send its mail (SPF), receive its mail reports (DMARC) and host its mailboxes
// (MX). It only asks public DNS, so it runs under --passive. It never fetches
// an MTA-STS policy file.
type Email struct{}

// NewEmail returns the email stage.
func NewEmail() *Email { return &Email{} }

func (*Email) Name() string                      { return "email" }
func (*Email) Contact() run.Contact              { return run.ThirdParty }
func (*Email) Sources() []string                 { return nil }
func (*Email) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedChecks: a check for a changed selector list supersedes the old one's evidence.
func (*Email) RetiresUnlistedChecks() {}

// mtaSTSToken ends every check key: a check made before MTA-STS was read does
// not have it, so an engagement from before runs its email checks again once.
const mtaSTSToken = "|mta-sts"

// input is the Check.Input: the root, and the scope, which says which of its
// mail hosts are outside it.
type input struct {
	root string
	sc   *scope.Scope
}

// Checks yields one check per in-scope input root; a changed selector list creates new checks.
func (*Email) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, root := range v.InScopeRoots() {
			if !yield(run.Check{Key: root + "|dkim=" + config.DKIMSelectorHash() + mtaSTSToken + serveraddr.KeyToken, Input: input{root, v.Scope()}}, nil) {
				return
			}
		}
	}
}

// txt returns the TXT strings at name. A timeout or SERVFAIL is an error; NXDOMAIN and NODATA are no records.
func txt(ctx context.Context, e egress.Clients, name string) ([]string, error) {
	res, err := e.DNS.Query(ctx, name, egress.TypeTXT)
	if err != nil {
		return nil, err
	}
	if res.RCode == egress.RCodeServFail {
		return nil, fmt.Errorf("%s: SERVFAIL", name)
	}
	var out []string
	for _, a := range res.Answers {
		if a.Type == "TXT" {
			out = append(out, a.Value)
		}
	}
	return out, nil
}

// withPrefix returns the records that start with prefix (case-insensitively)
// followed by the end or a space.
func withPrefix(records []string, prefix string) []string {
	var out []string
	for _, r := range records {
		t := strings.TrimSpace(r)
		if len(t) >= len(prefix) && strings.EqualFold(t[:len(prefix)], prefix) && (len(t) == len(prefix) || t[len(prefix)] == ' ' || t[len(prefix)] == ';') {
			out = append(out, t)
		}
	}
	return out
}

// Run reads the posture. A timeout or SERVFAIL on MX, the root's TXT, an SPF
// include or redirect, the DMARC names or _mta-sts fails the check (it is
// retried next run, and records no third parties); one on a DKIM selector is
// recorded in dkim_errors, and one on a mail host's own address is ignored. An
// include that does not exist or has no single SPF record makes the SPF invalid.
func (*Email) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(input)
	root := in.root
	var attrs kinds.EmailPostureAttrs
	tp := &thirdParties{root: root, found: map[string]int{}}

	mx, err := e.DNS.Query(ctx, root, egress.TypeMX)
	if err != nil {
		return nil, err
	}
	if mx.RCode == egress.RCodeServFail {
		return nil, fmt.Errorf("%s MX: SERVFAIL", root)
	}
	var hosts []string
	for _, a := range mx.Answers {
		if a.Type != "MX" {
			continue
		}
		if _, host, ok := strings.Cut(a.Value, " "); ok && host != "." && host != "" {
			hosts = append(hosts, host)
		}
	}
	slices.Sort(hosts)
	attrs.MX = strings.Join(hosts, ";")
	for _, h := range hosts {
		tp.add(kinds.MechanismMX, dnsname.Registrable(h), 0)
	}

	rootTXT, err := txt(ctx, e, root)
	if err != nil {
		return nil, err
	}
	spfs := withPrefix(rootTXT, "v=spf1")
	attrs.SPFRecords = len(spfs)
	if len(spfs) > 0 {
		attrs.SPF = spfs[0]
	}
	switch {
	case len(spfs) > 1:
		attrs.SPFError = fmt.Sprintf("%d v=spf1 records", len(spfs))
	case len(spfs) == 1:
		ev := &spfEval{ctx: ctx, e: e, tp: tp}
		all := ev.walk(spfs[0], map[string]bool{root: true}, 0)
		if ev.tempErr != nil {
			return nil, ev.tempErr
		}
		attrs.SPFAll, attrs.SPFLookups, attrs.SPFError = all, ev.lookups, ev.err
	}

	// DMARC: the root's own record, else the organisational domain's.
	rec, err := dmarc(ctx, e, "_dmarc."+root)
	if err != nil {
		return nil, err
	}
	source, sub := "root", false
	if org, ok := dnsname.ETLDPlusOne(root); ok && org != root {
		sub = true
		if rec == "" {
			if rec, err = dmarc(ctx, e, "_dmarc."+org); err != nil {
				return nil, err
			}
			source = "org"
		}
	}
	if rec != "" {
		tags := dmarcTags(rec)
		policy := tags["p"]
		if sub && source == "org" && tags["sp"] != "" {
			policy = tags["sp"]
		}
		attrs.DMARC, attrs.DMARCPolicy, attrs.DMARCSource = rec, strings.ToLower(policy), source
		for _, tag := range []string{"rua", "ruf"} {
			for _, domain := range reportDomains(tags[tag]) {
				tp.add(kinds.MechanismDMARC, domain, 0)
			}
		}
	}

	// The selectors, _mta-sts and the mail hosts' addresses are independent
	// lookups, so they are asked at once (egress still rate-limits them); the
	// results keep the selectors' and the hosts' order. The addresses are
	// best-effort: a failed lookup leaves the host without one, and never fails or
	// retires the check (a cancelled context is caught below).
	mailHosts := slices.Compact(slices.Clone(hosts))
	mailAddrs := make([][]run.Observation, len(mailHosts))
	sels := config.DKIMSelectors()
	type lookup struct {
		recs []string
		err  error
	}
	res := make([]lookup, len(sels))
	var mtaSTS lookup
	var wg sync.WaitGroup
	for i, sel := range sels {
		wg.Go(func() {
			defer run.RecoverInto(&res[i].err)
			res[i].recs, res[i].err = txt(ctx, e, sel+"._domainkey."+root)
		})
	}
	// MTA-STS: only a root that receives mail has a policy to publish. Its own
	// name is asked, never the organisational domain's, and the policy file over
	// HTTPS is never fetched.
	if len(hosts) > 0 {
		wg.Go(func() {
			defer run.RecoverInto(&mtaSTS.err)
			mtaSTS.recs, mtaSTS.err = txt(ctx, e, "_mta-sts."+root)
		})
	}
	for i, h := range mailHosts {
		wg.Go(func() {
			var ignored error // the addresses are best-effort, as below
			defer run.RecoverInto(&ignored)
			mailAddrs[i], _ = serveraddr.Observations(ctx, e, in.sc, h)
		})
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if mtaSTS.err != nil {
		return nil, mtaSTS.err
	}
	if len(hosts) > 0 {
		attrs.MTASTS = "absent"
		if len(withPrefix(mtaSTS.recs, "v=STSv1")) == 1 {
			attrs.MTASTS = "present"
		}
	}
	var found, failed []string
	for i, sel := range sels {
		if res[i].err != nil {
			failed = append(failed, sel)
			continue
		}
		if slices.ContainsFunc(res[i].recs, isDKIMKey) {
			found = append(found, sel)
		}
	}
	attrs.DKIMSelectors, attrs.DKIMErrors = strings.Join(found, ";"), strings.Join(failed, ";")
	obs := append([]run.Observation{kinds.EmailPosture.Obs(root, attrs)}, tp.observations()...)
	for _, addrs := range mailAddrs {
		obs = append(obs, addrs...)
	}
	return obs, nil
}

// thirdParties collects the third parties one check found, one per mechanism and
// domain, with the nearest depth a domain was named at. Whether a domain is a
// third party at all is decided on read (one in scope is not); the stage drops
// only a domain in the root's own registrable domain.
type thirdParties struct {
	root  string
	found map[string]int // "<mechanism>|<domain>" -> depth
}

// add records a domain named at depth. A name that cannot be looked up (a
// macro, a malformed name, an address an MX record wrongly names) is not a
// third party, so it is not recorded.
func (t *thirdParties) add(mechanism, domain string, depth int) {
	domain = dnsname.Normalise(domain)
	if !lookupable(domain) || sameRegistrable(domain, t.root) {
		return
	}
	k := mechanism + "|" + domain
	if d, ok := t.found[k]; !ok || depth < d {
		t.found[k] = depth
	}
}

func (t *thirdParties) observations() []run.Observation {
	var obs []run.Observation
	for _, k := range slices.Sorted(maps.Keys(t.found)) {
		mechanism, domain, _ := strings.Cut(k, "|")
		owner, _ := provider.Default().DomainOwner(domain)
		obs = append(obs, kinds.ThirdParty.Obs(kinds.ThirdPartyKey(t.root, mechanism, domain),
			kinds.ThirdPartyAttrs{Root: t.root, Mechanism: mechanism, Domain: domain, Provider: owner, Depth: t.found[k]}))
	}
	return obs
}

// sameRegistrable reports whether two names share a registrable domain (or,
// for a name that has none, are the same name or one is under the other).
func sameRegistrable(a, b string) bool {
	ra, oka := dnsname.ETLDPlusOne(a)
	rb, okb := dnsname.ETLDPlusOne(b)
	if oka && okb {
		return ra == rb
	}
	return dnsname.Under(a, b) || dnsname.Under(b, a)
}

// reportDomains are the mailbox domains of a DMARC rua or ruf value: a
// comma-separated list of URIs, each with an optional "!size" suffix. Only
// mailto: URIs name a mailbox; any other scheme is ignored.
func reportDomains(value string) []string {
	var out []string
	for _, uri := range strings.Split(value, ",") {
		rest, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(uri)), "mailto:")
		if !ok {
			continue
		}
		addr, _, _ := strings.Cut(rest, "!")
		if _, domain, ok := strings.Cut(addr, "@"); ok {
			out = append(out, domain)
		}
	}
	return out
}

func dmarc(ctx context.Context, e egress.Clients, name string) (string, error) {
	recs, err := txt(ctx, e, name)
	if err != nil {
		return "", err
	}
	if m := withPrefix(recs, "v=DMARC1"); len(m) > 0 {
		return m[0], nil
	}
	return "", nil
}

// isDKIMKey reports whether a TXT record is a usable DKIM key (RFC 6376 3.6.1):
// a v= tag, if present, is DKIM1 and the p= tag is non-empty. A revoked key
// (empty p=) and an unrelated record a wildcard returns are not.
func isDKIMKey(rec string) bool {
	t := dmarcTags(rec)
	if v, ok := t["v"]; ok && !strings.EqualFold(v, "DKIM1") {
		return false
	}
	return strings.Join(strings.Fields(t["p"]), "") != ""
}

// dmarcTags parses a tag=value list (DMARC, DKIM), lower-casing the tag names.
func dmarcTags(rec string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return tags
}

// spfEval counts the DNS-querying terms of an SPF record and its includes and
// redirects (RFC 7208 4.6.4), following them with loop detection and a hard stop.
// err is a permanent error (the SPF is invalid); tempErr is a timeout or
// SERVFAIL on an include or redirect, which fails the check so it is retried
// (an RFC 7208 temperror, not a permerror).
type spfEval struct {
	ctx     context.Context
	e       egress.Clients
	lookups int
	queries int
	err     string
	tempErr error
	// tp collects each domain a record names (an include, a followed redirect, or
	// an a:, mx: or exists: argument) at the depth it was named at: 0 in the
	// root's own record, one more in each record followed.
	tp *thirdParties
}

const spfMaxQueries = 30 // a hard stop on what one record may make us ask

func (s *spfEval) fail(msg string) {
	if s.err == "" {
		s.err = msg
	}
}

// name records a domain a record at depth names.
func (s *spfEval) name(domain string, depth int) { s.tp.add(kinds.MechanismSPF, domain, depth) }

// walk evaluates one record, found at depth, and returns its "all" mechanism
// with qualifier ("" if none).
func (s *spfEval) walk(record string, path map[string]bool, depth int) string {
	all, redirect := "", ""
	for _, term := range strings.Fields(record)[1:] {
		q := byte('+')
		if strings.ContainsRune("+-~?", rune(term[0])) {
			q, term = term[0], term[1:]
		}
		name, arg, _ := strings.Cut(term, ":")
		if n, a, ok := strings.Cut(term, "="); ok && strings.EqualFold(n, "redirect") {
			name, arg = "redirect", a
		}
		name = strings.ToLower(strings.SplitN(name, "/", 2)[0])
		switch name {
		case "all":
			all = string(q) + "all"
		case "include":
			s.lookups++
			s.name(arg, depth)
			s.follow(arg, path, depth+1)
		case "redirect":
			redirect = arg
		case "a", "mx", "exists":
			s.lookups++
			// An argument may carry a CIDR length ("a:host/24"); a bare a or mx names the root itself.
			host, _, _ := strings.Cut(arg, "/")
			s.name(host, depth)
		case "ptr":
			s.lookups++
		}
	}
	// A redirect is ignored, and never queried, when the record has an "all" (RFC 7208 6.1).
	if redirect != "" && all == "" {
		s.lookups++
		s.name(redirect, depth)
		return s.follow(redirect, path, depth+1)
	}
	return all
}

// spfDomain matches a domain that can be looked up: dot-separated labels of
// letters, digits, "-" and "_".
var spfDomain = regexp.MustCompile(`^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)+$`)

// lookupable reports whether a normalised name is a domain that can be looked
// up: a name spfDomain matches (so never a macro, whose "%" it rejects) of at
// most 253 characters, and not an address.
func lookupable(domain string) bool {
	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}
	return len(domain) <= 253 && spfDomain.MatchString(domain)
}

// follow fetches and evaluates the SPF record of an included or redirected domain.
func (s *spfEval) follow(domain string, path map[string]bool, depth int) string {
	domain = dnsname.Normalise(domain)
	switch {
	case s.tempErr != nil:
		return ""
	case domain == "":
		s.fail("include with no domain")
		return ""
	case strings.Contains(domain, "%"):
		return "" // a macro expands per message, so it cannot be followed here
	case len(domain) > 253 || !spfDomain.MatchString(domain):
		s.fail(fmt.Sprintf("include %q is not a domain name", domain))
		return ""
	case path[domain]:
		s.fail("include loop at " + domain)
		return ""
	case s.queries >= spfMaxQueries:
		s.fail("too many includes")
		return ""
	}
	s.queries++
	recs, err := txt(s.ctx, s.e, domain)
	if err != nil {
		s.tempErr = fmt.Errorf("SPF include %s: %w", domain, err)
		return ""
	}
	spfs := withPrefix(recs, "v=spf1")
	if len(spfs) != 1 {
		s.fail(fmt.Sprintf("include %s: %d SPF records", domain, len(spfs)))
		return ""
	}
	path[domain] = true
	defer delete(path, domain)
	return s.walk(spfs[0], path, depth)
}
