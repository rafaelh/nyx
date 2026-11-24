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
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/scope"
	"github.com/rafaelh/nyx/internal/serveraddr"
)

// Email collects root mail posture and SPF/DMARC/MX dependencies through public DNS, including
// passive runs. It does not fetch HTTPS MTA-STS policy files.
type Email struct{}

// NewEmail returns the email procedure.
func NewEmail() *Email { return &Email{} }

func (*Email) Name() string                      { return "email" }
func (*Email) Contact() run.Contact              { return run.ThirdParty }
func (*Email) Sources() []string                 { return nil }
func (*Email) Configured(run.Env) (bool, string) { return true, "" }

// RetiresUnlistedJobs replaces evidence from superseded selector-list jobs.
func (*Email) RetiresUnlistedJobs() {}

// mtaSTSToken versions jobs so engagements created before MTA-STS support run their email
// jobs once more.
const mtaSTSToken = "|mta-sts"

// input carries the root and scope for classifying external mail dependencies.
type input struct {
	root string
	sc   *scope.Scope
}

// Jobs versions each in-scope input root by the selector list.
func (*Email) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return func(yield func(run.Job, error) bool) {
		for _, root := range v.InScopeRoots() {
			if !yield(run.Job{Key: root + "|dkim=" + config.DKIMSelectorHash() + mtaSTSToken + serveraddr.KeyToken, Input: input{root, v.Scope()}}, nil) {
				return
			}
		}
	}
}

// txt treats NXDOMAIN/NODATA as empty and timeout/SERVFAIL as errors.
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

// withPrefix requires a case-insensitive tag prefix followed by whitespace or end of text.
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

// Run retries the whole job for core DNS, SPF traversal, DMARC or MTA-STS transient failures,
// storing no partial third parties. DKIM failures are recorded separately; mail-host address
// failures are best-effort. Missing or ambiguous included SPF records make SPF invalid.
func (*Email) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(input)
	root := in.root
	var attrs kinds.EmailPostureAttrs
	tp := &thirdParties{root: root, found: map[string]int{}}

	hosts, err := mxHosts(ctx, e, root)
	if err != nil {
		return nil, err
	}
	attrs.MX = strings.Join(hosts, ";")
	for _, h := range hosts {
		tp.add(kinds.MechanismMX, dnsname.Registrable(h), 0)
	}
	if err := readSPF(ctx, e, root, tp, &attrs); err != nil {
		return nil, err
	}
	if err := readDMARC(ctx, e, root, tp, &attrs); err != nil {
		return nil, err
	}

	l := lookUpConcurrently(ctx, e, in, hosts)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if l.mtaSTS.err != nil {
		return nil, l.mtaSTS.err
	}
	if len(hosts) > 0 {
		attrs.MTASTS = "absent"
		if len(withPrefix(l.mtaSTS.recs, "v=STSv1")) == 1 {
			attrs.MTASTS = "present"
		}
	}
	attrs.DKIMSelectors, attrs.DKIMErrors = l.dkimResults()
	obs := append([]run.Observation{kinds.EmailPosture.Obs(root, attrs)}, tp.observations()...)
	for _, addrs := range l.mailAddrs {
		obs = append(obs, addrs...)
	}
	return obs, nil
}

// mxHosts returns the root's mail hosts, sorted. A timeout or SERVFAIL is an error.
func mxHosts(ctx context.Context, e egress.Clients, root string) ([]string, error) {
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
	return hosts, nil
}

// readSPF evaluates includes/redirects only when exactly one SPF record exists.
func readSPF(ctx context.Context, e egress.Clients, root string, tp *thirdParties, attrs *kinds.EmailPostureAttrs) error {
	rootTXT, err := txt(ctx, e, root)
	if err != nil {
		return err
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
			return ev.tempErr
		}
		attrs.SPFAll, attrs.SPFLookups, attrs.SPFError = all, ev.lookups, ev.err
	}
	return nil
}

// readDMARC prefers the root record, then the organisational domain.
func readDMARC(ctx context.Context, e egress.Clients, root string, tp *thirdParties, attrs *kinds.EmailPostureAttrs) error {
	rec, err := dmarc(ctx, e, "_dmarc."+root)
	if err != nil {
		return err
	}
	source, sub := "root", false
	if org, ok := dnsname.ETLDPlusOne(root); ok && org != root {
		sub = true
		if rec == "" {
			if rec, err = dmarc(ctx, e, "_dmarc."+org); err != nil {
				return err
			}
			source = "org"
		}
	}
	if rec == "" {
		return nil
	}
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
	return nil
}

// txtLookup is the result of one TXT lookup.
type txtLookup struct {
	recs []string
	err  error
}

// concurrentLookups preserves selector/mail-host ordering despite concurrent requests.
type concurrentLookups struct {
	sels      []string
	dkim      []txtLookup
	mtaSTS    txtLookup
	mailAddrs [][]run.Observation
}

// lookUpConcurrently resolves independent DKIM, MTA-STS and mail-host addresses while
// preserving result order. Egress still paces requests. Address failures leave no address
// rather than failing the email job; cancellation is handled by the caller.
func lookUpConcurrently(ctx context.Context, e egress.Clients, in input, hosts []string) *concurrentLookups {
	root := in.root
	mailHosts := slices.Compact(slices.Clone(hosts))
	l := &concurrentLookups{sels: config.DKIMSelectors(), mailAddrs: make([][]run.Observation, len(mailHosts))}
	l.dkim = make([]txtLookup, len(l.sels))
	var wg sync.WaitGroup
	for i, sel := range l.sels {
		wg.Go(func() {
			defer run.RecoverInto(&l.dkim[i].err)
			l.dkim[i].recs, l.dkim[i].err = txt(ctx, e, sel+"._domainkey."+root)
		})
	}
	// Only receiving roots need MTA-STS. Query their own DNS name without
	// organisational-domain fallback or fetching a policy file.
	if len(hosts) > 0 {
		wg.Go(func() {
			defer run.RecoverInto(&l.mtaSTS.err)
			l.mtaSTS.recs, l.mtaSTS.err = txt(ctx, e, "_mta-sts."+root)
		})
	}
	for i, h := range mailHosts {
		wg.Go(func() {
			var ignored error // the addresses are best-effort, as above
			defer run.RecoverInto(&ignored)
			l.mailAddrs[i], _ = serveraddr.Observations(ctx, e, in.sc, h)
		})
	}
	wg.Wait()
	return l
}

// dkimResults joins usable and failed selectors into separate semicolon-separated fields.
func (l *concurrentLookups) dkimResults() (found, failed string) {
	var ok, bad []string
	for i, sel := range l.sels {
		if l.dkim[i].err != nil {
			bad = append(bad, sel)
			continue
		}
		if slices.ContainsFunc(l.dkim[i].recs, isDKIMKey) {
			ok = append(ok, sel)
		}
	}
	return strings.Join(ok, ";"), strings.Join(bad, ";")
}

// thirdParties deduplicates mechanism/domain pairs and keeps nearest depth. It drops the root's
// own registrable domain; current scope decides whether other domains remain external when
// read.
type thirdParties struct {
	root  string
	found map[string]int // "<mechanism>|<domain>" -> depth
}

// add records lookupable dependency domains at depth, rejecting macros, malformed names and
// address literals.
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
		obs = append(obs, kinds.ThirdPartyObs(t.root, mechanism, domain, t.found[k]))
	}
	return obs
}

// sameRegistrable compares registrable domains, falling back to equal/ancestor names where no
// registrable domain exists.
func sameRegistrable(a, b string) bool {
	ra, oka := dnsname.ETLDPlusOne(a)
	rb, okb := dnsname.ETLDPlusOne(b)
	if oka && okb {
		return ra == rb
	}
	return dnsname.Under(a, b) || dnsname.Under(b, a)
}

// reportDomains extracts mailbox domains from DMARC mailto URIs, ignoring other schemes and
// optional !size suffixes.
func reportDomains(value string) []string {
	var out []string
	for uri := range strings.SplitSeq(value, ",") {
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

// isDKIMKey requires a nonempty p= and, when present, v=DKIM1. Revoked keys and unrelated
// wildcard TXT records do not count.
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
	for part := range strings.SplitSeq(rec, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return tags
}

// spfEval counts DNS-querying SPF terms through includes/redirects with loop detection and a
// hard stop. err marks permanent invalidity; tempErr preserves timeout/SERVFAIL so the whole
// job can retry.
type spfEval struct {
	ctx     context.Context
	e       egress.Clients
	lookups int
	queries int
	err     string
	tempErr error
	// tp collects dependency domains with traversal depth: zero in the root record,
	// increasing for followed includes/redirects.
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

// walk evaluates one SPF record and returns its qualified all mechanism, if any.
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
			// Strip CIDR suffixes from lookup arguments; bare a/mx refers to the
			// root.
			host, _, _ := strings.Cut(arg, "/")
			s.name(host, depth)
		case "ptr":
			s.lookups++
		}
	}
	// An all mechanism suppresses redirect evaluation, per RFC 7208 section 6.1.
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

// lookupable requires a normalised domain matching spfDomain, at most 253 characters, with
// neither macros nor address literals.
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
