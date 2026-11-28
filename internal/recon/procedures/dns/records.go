package dns

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/knowledge/addrkind"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/knowledge/provider"
	"github.com/rafaelh/nyx/internal/knowledge/spf"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/scope"
)

// DNSRecords asks each in-scope name below the input roots for its own NS, MX and TXT records,
// so that delegated zones, mail hosts, alias targets and names written in TXT records are found,
// and an organisation's SPF ranges are listed as candidates. A name with NS records of its own is
// a delegated zone and is also asked for its SOA and CAA records and the SRV service list, as a
// root is. An in-scope domain an SPF record includes or redirects to is asked for its TXT records
// only. Every lookup goes to the public resolvers; a timeout fails one name's lookup of one type,
// and SERVFAIL, NXDOMAIN and an empty answer are results, so a broken delegation never keeps a run
// partial.
type DNSRecords struct{ recordProcedure }

// NewDNSRecords returns the dnsrecords procedure.
func NewDNSRecords() *DNSRecords { return &DNSRecords{recordProcedure{base{"dnsrecords"}}} }

// recordProcedure is what dnsroot and dnsrecords share: the procedures whose TXT jobs give SPF
// candidates.
type recordProcedure struct{ base }

// spfSource is the candidate source, and family, of an SPF record's addresses.
const spfSource = "spf"

// CandidateSources: an SPF record's addresses are a family of their own.
func (recordProcedure) CandidateSources() map[string]string {
	return map[string]string{spfSource: spfSource}
}

// Evidence gives a TXT job's candidates the source spf and the asked name as the item; any other
// job is the default.
func (p recordProcedure) Evidence(jobKey string) (source, item string) {
	if name, ok := strings.CutSuffix(jobKey, "|TXT"); ok {
		return spfSource, name
	}
	return p.Name(), jobKey
}

// recordTypes are the types asked of every listed name; delegatedTypes those asked too of a
// listed name with NS records of its own, with the SRV service list.
var (
	recordTypes    = []rootType{nsType, mxType}
	delegatedTypes = []rootType{soaType, caaType}
)

// Jobs yields, for each listed name, its NS and MX jobs and, once its NS records are known, the
// SOA, CAA and SRV jobs of a delegated zone; then one TXT job for each listed name and included
// SPF domain.
func (d *DNSRecords) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	sc := v.Scope()
	names := recordNames(v)
	txt, delegated := map[string][]string{}, map[string]bool{}
	for _, rec := range v.Records(kinds.Resolution) {
		switch a := kinds.Resolution.Attrs(rec); a.Type {
		case "TXT":
			txt[a.Name] = append(txt[a.Name], a.Value)
		case "NS":
			delegated[a.Name] = true
		}
	}
	job := func(key, name string, t rootType, depth int) run.Job {
		return run.Job{Key: key, Input: recordInput{name: name, root: sc.RootOf(name), t: t, sc: sc, depth: depth,
			shared: v.SharedAddr, spfThirdParties: true}}
	}
	var jobs []run.Job
	for _, n := range names {
		types := recordTypes
		if delegated[n] {
			types = slices.Concat(recordTypes, delegatedTypes)
			jobs = append(jobs, job(n+"|SRV|"+srvKeyToken, n, srvType, 0))
		}
		for _, t := range types {
			jobs = append(jobs, job(n+"|"+t.name, n, t, 0))
		}
	}
	depths := includedDepths(append(v.InScopeRoots(), names...), txt, sc)
	for _, n := range slices.Sorted(maps.Keys(depths)) {
		if sc.RootOf(n) != n { // the roots' TXT is dnsroot's
			jobs = append(jobs, job(n+"|TXT", n, txtType, depths[n]))
		}
	}
	return func(yield func(run.Job, error) bool) {
		for _, j := range jobs {
			if !yield(j, nil) {
				return
			}
		}
	}
}

// recordNames lists the names to ask, sorted: the hostnames below the roots that resolve has
// answered other than NXDOMAIN and whose zone's wildcard check is done, and the parent names that
// do not resolve.
func recordNames(v run.View) []string {
	resolve := NewResolve().Name()
	zones := wildcardZones(v)
	ready := func(name string) bool {
		_, zone, _ := strings.Cut(name, ".")
		return !wildcardPending(v, zones, zone)
	}
	nxdomain, hosts := map[string]bool{}, map[string]bool{}
	for _, rec := range v.Records(kinds.Unresolved) {
		if kinds.Unresolved.Attrs(rec).RCode == "NXDOMAIN" {
			nxdomain[rec.Key] = true
		}
	}
	for _, rec := range v.Records(kinds.Hostname) {
		hosts[rec.Key] = true
	}
	var out []string
	for _, n := range v.RecordNames() {
		if (v.DoneBy(resolve, n) || v.DoneBy(resolve, parentPrefix+n)) && !nxdomain[n] && ready(n) {
			out = append(out, n)
		}
	}
	sc := v.Scope()
	for _, p := range v.ParentNames(resolve) {
		if !hosts[p] && sc.HostInScope(p) && v.DoneBy(resolve, parentPrefix+p) && ready(p) {
			out = append(out, p)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Run asks one name for one type. SERVFAIL is a result with no records, as NXDOMAIN and NODATA
// are; only a timeout fails the job.
func (*DNSRecords) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	obs, _, err := runRecord(ctx, c.Input.(recordInput), e)
	return obs, err
}

// runRecord asks the input's name for its type (the SRV service list for srvType) and returns the
// observations and the records the name owns. SERVFAIL fails the job only when the input says
// so; otherwise it is an answer with no records.
func runRecord(ctx context.Context, in recordInput, e egress.Clients) ([]run.Observation, []string, error) {
	if in.t == srvType {
		obs, err := runSRV(ctx, in, e)
		return obs, nil, err
	}
	res, err := lookup(ctx, e, in.name, in.t.code)
	switch {
	case err != nil:
		return nil, nil, err
	case res.RCode == egress.RCodeServFail && in.servFailFails:
		return nil, nil, fmt.Errorf("%s %s: resolver answered SERVFAIL", in.name, in.t.name)
	}
	return recordObservations(in, res.Answers), in.owned(res.Answers), nil
}

// recordInput is what the record handler needs to turn one name's answer of one type into
// observations.
type recordInput struct {
	name, root      string                // the asked name and its input root
	t               rootType              // the type asked
	sc              *scope.Scope          // the scope snapshot
	depth           int                   // the SPF depth of this name's TXT
	shared          func(netip.Addr) bool // a known shared provider address
	spfThirdParties bool                  // write spf third parties
	mxByEmail       bool                  // a root's: its mx third parties are email's, so write none
	servFailFails   bool                  // SERVFAIL fails the job rather than being an empty answer
}

// recordHost is the rule for a target or a name written in a record becoming a hostname: it is in
// scope under an input root and no label of it starts with "_".
func recordHost(sc *scope.Scope, host string) bool {
	return host != "" && sc.HostInScope(host) && sc.RootOf(host) != "" &&
		!strings.HasPrefix(host, "_") && !strings.Contains(host, "._")
}

// target records a host a record points at: a hostname when recordHost accepts it, otherwise,
// when a mechanism is given, a third party of the root by its registrable domain, unless that is
// the root's own. An address written where a name belongs is neither.
func (in recordInput) target(mechanism, host string) []run.Observation {
	host = dnsname.Normalise(host)
	if _, err := netip.ParseAddr(host); err == nil || host == "" {
		return nil
	}
	switch {
	case recordHost(in.sc, host):
		return []run.Observation{kinds.Hostname.Obs(host, kinds.HostnameAttrs{})}
	case mechanism == "":
		return nil
	}
	domain := dnsname.Registrable(host)
	if domain == dnsname.Registrable(in.root) { // the root's own registrable domain is no third party
		return nil
	}
	return []run.Observation{kinds.ThirdPartyObs(in.root, mechanism, domain, 0)}
}

// owned returns the values of the records of the asked type that the name owns: an alias's answer
// carries its target's records, owned by the target.
func (in recordInput) owned(answers []egress.Answer) []string {
	var out []string
	for _, a := range answers {
		if a.Type == in.t.name && a.Value != "" && a.Name == in.name {
			out = append(out, a.Value)
		}
	}
	return out
}

// recordObservations turns the answers to one name's lookup of one type into observations. Only
// records the name owns are kept.
func recordObservations(in recordInput, answers []egress.Answer) []run.Observation {
	var obs []run.Observation
	values := in.owned(answers)
	for _, v := range values {
		obs = append(obs, kinds.Resolution.Obs(kinds.ResolutionAttrs{Name: in.name, Type: in.t.name, Value: v}))
		switch in.t.name {
		case "NS":
			obs = append(obs, in.target(kinds.MechanismNS, v)...)
		case "MX":
			mechanism := kinds.MechanismMX
			if in.mxByEmail {
				mechanism = "" // email writes a root's, with its own filter
			}
			if _, host, _ := strings.Cut(v, " "); host != "." { // the null MX names no host
				obs = append(obs, in.target(mechanism, host)...)
			}
		case "SOA":
			primary, _, _ := strings.Cut(v, " ")
			obs = append(obs, in.target("", primary)...) // an SOA primary outside the scope adds nothing
		case "TXT":
			if platform, ok := provider.Default().Verification(v); ok {
				obs = append(obs, kinds.ThirdParty.Obs(
					kinds.ThirdPartyAttrs{Root: in.root, Mechanism: kinds.MechanismTXTVerification, Provider: platform}))
			}
		}
	}
	if in.t != txtType {
		return obs
	}
	// A TXT value is read with the reader that web text uses (dnsname.HostnamesIn), so there is one
	// reader of hostnames in text. TXT still drops an excluded name (and any name recordHost
	// refuses) here, where web text records it as excluded.
	seen := map[string]bool{}
	for _, v := range values {
		for h := range dnsname.HostnamesIn(v, false) {
			if !seen[h] && h != in.name && in.sc.RootOf(h) != h && recordHost(in.sc, h) {
				seen[h] = true
				obs = append(obs, kinds.Hostname.Obs(h, kinds.HostnameAttrs{}))
			}
		}
	}
	if record, ok := spf.Record(values); ok {
		obs = append(obs, in.spfObservations(spf.Parse(record))...)
	}
	return obs
}

// spfObservations gives an SPF record's netblock candidates and, when asked to, its spf third
// parties.
func (in recordInput) spfObservations(p spf.Policy) []run.Observation {
	var obs []run.Observation
	registrable := dnsname.Registrable(in.root)
	for _, t := range p.Terms {
		if !p.Applies(t) {
			continue // after all, or a redirect beside all
		}
		if prefix, ok := t.Network(); ok {
			if t.Qualifier == '+' && in.candidateRange(prefix) {
				obs = append(obs, kinds.Netblock.Obs(prefix.String(), kinds.NetblockAttrs{}))
			}
			continue
		}
		if !in.spfThirdParties {
			continue
		}
		// The kind's visibility hides a domain that is in scope; the root's own registrable
		// domain is not a third party at all.
		if domain, ok := t.Domain(); ok && !dnsname.Under(domain, registrable) {
			obs = append(obs, kinds.ThirdPartyObs(in.root, kinds.MechanismSPF, domain, in.depth))
		}
	}
	return obs
}

// Widest SPF ranges that give a candidate: anything wider is a provider's pool or a mistake.
const (
	maxV4Width = 16
	maxV6Width = 32
)

// candidateRange reports whether an authorised range may be the organisation's own: no wider
// than /16 or /32, public, and not a range wholly in known shared provider space (a single
// address there is most likely the organisation's own host).
func (in recordInput) candidateRange(p netip.Prefix) bool {
	if p.Addr().Is4() && p.Bits() < maxV4Width || p.Addr().Is6() && p.Bits() < maxV6Width || !addrkind.PublicPrefix(p) {
		return false
	}
	single := p.Bits() == p.Addr().BitLen()
	return single || !in.shared(p.Addr()) || !in.shared(input.LastAddr(p))
}

// includedDepths walks breadth-first from starts (depth 0) over txt (a name's current TXT row
// values) and returns every name to ask for TXT with its depth, starts included at 0. A name's one
// SPF record includes each include domain, and its redirect domain when the record has no all,
// that is in scope under an input root and is not one, at the includer's depth plus one. The
// first depth found is the smallest, and a name already seen is not walked again, so a loop ends.
func includedDepths(starts []string, txt map[string][]string, sc *scope.Scope) map[string]int {
	depths := map[string]int{}
	var queue []string
	for _, s := range starts {
		if _, ok := depths[s]; !ok {
			depths[s] = 0
			queue = append(queue, s)
		}
	}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		record, ok := spf.Record(txt[name])
		if !ok {
			continue
		}
		p := spf.Parse(record)
		for _, t := range p.Terms {
			if t.Name != "include" && t.Name != "redirect" || !p.Applies(t) {
				continue
			}
			d, ok := t.Domain()
			if _, seen := depths[d]; !ok || seen || !sc.NameInScope(d) || sc.RootOf(d) == d { // in scope is below a root
				continue
			}
			depths[d] = depths[name] + 1
			queue = append(queue, d)
		}
	}
	return depths
}
