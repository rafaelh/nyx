package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/url"
	"strconv"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/recon/analysis/candidates"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/procedures/httpsrc"
	"github.com/rafaelh/nyx/internal/recon/run"
	"github.com/rafaelh/nyx/internal/scope"
)

// DNS collects Shodan subdomains and DNS claims for in-scope roots. In-scope CNAME/MX/NS
// targets also become hostnames. Claims never become confirmed resolutions or IP records and
// cannot change contact decisions.
type DNS struct{ shodanAPI }

// NewDNS returns the shodan-dns procedure.
func NewDNS() *DNS { return &DNS{} }

func (*DNS) Name() string { return "shodan-dns" }

// Paid: each result page spends a Shodan query credit, which a free account lacks.
func (*DNS) Paid() {}

// CandidateSources classifies Shodan evidence as passive DNS.
func (*DNS) CandidateSources() map[string]string {
	return map[string]string{"shodan-dns": candidates.PassiveDNS}
}

// dnsInput carries scope to classify returned CNAME targets.
type dnsInput struct {
	root  string
	pages int
	sc    *scope.Scope
}

// Jobs versions each root by shodan_dns.max_pages so raised caps rerun it.
func (*DNS) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	pages := v.Settings().ShodanDNS.MaxPages
	return run.JobsOf(v.InScopeRoots(), func(r string) run.Job {
		return run.Job{Key: fmt.Sprintf("%s|pages=%d", r, pages), Input: dnsInput{root: r, pages: pages, sc: v.Scope()}}
	})
}

type dnsAnswer struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Data       []struct {
		Subdomain string `json:"subdomain"`
		Type      string `json:"type"`
		Value     string `json:"value"`
	} `json:"data"`
	More bool `json:"more"`
}

// Run reads capped credit-consuming pages, treating 404 as no Shodan data.
func (*DNS) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	in := c.Input.(dnsInput)
	out := &dnsObs{in: in, seen: map[string]bool{}}
	for page := 1; ; page++ {
		q := url.Values{"page": {strconv.Itoa(page)}}
		body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{
			Method: "GET", URL: "https://api.shodan.io/dns/domain/" + url.PathEscape(in.root) + "?" + q.Encode(), KeySource: "shodan", KeyParam: "key",
		})
		if errors.Is(err, httpsrc.ErrNotFound) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("shodan-dns %s: %w", in.root, err)
		}
		var r dnsAnswer
		if err := json.Unmarshal(body, &r); err != nil || r.Domain == "" && r.Subdomains == nil && r.Data == nil {
			return nil, fmt.Errorf("shodan-dns %s: unreadable response", in.root)
		}
		for _, n := range httpsrc.JoinLabels(in.root, r.Subdomains) {
			if n = input.CleanName(n); n != "" {
				out.hostname(n)
			}
		}
		for _, d := range r.Data {
			out.record(d.Subdomain, d.Type, d.Value)
		}
		if !r.More {
			break
		}
		if page == in.pages {
			run.Warnf(ctx, "shodan-dns %s: result truncated after %d pages; raise shodan_dns.max_pages to read more (each page costs one Shodan query credit)", in.root, in.pages)
			break
		}
	}
	return out.obs, nil
}

// dnsObs accumulates a job's observations without repeating any.
type dnsObs struct {
	in   dnsInput
	seen map[string]bool
	obs  []run.Observation
}

// hostname records a name already in canonical form (input.CleanName).
func (o *dnsObs) hostname(name string) {
	if !o.seen["h|"+name] {
		o.seen["h|"+name] = true
		o.obs = append(o.obs, kinds.Hostname.Obs(name, kinds.HostnameAttrs{}))
	}
}

// record adds the queried hostname, then supported valid A/AAAA/CNAME/MX/NS claims. Wildcard
// names and unreadable values contribute no claim.
func (o *dnsObs) record(sub, typ, value string) {
	typ = strings.ToUpper(typ)
	if strings.Contains(sub, "*") {
		return
	}
	name := o.in.root
	if sub != "" {
		name = sub + "." + o.in.root
	}
	if name = input.CleanName(name); name == "" {
		return
	}
	o.hostname(name)
	var target string
	switch typ {
	case "A", "AAAA":
		a, ok := input.IPLiteral(strings.TrimSpace(value))
		if !ok {
			return
		}
		// Infer A/AAAA from the address so mislabelled reports still produce canonical
		// keys.
		typ, value = "AAAA", a.String()
		if a.Is4() {
			typ = "A"
		}
	case "CNAME", "MX", "NS":
		if f := strings.Fields(value); len(f) > 0 {
			value = f[len(f)-1] // an MX value may begin with its preference
		}
		if value = input.CleanName(value); value == "" {
			return
		}
		target = value
	default:
		return
	}
	if target != "" && o.in.sc.HostInScope(target) {
		o.hostname(target)
	}
	if c := kinds.DNSClaim.Obs(kinds.DNSClaimAttrs{Name: name, Type: typ, Value: value, Source: "shodan"}); !o.seen[c.Key] {
		o.seen[c.Key] = true
		o.obs = append(o.obs, c)
	}
}
