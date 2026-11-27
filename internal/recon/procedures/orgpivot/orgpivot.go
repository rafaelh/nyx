// Package orgpivot discovers candidate roots/netblocks from organisation names. Scope
// classifies results; candidate discoveries are recorded without enumeration.
package orgpivot

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/netip"
	"net/url"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/knowledge/dnsname"
	"github.com/rafaelh/nyx/internal/knowledge/orgname"
	"github.com/rafaelh/nyx/internal/recon/analysis/candidates"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/procedures/httpsrc"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// maxASNsPerOrg caps the autonomous systems taken for one organisation. The
// value is a reasonable guess, not a source limit.
const maxASNsPerOrg = 10

// orgProcedure is the part every organisation procedure shares: one job per input organisation.
type orgProcedure struct {
	name    string
	family  string // of the candidates it finds; see package candidates
	sources []string
	keyed   bool
}

func (s orgProcedure) Name() string       { return s.name }
func (orgProcedure) Contact() run.Contact { return run.ThirdParty }
func (s orgProcedure) Sources() []string  { return s.sources }
func (s orgProcedure) Configured(e run.Env) (bool, string) {
	return httpsrc.Configured(e, s.name, s.keyed)
}

// CandidateSources declares the procedure's evidence family.
func (s orgProcedure) CandidateSources() map[string]string {
	return map[string]string{s.name: s.family}
}

func (orgProcedure) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return run.JobsOf(v.Inputs().Orgs, func(o string) run.Job { return run.Job{Key: o, Input: o} })
}

// searchable reports whether org has a word to search by once legal suffixes are left out, and
// warns when it has none: searching "Pty Ltd" would match unrelated organisations (and, for a
// paid source, spend a credit on them).
func (s orgProcedure) searchable(ctx context.Context, org string) bool {
	if len(orgname.Tokens(org)) > 0 {
		return true
	}
	run.Warnf(ctx, "%s: %q has no words to search by once legal suffixes are left out, so it is not searched", s.name, org)
	return false
}

func rootObs(names []string) []run.Observation {
	seen := map[string]bool{}
	var obs []run.Observation
	for _, n := range names {
		n = dnsname.Normalise(strings.TrimPrefix(strings.TrimSpace(n), "*."))
		if n == "" || strings.ContainsAny(n, "*@/: ") {
			continue
		}
		if _, err := netip.ParseAddr(n); err == nil {
			continue // an address, whose last two octets would pass for a registrable domain
		}
		root, ok := dnsname.ETLDPlusOne(n)
		if !ok || seen[root] {
			continue
		}
		seen[root] = true
		obs = append(obs, kinds.Root.Obs(root))
	}
	return obs
}

// --- ct-org ---

// CTOrg finds roots from the organisation field of certificates in CT logs. It
// searches certificates, so it is a certificate transparency source.
type CTOrg struct{ orgProcedure }

// NewCTOrg returns the ct-org procedure.
func NewCTOrg() *CTOrg {
	return &CTOrg{orgProcedure{name: "ct-org", family: candidates.CertTransparency, sources: []string{"crt.sh"}}}
}

// Run searches crt.sh by organisation (O=) and reduces the names to registrable domains.
func (p *CTOrg) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	if !p.searchable(ctx, c.Key) {
		return nil, nil
	}
	body, err := httpsrc.Crtsh(ctx, e, url.Values{"O": {c.Key}})
	if err != nil {
		return nil, fmt.Errorf("ct-org %s: %w", c.Key, err)
	}
	// For an O= search crt.sh puts the matched organisation in name_value; the
	// certificate's names are in common_name.
	var rows []struct {
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("ct-org %s: unreadable crt.sh response: %w", c.Key, err)
	}
	var names []string
	for _, r := range rows {
		names = append(names, r.CommonName)
	}
	return rootObs(names), nil
}

// --- whoisxml ---

// WhoisXML finds roots by reverse WHOIS on the organisation name (keyed). The
// job is remembered, so each organisation costs one credit per engagement.
type WhoisXML struct{ orgProcedure }

// NewWhoisXML returns the whoisxml procedure.
func NewWhoisXML() *WhoisXML {
	return &WhoisXML{orgProcedure{name: "whoisxml", family: candidates.Registrant, sources: []string{"reverse-whois.whoisxmlapi.com"}, keyed: true}}
}

// Paid: reverse WHOIS is bought per search, and a free account gets only a one-off allowance.
func (*WhoisXML) Paid() {}

// Run buys the reverse WHOIS result for the organisation. The client puts the key in the body.
func (p *WhoisXML) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	if !p.searchable(ctx, c.Key) {
		return nil, nil
	}
	body, _ := json.Marshal(map[string]any{
		"mode":             "purchase",
		"basicSearchTerms": map[string]any{"include": []string{c.Key}},
	})
	out, err := httpsrc.GetCredits(ctx, e, egress.ThirdPartyRequest{
		Method: "POST", URL: "https://reverse-whois.whoisxmlapi.com/api/v2", Body: body, ContentType: "application/json",
		KeySource: "whoisxml", KeyBodyField: "apiKey",
	})
	if err != nil {
		return nil, fmt.Errorf("whoisxml %s: %w", c.Key, err)
	}
	var r struct {
		DomainsList []string `json:"domainsList"`
	}
	if err := json.Unmarshal(out, &r); err != nil {
		return nil, fmt.Errorf("whoisxml %s: unreadable response: %w", c.Key, err)
	}
	return rootObs(r.DomainsList), nil
}

// --- org-asn ---

// OrgASN records RIPEstat organisation-search netblocks as candidates. Only input-ASN expansion
// brings discovered blocks into scope. Its registrant evidence relies on RIPEstat matching
// registry organisation names.
type OrgASN struct{ orgProcedure }

// NewOrgASN returns the org-asn procedure.
func NewOrgASN() *OrgASN {
	return &OrgASN{orgProcedure{name: "org-asn", family: candidates.Registrant, sources: []string{"stat.ripe.net"}}}
}

// Run follows matching organisation ASNs to announced prefixes, applying the shared word rule
// to ASN holders.
func (p *OrgASN) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	if !p.searchable(ctx, c.Key) {
		return nil, nil
	}
	q := url.Values{"resource": {c.Key}, "limit": {"50"}, "sourceapp": {"nyx"}}
	body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: "https://stat.ripe.net/data/searchcomplete/data.json?" + q.Encode()})
	if err != nil {
		return nil, fmt.Errorf("org-asn %s: %w", c.Key, err)
	}
	var sc struct {
		Status string `json:"status"`
		Data   struct {
			Categories []struct {
				Category    string `json:"category"`
				Suggestions []struct {
					Value       string `json:"value"`
					Description string `json:"description"`
				} `json:"suggestions"`
			} `json:"categories"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &sc); err != nil {
		return nil, fmt.Errorf("org-asn %s: unreadable RIPEstat response: %w", c.Key, err)
	}
	if sc.Status != "ok" {
		return nil, fmt.Errorf("org-asn %s: RIPEstat status %q", c.Key, sc.Status)
	}
	var asns []string
	seen := map[string]bool{}
	truncated := false
	org := orgname.New(c.Key)
	for _, cat := range sc.Data.Categories {
		if cat.Category != "ASNs" {
			continue
		}
		for _, s := range cat.Suggestions {
			asn := strings.ToUpper(strings.TrimSpace(s.Value))
			if asn == "" || seen[asn] || !org.Matches(s.Description) {
				continue
			}
			if len(asns) == maxASNsPerOrg {
				truncated = true
				break
			}
			seen[asn] = true
			asns = append(asns, asn)
		}
	}
	if truncated {
		run.Warnf(ctx, "org-asn: RIPEstat matched more than %d autonomous systems for %q; the first %d are kept",
			maxASNsPerOrg, c.Key, maxASNsPerOrg)
	}
	var obs []run.Observation
	for _, asn := range asns {
		prefixes, err := httpsrc.Announced(ctx, e, asn)
		if err != nil {
			return nil, fmt.Errorf("org-asn %s %s: %w", c.Key, asn, err)
		}
		for _, p := range prefixes {
			obs = append(obs, kinds.Netblock.Obs(p, kinds.NetblockAttrs{ASN: asn, Org: c.Key}))
		}
	}
	return obs, nil
}
