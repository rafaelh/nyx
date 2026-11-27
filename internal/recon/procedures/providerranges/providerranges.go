// Package providerranges fetches published ranges for provider classification. Supported
// sources distinguish customer VMs from shared services. Azure uses ASN-only classification
// because its range download URL changes.
package providerranges

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/procedures/httpsrc"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// rangeEntry is one parsed range. prefix is not yet validated.
type rangeEntry struct{ prefix, service, region string }

// list represents one publisher/job. Its stable key means successful downloads are reused
// until redo.
type list struct {
	key, provider, url string
	parse              func([]byte) ([]rangeEntry, error)
}

// lists preserves publisher job order, with separate Cloudflare IPv4 and IPv6 files.
var lists = []list{
	{"aws", "aws", "https://ip-ranges.amazonaws.com/ip-ranges.json", parseAWS},
	{"gcp", "gcp", "https://www.gstatic.com/ipranges/cloud.json", parseGCP},
	{"cloudflare-v4", "cloudflare", "https://www.cloudflare.com/ips-v4", parseLines},
	{"cloudflare-v6", "cloudflare", "https://www.cloudflare.com/ips-v6", parseLines},
	{"fastly", "fastly", "https://api.fastly.com/public-ip-list", parseFastly},
	{"digitalocean", "digitalocean", "https://www.digitalocean.com/geo/google.csv", parseLines},
	{"oracle", "oracle", "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", parseOracle},
	{"linode", "linode", "https://geoip.linode.com/", parseLines},
}

// Procedure is the providerranges procedure: one job per list, refreshed by --redo providerranges.
type Procedure struct{}

// New returns the providerranges procedure.
func New() *Procedure { return &Procedure{} }

func (*Procedure) Name() string                      { return "providerranges" }
func (*Procedure) Contact() run.Contact              { return run.ThirdParty }
func (*Procedure) Configured(run.Env) (bool, string) { return true, "" }

// Required: provider ranges identify shared addresses that must not be port-checked, so it
// cannot be skipped.
func (*Procedure) Required() {}

// RetiresUnlistedJobs: the ranges of a list nyx no longer fetches stop being current, rather
// than classifying addresses forever from an engagement's first download.
func (*Procedure) RetiresUnlistedJobs() {}

// Sources are the hosts the lists are fetched from.
func (*Procedure) Sources() []string {
	var hosts []string
	for _, l := range lists {
		if u, err := url.Parse(l.url); err == nil && !slices.Contains(hosts, u.Host) {
			hosts = append(hosts, u.Host)
		}
	}
	return hosts
}

func (*Procedure) Jobs(ctx context.Context, v run.View) iter.Seq2[run.Job, error] {
	return run.JobsOf(lists, func(l list) run.Job { return run.Job{Key: l.key, Input: l} })
}

// Run requires a readable, nonempty range list. Failures retry on later runs while the previous
// successful ranges remain usable.
func (*Procedure) Run(ctx context.Context, c run.Job, e egress.Clients) ([]run.Observation, error) {
	l := c.Input.(list)
	body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: l.url})
	if err != nil {
		return nil, fmt.Errorf("%s ranges: %w", l.provider, err)
	}
	return l.observations(body)
}

// Prefixes wider than these are not a provider's published range but a broken or hostile list:
// one would classify every address as that provider's, overriding every other rule.
const minBits4, minBits6 = 8, 16

// usablePrefix parses a published prefix, writing an IPv4-mapped one as IPv4 (as addresses are
// unmapped when matched) and refusing one wider than minBits4 or minBits6.
func usablePrefix(s string) (netip.Prefix, bool) {
	p, err := input.ParseCIDR(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	if p.Addr().Is4() {
		return p, p.Bits() >= minBits4
	}
	return p, p.Bits() >= minBits6
}

// observations skips invalid prefixes and rejects bodies leaving no usable ranges.
func (l list) observations(body []byte) ([]run.Observation, error) {
	entries, err := l.parse(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	if err != nil {
		return nil, fmt.Errorf("%s ranges: unreadable response: %w", l.provider, err)
	}
	var obs []run.Observation
	for _, e := range entries {
		p, ok := usablePrefix(e.prefix)
		if !ok {
			continue
		}
		obs = append(obs, kinds.ProviderRange.Obs(kinds.ProviderRangeAttrs{Provider: l.provider, Prefix: p.String(), Service: e.service, Region: e.region}))
	}
	if len(obs) == 0 {
		return nil, fmt.Errorf("%s ranges: the response holds no ranges", l.provider)
	}
	return obs, nil
}

func parseAWS(body []byte) ([]rangeEntry, error) {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6 []struct {
			IPPrefix string `json:"ipv6_prefix"`
			Region   string `json:"region"`
			Service  string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []rangeEntry
	for _, p := range doc.Prefixes {
		out = append(out, rangeEntry{p.IPPrefix, p.Service, p.Region})
	}
	for _, p := range doc.IPv6 {
		out = append(out, rangeEntry{p.IPPrefix, p.Service, p.Region})
	}
	return out, nil
}

func parseGCP(body []byte) ([]rangeEntry, error) {
	var doc struct {
		Prefixes []struct {
			IPv4  string `json:"ipv4Prefix"`
			IPv6  string `json:"ipv6Prefix"`
			Scope string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []rangeEntry
	for _, p := range doc.Prefixes {
		prefix := p.IPv4
		if prefix == "" {
			prefix = p.IPv6
		}
		out = append(out, rangeEntry{prefix, "", p.Scope})
	}
	return out, nil
}

// parseLines accepts plain prefixes and RFC 8805 geofeeds. It skips blanks/comments and uses
// the third CSV field as region when present.
func parseLines(body []byte) ([]rangeEntry, error) {
	lines, err := input.ParseList(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	var out []rangeEntry
	for _, line := range lines {
		f := strings.Split(line, ",")
		e := rangeEntry{prefix: csvField(f[0])}
		if len(f) > 2 {
			e.region = csvField(f[2])
		}
		out = append(out, e)
	}
	return out, nil
}

// csvField trims a geofeed field and the double quotes RFC 4180 lets it carry.
func csvField(s string) string {
	return strings.TrimSpace(strings.Trim(strings.TrimSpace(s), `"`))
}

func parseFastly(body []byte) ([]rangeEntry, error) {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []rangeEntry
	for _, p := range slices.Concat(doc.Addresses, doc.IPv6Addresses) {
		out = append(out, rangeEntry{prefix: p})
	}
	return out, nil
}

// parseOracle emits one range per service tag so overlapping OCI, OSN and OBJECT_STORAGE
// classifications remain distinct.
func parseOracle(body []byte) ([]rangeEntry, error) {
	var doc struct {
		Regions []struct {
			Region string `json:"region"`
			CIDRs  []struct {
				CIDR string   `json:"cidr"`
				Tags []string `json:"tags"`
			} `json:"cidrs"`
		} `json:"regions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	var out []rangeEntry
	for _, r := range doc.Regions {
		for _, c := range r.CIDRs {
			tags := c.Tags
			if len(tags) == 0 {
				tags = []string{""}
			}
			for _, t := range tags {
				out = append(out, rangeEntry{c.CIDR, t, r.Region})
			}
		}
	}
	return out, nil
}
