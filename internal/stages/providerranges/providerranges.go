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
	"net/url"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/httpsrc"
	"github.com/rafaelh/nyx/internal/input"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
)

// rangeEntry is one parsed range. prefix is not yet validated.
type rangeEntry struct{ prefix, service, region string }

// list represents one publisher/check. Its stable key means successful downloads are reused
// until redo.
type list struct {
	key, provider, url string
	parse              func([]byte) ([]rangeEntry, error)
}

// lists preserves publisher check order, with separate Cloudflare IPv4 and IPv6 files.
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

// Stage is the providerranges stage: one check per list, refreshed by --redo providerranges.
type Stage struct{}

// New returns the providerranges stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string                      { return "providerranges" }
func (*Stage) Contact() run.Contact              { return run.ThirdParty }
func (*Stage) Configured(run.Env) (bool, string) { return true, "" }

// Sources are the hosts the lists are fetched from.
func (*Stage) Sources() []string {
	var hosts []string
	for _, l := range lists {
		if u, err := url.Parse(l.url); err == nil && !slices.Contains(hosts, u.Host) {
			hosts = append(hosts, u.Host)
		}
	}
	return hosts
}

func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, l := range lists {
			if !yield(run.Check{Key: l.key, Input: l}, nil) {
				return
			}
		}
	}
}

// Run requires a readable, nonempty range list. Failures retry on later runs while the previous
// successful ranges remain usable.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	l := c.Input.(list)
	body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{Method: "GET", URL: l.url})
	if err != nil {
		return nil, fmt.Errorf("%s ranges: %w", l.provider, err)
	}
	return l.observations(body)
}

// observations skips invalid prefixes and rejects bodies leaving no usable ranges.
func (l list) observations(body []byte) ([]run.Observation, error) {
	entries, err := l.parse(body)
	if err != nil {
		return nil, fmt.Errorf("%s ranges: unreadable response: %w", l.provider, err)
	}
	var obs []run.Observation
	for _, e := range entries {
		p, err := input.ParseCIDR(e.prefix)
		if err != nil {
			continue
		}
		prefix := p.String()
		key := l.provider + "|" + prefix + "|" + e.service
		obs = append(obs, kinds.ProviderRange.Obs(key, kinds.ProviderRangeAttrs{Provider: l.provider, Prefix: prefix, Service: e.service, Region: e.region}))
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
		e := rangeEntry{prefix: strings.TrimSpace(f[0])}
		if len(f) > 2 {
			e.region = strings.TrimSpace(f[2])
		}
		out = append(out, e)
	}
	return out, nil
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
