// Package shodan retrieves netblock search results, individual hosts not covered by search and
// root DNS claims. Reported services use reported_port and never expand permission to contact
// targets.
package shodan

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/candidates"
	"github.com/rafaelh/nyx/internal/dnsname"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

// maxPages caps the result pages read per netblock (each page past the first costs a credit).
const maxPages = 10

// reportedPort accepts TCP services, treating missing transport as TCP and rejecting UDP or
// invalid addresses. It keeps the date from Shodan's timestamp.
func reportedPort(ip string, port int, transport, banner, timestamp string) (run.Observation, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || port < 1 || port > 65535 || !isTCP(transport) {
		return run.Observation{}, false
	}
	addr = addr.Unmap()
	seen := ""
	if len(timestamp) >= len(time.DateOnly) {
		if _, err := time.Parse(time.DateOnly, timestamp[:len(time.DateOnly)]); err == nil {
			seen = timestamp[:len(time.DateOnly)]
		}
	}
	return kinds.ReportedPort.Obs(kinds.ReportedPortAttrs{
		IP: addr.String(), Port: port, Banner: kinds.ShodanBanner(banner), LastSeen: seen}), true
}

// shodanAPI shares the configured Shodan credential across API stages.
type shodanAPI struct{}

func (shodanAPI) Contact() run.Contact { return run.ThirdParty }
func (shodanAPI) Sources() []string    { return []string{"api.shodan.io"} }

func (shodanAPI) Configured(e run.Env) (bool, string) { return httpsrc.Configured(e, "shodan", true) }

// Stage is the shodan stage.
type Stage struct{ shodanAPI }

// New returns the shodan stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string { return "shodan" }

// CandidateSources classifies Shodan evidence as passive DNS.
func (*Stage) CandidateSources() map[string]string {
	return map[string]string{"shodan": candidates.PassiveDNS}
}

// Notes reports capped netblock searches so missing results are not mistaken for Shodan having
// no data.
func (*Stage) Notes(v run.View) []string {
	// Host lookup shares the search credential; --skip controls it independently.
	then := "shodan-host looks up the addresses in it that the search missed"
	if slices.Contains(v.Settings().Skip, (&Host{}).Name()) {
		then = "shodan-host is skipped, so addresses in it may be missing"
	}
	var notes []string
	for _, p := range truncated(v) {
		notes = append(notes, fmt.Sprintf("shodan: the search of %s was truncated at %d pages; %s", p, maxPages, then))
	}
	return notes
}

// truncated lists capped, incomplete netblock searches sorted by textual CIDR.
func truncated(v run.View) []netip.Prefix {
	sc := v.Scope()
	var out []netip.Prefix
	for _, rec := range v.Records(kinds.ShodanNetblock) {
		if p, err := netip.ParsePrefix(rec.Key); err == nil && kinds.ShodanNetblock.Attrs(rec).Truncated && sc.HasNetblock(rec.Key) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// isTCP reports whether a Shodan transport is TCP; a service with none is.
func isTCP(transport string) bool { return transport == "" || strings.EqualFold(transport, "tcp") }

// Checks yields one check per in-scope netblock, keyed by its CIDR.
func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, p := range v.Scope().Netblocks() {
			if !yield(run.Check{Key: p.Masked().String(), Input: p.Masked().String()}, nil) {
				return
			}
		}
	}
}

type search struct {
	Matches []struct {
		IPStr     string   `json:"ip_str"`
		Port      int      `json:"port"`
		Transport string   `json:"transport"`
		Data      string   `json:"data"`
		Timestamp string   `json:"timestamp"`
		Hostnames []string `json:"hostnames"`
	} `json:"matches"`
	Total int `json:"total"`
}

// Run searches net:<cidr>, recording addresses, names, TCP services and whether the page cap
// left results unread.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	var obs []run.Observation
	seen := map[string]bool{}
	got := 0
	complete := false
	for page := 1; page <= maxPages; page++ {
		q := url.Values{"query": {"net:" + c.Key}, "page": {strconv.Itoa(page)}}
		body, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{
			Method: "GET", URL: "https://api.shodan.io/shodan/host/search?" + q.Encode(), KeySource: "shodan", KeyParam: "key",
		})
		if err != nil {
			return nil, fmt.Errorf("shodan %s: %w", c.Key, err)
		}
		var r search
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("shodan %s: unreadable response: %w", c.Key, err)
		}
		for _, m := range r.Matches {
			if m.IPStr != "" && !seen["ip|"+m.IPStr] {
				seen["ip|"+m.IPStr] = true
				obs = append(obs, kinds.IP.Obs(m.IPStr))
			}
			if o, ok := reportedPort(m.IPStr, m.Port, m.Transport, m.Data, m.Timestamp); ok && !seen["port|"+o.Key] {
				seen["port|"+o.Key] = true
				obs = append(obs, o)
			}
			for _, h := range m.Hostnames {
				h = dnsname.Normalise(h)
				if h == "" {
					continue
				}
				back := kinds.IPHostname.Obs(kinds.IPHostnameAttrs{IP: m.IPStr, Hostname: h, Source: "shodan"})
				if seen[back.Key] {
					continue
				}
				seen[back.Key] = true
				obs = append(obs, kinds.Hostname.Obs(h, kinds.HostnameAttrs{}), back)
			}
		}
		got += len(r.Matches)
		if len(r.Matches) == 0 || got >= r.Total {
			complete = true
			break
		}
	}
	// Warn when the page cap leaves fewer read matches than the reported total.
	return append(obs, kinds.ShodanNetblock.Obs(c.Key, kinds.ShodanNetblockAttrs{Truncated: !complete})), nil
}
