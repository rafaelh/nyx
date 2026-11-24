// Package dnshistory retrieves past addresses of CDN/WAF-fronted hosts as possible
// origin-server evidence.
package dnshistory

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/httpsrc"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
)

// maxPages caps the result pages read for one hostname and record type (one query credit each).
const maxPages = 5

// Stage queries SecurityTrails A/AAAA history for in-scope CDN/WAF hosts. It records
// historical_address and ip evidence for reporting and ownership lookup, never current DNS
// resolution or permission to probe.
//
// Each hostname is fetched once unless --redo dnshistory is used. Hosts becoming fronted later
// become eligible then. dnshistory.max_hosts budgets checks in name order, leaving the rest for
// later runs.
type Stage struct{}

// New returns the dnshistory stage.
func New() *Stage { return &Stage{} }

func (*Stage) Name() string         { return "dnshistory" }
func (*Stage) Contact() run.Contact { return run.ThirdParty }
func (*Stage) Sources() []string    { return []string{"api.securitytrails.com"} }

// Configured: it needs keys.securitytrails.
func (*Stage) Configured(e run.Env) (bool, string) {
	return httpsrc.Configured(e, "securitytrails", true)
}

// Budget is dnshistory.max_hosts: each check is one hostname.
func (*Stage) Budget(s config.Settings) int { return s.DNSHistory.MaxHosts }

// Checks yields, in name order, each fronted in-scope hostname.
func (*Stage) Checks(_ context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, h := range v.FrontedHostnames() {
			if !yield(run.Check{Key: h, Input: h, Cost: 1}, nil) {
				return
			}
		}
	}
}

// record is one period of a history: the addresses a name had, and when it was seen to.
type record struct {
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Values    []struct {
		IP   string `json:"ip"`
		IPv6 string `json:"ipv6"`
	} `json:"values"`
}

// history is one page of the SecurityTrails answer for a record type.
type history struct {
	Pages   int      `json:"pages"`
	Records []record `json:"records"`
}

// Run fetches A then AAAA history. A 404 completes without discoveries. Repeated address
// periods merge using earliest first_seen and latest last_seen.
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	host := c.Input.(string)
	sp := &spans{byAddr: map[netip.Addr]*span{}}
	for _, typ := range []string{"a", "aaaa"} {
		recs, err := fetch(ctx, e, host, typ)
		if err != nil {
			return nil, fmt.Errorf("dnshistory %s: %w", host, err)
		}
		for _, r := range recs {
			for _, v := range r.Values {
				if a, ok := historyAddr(typ, cmp.Or(v.IP, v.IPv6)); ok {
					sp.add(a, date(r.FirstSeen), date(r.LastSeen))
				}
			}
		}
	}
	var obs []run.Observation
	for _, a := range sp.order {
		s, typ := sp.byAddr[a], "A"
		if a.Is6() {
			typ = "AAAA"
		}
		obs = append(obs,
			kinds.HistoricalAddress.Obs(
				kinds.HistoricalAddressAttrs{Host: host, Addr: a.String(), Type: typ, FirstSeen: s.first, LastSeen: s.last}),
			kinds.IP.Obs(a.String()))
	}
	return obs, nil
}

// historyAddr accepts global-unicast addresses matching the requested A/AAAA family.
func historyAddr(typ, s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.IsGlobalUnicast() {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if (typ == "a") != a.Is4() {
		return netip.Addr{}, false
	}
	return a, true
}

// span is when an address was seen: the earliest first_seen and the latest last_seen.
type span struct{ first, last string }

// spans collects one span per address, in the order the addresses were first seen.
type spans struct {
	byAddr map[netip.Addr]*span
	order  []netip.Addr
}

// add widens the address's span to cover a period from first to last; an
// empty date is ignored.
func (sp *spans) add(a netip.Addr, first, last string) {
	s, ok := sp.byAddr[a]
	if !ok {
		s = &span{}
		sp.byAddr[a] = s
		sp.order = append(sp.order, a)
	}
	if first != "" && (s.first == "" || first < s.first) {
		s.first = first
	}
	if last != "" && last > s.last {
		s.last = last
	}
}

// date is a YYYY-MM-DD date, or "" for anything else.
func date(s string) string {
	if _, err := time.Parse(time.DateOnly, s); err != nil {
		return ""
	}
	return s
}

// fetch paginates one host/type through the reported last page or maxPages, warning if capped.
func fetch(ctx context.Context, e egress.Clients, host, typ string) ([]record, error) {
	var out []record
	for page := 1; ; page++ {
		raw, err := httpsrc.Get(ctx, e, egress.ThirdPartyRequest{
			Method: "GET", URL: "https://api.securitytrails.com/v1/history/" + url.PathEscape(host) + "/dns/" + typ + "?page=" + strconv.Itoa(page),
			KeySource: "securitytrails", KeyHeader: "APIKEY",
		})
		if errors.Is(err, httpsrc.ErrNotFound) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		var h history
		if err := json.Unmarshal(raw, &h); err != nil {
			return nil, errors.New("unreadable SecurityTrails response")
		}
		out = append(out, h.Records...)
		if page >= h.Pages {
			return out, nil
		}
		if page == maxPages {
			run.Warnf(ctx, "dnshistory %s: SecurityTrails %s history truncated after %d pages", host, typ, page)
			return out, nil
		}
	}
}

// HistoricalAddresses marks DNS-history evidence, which alone cannot establish that the
// engagement still uses an address.
func (*Stage) HistoricalAddresses() {}
