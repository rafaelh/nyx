// Package dnshistory is the dnshistory stage: the addresses a hostname behind a CDN or WAF resolved
// to in the past, which may be where its origin server is.
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
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/httpsrc"
)

// maxPages caps the result pages read for one hostname and record type (one query credit each).
const maxPages = 5

// Stage asks SecurityTrails for the historical A and AAAA records of every in-scope hostname that
// currently resolves to a known CDN or WAF provider. Each historical address is a historical_address
// record and an ip record, so it appears in ips.csv and is looked up for its owner. It is never a
// current address: only resolution records are, so nothing here makes an address probed, port-checked
// or wildcard-tested, and nothing that decides contact reads historical_address.
//
// The check is the hostname, so a history is fetched again only by --redo dnshistory. The key
// carries no scope or provider data: a host that is fronted later is asked then. The stage is
// budgeted by dnshistory.max_hosts, one hostname per check, in name order; the rest wait for the
// next run.
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
func (*Stage) Checks(ctx context.Context, v run.View) iter.Seq2[run.Check, error] {
	return func(yield func(run.Check, error) bool) {
		for _, h := range v.FrontedHostnames() {
			if ctx.Err() != nil || !yield(run.Check{Key: h, Input: h, Cost: 1}, nil) {
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

// Run asks for the A and then the AAAA history. A host SecurityTrails does not know (404) is a
// completed check with nothing found. An address seen in several periods is one record, from the
// earliest first_seen to the latest last_seen.
//
//nolint:gocognit // TODO: split; predates the complexity ceiling
func (*Stage) Run(ctx context.Context, c run.Check, e egress.Clients) ([]run.Observation, error) {
	host := c.Input.(string)
	type span struct{ first, last string }
	spans := map[netip.Addr]*span{}
	var order []netip.Addr
	for _, typ := range []string{"a", "aaaa"} {
		recs, err := fetch(ctx, e, host, typ)
		if err != nil {
			return nil, fmt.Errorf("dnshistory %s: %w", host, err)
		}
		for _, r := range recs {
			for _, v := range r.Values {
				a, err := netip.ParseAddr(cmp.Or(v.IP, v.IPv6))
				if err != nil || !a.IsGlobalUnicast() {
					continue
				}
				a = a.Unmap()
				if (typ == "a") != a.Is4() {
					continue
				}
				s, ok := spans[a]
				if !ok {
					s = &span{}
					spans[a] = s
					order = append(order, a)
				}
				if first := date(r.FirstSeen); first != "" && (s.first == "" || first < s.first) {
					s.first = first
				}
				if last := date(r.LastSeen); last != "" && last > s.last {
					s.last = last
				}
			}
		}
	}
	var obs []run.Observation
	for _, a := range order {
		s, typ := spans[a], "A"
		if a.Is6() {
			typ = "AAAA"
		}
		obs = append(obs,
			kinds.HistoricalAddress.Obs(host+"|"+typ+"|"+a.String(),
				kinds.HistoricalAddressAttrs{Host: host, Addr: a.String(), Type: typ, FirstSeen: s.first, LastSeen: s.last}),
			kinds.IP.Obs(a.String()))
	}
	return obs, nil
}

// date is a YYYY-MM-DD date, or "" for anything else.
func date(s string) string {
	if _, err := time.Parse(time.DateOnly, s); err != nil {
		return ""
	}
	return s
}

// fetch reads the pages of one record type for a host. It stops at the last page the answer
// reports or at maxPages, and says so when it stopped early.
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
