package subdomains

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/procedures/httpsrc"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// Unkeyed sources contribute hostnames only; parsers discard other data and Run filters
// outside-root names. A 404 is empty; quota 429 aborts through GetQuota. Unexpected 200 bodies
// are errors so source failures cannot be saved as completed empty results.

func fetchNames(ctx context.Context, c egress.Clients, u string, parse func([]byte) ([]string, error)) (result, error) {
	names, err := httpsrc.GetNames(ctx, c, u, parse)
	return result{names: names}, err
}

// --- HackerTarget (hostsearch) ---

func hackertarget(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	return fetchNames(ctx, c, "https://api.hackertarget.com/hostsearch/?"+url.Values{"q": {in.root}}.Encode(), hackertargetNames)
}

// hackertargetNames parses host/address lines with shared HackerTarget quota/no-data rules.
func hackertargetNames(body []byte) ([]string, error) {
	lines, err := httpsrc.HackerTargetLines(body)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range lines {
		host, _, ok := strings.Cut(line, ",")
		if !ok {
			return nil, errors.New("unreadable HackerTarget response")
		}
		names = append(names, host)
	}
	return names, nil
}

// --- urlscan.io (search) ---

// urlscan reads the first page of search results only; it warns when there are more.
func urlscan(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	return fetchNames(ctx, c, "https://urlscan.io/api/v1/search/?"+url.Values{"q": {"domain:" + in.root}}.Encode(), func(body []byte) ([]string, error) {
		names, more, err := urlscanNames(body)
		if err == nil && more {
			run.Warnf(ctx, "urlscan %s: result truncated after the first page of search results", in.root)
		}
		return names, err
	})
}

// urlscanNames checks both has_more and total because responses may report false while more
// results remain.
func urlscanNames(body []byte) ([]string, bool, error) {
	var r struct {
		HasMore bool `json:"has_more"`
		Total   int  `json:"total"`
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
			Task struct {
				Domain string `json:"domain"`
			} `json:"task"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Results == nil {
		return nil, false, errors.New("unreadable urlscan response")
	}
	var names []string
	for _, x := range r.Results {
		names = append(names, x.Page.Domain, x.Task.Domain)
	}
	return names, r.HasMore || r.Total > len(r.Results), nil
}

// --- Cert Spotter (issuances) ---

// certspotter follows up to in.pages pages. Its optional key raises the rate limit and is sent
// only when present during job construction.
func certspotter(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	var names []string
	after := ""
	for page := 0; ; page++ {
		if page == in.pages {
			run.Warnf(ctx, "certspotter %s: result truncated after %d pages; raise certspotter.max_pages to read more", in.root, in.pages)
			break
		}
		q := url.Values{"domain": {in.root}, "include_subdomains": {"true"}, "expand": {"dns_names"}}
		if after != "" {
			q.Set("after", after)
		}
		req := egress.ThirdPartyRequest{Method: "GET", URL: "https://api.certspotter.com/v1/issuances?" + q.Encode()}
		if in.keyed {
			req.KeySource, req.KeyHeader, req.KeyPrefix = "certspotter", "Authorization", "Bearer "
		}
		body, err := httpsrc.GetQuota(ctx, c, req)
		if errors.Is(err, httpsrc.ErrNotFound) {
			break
		}
		if err != nil {
			return result{}, err
		}
		var rows []struct {
			ID       string   `json:"id"`
			DNSNames []string `json:"dns_names"`
		}
		if err := json.Unmarshal(body, &rows); err != nil || rows == nil {
			return result{}, errors.New("unreadable Cert Spotter response")
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			names = append(names, r.DNSNames...)
		}
		if after = rows[len(rows)-1].ID; after == "" {
			return result{}, errors.New("unreadable Cert Spotter response: an issuance has no id to page from")
		}
	}
	return result{names: names}, nil
}
