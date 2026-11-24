package subdomains

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/httpsrc"
	"github.com/rafaelh/nyx/internal/run"
)

// Keyed sources abort on 401/403/429, return empty for 404 and reject unexpected body shapes as
// retryable failures.

// --- Censys (certificate search) ---

// censysPageSize is the most results the Platform API returns per page.
const censysPageSize = 100

// censys paginates certificate-name searches up to in.pages using a personal access token.
func censys(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	var names []string
	token := ""
	for page := 1; ; page++ {
		reqBody := map[string]any{"query": `cert.names: "` + in.root + `"`, "page_size": censysPageSize}
		if token != "" {
			reqBody["page_token"] = token
		}
		b, err := json.Marshal(reqBody)
		if err != nil {
			return result{}, err
		}
		body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{
			Method: "POST", URL: "https://api.platform.censys.io/v3/global/search/query", Body: b,
			ContentType: "application/json", Accept: "application/json",
			KeySource: "censys", KeyHeader: "Authorization", KeyPrefix: "Bearer ",
		})
		if errors.Is(err, httpsrc.ErrNotFound) {
			break
		}
		if err != nil {
			return result{}, err
		}
		var r struct {
			Result *struct {
				NextPageToken string `json:"next_page_token"`
				Hits          []struct {
					Certificate struct {
						Resource struct {
							Names []string `json:"names"`
						} `json:"resource"`
					} `json:"certificate_v1"`
				} `json:"hits"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &r); err != nil || r.Result == nil {
			return result{}, errors.New("unreadable Censys response")
		}
		for _, h := range r.Result.Hits {
			names = append(names, h.Certificate.Resource.Names...)
		}
		if token = r.Result.NextPageToken; token == "" {
			break
		}
		if page == in.pages {
			run.Warnf(ctx, "censys %s: result truncated after %d pages; raise censys.max_pages to read more", in.root, in.pages)
			break
		}
	}
	return result{names: names}, nil
}

// --- Chaos (ProjectDiscovery) ---

// chaos returns a whole list in one response, so its page cap never binds. It sends the key
// without an authentication scheme prefix.
func chaos(ctx context.Context, in rootInput, c egress.Clients) (result, error) {
	body, err := httpsrc.Get(ctx, c, egress.ThirdPartyRequest{
		Method: "GET", URL: "https://dns.projectdiscovery.io/dns/" + url.PathEscape(in.root) + "/subdomains",
		KeySource: "chaos", KeyHeader: "Authorization",
	})
	if errors.Is(err, httpsrc.ErrNotFound) {
		return result{}, nil
	}
	if err != nil {
		return result{}, err
	}
	var r struct {
		Domain     string   `json:"domain"`
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.Domain == "" && r.Subdomains == nil {
		return result{}, errors.New("unreadable Chaos response")
	}
	return result{names: httpsrc.JoinLabels(in.root, r.Subdomains)}, nil
}
