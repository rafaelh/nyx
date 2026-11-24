package httpsrc

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// SecurityTrailsDomains paginates a domain-filter search, passing total count and hostnames to
// the callback. It stops on callback request, exhaustion or maxPages, warning on the cap. A 404
// is empty; keyed 401/403/429 responses abort through Get.
func SecurityTrailsDomains(ctx context.Context, c egress.Clients, field, value string, maxPages int, who string,
	page func(total int, names []string) (stop bool)) error {
	body, err := json.Marshal(map[string]any{"filter": map[string]string{field: value}})
	if err != nil {
		return err
	}
	for n := 1; ; n++ {
		raw, err := Get(ctx, c, egress.ThirdPartyRequest{
			Method: "POST", URL: "https://api.securitytrails.com/v1/domains/list?" + url.Values{
				"include_ips": {"false"}, "scroll": {"false"}, "page": {strconv.Itoa(n)}}.Encode(),
			Body: body, ContentType: "application/json", KeySource: "securitytrails", KeyHeader: "APIKEY",
		})
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		// Use both pagination fields and take the larger count so either response shape
		// can expose pages after the first.
		var r struct {
			Pages       int `json:"pages"`
			RecordCount int `json:"record_count"`
			Meta        struct {
				TotalPages int `json:"total_pages"`
			} `json:"meta"`
			Records []struct {
				Hostname string `json:"hostname"`
			} `json:"records"`
		}
		if err := json.Unmarshal(raw, &r); err != nil || r.Records == nil {
			return errors.New("unreadable SecurityTrails response")
		}
		names := make([]string, len(r.Records))
		for i, rec := range r.Records {
			names[i] = rec.Hostname
		}
		if page(r.RecordCount, names) || n >= max(r.Pages, r.Meta.TotalPages) {
			return nil
		}
		if n == maxPages {
			run.Warnf(ctx, "%s: SecurityTrails result truncated after %d pages", who, n)
			return nil
		}
	}
}
