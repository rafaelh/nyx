package httpsrc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/rafaelh/nyx/internal/egress"
)

// Announced requires a well-formed successful RIPEstat response before returning prefixes. Each
// prefix is returned once, in its canonical (masked) form; an entry that is not a prefix is
// skipped, so it never becomes a netblock record.
func Announced(ctx context.Context, e egress.Clients, asn string) ([]string, error) {
	q := url.Values{"resource": {asn}, "sourceapp": {"nyx"}}
	raw, err := Get(ctx, e, egress.ThirdPartyRequest{
		Method: "GET", URL: "https://stat.ripe.net/data/announced-prefixes/data.json?" + q.Encode(),
	})
	if err != nil {
		return nil, fmt.Errorf("RIPEstat: %w", err)
	}
	var body struct {
		Status string `json:"status"`
		Data   struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("unreadable RIPEstat response: %w", err)
	}
	if body.Status != "ok" {
		return nil, fmt.Errorf("RIPEstat status %q", body.Status)
	}
	var out []string
	seen := map[netip.Prefix]bool{}
	for _, p := range body.Data.Prefixes {
		pfx, err := netip.ParsePrefix(strings.TrimSpace(p.Prefix))
		if err != nil {
			continue
		}
		if pfx = pfx.Masked(); !seen[pfx] {
			seen[pfx] = true
			out = append(out, pfx.String())
		}
	}
	return out, nil
}
