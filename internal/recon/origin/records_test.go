package origin_test

import (
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/recon/kinds"
	"github.com/rafaelh/nyx/internal/recon/origin"
	"github.com/rafaelh/nyx/internal/recon/store"
)

func webService(a kinds.WebServiceAttrs) store.Record {
	o := kinds.WebService.Obs(a.URL, a)
	return store.Record{Kind: o.Kind, Key: o.Key, Current: true, Attrs: o.Attrs}
}

// A probe that followed a redirect to another host saw that host's page, so its title matches
// nothing: an unfronted host redirecting to the fronted one is not its sibling by title.
func TestPairs_RedirectedTitleIsNotASibling(t *testing.T) {
	t.Parallel()
	inv, sc := standard().build()
	recs := []store.Record{
		webService(kinds.WebServiceAttrs{URL: "https://www.example.com", Host: "www.example.com", Port: 443, Scheme: "https",
			Status: 200, Title: "Acme", FinalURL: "https://www.example.com/"}),
		// api.example.com redirects to www and reports www's title.
		webService(kinds.WebServiceAttrs{URL: "https://api.example.com", Host: "api.example.com", Port: 443, Scheme: "https",
			Status: 301, Title: "Acme", Redirect: "https://www.example.com/", FinalURL: "https://www.example.com/"}),
		// title.example.com serves its own page with the same title.
		webService(kinds.WebServiceAttrs{URL: "https://title.example.com", Host: "title.example.com", Port: 443, Scheme: "https",
			Status: 200, Title: "Acme", FinalURL: "https://title.example.com/"}),
	}
	records := func(k kinds.Named) []store.Record {
		if k.Name() == kinds.WebService.Name() {
			return recs
		}
		return nil
	}
	var got []string
	for _, p := range origin.Pairs(sc, inv, kinds.NewVisibility(sc, inv), records, 5) {
		got = append(got, p.Addr.String())
	}
	if !slices.Equal(got, []string{"203.0.113.50"}) {
		t.Errorf("pairs = %v, want only title.example.com's address", got)
	}
}
