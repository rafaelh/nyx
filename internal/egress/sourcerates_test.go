package egress_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
)

// timeRequests makes n requests to https://host/ through a stage whose sources are sources, and
// returns how long they took.
func timeRequests(t *testing.T, opts egress.Options, host string, n int, sources ...string) time.Duration {
	t.Helper()
	c := thirdPartyServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }, opts, sources...)
	start := time.Now()
	for range n {
		if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://" + host + "/"}); err != nil {
			t.Fatal(err)
		}
	}
	return time.Since(start)
}

// A source with its own pace is held to it, however fast the default is.
func TestSourceRatesSlowerThanTheDefault(t *testing.T) {
	t.Parallel()
	opts := egress.Options{RatePerSource: 1000, SourceRates: map[string]float64{"slow.example.net": 4}}
	// Three requests at 4/s: the second and third wait 250ms each.
	if el := timeRequests(t, opts, "slow.example.net", 3, "slow.example.net"); el < 450*time.Millisecond {
		t.Errorf("3 requests at 4/s took %v; want >= 500ms", el)
	}
}

// A source with its own pace overrides a slower default.
func TestSourceRatesFasterThanTheDefault(t *testing.T) {
	t.Parallel()
	opts := egress.Options{RatePerSource: 1, SourceRates: map[string]float64{"fast.example.net": 1000}}
	// At the default 1/s, three requests would take two seconds.
	if el := timeRequests(t, opts, "fast.example.net", 3, "fast.example.net"); el > 900*time.Millisecond {
		t.Errorf("3 requests at 1000/s took %v; want well under the default pace of 1/s", el)
	}
}

// Wildcard hosts share one limiter keyed by the declared source pattern.
func TestSourceRatesKeyedByPattern(t *testing.T) {
	t.Parallel()
	opts := egress.Options{RatePerSource: 1000, SourceRates: map[string]float64{"*.registry.example.net": 4}}
	c := thirdPartyServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }, opts, "*.registry.example.net")
	start := time.Now()
	for _, h := range []string{"a", "b", "c"} {
		if _, err := c.Do(context.Background(), egress.ThirdPartyRequest{Method: "GET", URL: "https://" + h + ".registry.example.net/"}); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 450*time.Millisecond {
		t.Errorf("3 requests to one pattern at 4/s took %v; want >= 500ms", el)
	}
}

// A source with no entry keeps RatePerSource, even when another source has one.
func TestSourceRatesLeaveOtherSourcesAlone(t *testing.T) {
	t.Parallel()
	opts := egress.Options{RatePerSource: 4, SourceRates: map[string]float64{"other.example.net": 1000}}
	if el := timeRequests(t, opts, "plain.example.net", 3, "plain.example.net", "other.example.net"); el < 450*time.Millisecond {
		t.Errorf("3 requests at the default 4/s took %v; want >= 500ms", el)
	}
}
