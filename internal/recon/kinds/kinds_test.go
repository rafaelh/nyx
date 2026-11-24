package kinds_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/recon/kinds"
)

// Pin discovery-kind counting and event roles.
func TestDiscoveryKinds(t *testing.T) {
	t.Parallel()
	want := map[string]string{ // category mapping; unprinted categories count without events
		"ip": "ips", "unresolved": "unresolved names",
		"wildcard": "", "ip_owner": "", "ip_hostname": "", "provider_range": "", "resolution": "",
	}
	for name, category := range want {
		k, ok := kinds.Get(name)
		if !ok {
			t.Errorf("kind %s not registered", name)
			continue
		}
		if k.Category != category || k.Printed || k.Entity() {
			t.Errorf("%s = %+v, want category %q, not printed, not an entity", name, k, category)
		}
	}
	if k, _ := kinds.Get("hostname"); !k.Printed {
		t.Error("hostname still prints")
	}
}
