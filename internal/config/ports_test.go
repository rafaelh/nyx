package config_test

import (
	"slices"
	"testing"
)

// Every default risky port is scanned by default.
func TestDefaultPortsCoverRiskyPorts(t *testing.T) {
	t.Parallel()
	s, err := load(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range s.RiskyPorts {
		if !slices.Contains(s.Ports, p) {
			t.Errorf("risky port %d is not in the default scan list", p)
		}
	}
}

// --concurrency's help says it does not bound the port sweep.
func TestConcurrencyHelpNamesPortConcurrency(t *testing.T) {
	t.Parallel()
	if c := newFlagSetForHelp().Lookup("concurrency"); c == nil || c.Usage != "Workers per stage (ports: --port-concurrency)" {
		t.Errorf("--concurrency usage = %+v", c)
	}
}
