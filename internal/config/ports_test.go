package config_test

import (
	"slices"
	"testing"
)

// Default sweeps include every risky-port default.
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

// Help distinguishes general concurrency from port-sweep workers.
func TestConcurrencyHelpNamesPortConcurrency(t *testing.T) {
	t.Parallel()
	if c := newFlagSetForHelp().Lookup("concurrency"); c == nil || c.Usage != "Workers per stage (ports: --port-concurrency)" {
		t.Errorf("--concurrency usage = %+v", c)
	}
}
