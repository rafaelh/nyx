package dnshistory_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/dnshistory"
)

// Historical exclusion uses the stage marker rather than special-casing the dnshistory name.
func TestStageIsHistorical(t *testing.T) {
	t.Parallel()
	if _, ok := any(dnshistory.New()).(run.Historical); !ok {
		t.Error("the dnshistory stage is not a run.Historical")
	}
}
