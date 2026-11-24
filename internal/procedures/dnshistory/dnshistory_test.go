package dnshistory_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/procedures/dnshistory"
	"github.com/rafaelh/nyx/internal/run"
)

// Historical exclusion uses the procedure marker rather than special-casing the dnshistory name.
func TestProcedureIsHistorical(t *testing.T) {
	t.Parallel()
	if _, ok := any(dnshistory.New()).(run.Historical); !ok {
		t.Error("the dnshistory stage is not a run.Historical")
	}
}
