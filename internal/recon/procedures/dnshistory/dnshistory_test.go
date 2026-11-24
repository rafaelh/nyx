package dnshistory_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/recon/procedures/dnshistory"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// Historical exclusion uses the procedure marker rather than special-casing the dnshistory name.
func TestProcedureIsHistorical(t *testing.T) {
	t.Parallel()
	if _, ok := any(dnshistory.New()).(run.Historical); !ok {
		t.Error("the dnshistory procedure is not a run.Historical")
	}
}
