package dnshistory_test

import (
	"testing"

	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/stages/dnshistory"
)

// dnshistory says its addresses come from DNS history, so that an address only it names is not
// checked against the abusive lists: the runner reads the marker, and no code names the stage.
func TestStageIsHistorical(t *testing.T) {
	t.Parallel()
	if _, ok := any(dnshistory.New()).(run.Historical); !ok {
		t.Error("the dnshistory stage is not a run.Historical")
	}
}
