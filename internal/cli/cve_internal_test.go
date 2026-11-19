package cli

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/cve"
)

// A panic in one task is that ID's unexpected failure; the other IDs are
// returned, each in its own slot, and no more than four run at once.
func TestLookUp_APanicIsThatIDsFailure(t *testing.T) {
	t.Parallel()
	results := make([]cve.Result, 9)
	for i := range results {
		results[i].ID = fmt.Sprintf("CVE-2024-%d", 1000+i)
	}
	var mu sync.Mutex
	running, most := 0, 0
	lookUp(context.Background(), results, func(_ context.Context, id string) (cve.Record, error) {
		mu.Lock()
		running++
		most = max(most, running)
		mu.Unlock()
		defer func() { mu.Lock(); running--; mu.Unlock() }()
		time.Sleep(20 * time.Millisecond)
		if id == results[3].ID {
			panic("boom")
		}
		return cve.Record{ID: id}, nil
	})
	for i, r := range results {
		if i == 3 {
			if r.Record != nil || r.Fail == nil || r.Fail.Err.Code != clierr.Unexpected || r.Fail.Err.Message != "unexpected failure: boom" {
				t.Errorf("the panicking ID: %+v", r)
			}
			continue
		}
		if r.Fail != nil || r.Record == nil || r.Record.ID != r.ID {
			t.Errorf("slot %d: %+v", i, r)
		}
	}
	if most > 4 || most < 2 {
		t.Errorf("%d tasks ran at once, want 2 to 4", most)
	}
}
