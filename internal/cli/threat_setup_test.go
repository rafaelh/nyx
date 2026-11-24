package cli_test

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/threatdata"
)

// Threat-tab updates write data without changing config or creating an unsaved-changes prompt.
func TestThreatSetup_UpdatesFromTheTab(t *testing.T) {
	t.Parallel()
	w := newThreatWorldOn(t, setupHarness(t))
	config := tdSnapshot(t, w.h.configFile())
	keys := []string{keyTab, keyTab, keyTab, "u", "q"}
	w.h.stdin = &sequence{chunks: keys, before: map[int]func(){
		len(keys) - 1: func() { // before q: wait for the update to finish
			done := func() bool {
				return tdReadState(t, w.dir(), threatdata.Spamhaus).LastChecked != nil &&
					tdReadState(t, w.dir(), threatdata.Ipapi).LastChecked != nil
			}
			if !tdPoll(10*time.Second, done) {
				t.Errorf("u on the Threat data tab did not finish an update: the hosts saw %v", w.requests())
			}
			time.Sleep(100 * time.Millisecond) // for the result to be drawn
		},
	}}
	if code := w.h.execRootTimeout("setup"); code != 0 {
		t.Fatalf("exit %d, want 0\nstderr %q", code, w.h.stderr.String())
	}
	for _, f := range []string{tdSpamhausData, tdIpapiData} {
		if !tdExists(w.path(f)) {
			t.Errorf("%s was not written", f)
		}
	}
	if got := w.requests(); len(got) != len(tdFiveRequests) {
		t.Errorf("the hosts saw %v, want one request per list", got)
	}
	if out := w.h.stdout.String(); !strings.Contains(out, "Threat data") {
		t.Error("the Threat data tab was never drawn")
	}
	tdUnchanged(t, w.h.configFile(), config)
	if w.h.stderr.Len() != 0 {
		t.Errorf("stderr %q", w.h.stderr.String())
	}
}

// An update from setup that fails for both sources leaves setup's exit code alone: quitting exits 0,
// with no error.
func TestThreatSetup_AFailedUpdateLeavesTheExitCode(t *testing.T) {
	t.Parallel()
	w := newThreatWorldOn(t, setupHarness(t))
	w.fail(threatdata.Spamhaus, http.StatusInternalServerError)
	w.fail(threatdata.Ipapi, http.StatusInternalServerError)
	keys := []string{keyTab, keyTab, keyTab, "u", "q"}
	w.h.stdin = &sequence{chunks: keys, before: map[int]func(){
		len(keys) - 1: func() {
			answered := func() bool {
				return tdReadState(t, w.dir(), threatdata.Spamhaus).LastResponse != nil &&
					tdReadState(t, w.dir(), threatdata.Ipapi).LastResponse != nil
			}
			if !tdPoll(10*time.Second, answered) {
				t.Errorf("u on the Threat data tab sent no update: the hosts saw %v", w.requests())
			}
			time.Sleep(300 * time.Millisecond) // for the update to end and its result to be drawn
		},
	}}
	if code := w.h.execRootTimeout("setup"); code != 0 {
		t.Fatalf("exit %d, want 0 whatever the update's result\nstderr %q", code, w.h.stderr.String())
	}
	if w.h.stderr.Len() != 0 {
		t.Errorf("stderr %q", w.h.stderr.String())
	}
	if _, err := os.Stat(w.path(tdSpamhausData)); err == nil {
		t.Error("a failed update wrote Spamhaus's data file")
	}
}
