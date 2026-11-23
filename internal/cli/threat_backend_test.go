package cli_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/threatdata"
)

// The Backend setup is given for the Threat data tab: what it reads from the threat-data directory
// and how it reports an update, through the real editor.

// threatTab sends the keys to open the Threat data tab, then keys, then q, with wait run before q.
func threatTab(w *threatWorld, wait func(), keys ...string) int {
	chunks := append([]string{keyTab, keyTab, keyTab}, keys...)
	chunks = append(chunks, "q")
	w.h.stdin = &sequence{chunks: chunks, before: map[int]func(){len(chunks) - 1: wait}}
	return w.h.execRootTimeout("setup")
}

// With nowhere to keep the data, the tab says why and u sends nothing.
func TestThreatSetup_NowhereToKeepTheDataIsSaidOnTheTab(t *testing.T) {
	t.Parallel()
	w := newThreatWorldOn(t, setupHarness(t))
	cfg := writeFile(t, t.TempDir(), "nyx.yaml", "")
	w.h.setenv("XDG_CONFIG_HOME", "")
	w.h.setenv("HOME", "")
	w.h.stdin = &sequence{chunks: []string{keyTab, keyTab, keyTab, "u", "q"}}
	if code := w.h.execRootTimeout("setup", "--config", cfg); code != 0 {
		t.Fatalf("exit %d, want 0\nstderr %s", code, w.h.stderr.String())
	}
	if out := w.h.stdout.String(); !strings.Contains(out, "nowhere to keep threat data") {
		t.Errorf("the tab does not say why the data cannot be updated:\n%s", out)
	}
	if r := w.requests(); len(r) != 0 {
		t.Errorf("u sent %v, want nothing", r)
	}
}

// A source that answered within the hour is skipped by u, and its row says when it can be updated.
func TestThreatSetup_ASkippedSourceSaysWhen(t *testing.T) {
	t.Parallel()
	w := newThreatWorldOn(t, setupHarness(t))
	w.skipped(threatdata.Spamhaus)
	wait := func() {
		if !tdPoll(10*time.Second, func() bool { return tdReadState(t, w.dir(), threatdata.Ipapi).LastChecked != nil }) {
			t.Errorf("u did not finish: the hosts saw %v", w.requests())
		}
		time.Sleep(200 * time.Millisecond) // for the result to be drawn
	}
	if code := threatTab(w, wait, "u"); code != 0 {
		t.Fatalf("exit %d, want 0\nstderr %s", code, w.h.stderr.String())
	}
	if n := w.sh.count(tdPathV4); n != 0 {
		t.Errorf("Spamhaus was asked %d times, want none: it answered ten minutes ago", n)
	}
	if out := w.h.stdout.String(); !strings.Contains(out, "can be updated after") {
		t.Errorf("the tab does not say when the skipped source can be updated:\n%s", out)
	}
}

// A downloaded copy that cannot be read is said on the tab, as a note on each of its lists.
func TestThreatSetup_AnUnreadableCopyIsNoted(t *testing.T) {
	t.Parallel()
	w := newThreatWorldOn(t, setupHarness(t))
	tdWrite(t, w.dir(), tdSpamhausData, []byte("not a bundle\n"))
	if code := threatTab(w, func() { time.Sleep(200 * time.Millisecond) }); code != 0 {
		t.Fatalf("exit %d, want 0\nstderr %s", code, w.h.stderr.String())
	}
	if out := w.h.stdout.String(); !strings.Contains(out, "unreadable") {
		t.Errorf("the tab does not say the downloaded copy is unreadable:\n%s", out)
	}
	if b, _ := os.ReadFile(w.path(tdSpamhausData)); string(b) != "not a bundle\n" {
		t.Errorf("opening the tab changed the copy: %q", b)
	}
}
