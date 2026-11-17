package cli_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/testkit"
)

const changesHeader = "change,kind,key,scope,severity,current,first_seen,last_seen"

// changeKeys are the rows of changes.csv as "change kind key", sorted.
func changeKeys(t *testing.T, h *harness) []string {
	t.Helper()
	body := h.readOut("a.com", "changes.csv")
	if body == "" {
		return nil
	}
	recs := csvRows(t, body)
	if got := strings.Join(recs[0], ","); got != changesHeader {
		t.Fatalf("changes.csv header = %s", got)
	}
	var out []string
	for _, r := range recs[1:] {
		out = append(out, r[0]+" "+r[1]+" "+r[2])
	}
	slices.Sort(out)
	return out
}

// changeRow is the row of changes.csv for "change kind key", by column name.
func changeRow(t *testing.T, h *harness, want string) map[string]string {
	t.Helper()
	body := h.readOut("a.com", "changes.csv")
	if body == "" {
		t.Fatalf("no changes.csv, want a row %q", want)
	}
	recs := csvRows(t, body)
	for _, r := range recs[1:] {
		if r[0]+" "+r[1]+" "+r[2] == want {
			m := map[string]string{}
			for i, c := range recs[0] {
				m[c] = r[i]
			}
			return m
		}
	}
	t.Fatalf("no changes.csv row %q in\n%s", want, body)
	return nil
}

func wantChanges(t *testing.T, h *harness, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := changeKeys(t, h); !slices.Equal(got, want) {
		t.Errorf("changes.csv rows\n got %q\nwant %q", got, want)
	}
}

func webSvc(url, host string) run.Observation {
	return obs("web_service", url, "url", url, "host", host, "scheme", "https", "port", 443, "status", 200)
}

// certSvc is a web service whose certificate expires on expiry.
func certSvc(host, expiry string) run.Observation {
	return obs("web_service", "https://"+host, "url", "https://"+host, "host", host, "scheme", "https", "port", 443, "status", 200,
		"tls_subject", host, "tls_expiry", expiry, "tls_trust", "trusted")
}

// A first run has nothing to compare with: no changes.csv, no change events, no
// changes in the summary event and no block in the console summary.
func TestChanges_FirstRunReportsNothing(t *testing.T) {
	t.Parallel()
	h := newHarness(t, newSrc("crtsh", finds("k1", list(host("h1.a.com"), webSvc("https://h1.a.com", "h1.a.com")))))
	if code := h.exec("a.com", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if body := h.readOut("a.com", "changes.csv"); body != "" {
		t.Errorf("a first run wrote changes.csv:\n%s", body)
	}
	if n := len(ofType(h.events(), "change")); n != 0 {
		t.Errorf("a first run emitted %d change events", n)
	}
	if _, ok := h.summaryEvent()["changes"]; ok {
		t.Error("the summary event of a first run has changes")
	}

	h2 := newHarness(t, newSrc("crtsh", finds("k1", list(host("h1.a.com")))))
	if code := h2.exec("a.com"); code != 0 {
		t.Fatal(h2.stderr.String())
	}
	if strings.Contains(h2.stdout.String(), "Since last run") {
		t.Errorf("a first run printed the block:\n%s", h2.stdout.String())
	}
}

// A second run lists what is new, what returned and what is gone, each with the
// scope it has (a gone row, the scope it had) and the standard columns.
func TestChanges_NewReturnedAndGone(t *testing.T) {
	t.Parallel()
	crtsh := newSrc("crtsh", finds("k1", list(host("h1.a.com"), host("h2.a.com"), webSvc("https://h2.a.com", "h2.a.com"))))
	h := newHarness(t, crtsh)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}

	// Run 2: h2 and its web service disappear, h3 appears.
	crtsh.finds = finds("k1", list(host("h1.a.com"), host("h3.a.com")))
	h.now = h.now.Add(24 * time.Hour)
	if code := h.exec("-e", "a.com", "--redo", "crtsh"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantChanges(t, h, "new hostname h3.a.com", "gone hostname h2.a.com", "gone web service https://h2.a.com")
	if r := changeRow(t, h, "new hostname h3.a.com"); r["scope"] != "in-scope" || r["current"] != "true" || r["first_seen"] != "2026-11-02" || r["last_seen"] != "2026-11-02" || r["severity"] != "" {
		t.Errorf("new row = %v", r)
	}
	if r := changeRow(t, h, "gone hostname h2.a.com"); r["scope"] != "in-scope" || r["current"] != "false" || r["first_seen"] != "2026-11-01" {
		t.Errorf("gone row = %v", r)
	}
	if r := changeRow(t, h, "gone web service https://h2.a.com"); r["scope"] != "in-scope" || r["current"] != "false" {
		t.Errorf("gone web service row = %v", r)
	}

	// Run 3: h2 and its web service come back, h3 goes.
	crtsh.finds = finds("k1", list(host("h1.a.com"), host("h2.a.com"), webSvc("https://h2.a.com", "h2.a.com")))
	h.now = h.now.Add(24 * time.Hour)
	if code := h.exec("-e", "a.com", "--redo", "crtsh"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantChanges(t, h, "returned hostname h2.a.com", "returned web service https://h2.a.com", "gone hostname h3.a.com")
	if r := changeRow(t, h, "returned hostname h2.a.com"); r["current"] != "true" || r["first_seen"] != "2026-11-01" || r["last_seen"] != "2026-11-03" {
		t.Errorf("returned row = %v", r)
	}
}

// A run with no changes removes the file an earlier run wrote, still ends with
// the block (counting nothing) and emits no change events.
func TestChanges_NoChangesRemovesTheFile(t *testing.T) {
	t.Parallel()
	crtsh := newSrc("crtsh", finds("k1", list(host("h1.a.com"))))
	h := newHarness(t, crtsh)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	crtsh.finds = finds("k1", list(host("h2.a.com")))
	if code := h.exec("-e", "a.com", "--redo", "crtsh"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if h.readOut("a.com", "changes.csv") == "" {
		t.Fatal("run 2 has changes and wrote no file")
	}
	if code := h.exec("-e", "a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if body := h.readOut("a.com", "changes.csv"); body != "" {
		t.Errorf("a run with no changes left changes.csv:\n%s", body)
	}
	if out := h.stdout.String(); !strings.Contains(out, "Since last run\n  new hostnames    0") {
		t.Errorf("the block of a run with no changes:\n%s", out)
	}
	if code := h.exec("-e", "a.com", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if n := len(ofType(h.events(), "change")); n != 0 {
		t.Errorf("%d change events with no changes", n)
	}
	if _, ok := h.summaryEvent()["changes"]; !ok {
		t.Error("a run after a first run has no changes field in its summary")
	}
}

// A certificate that crosses its expiry date with no contact makes one finding
// gone and another new, at the severity each had; the console block counts them
// and lists the new one, and the summary event carries the same.
func TestChanges_CertificateCrossesItsExpiryWithNoContact(t *testing.T) {
	t.Parallel()
	crtsh := newSrc("crtsh", finds("k1", list(host("old.a.com"), certSvc("old.a.com", "2026-11-20"))))
	h := newHarness(t, crtsh)
	if code := h.exec("a.com"); code != 0 { // 19 days from the fixed clock: expiring, low
		t.Fatal(h.stderr.String())
	}
	crtsh.Reset()
	h.now = time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC) // the certificate has expired
	if code := h.exec("-e", "a.com", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if got := ran(crtsh); len(got) != 0 {
		t.Errorf("the second run executed %v; it was to be a run with no work", got)
	}
	if h.network() != 0 {
		t.Error("the second run made network contact")
	}
	wantChanges(t, h, "new finding certificates|expired|https://old.a.com", "gone finding certificates|expiring|https://old.a.com")
	if r := changeRow(t, h, "new finding certificates|expired|https://old.a.com"); r["severity"] != "medium" || r["current"] != "true" {
		t.Errorf("new finding = %v", r)
	}
	if r := changeRow(t, h, "gone finding certificates|expiring|https://old.a.com"); r["severity"] != "low" || r["current"] != "false" {
		t.Errorf("gone finding = %v", r)
	}
	ch, _ := h.summaryEvent()["changes"].(map[string]any)
	counts, _ := ch["counts"].(map[string]any)
	fc, _ := counts["finding"].(map[string]any)
	if fc["new"] != float64(1) || fc["gone"] != float64(1) {
		t.Errorf("summary finding counts = %v", fc)
	}
	listed, _ := ch["findings"].([]any)
	if len(listed) != 1 {
		t.Fatalf("summary changes.findings = %v", ch["findings"])
	}
	if f, _ := listed[0].(map[string]any); f["severity"] != "medium" || f["category"] != "certificates" || f["target"] != "https://old.a.com" {
		t.Errorf("listed finding = %v", listed[0])
	}

	// The same comparison on the console: a third day, a fresh baseline.
	h2 := newHarness(t, newSrc("crtsh", finds("k1", list(host("old.a.com"), certSvc("old.a.com", "2026-11-20")))))
	if code := h2.exec("a.com"); code != 0 {
		t.Fatal(h2.stderr.String())
	}
	h2.now = time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)
	if code := h2.exec("-e", "a.com"); code != 0 {
		t.Fatal(h2.stderr.String())
	}
	out := h2.stdout.String()
	for _, w := range []string{"Since last run\n", "  new findings     1\n", "  gone findings    1", "New findings (high and medium)\n  medium   certificates https://old.a.com"} {
		if !strings.Contains(out, w) {
			t.Errorf("console summary lacks %q:\n%s", w, out)
		}
	}
}

// A changed setting changes findings with no contact: a longer expiry horizon
// makes a certificate's finding new.
func TestChanges_ChangedSetting(t *testing.T) {
	t.Parallel()
	crtsh := newSrc("crtsh", finds("k1", list(host("w.a.com"), certSvc("w.a.com", "2026-12-15"))))
	h := newHarness(t, crtsh)
	if code := h.exec("a.com"); code != 0 { // 44 days out, beyond the 30-day horizon
		t.Fatal(h.stderr.String())
	}
	if code := h.exec("-e", "a.com", "--cert-expiry-days", "60"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantChanges(t, h, "new finding certificates|expiring|https://w.a.com")
	if code := h.exec("-e", "a.com"); code != 0 { // back to the default: the finding goes
		t.Fatal(h.stderr.String())
	}
	wantChanges(t, h, "gone finding certificates|expiring|https://w.a.com")
}

// A new exclusion hides a hostname that was shown: it is gone as a hostname and
// new as an excluded name, and its web service is gone.
func TestChanges_NewExclusion(t *testing.T) {
	t.Parallel()
	h := newHarness(t, newSrc("crtsh", finds("k1", list(host("h1.a.com"), host("h2.a.com"), webSvc("https://h2.a.com", "h2.a.com")))))
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if code := h.exec("-e", "a.com", "-x", "h2.a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantChanges(t, h, "gone hostname h2.a.com", "gone web service https://h2.a.com", "new excluded h2.a.com")
	if r := changeRow(t, h, "new excluded h2.a.com"); r["scope"] != "excluded" {
		t.Errorf("excluded row = %v", r)
	}
}

// A --passive run does not report a web service gone after a scope change,
// because the stage that observed it did not run; a hostname a third-party stage
// observed is still gone. An active run reports both.
func TestChanges_PassiveRunDoesNotReportTargetRecordsGone(t *testing.T) {
	t.Parallel()
	for _, passive := range []bool{true, false} {
		crtsh := newSrc("crtsh", finds("k1", list(host("h1.a.com"))))
		probe := newSrc("httpprobe", finds("p1", list(webSvc("https://h1.a.com", "h1.a.com"))))
		probe.Stage.Kind = run.Target
		h := newHarness(t, crtsh, probe)
		if code := h.exec("a.com", "--authorised"); code != 0 {
			t.Fatal(h.stderr.String())
		}
		args := []string{"-e", "a.com", "-x", "h1.a.com"}
		if passive {
			args = append(args, "--passive")
		}
		if code := h.exec(args...); code != 0 {
			t.Fatal(h.stderr.String())
		}
		want := []string{"gone hostname h1.a.com", "new excluded h1.a.com"}
		if !passive {
			want = append(want, "gone web service https://h1.a.com")
		}
		wantChanges(t, h, want...)
		if passive {
			// The web service was left out, not forgotten: the next run that makes contact
			// reports it gone.
			if code := h.exec("-e", "a.com"); code != 0 {
				t.Fatal(h.stderr.String())
			}
			wantChanges(t, h, "gone web service https://h1.a.com")
		}
	}
}

// A budgeted stage's deferred checks are neither failed nor retired, so the
// records of the checks it already ran are not gone when later ones wait.
func TestChanges_DeferredChecksAreNotGone(t *testing.T) {
	t.Parallel()
	checks := []run.Check{{Key: "c0", Cost: 1}}
	st := &retiringBudgeted{testkit.Budgeted{Stage: &testkit.Stage{StageName: "budgeted", Kind: run.ThirdParty,
		ChecksFn: func(run.View) []run.Check { return checks },
		RunFn: func(_ context.Context, c run.Check, _ egress.Clients) ([]run.Observation, error) {
			return []run.Observation{host(c.Key + ".a.com")}, nil
		}}, Limit: 1}}
	h := newHarness(t, st)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	checks = []run.Check{{Key: "c0", Cost: 1}, {Key: "c1", Cost: 1}, {Key: "c2", Cost: 1}}
	if code := h.exec("-e", "a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantChanges(t, h, "new hostname c1.a.com")
}

// An engagement last written by a nyx that kept no baseline gets one worked out
// once from its stored records, so the first run with this nyx reports only what
// changed, not everything.
func TestChanges_BaselineFromStoredRecords(t *testing.T) {
	t.Parallel()
	crtsh := newSrc("crtsh", finds("k1", list(host("h1.a.com"), host("h2.a.com"))))
	h := newHarness(t, crtsh)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	db := h.openDB("a.com")
	for _, q := range []string{"DELETE FROM shown", "DELETE FROM meta WHERE key LIKE 'shown%'"} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	crtsh.finds = finds("k1", list(host("h1.a.com"), host("h3.a.com")))
	if code := h.exec("-e", "a.com", "--redo", "crtsh"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	wantChanges(t, h, "new hostname h3.a.com", "gone hostname h2.a.com")
}

// The change events follow the summary event, one for each row of changes.csv,
// after the found events of the run.
func TestChanges_EventsFollowTheSummary(t *testing.T) {
	t.Parallel()
	crtsh := newSrc("crtsh", finds("k1", list(host("h1.a.com"), host("h2.a.com"))))
	h := newHarness(t, crtsh)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	crtsh.finds = finds("k1", list(host("h1.a.com"), host("h3.a.com")))
	if code := h.exec("-e", "a.com", "--redo", "crtsh", "--json"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	evs := h.events()
	sum := -1
	var changes []event
	for i, e := range evs {
		switch e.str("type") {
		case "summary":
			sum = i
		case "change":
			changes = append(changes, e)
			if sum < 0 || i < sum {
				t.Errorf("change event %d comes before the summary (%d)", i, sum)
			}
		}
	}
	if len(changes) != 2 {
		t.Fatalf("%d change events", len(changes))
	}
	if evs[len(evs)-1].str("type") != "run_end" {
		t.Errorf("the last event is %v, want run_end", evs[len(evs)-1])
	}
	got := map[string]event{}
	for _, c := range changes {
		got[c.str("change")+" "+c.str("kind")+" "+c.str("key")] = c
	}
	if c, ok := got["new hostname h3.a.com"]; !ok || c.str("scope") != "in-scope" {
		t.Errorf("events = %v", got)
	}
	if _, ok := got["gone hostname h2.a.com"]; !ok {
		t.Errorf("events = %v", got)
	}
	// The found events of the run are still emitted, as before.
	found := false
	for _, e := range ofType(evs, "found") {
		found = found || e.str("value") == "h3.a.com"
	}
	if !found {
		t.Error("no found event for the new hostname")
	}
}

// Changes are counted over what the files show: a hostname that returns counts as
// new in the block, and only the six kinds are counted.
func TestChanges_BlockCountsReturnedAsNew(t *testing.T) {
	t.Parallel()
	crtsh := newSrc("crtsh", finds("k1", list(host("h1.a.com"), host("h2.a.com"))))
	h := newHarness(t, crtsh)
	if code := h.exec("a.com"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	crtsh.finds = finds("k1", list(host("h1.a.com")))
	if code := h.exec("-e", "a.com", "--redo", "crtsh"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	crtsh.finds = finds("k1", list(host("h1.a.com"), host("h2.a.com"), host("h3.a.com")))
	if code := h.exec("-e", "a.com", "--redo", "crtsh"); code != 0 {
		t.Fatal(h.stderr.String())
	}
	if out := h.stdout.String(); !strings.Contains(out, "  new hostnames    2\n") { // h2 returned, h3 new
		t.Errorf("the block does not count the returned and the new:\n%s", out)
	}
}
