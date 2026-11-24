package setup

import (
	"context"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
)

// recordToday is the day the record tests run on.
var recordToday = time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)

// onDay fixes the displayed local date east of UTC so record dates follow the clock's calendar
// day.
func onDay(day time.Time) thOpt {
	zone := time.FixedZone("AEDT", 11*3600)
	at := time.Date(day.Year(), day.Month(), day.Day(), 1, 0, 0, 0, zone)
	return func(o *Options) { o.Now = func() time.Time { return at } }
}

func withRecord(b *fakeBackend, name, key, result string, day time.Time) {
	b.snap.Keys[name] = KeyState{Value: config.Secret(key), Record: &KeyRecord{Result: result, Day: day}}
}

func daysAgo(n int) time.Time { return recordToday.AddDate(0, 0, -n) }

func TestKeyRecord_StatusShownFromTheFile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		record *KeyRecord
		want   string // "" is no status at all
	}{
		{"no record", nil, "not tested"},
		{"accepted today", &KeyRecord{RecordAccepted, recordToday}, "accepted"},
		{"rejected 89 days ago", &KeyRecord{RecordRejected, daysAgo(89)}, "rejected"},
		{"not tested 10 days ago", &KeyRecord{RecordNotTested, daysAgo(10)}, "not tested"},
		{"accepted 90 days ago", &KeyRecord{RecordAccepted, daysAgo(90)}, ""},
		{"rejected 400 days ago", &KeyRecord{RecordRejected, daysAgo(400)}, ""},
		{"not tested 90 days ago", &KeyRecord{RecordNotTested, daysAgo(90)}, ""},
		{"dated tomorrow", &KeyRecord{RecordAccepted, recordToday.AddDate(0, 0, 1)}, "not tested"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := newFake()
			b.snap.Keys["shodan"] = KeyState{Value: "abcdefghijklmnop", Record: tc.record}
			h := newTH(t, b, onDay(recordToday))
			line := lineFor(h.view(), "shodan")
			if tc.want != "" {
				mustHave(t, line, tc.want)
			}
			mustNotHave(t, line, otherStatuses(tc.want)...)
			if h.m.changes() != 0 {
				t.Errorf("changes = %d, want 0: a record is not a change", h.m.changes())
			}
		})
	}
}

// otherStatuses are the statuses a row must not show when it shows want.
func otherStatuses(want string) []string {
	var out []string
	for _, s := range []string{"accepted", "rejected", "not tested", "could not check", "testing"} {
		if s != want {
			out = append(out, s)
		}
	}
	return out
}

func TestKeyRecord_UnsetKeyShowsNoStatus(t *testing.T) {
	t.Parallel()
	b := newFake()
	h := newTH(t, b, onDay(recordToday))
	mustNotHave(t, lineFor(h.view(), "shodan"), otherStatuses("")...)
}

func TestKeyRecord_EnteredKeyIsNotTestedAndSavedSo(t *testing.T) {
	t.Parallel()
	b := newFake()
	withRecord(b, "shodan", "abcdefghijklmnop", RecordAccepted, daysAgo(3))
	h := newTH(t, b, onDay(recordToday))
	h.goTo(0, 1)
	h.press("enter")
	h.typ("a-brand-new-shodan-key")
	h.press("enter")
	mustHave(t, lineFor(h.view(), "shodan"), "not tested")
	mustNotHave(t, lineFor(h.view(), "shodan"), "accepted")
	h.press("ctrl+s")
	got := b.save(t, 0).Records["shodan"]
	if want := (KeyRecord{RecordNotTested, recordToday}); got != want {
		t.Errorf("record = %+v, want %+v", got, want)
	}
	mustHave(t, lineFor(h.view(), "shodan"), "not tested")
}

func TestKeyRecord_TestResultIsAChangeSavedWithTheDay(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		status TestStatus
		want   string
	}{
		{TestAccepted, RecordAccepted},
		{TestRejected, RecordRejected},
	} {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			b := newFake()
			withRecord(b, "shodan", "abcdefghijklmnop", RecordNotTested, daysAgo(200))
			b.testFn = func(context.Context, string, config.Secret) TestResult { return TestResult{Status: tc.status} }
			h := newTH(t, b, onDay(recordToday))
			h.goTo(0, 1)
			h.run(h.press("t"))
			if h.m.changes() != 1 {
				t.Fatalf("changes = %d after a test, want 1", h.m.changes())
			}
			h.press("ctrl+s")
			e := b.save(t, 0)
			if len(e.Set) != 0 || len(e.Clear) != 0 {
				t.Errorf("the key itself was written: %+v", e)
			}
			if got, want := e.Records["shodan"], (KeyRecord{tc.want, recordToday}); got != want {
				t.Errorf("record = %+v, want %+v", got, want)
			}
			if h.m.changes() != 0 {
				t.Errorf("changes = %d after the save, want 0", h.m.changes())
			}
			mustHave(t, lineFor(h.view(), "shodan"), tc.want)
		})
	}
}

func TestKeyRecord_TestedThenDiscardedWritesNothing(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	h := newTH(t, b, onDay(recordToday))
	h.goTo(0, 1)
	h.run(h.press("t"))
	h.press("q")
	if h.m.mode != modeQuit {
		t.Fatal("quitting after a test did not ask to save it")
	}
	h.press("d")
	if n, _, _ := b.counts(); n != 0 {
		t.Errorf("saves = %d, want 0", n)
	}
}

func TestKeyRecord_CouldNotCheckKeepsTheRecord(t *testing.T) {
	t.Parallel()
	b := newFake()
	withRecord(b, "shodan", "abcdefghijklmnop", RecordAccepted, daysAgo(5))
	b.testFn = func(context.Context, string, config.Secret) TestResult {
		return TestResult{Status: TestUnknown, Reason: "rate limited"}
	}
	h := newTH(t, b, onDay(recordToday))
	h.goTo(0, 1)
	h.run(h.press("t"))
	mustHave(t, lineFor(h.view(), "shodan"), "could not check: rate limited")
	if h.m.changes() != 0 {
		t.Errorf("changes = %d, want 0", h.m.changes())
	}
	if _, ok := h.m.edits().Records["shodan"]; ok {
		t.Error("an inconclusive test would replace the record")
	}
}

func TestKeyRecord_KeyWithoutOneGetsNotTestedOnTheNextSave(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	withRecord(b, "github", "ghp_abcdefghijklmnop", RecordAccepted, daysAgo(120))
	h := newTH(t, b, onDay(recordToday))
	h.press("ctrl+s")
	if n, _, _ := b.counts(); n != 0 {
		t.Fatal("a missing record alone was saved")
	}
	mustHave(t, h.view(), "No changes to save")
	h.goTo(1, 1)
	h.press("enter", "ctrl+u")
	h.typ("4")
	h.press("enter", "ctrl+s")
	e := b.save(t, 0)
	want := map[string]KeyRecord{"shodan": {RecordNotTested, recordToday}}
	if len(e.Records) != len(want) || e.Records["shodan"] != want["shodan"] {
		t.Errorf("records = %+v, want %+v (an old record is kept as it is)", e.Records, want)
	}
}

func TestKeyRecord_ClearedKeySendsNoRecord(t *testing.T) {
	t.Parallel()
	b := newFake()
	withRecord(b, "shodan", "abcdefghijklmnop", RecordAccepted, daysAgo(1))
	h := newTH(t, b, onDay(recordToday))
	h.goTo(0, 1)
	h.press("x", "ctrl+s")
	if _, ok := b.save(t, 0).Records["shodan"]; ok {
		t.Error("a cleared key was given a record")
	}
	mustNotHave(t, lineFor(h.view(), "shodan"), otherStatuses("")...)
}
