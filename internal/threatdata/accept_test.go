package threatdata_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/threatdata"
)

// A list with no entries is refused, and one with any is not.
func TestCheckEmpty(t *testing.T) {
	t.Parallel()
	if err := threatdata.CheckEmpty("drop_v4", 0); err == nil {
		t.Error("a list of 0 entries was accepted")
	} else if !strings.Contains(err.Error(), "drop_v4") {
		t.Errorf("the refusal %q doesn't name the list", err)
	}
	for _, n := range []int{1, 2, 1752} {
		if err := threatdata.CheckEmpty("drop_v4", n); err != nil {
			t.Errorf("a list of %d entries: %v", n, err)
		}
	}
}

// A list holding fewer than half the entries of the copy in use is refused; half or more passes.
func TestCheckShrink(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		entries, inUse int
		refused        bool
	}{
		{entries: 49, inUse: 100, refused: true},
		{entries: 50, inUse: 100},
		{entries: 50, inUse: 101, refused: true},
		{entries: 51, inUse: 101},
		{entries: 1, inUse: 3, refused: true},
		{entries: 2, inUse: 3},
		{entries: 100, inUse: 100},
		{entries: 900, inUse: 100},
		{entries: 1, inUse: 0},
	} {
		err := threatdata.CheckShrink("asndrop", c.entries, c.inUse)
		if (err != nil) != c.refused {
			t.Errorf("%d entries against %d in use: err = %v, want refused=%v", c.entries, c.inUse, err, c.refused)
		}
	}
}

// A refusal for shrinking names the list, the rule and both counts, and says that a newer build
// of nyx is the remedy.
func TestCheckShrink_Message(t *testing.T) {
	t.Parallel()
	err := threatdata.CheckShrink("drop_v6", 37, 812)
	if err == nil {
		t.Fatal("37 entries against 812 in use was accepted")
	}
	for _, want := range []string{"drop_v6", "half", "37", "812", "a newer build of nyx"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q doesn't contain %q", err, want)
		}
	}
}

// A list dated at or after 00:00 UTC two days from now is refused: up to the end of tomorrow, UTC,
// passes, however the clock's zone places it.
func TestCheckDate(t *testing.T) {
	t.Parallel()
	clock := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	endOfTomorrow := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	brisbane := time.FixedZone("AEST", 10*3600)
	for _, c := range []struct {
		name    string
		date    time.Time
		now     time.Time
		refused bool
	}{
		{"just before the end of tomorrow", endOfTomorrow.Add(-time.Second), clock, false},
		{"at the end of tomorrow", endOfTomorrow, clock, true},
		{"after the end of tomorrow", endOfTomorrow.Add(time.Hour), clock, true},
		{"now", clock, clock, false},
		{"a year ago", clock.AddDate(-1, 0, 0), clock, false},
		{"tomorrow at 00:00 (an ipapi.is day)", time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), clock, false},
		{"the day after tomorrow at 00:00 (an ipapi.is day)", time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC), clock, true},
		// 2026-11-02 09:00 in Brisbane is 2026-11-01 23:00 UTC: tomorrow, UTC, is still 2026-11-02.
		{"the end of tomorrow by UTC, not the clock's zone", endOfTomorrow.Add(-time.Second), time.Date(2026, 11, 2, 9, 0, 0, 0, brisbane), false},
		{"at the end of tomorrow by UTC, with the clock in UTC+10", endOfTomorrow, time.Date(2026, 11, 2, 9, 0, 0, 0, brisbane), true},
		{"a date given in another zone", endOfTomorrow.In(brisbane), clock, true},
	} {
		err := threatdata.CheckDate("drop_v4", c.date, c.now)
		if (err != nil) != c.refused {
			t.Errorf("%s: err = %v, want refused=%v", c.name, err, c.refused)
		}
		if err != nil && !strings.Contains(err.Error(), "drop_v4") {
			t.Errorf("%s: the refusal %q doesn't name the list", c.name, err)
		}
	}
}

// Only a list dated later than the copy in use replaces it; the same date or an earlier one is
// already current.
func TestNewer(t *testing.T) {
	t.Parallel()
	inUse := time.Date(2026, 11, 20, 9, 56, 44, 0, time.UTC)
	for _, c := range []struct {
		date  time.Time
		newer bool
	}{
		{inUse.Add(time.Second), true},
		{inUse.AddDate(0, 0, 1), true},
		{inUse, false},
		{inUse.In(time.FixedZone("AEST", 10*3600)), false},
		{inUse.Add(-time.Second), false},
		{inUse.AddDate(-1, 0, 0), false},
	} {
		if got := threatdata.Newer(c.date, inUse); got != c.newer {
			t.Errorf("Newer(%v, %v) = %v, want %v", c.date, inUse, got, c.newer)
		}
	}
}
