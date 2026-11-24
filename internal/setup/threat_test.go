package setup

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The credit the fake's drop_v4 list carries.
const (
	testCopyright = "(c) 2026 The Spamhaus Project SLU"
	testTerms     = "https://www.spamhaus.org/drop/terms/"
)

// The texts the fake's results give.
const (
	skipText = "skipped: last contacted 2026-11-01T09:30:00Z; can be updated after 2026-11-01T10:30:00Z"
	failText = "failed: HTTP 503"
)

// testThreat mixes downloaded/built-in lists with small counts so digit grouping does not
// affect assertions.
func testThreat() []ThreatList {
	return []ThreatList{
		{Source: "spamhaus", List: "drop_v4", Date: "2026-11-21T17:56:44Z", Entries: 812, Downloaded: true, Copyright: testCopyright, Terms: testTerms},
		{Source: "spamhaus", List: "drop_v6", Date: "2026-11-20T09:56:44Z", Entries: 93},
		{Source: "spamhaus", List: "asndrop", Date: "2026-11-23T03:26:44Z", Entries: 459, Downloaded: true},
		{Source: "ipapi.is", List: "networks", Date: "2026-11-22", Entries: 637},
		{Source: "ipapi.is", List: "asns", Date: "2026-11-19", Entries: 288, Downloaded: true},
	}
}

func newThreatFake() *fakeBackend {
	b := newFake()
	b.threat = testThreat()
	return b
}

// resultOf assigns one outcome/message to unchanged lists grouped by source.
func resultOf(outcome map[string]ThreatOutcome, text map[string]string) ThreatResult {
	var r ThreatResult
	for _, l := range testThreat() {
		r.Lists = append(r.Lists, ThreatListResult{ThreatList: l, Outcome: outcome[l.Source], Text: text[l.Source]})
	}
	return r
}

func currentResult() ThreatResult {
	return resultOf(
		map[string]ThreatOutcome{"spamhaus": ThreatCurrent, "ipapi.is": ThreatCurrent},
		map[string]string{"spamhaus": "already current", "ipapi.is": "already current"})
}

// skippedAndFailed skips Spamhaus and fails ipapi.is.
func skippedAndFailed() ThreatResult {
	return resultOf(
		map[string]ThreatOutcome{"spamhaus": ThreatSkipped, "ipapi.is": ThreatFailed},
		map[string]string{"spamhaus": skipText, "ipapi.is": failText})
}

// toThreat moves to the Threat data tab with the tab key.
func (h *th) toThreat() {
	h.t.Helper()
	for range 4 {
		if strings.Contains(tabLineOf(h.view()), "[Threat data") {
			return
		}
		h.press("tab")
	}
	if !strings.Contains(tabLineOf(h.view()), "[Threat data") {
		h.t.Fatalf("no Threat data tab is reached with the tab key:\n%s", h.view())
	}
}

func tabLineOf(frame string) string {
	lines := strings.Split(frame, "\n")
	if len(lines) < 2 {
		return ""
	}
	return lines[1]
}

// word matches name as a whole word, so that "asns" is not found in "asndrop".
func word(name string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[^\w.])` + regexp.QuoteMeta(name) + `([^\w]|$)`)
}

// rowIndex is the index of the first body line naming list, or -1.
func rowIndex(frame, list string) int {
	re := word(list)
	for i, l := range strings.Split(frame, "\n") {
		if i >= bodyTop && re.MatchString(l) {
			return i
		}
	}
	return -1
}

// threatRow extracts one list's display block through the next row, blank, credit or end.
func threatRow(t *testing.T, frame, list string) string {
	t.Helper()
	lines := strings.Split(frame, "\n")
	start := rowIndex(frame, list)
	if start < 0 {
		t.Fatalf("no row names %s:\n%s", list, frame)
	}
	out := []string{lines[start]}
	for _, l := range lines[start+1 : max(len(lines)-3, start+1)] {
		other := slices.ContainsFunc(testThreat(), func(o ThreatList) bool { return word(o.List).MatchString(l) })
		if other || strings.TrimSpace(l) == "" || strings.Contains(l, "Spamhaus Project") {
			break
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// flat is s with every run of white space one space, so that a text wrapped onto two lines is found.
func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

func hasCount(s string, n int) bool {
	return regexp.MustCompile(`(^|\D)` + fmt.Sprint(n) + `(\D|$)`).MatchString(s)
}

var builtIn = regexp.MustCompile(`built[- ]in`)

// checkProvenance fails unless row says the copy in use is downloaded, or else built in.
func checkProvenance(t *testing.T, row string, downloaded bool) {
	t.Helper()
	switch {
	case downloaded && (!strings.Contains(row, "downloaded") || builtIn.MatchString(row)):
		t.Errorf("row does not say the copy is downloaded:\n%s", row)
	case !downloaded && (!builtIn.MatchString(row) || strings.Contains(row, "downloaded")):
		t.Errorf("row does not say the copy is built in:\n%s", row)
	}
}

func TestThreat_TheTabComesAfterSkipAndListsEachListWithItsSourceDateCountAndCopy(t *testing.T) {
	t.Parallel()
	h := newTH(t, newThreatFake(), atSize(120, 30))
	tabs := tabLineOf(h.view())
	if i, j := strings.Index(tabs, "Skip"), strings.Index(tabs, "Threat data"); i < 0 || j < 0 || j < i {
		t.Errorf("the tabs are not Skip then Threat data: %q", tabs)
	}
	h.press("tab", "tab", "tab")
	if !strings.Contains(tabLineOf(h.view()), "[Threat data") {
		t.Fatalf("the tab after Skip is not Threat data:\n%s", h.view())
	}
	f := h.view()
	for _, l := range testThreat() {
		row := threatRow(t, f, l.List)
		mustHave(t, row, l.Source, l.Date)
		if !hasCount(row, l.Entries) {
			t.Errorf("the %s row lacks its count %d:\n%s", l.List, l.Entries, row)
		}
		checkProvenance(t, row, l.Downloaded)
	}
	prev := -1
	for _, l := range testThreat() {
		i := rowIndex(f, l.List)
		if i <= prev {
			t.Errorf("the %s row is not after the one before it:\n%s", l.List, f)
		}
		prev = i
	}
}

func TestThreat_TheCreditSitsOnceAtTheFootOfTheTab(t *testing.T) {
	t.Parallel()
	h := newTH(t, newThreatFake(), atSize(120, 30))
	h.toThreat()
	f := h.view()
	last := 0
	for _, l := range testThreat() {
		last = max(last, rowIndex(f, l.List))
	}
	for _, credit := range []string{testCopyright, testTerms} {
		if n := strings.Count(f, credit); n != 1 {
			t.Errorf("the frame holds %q %d times, want once:\n%s", credit, n, f)
			continue
		}
		if i := slices.IndexFunc(strings.Split(f, "\n"), func(l string) bool { return strings.Contains(l, credit) }); i <= last {
			t.Errorf("%q is on line %d, not under the last list's row (line %d):\n%s", credit, i, last, f)
		}
	}
}

func TestThreat_ANoteIsShownWithItsList(t *testing.T) {
	t.Parallel()
	const note = "the downloaded copy is unreadable (bad row 3), so nyx uses its built-in copy"
	b := newThreatFake()
	b.threat[1].Note = note
	h := newTH(t, b, atSize(200, 30))
	h.toThreat()
	f := h.view()
	if !strings.Contains(flat(threatRow(t, f, "drop_v6")), note) {
		t.Errorf("the drop_v6 row lacks its note:\n%s", f)
	}
	mustNotHave(t, threatRow(t, f, "drop_v4"), "bad row 3")
}

func TestThreat_UStartsOneUpdateOnlyOnTheTabAndTheTabShowsItRunning(t *testing.T) {
	t.Parallel()
	b := newThreatFake()
	b.updateFn = func(context.Context) ThreatResult { return currentResult() }
	h := newTH(t, b, atSize(120, 30))
	// On the Keys tab, u is not the update.
	if cmd := h.press("u"); cmd != nil {
		h.run(cmd)
	}
	if b.updateCount() != 0 {
		t.Error("u on the Keys tab started an update")
	}
	mustNotHave(t, h.view(), "updating…")

	h.toThreat()
	first := h.press("u")
	if first == nil {
		t.Fatal("u on the Threat data tab started no update")
	}
	mustHave(t, h.view(), "updating…")
	if second := h.press("u"); second != nil {
		t.Error("a second update started while the first was running")
	}
	mustHave(t, h.view(), "updating…")
	h.run(first)
	if n := b.updateCount(); n != 1 {
		t.Errorf("UpdateThreatData was called %d times, want 1", n)
	}
	mustNotHave(t, h.view(), "updating…")
	if again := h.press("u"); again == nil {
		t.Error("an update could not be started after the first finished")
	}
}

func TestThreat_EachRowShowsItsResultInPlaceWithTheSkipTimeAndTheFailureReason(t *testing.T) {
	t.Parallel()
	b := newThreatFake()
	b.updateFn = func(context.Context) ThreatResult { return skippedAndFailed() }
	h := newTH(t, b, atSize(200, 30))
	h.toThreat()
	h.run(h.press("u"))
	f := h.view()
	mustNotHave(t, f, "updating…")
	prev := -1
	for _, l := range testThreat() {
		row := threatRow(t, f, l.List)
		want, other := skipText, failText
		if l.Source == "ipapi.is" {
			want, other = failText, "skipped"
		}
		if !strings.Contains(flat(row), want) {
			t.Errorf("the %s row lacks %q:\n%s", l.List, want, f)
		}
		mustNotHave(t, row, other)
		mustHave(t, row, l.Source, l.Date)
		if i := rowIndex(f, l.List); i <= prev {
			t.Errorf("the %s row moved:\n%s", l.List, f)
		} else {
			prev = i
		}
	}
	mustHave(t, f, testCopyright, testTerms)
}

func TestThreat_AnUpdatedListShowsItsNewDateCountCopyAndCredit(t *testing.T) {
	t.Parallel()
	const newCopyright = "(c) 2027 The Spamhaus Project SLU"
	b := newThreatFake()
	b.updateFn = func(context.Context) ThreatResult {
		r := currentResult()
		v4 := &r.Lists[0]
		v4.Date, v4.Entries, v4.Copyright = "2026-11-22T17:56:44Z", 815, newCopyright
		v4.Outcome, v4.Text = ThreatUpdated, "updated (+5, -2)"
		nets := &r.Lists[3]
		nets.Date, nets.Entries, nets.Downloaded = "2026-11-23", 640, true
		nets.Outcome, nets.Text = ThreatUpdated, "updated (+3, -0)"
		return r
	}
	h := newTH(t, b, atSize(200, 30))
	h.toThreat()
	h.run(h.press("u"))
	f := h.view()
	v4 := threatRow(t, f, "drop_v4")
	mustHave(t, v4, "2026-11-22T17:56:44Z", "updated (+5, -2)")
	mustNotHave(t, v4, "2026-11-21T17:56:44Z")
	if !hasCount(v4, 815) || hasCount(v4, 812) {
		t.Errorf("the drop_v4 row does not give the new count:\n%s", v4)
	}
	checkProvenance(t, v4, true)
	nets := threatRow(t, f, "networks")
	mustHave(t, nets, "2026-11-23", "updated (+3, -0)")
	if !hasCount(nets, 640) {
		t.Errorf("the networks row does not give the new count:\n%s", nets)
	}
	checkProvenance(t, nets, true)
	mustHave(t, threatRow(t, f, "drop_v6"), "already current")
	if n := strings.Count(f, newCopyright); n != 1 {
		t.Errorf("the new credit is shown %d times, want once:\n%s", n, f)
	}
	mustNotHave(t, f, testCopyright)
}

func TestThreat_AnUpdateIsNotAnUnsavedChange(t *testing.T) {
	t.Parallel()
	b := newThreatFake()
	b.updateFn = func(context.Context) ThreatResult { return skippedAndFailed() }
	h := newTH(t, b, atSize(120, 30))
	h.toThreat()
	cmd := h.press("u")
	if cmd == nil {
		t.Fatal("u started no update")
	}
	mustHave(t, strings.Split(h.view(), "\n")[0], "no unsaved changes")
	h.run(cmd)
	f := h.view()
	mustHave(t, strings.Split(f, "\n")[0], "no unsaved changes")
	mustNotHave(t, tabLineOf(f), "Threat data*")
	h.press("q")
	if !h.m.quitting {
		t.Errorf("q after an update did not quit at once:\n%s", h.view())
	}
	if n, o, _ := b.counts(); n != 0 || o != 0 {
		t.Errorf("the update wrote the config: %d saves, %d overwrites", n, o)
	}
}

// blockingUpdate is an update that runs until its context ends, and reports that it did.
func blockingUpdate(b *fakeBackend) <-chan error {
	seen := make(chan error, 1)
	b.updateFn = func(ctx context.Context) ThreatResult {
		<-ctx.Done()
		seen <- ctx.Err()
		return ThreatResult{}
	}
	return seen
}

func waitCancelled(t *testing.T, seen <-chan error, what string) {
	t.Helper()
	select {
	case err := <-seen:
		if err == nil {
			t.Errorf("%s: the update's context was not cancelled", what)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not cancel the update", what)
	}
}

func TestThreat_QuittingDuringAnUpdateQuitsAtOnceAndCancelsIt(t *testing.T) {
	t.Parallel()
	b := newThreatFake()
	seen := blockingUpdate(b)
	h := newTH(t, b)
	h.toThreat()
	cmd := h.press("u")
	if cmd == nil {
		t.Fatal("u started no update")
	}
	go cmd()
	h.press("q")
	if !h.m.quitting {
		t.Fatalf("did not quit with only an update running:\n%s", h.view())
	}
	waitCancelled(t, seen, "quitting")
}

func TestThreat_DiscardingFromTheQuitDialogCancelsARunningUpdate(t *testing.T) {
	t.Parallel()
	b := newThreatFake()
	seen := blockingUpdate(b)
	h := newTH(t, b)
	dirty(h)
	h.toThreat()
	cmd := h.press("u")
	if cmd == nil {
		t.Fatal("u started no update")
	}
	go cmd()
	h.press("q", "d")
	if !h.m.quitting {
		t.Fatalf("discarding did not quit:\n%s", h.view())
	}
	waitCancelled(t, seen, "discarding")
}

func TestThreat_TheUpdateHasNoKeyTestTimeout(t *testing.T) {
	t.Parallel()
	b := newThreatFake()
	var hasDeadline bool
	var errAfter error
	b.updateFn = func(ctx context.Context) ThreatResult {
		_, hasDeadline = ctx.Deadline()
		time.Sleep(60 * time.Millisecond)
		errAfter = ctx.Err()
		return currentResult()
	}
	h := newTH(t, b, atSize(120, 30), func(o *Options) { o.TestTimeout = 20 * time.Millisecond })
	h.toThreat()
	h.run(h.press("u"))
	if hasDeadline {
		t.Error("the update's context has a deadline")
	}
	if errAfter != nil {
		t.Errorf("the update's context ended after 60ms: %v", errAfter)
	}
	f := h.view()
	mustHave(t, threatRow(t, f, "drop_v4"), "already current")
	mustNotHave(t, f, "timed out")
}

func TestThreat_WithNowhereToKeepTheDataTheTabSaysWhyAndUShowsIt(t *testing.T) {
	t.Parallel()
	const why = "nowhere to keep threat data: neither XDG_CONFIG_HOME nor HOME is set"
	b := newThreatFake()
	b.info.ThreatUnavailable = why
	b.updateFn = func(context.Context) ThreatResult { return currentResult() }
	h := newTH(t, b, atSize(120, 30))
	h.toThreat()
	shown := func() int { return strings.Count(flat(h.view()), why) }
	before := shown()
	if before == 0 {
		t.Errorf("the tab does not say why:\n%s", h.view())
	}
	if cmd := h.press("u"); cmd != nil {
		h.run(cmd)
	}
	if shown() <= before {
		t.Errorf("u does not show the reason:\n%s", h.view())
	}
	if n := b.updateCount(); n != 0 {
		t.Errorf("u ran %d updates with nowhere to keep the data", n)
	}
	mustNotHave(t, h.view(), "updating…")
}

func TestThreat_TextFromTheBackendIsDrawnSanitised(t *testing.T) {
	t.Parallel()
	b := newThreatFake()
	b.threat[0].Copyright = "\x1b[31m" + testCopyright
	b.threat[1].Note = "bad \x1b]8;;http://x\x07copy"
	b.updateFn = func(context.Context) ThreatResult {
		r := skippedAndFailed()
		r.Lists[3].Text = "failed: \x1b[2Jboom"
		r.Lists[0].Copyright = "\x1b[31m" + testCopyright
		return r
	}
	h := newTH(t, b, atSize(200, 30))
	h.toThreat()
	h.run(h.press("u"))
	for _, f := range h.frames {
		mustNotHave(t, f, "\x1b", "\x07")
	}
	f := h.view()
	mustHave(t, f, testCopyright)
	mustHave(t, threatRow(t, f, "networks"), "boom")
}

func TestThreat_EveryFrameFitsInTheMinimumSize(t *testing.T) {
	t.Parallel()
	b := newThreatFake()
	b.threat[2].Note = strings.Repeat("a long note about this list ", 6)
	b.updateFn = func(context.Context) ThreatResult {
		r := skippedAndFailed()
		r.Lists[4].Text = "failed: " + strings.Repeat("a very long reason ", 10)
		return r
	}
	h := newTH(t, b, atSize(60, 16))
	h.toThreat()
	h.run(h.press("u"))
	h.press("down", "down", "down", "down", "down", "up")
	for _, f := range h.frames {
		if maxWidth(f) > 60 || lineCount(f) > 16 {
			t.Fatalf("frame is %dx%d:\n%s", maxWidth(f), lineCount(f), f)
		}
	}
}

func TestRun_AFailedThreatUpdateLeavesWhatRunReturnsAlone(t *testing.T) {
	t.Parallel()
	b := newThreatFake()
	returned := make(chan struct{})
	b.updateFn = func(context.Context) ThreatResult {
		defer close(returned)
		return resultOf(
			map[string]ThreatOutcome{"spamhaus": ThreatFailed, "ipapi.is": ThreatFailed},
			map[string]string{"spamhaus": failText, "ipapi.is": failText})
	}
	s := startSession(t, b, func(o *Options) { o.Width, o.Height = 120, 30 })
	s.waitOut("nyx setup")
	for range 3 {
		s.send("\t")
	}
	s.send("u")
	select {
	case <-returned:
		time.Sleep(50 * time.Millisecond) // let the Program take the result before q
	case <-time.After(2 * time.Second):
		t.Error("u on the Threat data tab started no update")
	}
	s.send("q")
	if err := s.result(); err != nil {
		t.Errorf("Run returned %v after a failed update, want nil", err)
	}
	if n, o, _ := b.counts(); n != 0 || o != 0 {
		t.Errorf("wrote the config: %d saves, %d overwrites", n, o)
	}
}

func TestThreat_AResultWithoutAListLeavesItsRowAsItWas(t *testing.T) {
	t.Parallel()
	b := newThreatFake()
	b.updateFn = func(context.Context) ThreatResult {
		r := currentResult()
		r.Lists = r.Lists[:2]
		return r
	}
	h := newTH(t, b, atSize(200, 30))
	h.toThreat()
	h.run(h.press("u"))
	f := h.view()
	mustNotHave(t, f, "updating…")
	mustHave(t, threatRow(t, f, "drop_v6"), "already current")
	row := threatRow(t, f, "networks")
	mustNotHave(t, row, "already current")
	mustHave(t, row, "2026-11-22")
	mustHave(t, f, testCopyright)
}

func TestThreat_WithNoListsTheFootStillSaysWhy(t *testing.T) {
	t.Parallel()
	const why = "nowhere to keep threat data"
	b := newFake()
	b.info.ThreatUnavailable = why
	h := newTH(t, b, atSize(120, 30))
	h.toThreat()
	mustHave(t, flat(h.view()), why)
	h.press("down", "up")
}
