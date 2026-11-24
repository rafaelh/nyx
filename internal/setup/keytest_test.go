package setup

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/rafaelh/nyx/internal/config"
)

func withKey(b *fakeBackend, name, key string) {
	b.snap.Keys[name] = KeyState{Value: config.Secret(key)}
}

func TestKeyTest_ShowsEachOutcome(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		res  TestResult
		want string
	}{
		{TestResult{Status: TestAccepted}, "accepted"},
		{TestResult{Status: TestRejected}, "rejected"},
		{TestResult{Status: TestUnknown, Reason: "rate limited"}, "could not check: rate limited"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			b := newFake()
			withKey(b, "shodan", "abcdefghijklmnop")
			b.testFn = func(context.Context, string, config.Secret) TestResult { return tc.res }
			h := newTH(t, b)
			h.goTo(0, 1)
			cmd := h.press("t")
			mustHave(t, lineFor(h.view(), "shodan"), "testing")
			h.run(cmd)
			mustHave(t, lineFor(h.view(), "shodan"), tc.want)
			if len(b.tests) != 1 || b.testCall(t, 0) != (testCall{"shodan", "abcdefghijklmnop"}) {
				t.Errorf("tests = %v", b.tests)
			}
		})
	}
}

func TestKeyTest_TestsAnEnteredUnsavedKey(t *testing.T) {
	t.Parallel()
	b := newFake()
	h := newTH(t, b)
	h.goTo(0, 3)
	h.press("enter")
	h.typ("entered-but-unsaved-key")
	h.press("enter")
	h.run(h.press("t"))
	if len(b.tests) != 1 || b.testCall(t, 0).key != "entered-but-unsaved-key" || b.testCall(t, 0).source != "whoisxml" {
		t.Errorf("tests = %v", b.tests)
	}
	if n, _, _ := b.counts(); n != 0 {
		t.Error("a test saved the key")
	}
}

func TestKeyTest_NoKeyIsNotTested(t *testing.T) {
	t.Parallel()
	b := newFake()
	h := newTH(t, b)
	if cmd := h.press("t"); cmd != nil {
		t.Error("a test was started with no key")
	}
	mustHave(t, h.view(), "no key")
}

func TestKeyTest_AnOlderGenerationIsDiscardedAndEditingRemovesTheResult(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	h := newTH(t, b)
	h.goTo(0, 1)
	stale := h.press("t")
	// Replace the key while its test is pending.
	h.press("enter")
	h.typ("a-different-key-1234")
	h.press("enter")
	h.run(stale)
	mustNotHave(t, lineFor(h.view(), "shodan"), "accepted", "testing")
	// New-key results display until editing invalidates them.
	h.run(h.press("t"))
	mustHave(t, lineFor(h.view(), "shodan"), "accepted")
	h.press("enter")
	h.typ("x")
	h.press("enter")
	mustNotHave(t, lineFor(h.view(), "shodan"), "accepted")
	// Clearing also invalidates the displayed result.
	h.run(h.press("t"))
	mustHave(t, lineFor(h.view(), "shodan"), "accepted")
	h.press("x")
	mustNotHave(t, lineFor(h.view(), "shodan"), "accepted")
	// Discard late results for cleared credentials.
	h.send(testDone{source: "shodan", gen: 0, res: TestResult{Status: TestAccepted}})
	mustNotHave(t, lineFor(h.view(), "shodan"), "accepted")
}

func TestKeyTest_EditingAKeyWhileItsTestRunsCancelsThatTest(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	seen := make(chan error, 1)
	b.testFn = func(ctx context.Context, _ string, _ config.Secret) TestResult {
		<-ctx.Done()
		seen <- ctx.Err()
		return TestResult{Status: TestUnknown, Reason: "cancelled"}
	}
	h := newTH(t, b)
	h.goTo(0, 1)
	cmd := h.press("t")
	if cmd == nil {
		t.Fatal("no test started")
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	h.press("x")
	select {
	case err := <-seen:
		if err == nil {
			t.Error("the test's context was not cancelled")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the test was not cancelled by clearing the key")
	}
	h.send(<-done)
	mustNotHave(t, lineFor(h.view(), "shodan"), "cancelled")
}

func TestKeyTest_TIsIgnoredWhileThatKeysTestRuns(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	withKey(b, "chaos", "abcdefghijklmnop")
	h := newTH(t, b)
	h.goTo(0, 1)
	first := h.press("t")
	if first == nil {
		t.Fatal("no test started")
	}
	if second := h.press("t"); second != nil {
		t.Error("a second test started while the first was running")
	}
	// One source's test state cannot affect another.
	h.goTo(0, 5)
	if other := h.press("t"); other == nil {
		t.Error("a test of another key was refused")
	}
	h.goTo(0, 1)
	h.run(first)
	if again := h.press("t"); again == nil {
		t.Error("a test could not be started after the first finished")
	}
}

func TestKeyTest_QuittingCancelsARunningTest(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	seen := make(chan error, 1)
	b.testFn = func(ctx context.Context, _ string, _ config.Secret) TestResult {
		<-ctx.Done()
		seen <- ctx.Err()
		return TestResult{Status: TestUnknown, Reason: "cancelled"}
	}
	h := newTH(t, b)
	h.goTo(0, 1)
	cmd := h.press("t")
	if cmd == nil {
		t.Fatal("no test started")
	}
	go cmd()
	h.press("q")
	if !h.m.quitting {
		t.Fatal("did not quit with only a test running")
	}
	select {
	case err := <-seen:
		if err == nil {
			t.Error("the test's context was not cancelled")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("quitting did not cancel the test")
	}
}

func TestKeyTest_DiscardingFromTheDialogCancelsARunningTest(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	seen := make(chan struct{}, 1)
	b.testFn = func(ctx context.Context, _ string, _ config.Secret) TestResult {
		<-ctx.Done()
		seen <- struct{}{}
		return TestResult{}
	}
	h := newTH(t, b)
	h.goTo(0, 1)
	cmd := h.press("t")
	if cmd == nil {
		t.Fatal("no test started")
	}
	go cmd()
	time.Sleep(10 * time.Millisecond)
	dirty(h)
	h.press("q", "d")
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("discarding did not cancel the test")
	}
}

func TestKeyTest_GivesUpAtTheTimeoutEvenWhenTheBackendIsLate(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	b.testFn = func(ctx context.Context, _ string, _ config.Secret) TestResult {
		<-ctx.Done()
		time.Sleep(5 * time.Millisecond)
		return TestResult{Status: TestAccepted} // response arriving after the timeout
	}
	h := newTH(t, b, func(o *Options) { o.TestTimeout = 20 * time.Millisecond })
	h.goTo(0, 1)
	h.run(h.press("t"))
	mustHave(t, lineFor(h.view(), "shodan"), "could not check: timed out")
}

func TestKeyTest_TheDefaultTimeoutIsFifteenSeconds(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	var left time.Duration
	b.testFn = func(ctx context.Context, _ string, _ config.Secret) TestResult {
		d, _ := ctx.Deadline()
		left = time.Until(d)
		return TestResult{Status: TestAccepted}
	}
	h := newTH(t, b)
	h.goTo(0, 1)
	h.run(h.press("t"))
	if left < 14*time.Second || left > 15*time.Second {
		t.Errorf("deadline in %v, want about 15s", left)
	}
}

func TestKeyTest_AnEchoedKeyInAResultIsNeverShown(t *testing.T) {
	t.Parallel()
	const key = "Zw8LnT3qYb6HcR1dKv9S"
	b := newFake()
	withKey(b, "shodan", key)
	b.testFn = func(context.Context, string, config.Secret) TestResult {
		return TestResult{Status: TestUnknown, Reason: "bad credentials for " + key}
	}
	h := newTH(t, b)
	h.goTo(0, 1)
	h.run(h.press("t"))
	f := h.view()
	mustHave(t, f, "could not check")
	noKeyIn(t, "the frame", f, key)
}

func TestKeyTest_ALongReasonIsCutToOneLine(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	b.testFn = func(context.Context, string, config.Secret) TestResult {
		return TestResult{Status: TestUnknown, Reason: strings.Repeat("very long reason ", 20)}
	}
	h := newTH(t, b, atSize(60, 16))
	h.goTo(0, 1)
	h.run(h.press("t"))
	f := h.view()
	if maxWidth(f) > 60 || lineCount(f) > 16 {
		t.Errorf("frame is %dx%d", maxWidth(f), lineCount(f))
	}
	mustHave(t, lineFor(f, "shodan"), "could not check: very", "…")
}

func TestKeyTest_ALongerKeyIsMaskedWholeWhenAShorterOneIsItsStart(t *testing.T) {
	t.Parallel()
	const short = "Fq9ZpL3xRw7T"
	const long = short + "Mn4Vb8Hc2Ys"
	b := newFake()
	withKey(b, "shodan", short)
	withKey(b, "chaos", long)
	b.testFn = func(_ context.Context, _ string, key config.Secret) TestResult {
		return TestResult{Status: TestUnknown, Reason: "bad credentials for " + long}
	}
	h := newTH(t, b)
	h.goTo(0, 5)
	h.run(h.press("t"))
	f := h.view()
	mustHave(t, f, "could not check: bad credentials for ****")
	noKeyIn(t, "the frame", f, long)
}
