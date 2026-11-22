package setup

import (
	"fmt"
	"slices"
	"testing"
)

func TestSkipTab_OffersTheSkippableStagesWithTheirDescriptions(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	h.press("tab", "tab")
	f := h.view()
	for _, s := range testInfo().Stages {
		mustHave(t, lineWith(f, "[ ] "+s.Name), s.Does)
	}
	mustNotHave(t, f, "] resolve", "[x] resolve")
}

func TestSkipTab_ADescriptionIsCutToOneLineWithAnEllipsis(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.info.Stages[0].Does = "resolves hostnames and then keeps on going with a very long description that cannot fit"
	h := newTH(t, b, atSize(60, 16))
	h.press("tab", "tab")
	f := h.view()
	mustHave(t, f, "…")
	if maxWidth(f) > 60 {
		t.Errorf("a line is %d cells wide:\n%s", maxWidth(f), f)
	}
}

func TestSkipTab_TogglingStagesBuildsTheWholeListInOrder(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Skip = []string{"web", "dns"}
	h := newTH(t, b)
	h.press("tab", "tab")
	mustHave(t, h.view(), "[x] web", "[x] dns", "[ ] ports")
	h.press("down", "enter") // ports on
	h.press("up", "enter")   // dns off
	mustHave(t, h.view(), "[ ] dns", "[x] ports")
	h.press("ctrl+s")
	if h.m.changes() != 0 {
		t.Fatalf("not saved: %v", h.view())
	}
	if got, want := b.save(t, 0).Skip, []string{"web", "ports"}; !slices.Equal(got, want) {
		t.Errorf("Skip = %v, want %v", got, want)
	}
}

func TestSkipTab_ProblemEntriesAreRemovedOneAtATime(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Skip = []string{"dns"}
	b.snap.SkipProblems = []SkipProblem{{Entry: "foo", Message: `unknown stage "foo"`}, {Entry: "resolve", Message: `stage "resolve" cannot be skipped`}}
	h := newTH(t, b)
	h.press("tab", "tab")
	mustHave(t, h.view(), "Skip!", "foo", "resolve")
	h.press("ctrl+s")
	if n, _, _ := b.counts(); n != 0 {
		t.Fatal("saved with problem entries still listed")
	}
	h.goTo(2, 4) // foo
	h.press("x")
	f := h.view()
	mustNotHave(t, f, `unknown stage "foo"`)
	mustHave(t, f, `stage "resolve" cannot be skipped`, "[x] dns")
	h.press("ctrl+s") // resolve is still invalid
	if n, _, _ := b.counts(); n != 0 {
		t.Fatal("saved with one problem entry left")
	}
	h.press("delete")
	mustNotHave(t, h.view(), "cannot be skipped")
	h.press("ctrl+s")
	if len(b.saves) != 1 || !slices.Equal(b.save(t, 0).Skip, []string{"dns"}) {
		t.Fatalf("saved %+v: dns is kept", b.saves)
	}
}

func TestSkipTab_AWholeListProblemIsClearedByXOrByEditing(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"x", "toggle"} {
		t.Run(how, func(t *testing.T) {
			t.Parallel()
			b := newFake()
			b.snap.Skip = []string{"dns"}
			b.snap.SkipListProblem = `skip: "none" cannot be combined with stage names`
			h := newTH(t, b)
			h.press("tab", "tab")
			mustHave(t, h.view(), `"none" cannot be combined`)
			if how == "x" {
				h.goTo(2, 4)
				h.press("x")
			} else {
				h.goTo(2, 1)
				h.press("enter")
			}
			mustNotHave(t, h.view(), "cannot be combined")
			h.press("ctrl+s")
			if len(b.saves) != 1 || b.save(t, 0).Skip == nil {
				t.Fatalf("saved %+v: the list is rewritten", b.saves)
			}
			for _, s := range b.save(t, 0).Skip {
				if s == "none" {
					t.Error("none was written")
				}
			}
		})
	}
}

func TestSkipTab_TogglingBackIsNoChangeAndEmptyingTheListWritesAnEmptyList(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Skip = []string{"dns"}
	h := newTH(t, b)
	h.press("tab", "tab", "down", "enter", "enter")
	if h.m.changes() != 0 {
		t.Errorf("toggled and toggled back is %d changes", h.m.changes())
	}
	h.press("up", "enter") // dns off: the list is empty
	if h.m.changes() != 1 {
		t.Fatalf("changes = %d", h.m.changes())
	}
	h.press("ctrl+s")
	if b.save(t, 0).Skip == nil || len(b.save(t, 0).Skip) != 0 {
		t.Errorf("Skip = %#v, want an empty non-nil list", b.save(t, 0).Skip)
	}
}

func TestSkipTab_ScrollsToKeepTheSelectionVisible(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.info.Stages = nil
	for i := range 37 {
		b.info.Stages = append(b.info.Stages, Stage{Name: fmt.Sprintf("stage%02d", i), Does: "does a thing"})
	}
	h := newTH(t, b, atSize(60, 16))
	h.press("tab", "tab")
	for i := range 37 {
		f := h.view()
		if lineCount(f) > 16 {
			t.Fatalf("frame is %d lines", lineCount(f))
		}
		sel := fmt.Sprintf("> [ ] stage%02d", i)
		mustHave(t, f, sel)
		h.press("down")
	}
	// And back up again.
	for i := 36; i >= 0; i-- {
		mustHave(t, h.view(), fmt.Sprintf("stage%02d", i))
		h.press("up")
	}
}
