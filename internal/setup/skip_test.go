package setup

import (
	"fmt"
	"slices"
	"testing"
)

func TestSkipTab_OffersTheSkippableProceduresWithTheirDescriptions(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	h.press("tab", "tab")
	f := h.view()
	for _, s := range testInfo().Procedures {
		mustHave(t, lineWith(f, "[x] "+s.Name), s.Does)
	}
	mustNotHave(t, f, "] resolve", "[x] resolve")
}

func TestSkipTab_ADescriptionIsCutToOneLineWithAnEllipsis(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.info.Procedures[0].Does = "resolves hostnames and then keeps on going with a very long description that cannot fit"
	h := newTH(t, b, atSize(60, 16))
	h.press("tab", "tab")
	f := h.view()
	mustHave(t, f, "…")
	if maxWidth(f) > 60 {
		t.Errorf("a line is %d cells wide:\n%s", maxWidth(f), f)
	}
}

func TestSkipTab_TogglingProceduresBuildsTheWholeListInOrder(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Skip = []string{"web", "dns"}
	h := newTH(t, b)
	h.press("tab", "tab")
	mustHave(t, h.view(), "[ ] web", "[ ] dns", "[x] ports")
	h.press("down", "enter") // initial skipped procedure
	h.press("up", "enter")   // initial enabled procedure
	mustHave(t, h.view(), "[x] dns", "[ ] ports")
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
	b.snap.SkipProblems = []SkipProblem{{Entry: "foo", Message: `unknown procedure "foo"`}, {Entry: "resolve", Message: `procedure "resolve" cannot be skipped`}}
	h := newTH(t, b)
	h.press("tab", "tab")
	mustHave(t, h.view(), "Skip!", "foo", "resolve")
	h.press("ctrl+s")
	if n, _, _ := b.counts(); n != 0 {
		t.Fatal("saved with problem entries still listed")
	}
	h.goTo(2, 4) // unknown entry
	h.press("x")
	f := h.view()
	mustNotHave(t, f, `unknown procedure "foo"`)
	mustHave(t, f, `procedure "resolve" cannot be skipped`, "[ ] dns")
	h.press("ctrl+s") // retain unrelated invalid entry
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
			b.snap.SkipListProblem = `skip: "none" cannot be combined with procedure names`
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
	h.press("up", "enter") // empty list enables DNS again
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
	b.info.Procedures = nil
	for i := range 37 {
		b.info.Procedures = append(b.info.Procedures, Procedure{Name: fmt.Sprintf("proc%02d", i), Does: "does a thing"})
	}
	h := newTH(t, b, atSize(60, 16))
	h.press("tab", "tab")
	for i := range 37 {
		f := h.view()
		if lineCount(f) > 16 {
			t.Fatalf("frame is %d lines", lineCount(f))
		}
		sel := fmt.Sprintf("> [x] proc%02d", i)
		mustHave(t, f, sel)
		h.press("down")
	}
	// Scroll back to the earlier row.
	for i := 36; i >= 0; i-- {
		mustHave(t, h.view(), fmt.Sprintf("proc%02d", i))
		h.press("up")
	}
}
