package setup

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// dirty makes one unsaved change: the concurrency setting.
func dirty(h *th) {
	h.t.Helper()
	h.goTo(1, 1)
	h.press("enter", "ctrl+u")
	h.typ("32")
	h.press("enter")
}

func TestQuit_WithChangesAsksAndEachAnswerDoesTheRightThing(t *testing.T) {
	t.Parallel()
	for _, quitKey := range []string{"q", "esc", "ctrl+c"} {
		t.Run("opens on "+quitKey, func(t *testing.T) {
			t.Parallel()
			b := newFake()
			h := newTH(t, b)
			dirty(h)
			h.press(quitKey)
			if h.m.quitting {
				t.Fatal("quit with unsaved changes")
			}
			mustHave(t, h.view(), "Unsaved changes", "s Save", "d Discard", "esc Back")
		})
	}
	t.Run("save", func(t *testing.T) {
		t.Parallel()
		b := newFake()
		h := newTH(t, b)
		dirty(h)
		h.press("q", "s")
		if len(b.saves) != 1 || b.save(t, 0).Set["concurrency"] != "32" || !h.m.quitting {
			t.Fatalf("saves %+v quitting %v", b.saves, h.m.quitting)
		}
	})
	t.Run("discard", func(t *testing.T) {
		t.Parallel()
		b := newFake()
		h := newTH(t, b)
		dirty(h)
		h.press("q", "d")
		if n, o, _ := b.counts(); n != 0 || o != 0 || !h.m.quitting {
			t.Fatalf("saves %d quitting %v", n, h.m.quitting)
		}
	})
	t.Run("back", func(t *testing.T) {
		t.Parallel()
		b := newFake()
		h := newTH(t, b)
		dirty(h)
		h.press("q", "esc")
		if h.m.quitting {
			t.Fatal("quit on back")
		}
		mustNotHave(t, h.view(), "Unsaved changes")
		mustHave(t, lineFor(h.view(), "concurrency"), "32")
		if h.m.changes() != 1 {
			t.Errorf("changes = %d: the edit is kept", h.m.changes())
		}
	})
}

func TestQuit_CtrlCIsAQuitInTheUI(t *testing.T) {
	t.Parallel()
	b := newFake()
	h := newTH(t, b)
	cmd := h.press("ctrl+c")
	if !h.m.quitting || cmd == nil {
		t.Fatal("ctrl+c with no changes did not quit")
	}
	if n, _, _ := b.counts(); n != 0 {
		t.Error("wrote on a quit with no change")
	}
}

func TestQuit_WithNoChangesWritesNothing(t *testing.T) {
	t.Parallel()
	for _, k := range []string{"q", "esc", "ctrl+c"} {
		b := newFake()
		h := newTH(t, b)
		h.press(k)
		if !h.m.quitting {
			t.Errorf("%s did not quit", k)
		}
		if n, o, _ := b.counts(); n != 0 || o != 0 {
			t.Errorf("%s wrote: saves %d overwrites %d", k, n, o)
		}
	}
}

func TestQuit_SavingFromTheDialogWithAnInvalidRowStaysAndSaysWhy(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Settings["rate.dns"] = Value{Text: "x", Set: true, Default: "50", Problem: "rate.dns: must be a number"}
	h := newTH(t, b)
	h.goTo(1, 1)
	h.press("enter", "ctrl+u")
	h.typ("32")
	h.press("enter", "q", "s")
	if h.m.quitting {
		t.Fatal("quit while a row was invalid")
	}
	mustHave(t, h.view(), "rate.dns: must be a number")
	if n, _, _ := b.counts(); n != 0 {
		t.Fatal("saved with an invalid row")
	}
}

func TestSave_FailureKeepsEditsAndShowsTheReasonAndPath(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.saveFn = func(Snapshot, Edits) (Snapshot, error) {
		return Snapshot{}, errors.New("open /home/tester/.config/nyx/.tmp: permission denied")
	}
	h := newTH(t, b)
	dirty(h)
	h.press("ctrl+s")
	f := h.view()
	mustHave(t, f, "permission denied", testPath, "Could not save")
	if h.m.changes() != 1 {
		t.Errorf("changes = %d after a failed save", h.m.changes())
	}
	mustHave(t, lineFor(f, "concurrency"), "32")
	if h.m.quitting {
		t.Error("quit after a failed save")
	}
	// The same from the quit dialog: setup stays open.
	h.press("q", "s")
	if h.m.quitting {
		t.Fatal("quit after a failed save from the dialog")
	}
	mustHave(t, h.view(), "permission denied")
}

func TestSave_AfterSuccessTheSavedStateIsTheBaseline(t *testing.T) {
	t.Parallel()
	b := newFake()
	h := newTH(t, b)
	dirty(h)
	h.press("ctrl+s")
	if h.m.changes() != 0 {
		t.Fatalf("changes = %d after a save", h.m.changes())
	}
	h.press("q")
	if !h.m.quitting {
		t.Error("q after a save did not quit")
	}
	if len(b.saves) != 1 {
		t.Errorf("saves = %d", len(b.saves))
	}
	// A second change is saved against the new snapshot.
	b2 := newFake()
	h2 := newTH(t, b2)
	dirty(h2)
	h2.press("ctrl+s")
	h2.press("x")
	h2.press("ctrl+s")
	if got := b2.saveSnap(t, 1).Token; got != 2 {
		t.Errorf("second save used token %v, want the one the first save returned", got)
	}
}

func TestSave_WithNothingChangedDoesNotCallSave(t *testing.T) {
	t.Parallel()
	b := newFake()
	h := newTH(t, b)
	h.press("ctrl+s")
	if n, _, _ := b.counts(); n != 0 {
		t.Error("Save called with no change")
	}
}

func conflictBackend() *fakeBackend {
	b := newFake()
	b.saveFn = func(Snapshot, Edits) (Snapshot, error) { return Snapshot{}, fmt.Errorf("check: %w", ErrConflict) }
	return b
}

func TestConflict_OpensTheDialogAndReloadDiscardsTheEdits(t *testing.T) {
	t.Parallel()
	b := conflictBackend()
	h := newTH(t, b)
	dirty(h)
	h.press("ctrl+s")
	f := h.view()
	mustHave(t, f, "changed on disk", "r Reload", "o Overwrite", "esc Back")
	if _, o, _ := b.counts(); o != 0 {
		t.Fatal("overwrote before being asked")
	}
	b.mu.Lock()
	b.snap.Settings["concurrency"] = Value{Text: "99", Set: true, Default: "8"}
	b.snap.Token = 7
	b.mu.Unlock()
	h.press("r")
	if _, _, opens := b.counts(); opens != 2 {
		t.Errorf("opens = %d, want the one at the start and the reload", opens)
	}
	if h.m.changes() != 0 {
		t.Errorf("changes = %d after a reload", h.m.changes())
	}
	mustHave(t, lineFor(h.view(), "concurrency"), "99")
	mustNotHave(t, h.view(), "changed on disk")
}

func TestConflict_OverwriteWritesTheEditsAndBackReturnsToTheEdits(t *testing.T) {
	t.Parallel()
	b := conflictBackend()
	h := newTH(t, b)
	dirty(h)
	h.press("ctrl+s", "esc")
	mustNotHave(t, h.view(), "changed on disk")
	if h.m.changes() != 1 {
		t.Fatalf("changes = %d after back", h.m.changes())
	}
	if _, o, _ := b.counts(); o != 0 {
		t.Fatal("overwrote on back")
	}
	h.press("ctrl+s", "o")
	if len(b.overs) != 1 || b.over(t, 0).Set["concurrency"] != "32" {
		t.Fatalf("overwrites %+v", b.overs)
	}
	if h.m.changes() != 0 {
		t.Errorf("changes = %d after an overwrite", h.m.changes())
	}
}

func TestConflict_NeverWritesWithoutTheDialog(t *testing.T) {
	t.Parallel()
	b := conflictBackend()
	h := newTH(t, b)
	dirty(h)
	// Every way of saving ends in the dialog, and Overwrite waits for o.
	h.press("ctrl+s")
	for _, k := range []string{"s", "enter", "x", "q", "ctrl+s", "ctrl+c", "d"} {
		h.press(k)
		if _, o, _ := b.counts(); o != 0 {
			t.Fatalf("Overwrite called after %q", k)
		}
	}
	h2 := newTH(t, b)
	dirty(h2)
	h2.press("q", "s") // the quit dialog's save meets the conflict
	mustHave(t, h2.view(), "changed on disk")
	if h2.m.quitting {
		t.Fatal("quit with the save in conflict")
	}
	if _, o, _ := b.counts(); o != 0 {
		t.Fatal("Overwrite called from the quit dialog")
	}
	h2.press("o")
	if _, o, _ := b.counts(); o != 1 {
		t.Fatalf("overwrites = %d, want 1", o)
	}
	if !h2.m.quitting {
		t.Error("the quit that asked for the save does not finish after the overwrite")
	}
}

func TestConflict_ReloadFindingProblemsKeepsEditsAndStillOffersOverwrite(t *testing.T) {
	t.Parallel()
	b := conflictBackend()
	h := newTH(t, b)
	dirty(h)
	h.press("ctrl+s")
	b.mu.Lock()
	b.openErr = &FileError{Path: testPath, Problems: []string{"line 3: could not parse the file", "unknown key: colour"}}
	b.mu.Unlock()
	h.press("r")
	f := h.view()
	mustHave(t, f, "line 3: could not parse the file", "unknown key: colour", testPath, "o Overwrite", "esc Back")
	if h.m.changes() != 1 {
		t.Fatalf("changes = %d: the edits are kept", h.m.changes())
	}
	h.press("o")
	if len(b.overs) != 1 || b.over(t, 0).Set["concurrency"] != "32" {
		t.Fatalf("overwrites %+v", b.overs)
	}
}

func TestConflict_OverwriteFailureStaysOpenAndShowsTheReason(t *testing.T) {
	t.Parallel()
	b := conflictBackend()
	b.overFn = func(Edits) (Snapshot, error) { return Snapshot{}, errors.New("disk full") }
	h := newTH(t, b)
	dirty(h)
	h.press("ctrl+s", "o")
	mustHave(t, h.view(), "disk full", testPath)
	if h.m.changes() != 1 {
		t.Errorf("changes = %d", h.m.changes())
	}
}

func TestFooter_ListsTheKeysOnEachTabAndInEachDialog(t *testing.T) {
	t.Parallel()
	type step struct {
		name string
		prep func(h *th)
		want []string
	}
	for _, size := range [][2]int{{60, 16}, {100, 30}} {
		for _, s := range []step{
			{"keys", func(*th) {}, []string{"↑/↓ Move", "←/→ Switch tab", "enter Edit", "t Test", "x Clear", "ctrl+s Save", "q/esc Quit"}},
			{"settings", func(h *th) { h.press("tab") }, []string{"↑/↓ Move", "←/→ Switch tab", "enter Edit", "x Clear", "ctrl+s Save", "q/esc Quit"}},
			{"skip", func(h *th) { h.press("tab", "tab") }, []string{"↑/↓ Move", "←/→ Switch tab", "enter Toggle", "x Remove entry", "ctrl+s Save", "q/esc Quit"}},
			{"field", func(h *th) { h.press("enter") }, []string{"enter Accept", "esc Cancel", "←/→ Move", "ctrl+u Clear"}},
			{"quit dialog", func(h *th) { dirty(h); h.press("q") }, []string{"s Save", "d Discard", "esc Back"}},
		} {
			t.Run(fmt.Sprintf("%s %dx%d", s.name, size[0], size[1]), func(t *testing.T) {
				t.Parallel()
				h := newTH(t, newFake(), atSize(size[0], size[1]))
				s.prep(h)
				f := h.view()
				mustHave(t, f, s.want...)
				if maxWidth(f) > size[0] || lineCount(f) > size[1] {
					t.Errorf("frame is %dx%d:\n%s", maxWidth(f), lineCount(f), f)
				}
			})
		}
		t.Run(fmt.Sprintf("conflict dialog %dx%d", size[0], size[1]), func(t *testing.T) {
			t.Parallel()
			h := newTH(t, conflictBackend(), atSize(size[0], size[1]))
			dirty(h)
			h.press("ctrl+s")
			f := h.view()
			mustHave(t, f, "r Reload", "o Overwrite", "esc Back")
			if maxWidth(f) > size[0] || lineCount(f) > size[1] {
				t.Errorf("frame is %dx%d:\n%s", maxWidth(f), lineCount(f), f)
			}
		})
	}
}

func TestDialogs_AProblemListTooLongForTheScreenIsCut(t *testing.T) {
	t.Parallel()
	b := conflictBackend()
	h := newTH(t, b, atSize(60, 16))
	dirty(h)
	h.press("ctrl+s")
	var problems []string
	for i := range 40 {
		problems = append(problems, fmt.Sprintf("problem number %02d with some words to make the line long enough to wrap around", i))
	}
	b.mu.Lock()
	b.openErr = &FileError{Path: testPath, Problems: problems}
	b.mu.Unlock()
	h.press("r")
	f := h.view()
	if lineCount(f) > 16 || maxWidth(f) > 60 {
		t.Errorf("frame is %dx%d", maxWidth(f), lineCount(f))
	}
	mustHave(t, f, "o Overwrite", "problem number 00", "more")
	if !strings.Contains(f, "esc Back") {
		t.Error("the footer was pushed off")
	}
}
