package setup

import (
	"errors"
	"strings"
	"testing"
)

func TestSettingsTab_ShowsFileValueOrDefaultAndTheRelativeExample(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Settings["concurrency"] = Value{Text: "16", Set: true, Default: "8"} // original YAML used hexadecimal syntax
	b.snap.Settings["wordlist"] = Value{Text: "words.txt", Set: true, Default: "built-in (1000 words)",
		Relative: "Relative: resolves against the directory nyx runs from, e.g. /work/words.txt"}
	h := newTH(t, b)
	h.press("tab")
	f := h.view()
	for _, k := range SettingKeys {
		if lineFor(f, k) == "" {
			t.Errorf("no row for %s:\n%s", k, f)
		}
	}
	mustHave(t, lineFor(f, "concurrency"), "16")
	mustNotHave(t, lineFor(f, "concurrency"), "0x10", "(default)")
	mustHave(t, lineFor(f, "rate.dns"), "50", "(default)")
	mustHave(t, lineFor(f, "wordlist"), "words.txt")
	mustHave(t, lineFor(f, "sensitive_paths"), "built-in (40 paths)", "(default)")
	mustHave(t, f,
		"Relative: resolves against the directory nyx runs from, e.g. /work/out",
		"Relative: resolves against the directory nyx runs from, e.g. /work/words.txt")
}

func TestSettingsTab_EditChecksTheValueAndStoresWhatCheckReturns(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.checkFn = func(key, value string) (string, error) {
		if key == "wordlist" {
			return "/work/" + value, nil
		}
		return value, nil
	}
	h := newTH(t, b)
	h.goTo(1, 5)
	h.press("enter")
	h.typ("  words.txt  ")
	h.press("enter")
	mustHave(t, lineFor(h.view(), "wordlist"), "/work/words.txt")
	h.press("ctrl+s")
	if got := b.save(t, 0).Set["wordlist"]; got != "/work/words.txt" {
		t.Fatalf("saved %q", got)
	}
	if len(b.checks) != 1 || b.check(t, 0) != "wordlist=words.txt" {
		t.Fatalf("Check was called with %q: the value is trimmed first", b.checks)
	}
}

func TestSettingsTab_ARejectedValueIsShownAndNotAccepted(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.checkFn = func(key, value string) (string, error) {
		return "", errors.New("concurrency must be a whole number from 1 to 1000, got " + value)
	}
	h := newTH(t, b)
	h.goTo(1, 1)
	h.press("enter")
	h.typ("abc")
	h.press("enter")
	f := h.view()
	mustHave(t, f, "concurrency must be a whole number from 1 to 1000, got abc")
	if h.m.changes() != 0 {
		t.Error("a rejected value counted as a change")
	}
	// Invalid edits remain open for correction; Escape preserves the previous value.
	h.press("esc")
	mustNotHave(t, lineFor(h.view(), "concurrency"), "abc")
	h.press("ctrl+s")
	if n, _, _ := b.counts(); n != 0 {
		t.Error("saved with nothing accepted")
	}
}

func TestSettingsTab_EmptyEntryClearsAndXClears(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Settings["concurrency"] = Value{Text: "16", Set: true, Default: "8"}
	b.snap.Settings["rate.dns"] = Value{Text: "20", Set: true, Default: "50"}
	h := newTH(t, b)
	h.goTo(1, 1)
	h.press("enter")
	h.press("ctrl+u")
	h.typ("   ")
	h.press("enter")
	mustHave(t, lineFor(h.view(), "concurrency"), "8", "(default)")
	h.goTo(1, 4)
	h.press("x")
	mustHave(t, lineFor(h.view(), "rate.dns"), "50", "(default)")
	h.press("ctrl+s")
	if len(b.save(t, 0).Clear) != 2 || len(b.save(t, 0).Set) != 0 {
		t.Fatalf("saved %+v", b.save(t, 0))
	}
	if len(b.checks) != 0 {
		t.Errorf("an empty entry was sent to Check: %v", b.checks)
	}
}

func TestSettingsTab_EditStartsFromTheFileValueAndKeepsExactRunes(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Settings["output_dir"] = Value{Text: "/data/out", Set: true, Default: "."}
	h := newTH(t, b)
	h.press("tab", "enter")
	h.press("backspace", "backspace", "backspace")
	h.paste("a\x1b[31mb c")
	h.press("enter")
	if got := b.check(t, 0); got != "output_dir=/data/a\x1b[31mb c" {
		t.Errorf("Check got %q: the value is stored as typed, not sanitised", got)
	}
}

func TestSettingsTab_AnInvalidValueBlocksSavingUntilFixedOrCleared(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"edit", "clear"} {
		t.Run(how, func(t *testing.T) {
			t.Parallel()
			b := newFake()
			b.snap.Settings["concurrency"] = Value{Text: "abc", Set: true, Default: "8", Problem: "concurrency: must be a whole number"}
			b.snap.Settings["rate.dns"] = Value{Text: "5", Set: true, Default: "50"}
			h := newTH(t, b)
			h.press("tab")
			f := h.view()
			mustHave(t, f, "Settings!", "concurrency: must be a whole number")
			h.goTo(1, 4)
			h.press("x") // create another unsaved field to exercise saving
			h.press("ctrl+s")
			if n, _, _ := b.counts(); n != 0 {
				t.Fatal("saved with an invalid row")
			}
			mustHave(t, h.view(), "concurrency")
			h.goTo(1, 1)
			if how == "edit" {
				h.press("enter", "ctrl+u")
				h.typ("12")
				h.press("enter")
			} else {
				h.press("x")
			}
			mustNotHave(t, h.view(), "must be a whole number")
			h.press("ctrl+s")
			if len(b.saves) != 1 {
				t.Fatalf("not saved once fixed:\n%s", h.view())
			}
			if how == "edit" && b.save(t, 0).Set["concurrency"] != "12" {
				t.Errorf("saved %+v", b.save(t, 0))
			}
		})
	}
}

func TestSettingsTab_AFixedRowIsRewrittenEvenWhenTheValueIsTheSame(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Settings["concurrency"] = Value{Text: "9", Set: true, Default: "8", Problem: "concurrency is set twice in the file, as Concurrency and concurrency"}
	h := newTH(t, b)
	h.press("tab", "down", "enter", "enter") // confirm without changing decoded value
	h.press("ctrl+s")
	if len(b.saves) != 1 || b.save(t, 0).Set["concurrency"] != "9" {
		t.Fatalf("saved %+v: both variants must collapse to one entry", b.saves)
	}
}

func TestChanges_ChangingAValueBackIsNoChange(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Settings["concurrency"] = Value{Text: "16", Set: true, Default: "8"}
	h := newTH(t, b)
	h.goTo(1, 1)
	h.press("enter", "ctrl+u")
	h.typ("32")
	h.press("enter")
	if h.m.changes() != 1 {
		t.Fatalf("changes = %d", h.m.changes())
	}
	h.press("enter", "ctrl+u")
	h.typ("16")
	h.press("enter")
	if h.m.changes() != 0 {
		t.Errorf("changed and changed back is %d changes", h.m.changes())
	}
	// No-op clears and equivalent re-entry do not mark the file changed.
	h.goTo(1, 2)
	h.press("x")
	if h.m.changes() != 0 {
		t.Errorf("clearing an unset setting is %d changes", h.m.changes())
	}
	h.goTo(1, 1)
	h.press("x")
	h.press("enter")
	h.typ("16")
	h.press("enter")
	if h.m.changes() != 0 {
		t.Errorf("cleared and re-entered is %d changes", h.m.changes())
	}
	h.press("q")
	if !h.m.quitting {
		t.Error("q with no change did not quit")
	}
	if n, _, _ := b.counts(); n != 0 {
		t.Error("saved with no change")
	}
}

func TestChanges_AKeyEnteredAndClearedAgainIsNoChange(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	h.press("enter")
	h.typ("abcdefghijklmnop")
	h.press("enter")
	if h.m.changes() != 1 {
		t.Fatalf("changes = %d", h.m.changes())
	}
	h.press("x")
	if h.m.changes() != 0 {
		t.Errorf("entered then cleared is %d changes", h.m.changes())
	}
	if !strings.Contains(h.view(), "no unsaved changes") {
		t.Errorf("header does not say so:\n%s", h.view())
	}
}
