package setup

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/term/layout"
)

func TestView_TooSmallShowsOnlyTheSizeMessage(t *testing.T) {
	t.Parallel()
	const msg = "Make the terminal at least 60×16"
	for _, tc := range []struct {
		w, h   int
		onlyIt bool
	}{
		{59, 16, true}, {60, 15, true}, {20, 5, true}, {60, 16, false}, {61, 17, false}, {120, 40, false},
	} {
		t.Run(fmt.Sprintf("%dx%d", tc.w, tc.h), func(t *testing.T) {
			t.Parallel()
			h := newTH(t, newFake(), atSize(tc.w, tc.h))
			f := h.view()
			if tc.onlyIt {
				if got := strings.Join(strings.Fields(f), " "); !strings.HasPrefix(msg, got) && got != msg {
					t.Errorf("view is %q, want only the message", f)
				}
				if tc.w >= 40 {
					mustHave(t, f, msg)
				}
				mustNotHave(t, f, "securitytrails", "Settings")
				return
			}
			mustHave(t, f, "securitytrails", "Keys", "Settings", "Skip", "q/esc Quit")
			mustNotHave(t, f, "terminal at least")
			if maxWidth(f) > tc.w || lineCount(f) > tc.h {
				t.Errorf("frame is %dx%d at %dx%d:\n%s", maxWidth(f), lineCount(f), tc.w, tc.h, f)
			}
		})
	}
}

func TestView_TheMessageComesBackToTheUIWhenTheWindowGrows(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake(), atSize(40, 10))
	mustNotHave(t, h.view(), "securitytrails")
	h.send(windowSize(80, 24))
	mustHave(t, h.view(), "securitytrails")
	h.send(windowSize(59, 24))
	mustNotHave(t, h.view(), "securitytrails")
}

func TestView_HeaderShowsThePathAndTheChangeCount(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	first, _, _ := strings.Cut(h.view(), "\n")
	mustHave(t, first, testPath, "no unsaved changes")
	dirty(h)
	mustHave(t, strings.Split(h.view(), "\n")[0], "1 unsaved change")
	h.goTo(0, 0)
	h.press("enter")
	h.typ("abcdefghijklmnop")
	h.press("enter")
	mustHave(t, strings.Split(h.view(), "\n")[0], "2 unsaved changes")
}

func TestView_ALongPathIsCutAtItsStart(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.info.Path = "/very/long/directory/name/that/goes/on/and/on/and/on/forever/and/ever/config.yaml"
	h := newTH(t, b, atSize(60, 16))
	first, _, _ := strings.Cut(h.view(), "\n")
	if maxWidth(first) > 60 {
		t.Errorf("header is %d wide", maxWidth(first))
	}
	mustHave(t, first, "…", "config.yaml", "no unsaved changes")
}

func TestView_TabTitlesCarryTheChangedAndInvalidMarks(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Settings["concurrency"] = Value{Text: "x", Set: true, Default: "8", Problem: "concurrency: bad"}
	b.snap.SkipProblems = []SkipProblem{{Entry: "foo", Message: "unknown"}}
	h := newTH(t, b)
	f := h.view()
	mustHave(t, f, "Settings!", "Skip!")
	mustNotHave(t, f, "Keys*", "Keys!", "Settings*")
	h.press("enter")
	h.typ("abcdefghijklmnop")
	h.press("enter")
	mustHave(t, h.view(), "Keys*")
	h.press("tab", "down", "enter", "ctrl+u")
	h.typ("12")
	h.press("enter")
	mustHave(t, h.view(), "Settings*")
	mustNotHave(t, h.view(), "Settings!", "Settings*!")
}

func TestView_TheSelectedRowIsMarkedAndTabSwitchingWraps(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	mustHave(t, lineFor(h.view(), "securitytrails"), ">")
	h.press("down", "j")
	if !strings.HasPrefix(lineFor(h.view(), "virustotal"), ">") {
		t.Errorf("selection did not move:\n%s", h.view())
	}
	h.press("k", "up", "up", "up")
	if !strings.HasPrefix(lineFor(h.view(), "securitytrails"), ">") {
		t.Errorf("selection left the list:\n%s", h.view())
	}
	h.press("shift+tab")
	mustHave(t, h.view(), "[Threat data]")
	h.press("shift+tab")
	mustHave(t, h.view(), "[x] dns")
	h.press("tab", "tab")
	mustHave(t, h.view(), "securitytrails")
}

func TestView_EveryFrameFitsInTheMinimumSize(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	b.snap.Settings["output_dir"] = Value{Text: "/a/very/long/path/to/an/output/directory/that/is/long", Set: true, Default: ".", Relative: "Relative: resolves against the directory nyx runs from, e.g. /a/very/long/path/to/an/output/directory"}
	b.snap.Settings["wordlist"] = Value{Text: "x", Set: true, Default: "d", Problem: "wordlist: cannot read /some/long/path/to/a/word/list/file.txt: no such file or directory"}
	h := newTH(t, b, atSize(60, 16))
	h.press("enter")
	h.typ(strings.Repeat("long ", 30))
	h.press("tab", "enter")
	h.typ(strings.Repeat("longer ", 30))
	h.press("esc", "esc")
	for _, f := range h.frames {
		if maxWidth(f) > 60 || lineCount(f) > 16 {
			t.Fatalf("frame is %dx%d:\n%s", maxWidth(f), lineCount(f), f)
		}
	}
}

func TestView_AnEscapeInASettingIsDrawnSanitisedButKeptInTheValue(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Settings["output_dir"] = Value{Text: "/data/\x1b[31mred", Set: true, Default: "."}
	h := newTH(t, b)
	h.press("tab")
	f := h.view()
	mustNotHave(t, f, "\x1b")
	mustHave(t, lineFor(f, "output_dir"), "/data/red")
	h.press("enter")
	mustNotHave(t, h.view(), "\x1b")
	h.press("enter")
	if got := b.check(t, 0); got != "output_dir=/data/\x1b[31mred" {
		t.Errorf("Check got %q", got)
	}
}

func TestView_WindowSizeMessageResizesTheFrame(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake(), atSize(60, 16))
	h.send(windowSize(100, 30))
	if lineCount(h.view()) > 30 || lineCount(h.view()) <= 16 {
		t.Errorf("frame is %d lines at height 30", lineCount(h.view()))
	}
}

func TestView_TheCursorIsPlacedInTheField(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	if _, cur := h.m.viewCursor(); cur != nil {
		t.Error("a cursor is shown while nothing is edited")
	}
	h.press("enter")
	h.typ("abc")
	frame, cur := h.m.viewCursor()
	if cur == nil {
		t.Fatal("no cursor while editing")
	}
	line := strings.Split(frame, "\n")[cur.Y]
	last := strings.LastIndex(line, "•")
	if last < 0 || cur.X != layout.Measure(line[:last+len("•")]) {
		t.Errorf("cursor at %d,%d is not just after the bullets in %q", cur.X, cur.Y, line)
	}
	h.press("left")
	_, cur2 := h.m.viewCursor()
	if cur2.X != cur.X-1 || cur2.Y != cur.Y {
		t.Errorf("cursor moved from %v to %v, want one cell left", cur, cur2)
	}
}
