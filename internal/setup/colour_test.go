package setup

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/palette"
)

func inColour(o *Options) { o.Depth = palette.TrueColor }

// paint is s in a setup role at 24-bit depth, as the frame should hold it.
func paint(role, s string) string { return palette.TrueColor.Text(palette.Setup, role, s) }

// rowOf is the frame line holding sub.
func rowOf(t *testing.T, frame, sub string) string {
	t.Helper()
	for l := range strings.SplitSeq(frame, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	t.Fatalf("no line holds %q:\n%s", sub, frame)
	return ""
}

func TestColour_TheSelectedRowIsBrightAndTheOthersDim(t *testing.T) {
	t.Parallel()
	b := newFake()
	withKey(b, "shodan", "abcdefghijklmnop")
	h := newTH(t, b, inColour)
	f := h.view()
	sel := rowOf(t, f, "securitytrails")
	mustHave(t, sel, paint(rolePointer, ">"), paint(roleName, "securitytrails"), paint(roleFaint, "not set"))
	other := rowOf(t, f, "shodan")
	mustHave(t, other, paint(roleNameDim, "shodan"), paint(roleValueDim, "••••mnop"))
	h.press("down")
	mustHave(t, rowOf(t, h.view(), "shodan"), paint(rolePointer, ">"), paint(roleName, "shodan"), paint(roleValue, "••••mnop"))
	mustHave(t, h.view(), paint(roleHelp, "subdomains and DNS history"))
}

func TestColour_ATestResultIsGreenWhenAcceptedAndRedWhenRejected(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		res        TestResult
		role, text string
	}{
		{TestResult{Status: TestAccepted}, roleGood, "accepted"},
		{TestResult{Status: TestRejected}, roleBad, "rejected"},
		{TestResult{Status: TestUnknown, Reason: "rate limited"}, roleCaution, "could not check: rate limited"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()
			b := newFake()
			withKey(b, "shodan", "abcdefghijklmnop")
			b.testFn = func(context.Context, string, config.Secret) TestResult { return tc.res }
			h := newTH(t, b, inColour)
			h.goTo(0, 1)
			h.run(h.press("t"))
			mustHave(t, rowOf(t, h.view(), "shodan"), paint(tc.role, tc.text))
		})
	}
}

func TestColour_TheFooterKeysAreAmberAndTheirDescriptionsMuted(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake(), inColour)
	f := h.view()
	for _, k := range []string{"↑", "↓", "←", "→", "q", "esc", "enter", "t", "x", "ctrl", "s"} {
		mustHave(t, f, paint(roleKey, k))
	}
	for _, d := range []string{"Move", "Switch tab", "Quit", "Edit", "Test", "Clear", "Save", "/", "+"} {
		mustHave(t, f, paint(roleHelp, d))
	}
}

func TestColour_ASkippedStageIsFaintAndARunningOneIsNot(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Skip = []string{"ports"}
	h := newTH(t, b, inColour)
	h.press("tab", "tab", "down", "down")
	f := h.view()
	mustHave(t, rowOf(t, f, "ports"), paint(roleFaint, "[ ] ports"), paint(roleFaint, "checks open TCP ports"))
	mustHave(t, rowOf(t, f, "dns"), paint(roleNameDim, "[x] dns"), paint(roleHelp, "resolves hostnames"))
	mustHave(t, rowOf(t, f, "web"), paint(roleName, "[x] web"))
	h.press("up")
	mustHave(t, rowOf(t, h.view(), "ports"), paint(roleHelp, "[ ] ports"))
}

// No frame, coloured and cut to the smallest window, splits an escape sequence or passes the width.
func TestColour_EveryColouredFrameFitsAndKeepsItsEscapesWhole(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.info.Stages[0].Does = strings.Repeat("a long description ", 10)
	b.snap.Settings["wordlist"] = Value{Text: "x", Set: true, Default: "d", Problem: "wordlist: cannot read " + strings.Repeat("/long", 30)}
	h := newTH(t, b, inColour, atSize(60, 16))
	h.press("down", "tab", "down", "tab", "up", "left", "left", "enter")
	h.typ(strings.Repeat("k", 80))
	h.press("esc")
	whole := regexp.MustCompile(`^\x1b\[[0-9;]*m`)
	for _, f := range h.frames {
		if maxWidth(f) > 60 || lineCount(f) > 16 {
			t.Fatalf("frame is %dx%d:\n%s", maxWidth(f), lineCount(f), f)
		}
		for i := strings.Index(f, "\x1b"); i >= 0; i = strings.Index(f, "\x1b") {
			if whole.FindString(f[i:]) == "" {
				t.Fatalf("a cut escape at %q", f[i:min(len(f), i+12)])
			}
			f = f[i+1:]
		}
	}
}

func TestView_TheArrowKeysSwitchTabsAndARuleSitsUnderThem(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	lines := strings.Split(h.view(), "\n")
	if lines[2] != strings.Repeat("─", 80) {
		t.Errorf("line 3 is %q, want the rule", lines[2])
	}
	h.press("right")
	mustHave(t, h.view(), "[Settings]")
	h.press("right", "right")
	mustHave(t, h.view(), "[Keys]")
	h.press("left")
	mustHave(t, h.view(), "[Skip]")
	h.press("tab")
	mustHave(t, h.view(), "[Keys]")
	mustNotHave(t, h.view(), "tab Switch")
}
