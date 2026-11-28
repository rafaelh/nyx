package setup

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/config"
)

func TestKeysTab_ListsNineSourcesWithWhatTheyTurnOn(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	f := h.view()
	for _, src := range testInfo().Sources {
		if lineFor(f, src.Name) == "" {
			t.Errorf("no row for %s:\n%s", src.Name, f)
		}
		mustHave(t, f, src.Turns)
	}
	mustHave(t, f, "also works without a key")
	if got := strings.Count(f, "not set"); got != 9 {
		t.Errorf("want nine keys not set, got %d:\n%s", got, f)
	}
}

func TestKeysTab_MaskedKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, key, want string
		absent          string
	}{
		{"twelve runes show the last four", "abcdefghijkl", "••••ijkl", "abcdefgh"},
		{"eleven runes show only set", "abcdefghijk", "set", "abcdefghijk"},
		{"twelve wide runes", "日本語日本語日本語日本語", "••••語日本語", "日本語日本語日"},
		{"empty in the file is not set", "", "not set", ""},
		{"a long key", "Qk7rT2mPz9XvB4nL", "••••B4nL", "Qk7rT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := newFake()
			b.snap.Keys["shodan"] = KeyState{Value: config.Secret(tc.key)}
			h := newTH(t, b)
			line := lineFor(h.view(), "shodan")
			mustHave(t, line, tc.want)
			if tc.absent != "" {
				mustNotHave(t, line, tc.absent)
			}
			if tc.key == "abcdefghijk" {
				mustNotHave(t, line, "••••")
			}
		})
	}
}

func TestKeysTab_KeyHoldingEscShowsSanitisedLastFour(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Keys["shodan"] = KeyState{Value: config.Secret("abcdefghi\x1bjkl")}
	h := newTH(t, b)
	f := h.view()
	line := lineFor(f, "shodan")
	mustHave(t, line, "••••jkl")
	mustNotHave(t, f, "\x1b", "abcdefghi")
}

func TestKeysTab_TypedAndPastedKeysShowOneBulletPerRune(t *testing.T) {
	t.Parallel()
	for _, how := range []string{"typed", "pasted"} {
		t.Run(how, func(t *testing.T) {
			t.Parallel()
			h := newTH(t, newFake())
			h.press("enter")
			text := "日本語キー🙂x"
			if how == "typed" {
				h.typ(text)
			} else {
				h.paste(text)
			}
			line := lineFor(h.view(), "securitytrails")
			if got, want := strings.Count(line, "•"), len([]rune(text)); got != want {
				t.Errorf("want %d bullets, got %d in %q", want, got, line)
			}
			mustNotHave(t, line, "日本", "x")
		})
	}
}

func TestKeysTab_EnterReplaceAndClearAKey(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Keys["shodan"] = KeyState{Value: config.Secret("oldkey-oldkey-1234")}
	h := newTH(t, b)
	h.goTo(0, 1)
	// Trim replacement-key whitespace before storage.
	h.press("enter")
	h.typ("  newkey value 5678  ")
	h.press("enter")
	mustHave(t, lineFor(h.view(), "shodan"), "••••5678")
	h.press("ctrl+s")
	if len(b.saves) != 1 || b.save(t, 0).Set["keys.shodan"] != "newkey value 5678" || len(b.save(t, 0).Clear) != 0 {
		t.Fatalf("saved %+v", b.saves)
	}
	// Clear the selected credential.
	h.press("x")
	mustHave(t, lineFor(h.view(), "shodan"), "not set")
	h.press("ctrl+s")
	if len(b.saves) != 2 || len(b.save(t, 1).Set) != 0 || len(b.save(t, 1).Clear) != 1 || b.save(t, 1).Clear[0] != "keys.shodan" {
		t.Fatalf("saved %+v", b.saves)
	}
}

func TestKeysTab_WhitespaceOnlyEntryClearsAndDeleteClears(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Keys["shodan"] = KeyState{Value: config.Secret("oldkey-oldkey-1234")}
	b.snap.Keys["chaos"] = KeyState{Value: config.Secret("chaoskey-chaoskey")}
	h := newTH(t, b)
	h.goTo(0, 1)
	h.press("enter")
	h.typ("   ")
	h.press("enter")
	mustHave(t, lineFor(h.view(), "shodan"), "not set")
	h.goTo(0, 5)
	h.press("delete")
	mustHave(t, lineFor(h.view(), "chaos"), "not set")
	h.press("ctrl+s")
	got := b.save(t, 0).Clear
	if len(got) != 2 || len(b.save(t, 0).Set) != 0 {
		t.Fatalf("saved %+v", b.save(t, 0))
	}
}

func TestKeysTab_EscapeCancelsAnEntry(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	h.press("enter")
	h.typ("abcdefghijklmnop")
	h.press("esc")
	mustHave(t, lineFor(h.view(), "securitytrails"), "not set")
	if h.m.changes() != 0 {
		t.Errorf("an entry cancelled counts as %d changes", h.m.changes())
	}
}

func TestKeysTab_KeyHeldInRowWithCaseVariantsIsInvalidUntilEdited(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Keys["shodan"] = KeyState{Value: config.Secret("abcdefghijklmn"), Problem: "keys.shodan is set twice in the file, as Shodan and shodan"}
	h := newTH(t, b)
	f := h.view()
	mustHave(t, f, "set twice in the file", "Keys!")
	h.press("ctrl+s")
	if n, _, _ := b.counts(); n != 0 {
		t.Fatal("saved while a row was invalid")
	}
	h.goTo(0, 1)
	h.press("enter", "enter") // empty accepted text removes the key
	mustNotHave(t, h.view(), "set twice")
	h.press("ctrl+s")
	if len(b.saves) != 1 {
		t.Fatalf("not saved after the row was cleared: %v", h.view())
	}
}

func TestKeysTab_EveryKeyIsPassedToOnSecret(t *testing.T) {
	t.Parallel()
	b := newFake()
	b.snap.Keys["shodan"] = KeyState{Value: config.Secret("from-the-file-1234")}
	h := newTH(t, b)
	h.goTo(0, 2)
	h.press("enter")
	h.typ("typed-key-abcdef")
	h.press("enter")
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, want := range []string{"from-the-file-1234", "typed-key-abcdef"} {
		found := false
		for _, s := range h.secrets {
			found = found || s == want
		}
		if !found {
			t.Errorf("OnSecret was not given %q (got %q)", want, h.secrets)
		}
	}
}

func TestKeysTab_NoKeyBeyondItsLastFourAnywhere(t *testing.T) {
	t.Parallel()
	const fileKey = "Fq9ZpL3xRw7TyN2vKd8H"
	const typedKey = "Xc4MbV6nJh1GsE5aWu0Y"
	const pastedKey = "Pm2QzD8kUo3RtB7iLf9C"
	b := newFake()
	b.snap.Keys["shodan"] = KeyState{Value: config.Secret(fileKey)}
	b.saveFn = func(Snapshot, Edits) (Snapshot, error) {
		return Snapshot{}, errTest("write failed for " + typedKey)
	}
	b.testFn = func(_ context.Context, _ string, key config.Secret) TestResult {
		return TestResult{Status: TestUnknown, Reason: "echoed " + key.Reveal()}
	}
	h := newTH(t, b)
	h.goTo(0, 0)
	h.press("enter")
	h.typ(typedKey)
	h.press("enter")
	h.goTo(0, 2)
	h.press("enter")
	h.paste(pastedKey)
	h.press("enter")
	h.run(h.press("t"))
	h.goTo(0, 1)
	h.run(h.press("t"))
	h.press("ctrl+s")
	all := strings.Join(h.frames, "\n")
	noKeyIn(t, "a frame", all, fileKey, typedKey, pastedKey)
	mustHave(t, all, "••••"+typedKey[len(typedKey)-4:])
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d"} {
		noKeyIn(t, "fmt "+verb, sprintf(verb, h.m), fileKey, typedKey, pastedKey)
		noKeyIn(t, "fmt "+verb+" of a value", sprintf(verb, *h.m), fileKey, typedKey, pastedKey)
	}
}

func TestKeysTab_PastedTextThatIsNotValidUTF8IsRefused(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	h.press("enter")
	h.paste("abc\xffdef")
	mustNotHave(t, lineFor(h.view(), "securitytrails"), "•")
	mustHave(t, h.view(), "not valid UTF-8")
	h.paste("abcdef")
	mustHave(t, lineFor(h.view(), "securitytrails"), "••••••")
}

func TestKeysTab_AShortAbandonedEntryIsNotMaskedAsAKey(t *testing.T) {
	t.Parallel()
	h := newTH(t, newFake())
	h.press("enter")
	h.typ("e")
	h.press("esc")
	if slices.Contains(h.secrets, "e") {
		t.Errorf("an abandoned one-rune entry was registered as a key: %q", h.secrets)
	}
	if got := h.m.text("Saved the file"); got != "Saved the file" {
		t.Errorf("text = %q: a short abandoned entry masks its letters everywhere", got)
	}
}
