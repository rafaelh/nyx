package setup

import (
	"strings"
	"testing"

	"github.com/rafaelh/nyx/internal/term/layout"
)

func TestField_EditsAtTheCursor(t *testing.T) {
	t.Parallel()
	f := newField(false, "abc")
	f.insert("d")
	if f.text() != "abcd" {
		t.Fatalf("text = %q", f.text())
	}
	f.press("left")
	f.press("left")
	f.insert("X")
	if f.text() != "abXcd" {
		t.Fatalf("text = %q", f.text())
	}
	f.press("backspace")
	f.press("delete")
	if f.text() != "abd" {
		t.Fatalf("text = %q", f.text())
	}
	f.press("home")
	f.press("delete")
	if f.text() != "bd" {
		t.Fatalf("text = %q", f.text())
	}
	f.press("backspace") // left boundary: no movement
	f.press("end")
	f.insert("é日")
	if f.text() != "bdé日" {
		t.Fatalf("text = %q", f.text())
	}
	f.press("right") // right boundary: no movement
	f.press("backspace")
	if f.text() != "bdé" {
		t.Fatalf("text = %q", f.text())
	}
	f.press("ctrl+a")
	f.insert(">")
	f.press("ctrl+e")
	f.insert("<")
	if f.text() != ">bdé<" {
		t.Fatalf("text = %q", f.text())
	}
	f.press("ctrl+u")
	if f.text() != "" || f.cur != 0 {
		t.Fatalf("text = %q cursor %d after clear", f.text(), f.cur)
	}
	if f.press("enter") || f.press("q") {
		t.Error("the field consumed a key it does not handle")
	}
}

func TestField_StoresRunesExactlyAsTyped(t *testing.T) {
	t.Parallel()
	const raw = "a\x1b[31mb\tc\u202ed é 日本"
	f := newField(false, "")
	f.insert(raw)
	if f.text() != raw {
		t.Errorf("text = %q, want %q", f.text(), raw)
	}
	s, _ := f.view(80)
	if strings.ContainsAny(s, "\x1b\t\u202e") {
		t.Errorf("drawn text holds control characters: %q", s)
	}
}

func TestField_ASecretFieldDrawsOneBulletPerRune(t *testing.T) {
	t.Parallel()
	f := newField(true, "")
	f.insert("日本語🙂abc")
	s, x := f.view(80)
	if s != strings.Repeat("•", 7) || x != 7 {
		t.Errorf("view = %q cursor %d", s, x)
	}
	f.press("left")
	if _, x := f.view(80); x != 6 {
		t.Errorf("cursor = %d after left", x)
	}
}

func TestField_AWideRuneCountsItsCellsForTheCursor(t *testing.T) {
	t.Parallel()
	f := newField(false, "日本a")
	if _, x := f.view(80); x != 5 {
		t.Errorf("cursor = %d, want 5", x)
	}
	f.press("left")
	f.press("left")
	if _, x := f.view(80); x != 2 {
		t.Errorf("cursor = %d, want 2", x)
	}
}

func TestField_ALongTextScrollsToKeepTheCursorVisible(t *testing.T) {
	t.Parallel()
	for _, secret := range []bool{false, true} {
		f := newField(secret, strings.Repeat("0123456789", 5))
		for _, pos := range []string{"end", "home", "end"} {
			f.press(pos)
			s, x := f.view(20)
			if layout.Measure(s) > 20 {
				t.Errorf("secret=%v: drawn %d cells wide at %s", secret, layout.Measure(s), pos)
			}
			if x < 0 || x > 20 {
				t.Errorf("secret=%v: cursor %d outside 20 at %s", secret, x, pos)
			}
		}
		f.press("home")
		for range 25 {
			f.press("right")
		}
		if s, x := f.view(20); x < 0 || x > 20 || layout.Measure(s) > 20 {
			t.Errorf("secret=%v: cursor %d, %d wide in the middle", secret, x, layout.Measure(s))
		}
	}
}

func TestField_AFieldFormatsWithoutItsText(t *testing.T) {
	t.Parallel()
	f := newField(true, "Hq7RzT4mWk2PbN9x")
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		noKeyIn(t, "fmt "+verb, sprintf(verb, f), "Hq7RzT4mWk2PbN9x")
		noKeyIn(t, "fmt "+verb, sprintf(verb, *f), "Hq7RzT4mWk2PbN9x")
	}
}
