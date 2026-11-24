package cli

import (
	"strings"
	"testing"
)

// Finalise incomplete lines before the closing margin; repeated close and empty writes add
// nothing.
func TestMargin_Close(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	m := &margin{}
	w := m.wrap(&b, true)
	if _, err := w.Write(nil); err != nil || b.Len() != 0 {
		t.Fatalf("an empty write: %v, %q", err, b.String())
	}
	m.close()
	if b.Len() != 0 {
		t.Fatalf("closed with nothing written: %q", b.String())
	}
	if _, err := w.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	m.close()
	m.close()
	if b.String() != "\npartial\n\n" {
		t.Errorf("got %q", b.String())
	}
}
