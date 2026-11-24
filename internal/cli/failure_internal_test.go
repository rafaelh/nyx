package cli

import (
	"bytes"
	"testing"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/palette"
)

// Human partial errors list failed targets after retry guidance; JSON keeps the fixed error
// shape.
func TestFailureWriter_TargetLines(t *testing.T) {
	t.Parallel()
	e := &clierr.Error{Code: clierr.Partial, Message: "2 of 3 lookups failed", Hint: "run the same command again for the failed ones",
		Transient: true, Input: map[string][]string{"id": {"CVE-1", "CVE-2"}},
		Targets: []clierr.Target{{Input: "CVE-1", Message: "not in the NVD", Code: clierr.NotFound}, {Input: "CVE-2", Message: "timed out", Code: clierr.Timeout}}}
	var human bytes.Buffer
	newFailureWriter(&human, false, palette.None, nil).write(e)
	want := "error: 2 of 3 lookups failed (PARTIAL)\n" +
		"hint: run the same command again for the failed ones\n" +
		"retry: may succeed after a wait\n" +
		"error: CVE-1: not in the NVD (NOT_FOUND)\n" +
		"error: CVE-2: timed out (TIMEOUT)\n"
	if human.String() != want {
		t.Errorf("human:\n got %q\nwant %q", human.String(), want)
	}
	var js bytes.Buffer
	newFailureWriter(&js, true, palette.None, nil).write(e)
	if want := `{"error":"2 of 3 lookups failed","code":"PARTIAL","hint":"run the same command again for the failed ones","input":{"id":["CVE-1","CVE-2"]},"transient":true}` + "\n"; js.String() != want {
		t.Errorf("JSON:\n got %s\nwant %s", js.String(), want)
	}
}

// Error writing is idempotent and uses the latest redactor when output actually occurs.
func TestFailureWriter_OnceAndRedacted(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	w := newFailureWriter(&b, false, palette.None, config.NewRedactor("early"))
	w.setRedactor(config.NewRedactor("early", "late"))
	w.write(&clierr.Error{Code: clierr.InvalidInput, Message: "early late", Hint: "late"})
	w.write(&clierr.Error{Code: clierr.Unexpected, Message: "second"})
	if want := "error: **** **** (INVALID_INPUT)\nhint: ****\n"; b.String() != want {
		t.Errorf("got %q, want %q", b.String(), want)
	}
}
