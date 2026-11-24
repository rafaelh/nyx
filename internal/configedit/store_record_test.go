package configedit_test

import (
	"testing"
	"time"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/setup"
)

var recordDay = time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)

// Fixture key fingerprints use eight SHA-256 hex digits.
const (
	shodanKey   = "shodan-key-123456"
	shodanPrint = "79dd2e2f"
	githubKey   = "ghp_abcdef"
	githubPrint = "2a36681b"
)

func TestStore_SaveWritesKeyRecordsAndOpenReadsThemBack(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("keys:\n  shodan: "+shodanKey+"\n"))
	out := w.save(w.open(), setup.Edits{
		Set: map[string]string{"keys.github": githubKey},
		Records: map[string]setup.KeyRecord{
			"shodan": {Result: setup.RecordAccepted, Day: recordDay},
			"github": {Result: setup.RecordNotTested, Day: recordDay.AddDate(0, 0, -1)},
		},
	})
	want := "keys:\n  shodan: " + shodanKey + "\n  github: " + githubKey + "\n" +
		"key_tests:\n" +
		"  shodan:\n    result: accepted\n    date: \"2026-11-22\"\n    key: " + shodanPrint + "\n" +
		"  github:\n    result: not tested\n    date: \"2026-11-21\"\n    key: " + githubPrint + "\n"
	if got := w.contents(); got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
	if got := out.Keys["shodan"].Record; got == nil || *got != (setup.KeyRecord{Result: setup.RecordAccepted, Day: recordDay}) {
		t.Errorf("shodan record read back = %+v", got)
	}
	if got := out.Keys["github"].Record; got == nil || got.Result != setup.RecordNotTested {
		t.Errorf("github record read back = %+v", got)
	}
	if _, err := config.Check([]byte(want), w.path, nil); err != nil {
		t.Errorf("nyx recon refuses a file with key records: %v", err)
	}
}

func TestStore_AKeyRecordMustBeForTheKeyTheFileHolds(t *testing.T) {
	t.Parallel()
	record := func(result, date, key string) string {
		return "keys:\n  shodan: " + shodanKey + "\nkey_tests:\n  shodan:\n    result: " + result +
			"\n    date: " + date + "\n    key: " + key + "\n"
	}
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{"as written", record("accepted", "2026-11-22", shodanPrint), true},
		{"date unquoted by hand", record("rejected", "2026-11-22", shodanPrint), true},
		{"date quoted", record("rejected", `"2026-11-22"`, shodanPrint), true},
		{"key changed by hand", record("accepted", "2026-11-22", githubPrint), false},
		{"no fingerprint", "keys:\n  shodan: " + shodanKey + "\nkey_tests:\n  shodan:\n    result: accepted\n    date: 2026-11-22\n", false},
		{"unknown result", record("great", "2026-11-22", shodanPrint), false},
		{"bad date", record("accepted", "22/11/2026", shodanPrint), false},
		{"not a block", "keys:\n  shodan: " + shodanKey + "\nkey_tests:\n  shodan: accepted\n", false},
		{"block is a list", "keys:\n  shodan: " + shodanKey + "\nkey_tests: [a, b]\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t, &tc.body)
			ks := w.open().Keys["shodan"]
			if ks.Problem != "" {
				t.Errorf("problem = %q: a record never makes the key invalid", ks.Problem)
			}
			if (ks.Record != nil) != tc.ok {
				t.Errorf("record = %+v, want one: %v", ks.Record, tc.ok)
			}
			if _, err := config.Check([]byte(tc.body), w.path, nil); err != nil {
				t.Errorf("nyx recon refuses the file: %v", err)
			}
		})
	}
}

func TestStore_SaveRemovesTheRecordOfAKeyNoLongerSet(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("keys:\n  shodan: "+shodanKey+"\nconcurrency: 3\n"+
		"key_tests:\n"+
		"  shodan: {result: accepted, date: 2026-11-22, key: "+shodanPrint+"}\n"+
		"  github: {result: accepted, date: 2026-11-22, key: "+githubPrint+"} # cleared by hand\n"+
		"  other: {result: accepted, date: 2026-11-22, key: 00000000} # not a source setup lists\n"))
	w.save(w.open(), setup.Edits{Clear: []string{"keys.shodan"}})
	want := "concurrency: 3\nkey_tests:\n  other: {result: accepted, date: 2026-11-22, key: 00000000} # not a source setup lists\n"
	if got := w.contents(); got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
}

func TestStore_SaveReplacesARecordInPlace(t *testing.T) {
	t.Parallel()
	w := newWorld(t, new("keys:\n  shodan: "+shodanKey+"\n"+
		"key_tests:\n  # written by nyx setup\n  shodan:\n    result: not tested\n    date: \"2026-01-01\"\n    key: "+shodanPrint+"\n"))
	w.save(w.open(), setup.Edits{Records: map[string]setup.KeyRecord{"shodan": {Result: setup.RecordRejected, Day: recordDay}}})
	want := "keys:\n  shodan: " + shodanKey + "\n" +
		"key_tests:\n  # written by nyx setup\n  shodan:\n    result: rejected\n    date: \"2026-11-22\"\n    key: " + shodanPrint + "\n"
	if got := w.contents(); got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
}
