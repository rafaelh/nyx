package store_test

import (
	"database/sql"
	"slices"
	"testing"

	"github.com/rafaelh/nyx/internal/store"
)

// A database nothing has been saved to has no baseline, which is not the same as
// a baseline of nothing shown.
func TestShown_NeverSavedIsNotEmpty(t *testing.T) {
	t.Parallel()
	s, _ := open(t, newClock(), nil)
	rows, saved, err := s.Shown()
	if err != nil || saved || len(rows) != 0 {
		t.Fatalf("Shown() = %v, %v, %v; want no rows, not saved", rows, saved, err)
	}
	if err := s.SaveShown(nil); err != nil {
		t.Fatal(err)
	}
	if rows, saved, err = s.Shown(); err != nil || !saved || len(rows) != 0 {
		t.Fatalf("after saving nothing: %v, %v, %v; want no rows, saved", rows, saved, err)
	}
}

// Each save replaces the table, and what comes back is what was saved, with the
// scope, severity and stages a gone row needs.
func TestShown_SaveReplaces(t *testing.T) {
	t.Parallel()
	s, _ := open(t, newClock(), nil)
	first := []store.ShownRow{ // in the order Shown returns them: by kind, then key
		{Kind: "finding", Key: "takeover|x", Stages: []string{"findings"}, Severity: "high"},
		{Kind: "hostname", Key: "a.a.com", Stages: []string{"crtsh", "resolve"}, Scope: "in-scope"},
	}
	if err := s.SaveShown(first); err != nil {
		t.Fatal(err)
	}
	got, saved, err := s.Shown()
	if err != nil || !saved {
		t.Fatal(saved, err)
	}
	if !slices.EqualFunc(got, first, store.ShownRow.Equal) {
		t.Errorf("got %+v, want %+v", got, first)
	}
	second := []store.ShownRow{{Kind: "hostname", Key: "b.a.com"}}
	if err := s.SaveShown(second); err != nil {
		t.Fatal(err)
	}
	if got, _, _ = s.Shown(); len(got) != 1 || got[0].Key != "b.a.com" || len(got[0].Stages) != 0 {
		t.Errorf("after a second save: %+v", got)
	}
}

// The table survives the store being closed and opened again.
func TestShown_Persists(t *testing.T) {
	t.Parallel()
	c := newClock()
	s, p := open(t, c, nil)
	if err := s.SaveShown([]store.ShownRow{{Kind: "hostname", Key: "a.a.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := store.Open(p, store.Options{Clock: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, saved, _ := s2.Shown(); !saved || len(got) != 1 {
		t.Errorf("after reopening: %v, %v", got, saved)
	}
}

// A database an earlier nyx wrote has no shown table; opening it makes one and
// the baseline reads as never saved.
func TestShown_TableCreatedInAnOlderDatabase(t *testing.T) {
	t.Parallel()
	c := newClock()
	s, p := open(t, c, nil)
	s.Complete("crtsh", "k", nil)
	mustFlush(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP TABLE shown"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s2, err := store.Open(p, store.Options{Clock: c.now})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, saved, err := s2.Shown(); err != nil || saved {
		t.Fatalf("Shown() saved=%v err=%v", saved, err)
	}
	if err := s2.SaveShown([]store.ShownRow{{Kind: "hostname", Key: "a.a.com"}}); err != nil {
		t.Fatal(err)
	}
}

// HasRecords is true once any record is stored, current or not.
func TestHasRecords(t *testing.T) {
	t.Parallel()
	c := newClock()
	s, _ := open(t, c, nil)
	if has, err := s.HasRecords(); err != nil || has {
		t.Fatalf("an empty store: %v, %v", has, err)
	}
	s.Complete("crtsh", "k", []store.Obs{{Kind: "hostname", Key: "a.a.com"}})
	mustFlush(t, s)
	if err := s.Redo("crtsh"); err != nil { // the record stays, with no completed check observing it
		t.Fatal(err)
	}
	if has, err := s.HasRecords(); err != nil || !has {
		t.Errorf("a store with a record: %v, %v", has, err)
	}
}
