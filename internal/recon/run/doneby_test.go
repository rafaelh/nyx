package run

import (
	"path/filepath"
	"testing"

	"github.com/rafaelh/nyx/internal/recon/store"
)

// doneByRunner is a runner over a new store, as procedures see it before the first scope build.
func doneByRunner(t *testing.T) (*Runner, *store.Store, *events) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ev := &events{}
	return &Runner{cfg: Config{Emitter: ev}, st: st}, st, ev
}

// warnings counts the warning events emitted.
func (e *events) warnings() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, ev := range e.got {
		if ev.Type == "warning" {
			n++
		}
	}
	return n
}

// DoneBy answers for the named procedure's completed jobs only.
func TestDoneBy_CompletedJobOfTheNamedProcedure(t *testing.T) {
	t.Parallel()
	r, st, ev := doneByRunner(t)
	st.Complete("wildcard", "example.com", nil) // a zone with no wildcard completes with no record
	st.Complete("resolve", "other.example.com", nil)
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	v := r.built.Load().view(r)
	if !v.DoneBy("wildcard", "example.com") {
		t.Error("a completed wildcard job is not done")
	}
	if v.DoneBy("wildcard", "other.example.com") {
		t.Error("another procedure's job key is done for wildcard")
	}
	if v.DoneBy("resolve", "example.com") {
		t.Error("wildcard's job key is done for resolve")
	}
	if v.DoneBy("wildcard", "unknown.example.com") {
		t.Error("an unknown key is done")
	}
	if n := ev.warnings(); n != 0 {
		t.Errorf("%d warnings, want none", n)
	}
}

// A job completed after one pass's view is done in the next pass's.
func TestDoneBy_NextPassSeesNewCompletions(t *testing.T) {
	t.Parallel()
	r, st, _ := doneByRunner(t)
	st.Complete("wildcard", "a.example.com", nil)
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	if first := r.built.Load().view(r); !first.DoneBy("wildcard", "a.example.com") || first.DoneBy("wildcard", "b.example.com") {
		t.Fatal("the first pass's view does not answer from the store")
	}
	st.Complete("wildcard", "b.example.com", nil)
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	if !r.built.Load().view(r).DoneBy("wildcard", "b.example.com") {
		t.Error("a job completed before the next pass is not done in it")
	}
}

// When the store cannot be read DoneBy answers false and warns once in the run, however often it
// is asked and in however many passes.
func TestDoneBy_StoreErrorAnswersFalseAndWarnsOnce(t *testing.T) {
	t.Parallel()
	r, st, ev := doneByRunner(t)
	st.Complete("wildcard", "example.com", nil)
	if err := st.Close(); err != nil { // reading a closed store fails
		t.Fatal(err)
	}
	if _, err := st.Completed("wildcard"); err == nil {
		t.Fatal("reading a closed store did not fail")
	}
	for range 2 {
		v := r.built.Load().view(r)
		for range 3 {
			if v.DoneBy("wildcard", "example.com") {
				t.Error("DoneBy answered true on a store error")
			}
		}
	}
	if n := ev.warnings(); n != 1 {
		t.Errorf("%d warnings, want 1", n)
	}
}
