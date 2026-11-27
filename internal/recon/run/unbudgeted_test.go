package run

import "testing"

// An unbudgeted job is admitted once the budget is spent and after another job was deferred,
// and adds nothing to the deferred cost.
func TestWithinBudget_UnbudgetedJobAdmittedAfterDeferral(t *testing.T) {
	t.Parallel()
	sr := &procedureRun{budget: 2}
	for i, c := range []Job{{Key: "a", Cost: 1}, {Key: "b", Cost: 1}} {
		if !sr.withinBudget(c) {
			t.Fatalf("job %d within the budget was deferred", i)
		}
	}
	if sr.withinBudget(Job{Key: "c", Cost: 1}) {
		t.Fatal("a job past the spent budget was admitted")
	}
	if sr.deferredCost != 1 {
		t.Fatalf("deferred cost = %d after one deferral, want 1", sr.deferredCost)
	}
	if !sr.withinBudget(Job{Key: "rows", Cost: 3, Unbudgeted: true}) {
		t.Error("an unbudgeted job after a deferral was not admitted")
	}
	if !sr.withinBudget(Job{Key: "rows-zero", Unbudgeted: true}) {
		t.Error("an unbudgeted job of cost zero after a deferral was not admitted")
	}
	if sr.deferredCost != 1 {
		t.Errorf("deferred cost = %d, want 1: unbudgeted jobs add nothing", sr.deferredCost)
	}
	if sr.spent != 2 {
		t.Errorf("spent = %d, want 2: unbudgeted jobs charge nothing", sr.spent)
	}
	if sr.withinBudget(Job{Key: "d", Cost: 1}) {
		t.Error("a budgeted job after the unbudgeted ones was admitted")
	}
	if sr.deferredCost != 2 {
		t.Errorf("deferred cost = %d after a second deferral, want 2", sr.deferredCost)
	}
}

// An unbudgeted job admitted when the budget is spent, before any deferral, charges nothing, and
// a budgeted job after it is deferred only by the budget it already spent.
func TestWithinBudget_UnbudgetedJobChargesNothing(t *testing.T) {
	t.Parallel()
	sr := &procedureRun{budget: 1}
	if !sr.withinBudget(Job{Key: "rows-first", Cost: 5, Unbudgeted: true}) {
		t.Fatal("an unbudgeted job was not admitted")
	}
	if sr.spent != 0 || sr.deferredCost != 0 {
		t.Fatalf("spent %d, deferred %d after an unbudgeted job, want 0 and 0", sr.spent, sr.deferredCost)
	}
	if !sr.withinBudget(Job{Key: "a", Cost: 1}) {
		t.Fatal("the first budgeted job was deferred after an unbudgeted one")
	}
	if !sr.withinBudget(Job{Key: "rows", Cost: 1, Unbudgeted: true}) {
		t.Error("an unbudgeted job after the budget was spent was not admitted")
	}
	if sr.spent != 1 || sr.deferredCost != 0 {
		t.Errorf("spent %d, deferred %d, want 1 and 0", sr.spent, sr.deferredCost)
	}
}
