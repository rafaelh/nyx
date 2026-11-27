package web

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/recon/run"
)

// The budget is warned about when the run ends.
var _ run.EndWarner = (*textBudget)(nil)

// hostsFrom returns n distinct names below example.com, from the index from on.
func hostsFrom(prefix string, from, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%05d.example.com", prefix, from+i)
	}
	return out
}

// numberRun is a number as a warning may write it, with or without thousands separators.
var numberRun = regexp.MustCompile(`\d{1,3}(?:,\d{3})+|\d+`)

// hasNumber reports whether s writes the number n, grouped by commas or not.
func hasNumber(s string, n int) bool {
	for _, m := range numberRun.FindAllString(s, -1) {
		if v, err := strconv.Atoi(strings.ReplaceAll(m, ",", "")); err == nil && v == n {
			return true
		}
	}
	return false
}

const budgetUnit = "https://www.example.com"

// checkWarning checks that a warning names the unit, the cap and the number left out.
func checkWarning(t *testing.T, w string, left int) {
	t.Helper()
	if !strings.Contains(w, budgetUnit) || !strings.Contains(w, "1,000") || !hasNumber(w, left) {
		t.Errorf("EndWarning() = %q, want the unit %s, the cap 1,000 and %d left out", w, budgetUnit, left)
	}
	if strings.Contains(w, "more than") {
		t.Errorf("EndWarning() = %q, want the exact number %d", w, left)
	}
}

func TestTextNames_KeepsDistinctNamesInOrder(t *testing.T) {
	t.Parallel()
	var c textNames
	for _, n := range []string{"b.example.com", "a.example.com", "b.example.com", "c.example.com", "a.example.com"} {
		if !c.add(n) {
			t.Fatalf("add(%q) stopped the scan of a small set", n)
		}
	}
	if want := []string{"b.example.com", "a.example.com", "c.example.com"}; !slices.Equal(c.names, want) {
		t.Errorf("names = %v, want %v", c.names, want)
	}
	if c.over {
		t.Error("a small set is over")
	}
}

// The set holds the cap plus the names counted as left out, and the next new name passes it.
func TestTextNames_BoundSetsOver(t *testing.T) {
	t.Parallel()
	if maxTextNames != 1000 || maxLeftOut != 10000 {
		t.Fatalf("maxTextNames, maxLeftOut = %d, %d, want 1000, 10000", maxTextNames, maxLeftOut)
	}
	var c textNames
	names := hostsFrom("h", 0, maxTextNames+maxLeftOut)
	for _, n := range names {
		if !c.add(n) {
			t.Fatalf("add(%q) stopped the scan within the bound", n)
		}
	}
	if len(c.names) != maxTextNames+maxLeftOut || c.over {
		t.Fatalf("at the bound: %d names, over %v; want %d, false", len(c.names), c.over, maxTextNames+maxLeftOut)
	}
	if !c.add(names[0]) || c.over {
		t.Error("a name already in the set at the bound stopped the scan")
	}
	past := "past.example.com"
	if c.add(past) {
		t.Error("the first new name past the bound did not stop the scan")
	}
	if !c.over {
		t.Error("the first new name past the bound did not set over")
	}
	if len(c.names) != maxTextNames+maxLeftOut || slices.Contains(c.names, past) {
		t.Errorf("past the bound: %d names (holds %s: %v), want %d without it",
			len(c.names), past, slices.Contains(c.names, past), maxTextNames+maxLeftOut)
	}
}

// underExample lets through the names below example.com.
func underExample(n string) bool { return strings.HasSuffix(n, ".example.com") }

// A response is read header values first, by sorted header key, then the body; the names of
// headers are not read.
func TestTextNames_ReadsHeaderValuesThenTheBody(t *testing.T) {
	t.Parallel()
	resp := egress.Response{
		Status: 200,
		Header: map[string][]string{
			"X-B":             {"b.example.com"},
			"A-Policy":        {"https://a.example.com other.net", "*.a2.example.com"},
			"Api.example.com": {"1"},
		},
		Body: []byte("<!-- body.example.com and a.example.com, not api.other.net --> end"),
	}
	var c textNames
	c.read(resp, underExample)
	want := []string{"a.example.com", "a2.example.com", "b.example.com", "body.example.com"}
	if !slices.Equal(c.names, want) {
		t.Errorf("names = %v, want %v", c.names, want)
	}
	if slices.Contains(c.names, "api.example.com") {
		t.Error("the name of a header was read")
	}
	if c.over {
		t.Error("one response of four names is over")
	}
}

// A body that the cap cut gives no name for the text that runs into the cut; an uncut body does.
func TestTextNames_ReadDropsTheNameAtACut(t *testing.T) {
	t.Parallel()
	body := []byte("see www.example.com and tail.example.com")
	var cut textNames
	cut.read(egress.Response{Status: 200, Body: body, Truncated: true}, underExample)
	if want := []string{"www.example.com"}; !slices.Equal(cut.names, want) {
		t.Errorf("truncated body: names = %v, want %v", cut.names, want)
	}
	var whole textNames
	whole.read(egress.Response{Status: 200, Body: body}, underExample)
	if want := []string{"www.example.com", "tail.example.com"}; !slices.Equal(whole.names, want) {
		t.Errorf("whole body: names = %v, want %v", whole.names, want)
	}
}

func TestTextBudget_TakesUpToTheCap(t *testing.T) {
	t.Parallel()
	b := newTextBudget(budgetUnit, nil)
	names := hostsFrom("h", 0, maxTextNames+1)
	kept := b.admit(names, false)
	if len(kept) != maxTextNames {
		t.Errorf("kept %d of %d new names, want %d", len(kept), len(names), maxTextNames)
	}
	if last := names[maxTextNames]; slices.Contains(kept, last) {
		t.Errorf("the 1,001st new name %s was kept", last)
	}
	checkWarning(t, b.EndWarning(), 1)
}

func TestTextBudget_NothingLeftOutWarnsNothing(t *testing.T) {
	t.Parallel()
	b := newTextBudget(budgetUnit, hostsFrom("seed", 0, 400))
	if kept := b.admit(hostsFrom("h", 0, 600), false); len(kept) != 600 {
		t.Errorf("kept %d of 600 names under the cap", len(kept))
	}
	if w := b.EndWarning(); w != "" {
		t.Errorf("EndWarning() at the cap with nothing left out = %q, want none", w)
	}
}

// The names already taken count against the cap.
func TestTextBudget_SeedCounts(t *testing.T) {
	t.Parallel()
	b := newTextBudget(budgetUnit, hostsFrom("seed", 0, maxTextNames-10))
	if kept := b.admit(hostsFrom("h", 0, 20), false); len(kept) != 10 {
		t.Errorf("kept %d of 20 new names with 990 taken, want 10", len(kept))
	}
	checkWarning(t, b.EndWarning(), 10)
}

// A name already taken, from the seed or by an earlier job, is kept when the cap is full.
func TestTextBudget_KeepsATakenNameAtTheCap(t *testing.T) {
	t.Parallel()
	seed := hostsFrom("seed", 0, maxTextNames)
	b := newTextBudget(budgetUnit, seed)
	if kept := b.admit([]string{seed[5], "new.example.com"}, false); !slices.Equal(kept, []string{seed[5]}) {
		t.Errorf("at the cap kept %v, want only the seeded %s", kept, seed[5])
	}
	checkWarning(t, b.EndWarning(), 1)

	b = newTextBudget(budgetUnit, nil)
	names := hostsFrom("h", 0, maxTextNames)
	b.admit(names, false)
	if kept := b.admit([]string{names[0]}, false); !slices.Equal(kept, []string{names[0]}) {
		t.Errorf("at the cap kept %v, want the name taken earlier %s", kept, names[0])
	}
	if w := b.EndWarning(); w != "" {
		t.Errorf("EndWarning() = %q with nothing left out", w)
	}
}

// A name left out by several jobs counts once.
func TestTextBudget_CountsDistinctNamesLeftOut(t *testing.T) {
	t.Parallel()
	b := newTextBudget(budgetUnit, hostsFrom("seed", 0, maxTextNames))
	b.admit([]string{"x.example.com"}, false)
	b.admit([]string{"x.example.com", "y.example.com"}, false)
	checkWarning(t, b.EndWarning(), 2)
}

func TestTextBudget_ExactAtTenThousand(t *testing.T) {
	t.Parallel()
	b := newTextBudget(budgetUnit, hostsFrom("seed", 0, maxTextNames))
	b.admit(hostsFrom("h", 0, maxLeftOut), false)
	checkWarning(t, b.EndWarning(), maxLeftOut)
}

func TestTextBudget_MoreThanTenThousand(t *testing.T) {
	t.Parallel()
	b := newTextBudget(budgetUnit, hostsFrom("seed", 0, maxTextNames))
	b.admit(hostsFrom("h", 0, maxLeftOut+1), false)
	if w := b.EndWarning(); !strings.Contains(w, "more than 10,000") || !strings.Contains(w, budgetUnit) {
		t.Errorf("EndWarning() past 10,000 = %q, want the unit and \"more than 10,000\"", w)
	}
}

// A collector that passed its bound left out more names than it counted.
func TestTextBudget_OverIsMoreThanTenThousand(t *testing.T) {
	t.Parallel()
	b := newTextBudget(budgetUnit, hostsFrom("seed", 0, maxTextNames))
	b.admit([]string{"x.example.com"}, true)
	if w := b.EndWarning(); !strings.Contains(w, "more than 10,000") || !strings.Contains(w, budgetUnit) {
		t.Errorf("EndWarning() after over = %q, want the unit and \"more than 10,000\"", w)
	}
}

// Jobs admitting overlapping names at once never take more than the cap between them, and every
// name is either taken or left out.
func TestTextBudget_ConcurrentJobsKeepTheCap(t *testing.T) {
	t.Parallel()
	const jobs, step, total = 50, 34, 1700 // each name is admitted by two jobs
	pool := hostsFrom("h", 0, total)
	b := newTextBudget(budgetUnit, nil)
	var (
		mu   sync.Mutex
		kept = map[string]bool{}
		wg   sync.WaitGroup
	)
	for i := range jobs {
		names := make([]string, 0, 2*step)
		for j := range 2 * step {
			names = append(names, pool[(i*step+j)%total])
		}
		wg.Go(func() {
			got := b.admit(names, false)
			mu.Lock()
			defer mu.Unlock()
			for _, n := range got {
				kept[n] = true
			}
		})
	}
	wg.Wait()
	if len(kept) != maxTextNames {
		t.Errorf("jobs took %d distinct names between them, want %d", len(kept), maxTextNames)
	}
	checkWarning(t, b.EndWarning(), total-maxTextNames)
}
