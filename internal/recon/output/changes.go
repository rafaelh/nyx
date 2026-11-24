package output

import (
	"cmp"
	"slices"
)

// Change describes an output row that became new, returned or gone relative to the run's
// baseline. Kind/Key identify the output entry. Scope and finding severity describe its
// placement; gone rows preserve their previous values and are non-current.
type Change struct {
	Change, Kind, Key, Scope, Severity string
	Current                            bool
	FirstSeen, LastSeen                string
}

// The kinds of change, in the order changes.csv lists them.
const (
	ChangeNew      = "new"
	ChangeReturned = "returned"
	ChangeGone     = "gone"
)

var changeRank = []string{ChangeNew, ChangeReturned, ChangeGone}

var changeColumns = []string{"change", "kind", "key", "scope", "severity"}

// CompareChanges sorts by new/returned/gone, then kind and key.
func CompareChanges(a, b Change) int {
	return cmp.Or(cmp.Compare(slices.Index(changeRank, a.Change), slices.Index(changeRank, b.Change)), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Key, b.Key))
}

func changeRows(s Snapshot) []Row {
	rows := make([]Row, 0, len(s.Changes))
	for _, c := range s.Changes {
		rows = append(rows, Row{Cells: []string{c.Change, c.Kind, c.Key, c.Scope, c.Severity}, Current: c.Current, FirstSeen: c.FirstSeen, LastSeen: c.LastSeen})
	}
	return rows
}

// changeOrder sorts changes.csv as CompareChanges does.
func changeOrder(a, b Row) int {
	row := func(r Row) Change { return Change{Change: r.Cells[0], Kind: r.Cells[1], Key: r.Cells[2]} }
	return CompareChanges(row(a), row(b))
}
