package output

import (
	"cmp"
	"slices"
)

// Change is one row of changes.csv: a difference between what the files showed
// when the run started and what they show now. Change is ChangeNew,
// ChangeReturned or ChangeGone, Kind the label of the thing that changed (a
// hostname, a web service, a finding, a candidate), and Key what the files call
// it. Scope is where it sits against the scope, and Severity is a finding's. A
// gone row has the scope and severity it had when it was shown, and is not current.
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

// CompareChanges orders changes as changes.csv lists them: new, then returned,
// then gone, each by kind and key.
func CompareChanges(a, b Change) int {
	return cmp.Or(compareChangeRank(a.Change, b.Change), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Key, b.Key))
}

func compareChangeRank(a, b string) int {
	return cmp.Compare(slices.Index(changeRank, a), slices.Index(changeRank, b))
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
