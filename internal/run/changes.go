package run

import (
	"cmp"
	"slices"

	"github.com/rafaelh/nyx/internal/findings"
	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/store"
)

// A change is a difference between what the output files showed when the run
// started and what they show now, for the kinds written to them. A thing the
// files list is an entry: one label and key, which may stand for several records
// when the files list them in one row. Its state is absent, on record (stored,
// but not current or not shown) or shown, and a change is a move to or from shown:
// new (absent to shown), returned (on record to shown) and gone (shown to
// anything else). The state at the start is the baseline.

// entry is one thing the output files list or could list, with whether they show
// it now.
type entry struct {
	label, key, scope, severity string
	stages                      []string // of the records shown, sorted
	shown                       bool
	first, last                 string // first_seen and last_seen over the records
}

type entryKey struct{ label, key string }

// entriesOf groups the records of the listed kinds into entries, deciding what
// is shown the way the files do: a current record the Visibility shows, a
// hostname that is not wildcard-only, a netblock an ASN input brought in, and a
// candidate or excluded value counted once however many records carry it.
// Evidence and internal kinds have no label and are skipped. The entries are
// sorted by label and key.
func entriesOf(snap output.Snapshot) []entry {
	vis := snap.Vis
	wildcardOnly := snap.Inv.WildcardOnly()
	byKey := map[entryKey]*entry{}
	for _, k := range kinds.All() {
		recs := snap.Records[k.Name]
		if len(recs) == 0 || !k.Entity && k.Change == "" {
			continue
		}
		named, _ := kinds.Lookup(k.Name)
		for _, r := range recs {
			label, place := vis.ChangeLabel(named, r)
			if label == "" {
				continue
			}
			shown := r.Current
			switch {
			case !k.Entity:
				shown = shown && vis.Shown(named, r)
			case label == kinds.LabelHostname:
				shown = shown && !wildcardOnly[r.Key]
			case label == kinds.LabelNetblock:
				_, ok := snap.ASNNetblocks[r.Key]
				shown = shown && ok
			}
			// The label and kind fix the scope, so every record of an entry has the same.
			e := byKey[entryKey{label, r.Key}]
			if e == nil {
				e = &entry{label: label, key: r.Key, scope: place}
				byKey[entryKey{label, r.Key}] = e
			}
			e.add(r, shown)
		}
	}
	out := make([]entry, 0, len(byKey))
	for _, e := range byKey {
		slices.Sort(e.stages)
		e.stages = slices.Compact(e.stages)
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b entry) int { return cmp.Or(cmp.Compare(a.label, b.label), cmp.Compare(a.key, b.key)) })
	return out
}

// add counts a record of the entry, shown or not, in its first_seen and
// last_seen, and a shown one in its stages and severity.
func (e *entry) add(r store.Record, shown bool) {
	if r.FirstSeen != "" && (e.first == "" || r.FirstSeen < e.first) {
		e.first = r.FirstSeen
	}
	e.last = max(e.last, r.LastSeen)
	if !shown {
		return
	}
	e.shown = true
	e.stages = append(e.stages, r.Stages...)
	if e.label == kinds.LabelFinding {
		e.severity = findings.FromRecord(r).Severity
	}
}

// shownRows are the entries shown now, as the baseline the next render, or the
// next run, compares against.
func shownRows(entries []entry) []store.ShownRow {
	var rows []store.ShownRow
	for _, e := range entries {
		if e.shown {
			rows = append(rows, store.ShownRow{Kind: e.label, Key: e.key, Stages: e.stages, Scope: e.scope, Severity: e.severity})
		}
	}
	return rows // entries are sorted by label and key, as Store.Shown returns them
}

// baseline is the state when the run started: what the files showed at the last
// render, saved, and which entries were on record then and not shown. It is not recomputed
// from the records, which would use today's date, settings, binary and scope and
// so absorb the very changes a certificate that expired overnight is. A nil
// baseline is a first run, with nothing to compare with.
type baseline struct {
	rows    []store.ShownRow
	started map[entryKey]bool
}

// compare lists what changed between the baseline and the entries now, in the
// order of changes.csv. A gone row has the scope and severity the baseline held,
// which the store has no attributes left to give. In a passive run a record is
// not gone when every stage that observed it at the baseline (target says which)
// made contact with the target, because those stages did not run; a finding, or
// any record a deriver stores, is observed by a pseudo-stage that makes no
// contact, so it is reported gone. compare also returns the baseline rows a
// passive run left out of the changes: the next baseline keeps them, so that the
// first run to make contact reports them gone, if they still are, instead of never.
func (b *baseline) compare(cur []entry, passive bool, target map[string]bool) (changes []output.Change, carried []store.ShownRow) {
	if b == nil {
		return nil, nil
	}
	base := make(map[entryKey]store.ShownRow, len(b.rows))
	for _, r := range b.rows {
		base[entryKey{r.Kind, r.Key}] = r
	}
	now := make(map[entryKey]*entry, len(cur))
	var out []output.Change
	for i := range cur {
		e := &cur[i]
		k := entryKey{e.label, e.key}
		now[k] = e
		if !e.shown {
			continue
		}
		if _, was := base[k]; was {
			continue
		}
		change := output.ChangeNew
		if b.started[k] {
			change = output.ChangeReturned
		}
		out = append(out, output.Change{Change: change, Kind: e.label, Key: e.key, Scope: e.scope, Severity: e.severity,
			Current: true, FirstSeen: e.first, LastSeen: e.last})
	}
	for _, r := range b.rows {
		e := now[entryKey{r.Kind, r.Key}]
		if e != nil && e.shown {
			continue
		}
		if passive && len(r.Stages) > 0 && slices.IndexFunc(r.Stages, func(s string) bool { return !target[s] }) < 0 {
			carried = append(carried, r)
			continue
		}
		c := output.Change{Change: output.ChangeGone, Kind: r.Kind, Key: r.Key, Scope: r.Scope, Severity: r.Severity}
		if e != nil {
			c.FirstSeen, c.LastSeen = e.first, e.last
		}
		out = append(out, c)
	}
	slices.SortFunc(out, output.CompareChanges)
	return out, carried
}

// loadBaseline reads the baseline when the run starts, before anything is
// derived. It is nil when the store has no records, a first run. The entries on
// record are those the stored records make under the scope they build, which is
// a function of the records and inputs alone. An engagement last written by a nyx
// that kept no baseline gets what was shown worked out the same way, once.
func (r *Runner) loadBaseline() (*baseline, error) {
	has, err := r.st.HasRecords()
	if err != nil || !has {
		return nil, err
	}
	rows, saved, err := r.st.Shown()
	if err != nil {
		return nil, err
	}
	built, err := BuildScope(r.inputs, runnerSource{r})
	if err != nil {
		return nil, err
	}
	snap, err := r.snapshot(built.Scope, built.Inv)
	if err != nil {
		return nil, err
	}
	entries := entriesOf(snap)
	if saved {
		r.lastShown, r.shownSaved = rows, true // a first render that shows the same need not save it again
	} else {
		rows = shownRows(entries)
	}
	// An entry shown under the scope at the start but not in the baseline came about
	// from an input added since the last render (an exclusion, a root): it is new,
	// not a return. Only entries on record and not shown can return.
	started := make(map[entryKey]bool, len(entries))
	for _, e := range entries {
		if !e.shown {
			started[entryKey{e.label, e.key}] = true
		}
	}
	return &baseline{rows: rows, started: started}, nil
}

// saveShown replaces the saved baseline with what the files show now, and the rows
// a passive run carried over, unless it is what was last saved. It follows the files, so that a crash between the two
// reports a change twice and never loses one.
func (r *Runner) saveShown(entries []entry, carried []store.ShownRow) error {
	rows := shownRows(entries)
	if len(carried) > 0 {
		rows = append(rows, carried...)
		slices.SortFunc(rows, func(a, b store.ShownRow) int { return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Key, b.Key)) })
	}
	if r.shownSaved && slices.EqualFunc(rows, r.lastShown, store.ShownRow.Equal) {
		return nil
	}
	if err := r.st.SaveShown(rows); err != nil {
		return err
	}
	r.lastShown, r.shownSaved = rows, true
	return nil
}

// targetStages is the set of stages that make contact with the target.
func targetStages(stages []Stage) map[string]bool {
	m := map[string]bool{}
	for _, s := range stages {
		if s.Contact() == Target {
			m[s.Name()] = true
		}
	}
	return m
}
