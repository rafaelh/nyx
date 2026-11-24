package run

import (
	"cmp"
	"slices"

	"github.com/rafaelh/nyx/internal/kinds"
	"github.com/rafaelh/nyx/internal/output"
	"github.com/rafaelh/nyx/internal/store"
)

// Changes compare the output at the start of a run with the output now. Each entry represents
// one output row, even if several records contribute to it. Entries can be absent, stored but
// hidden, or shown. Transitions into or out of shown become new, returned or gone changes. The
// saved starting state is the baseline.

// entry represents an output row and whether it is currently visible.
type entry struct {
	label, key, scope, severity string
	procedures                  []string // sorted procedures contributing visible records
	shown                       bool
	first, last                 string // earliest first_seen and latest last_seen across contributing records
}

type entryKey struct{ label, key string }

// entriesOf groups records into output rows using the same visibility rules as the files.
// Candidates and exclusions are counted once per value; evidence and internal records are
// omitted. Results are sorted by label and key.
func entriesOf(snap output.Snapshot) []entry {
	vis := snap.Vis
	wildcardOnly := snap.Inv.WildcardOnly()
	byKey := map[entryKey]*entry{}
	for _, k := range kinds.All() {
		recs := snap.Records[k.Name]
		if len(recs) == 0 || !k.Entity() && k.Change == "" {
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
			case !k.Entity():
				shown = shown && vis.Shown(named, r)
			case label == kinds.LabelHostname:
				shown = shown && !wildcardOnly[r.Key]
			case label == kinds.LabelNetblock:
				_, ok := snap.ASNNetblocks[r.Key]
				shown = shown && ok
			}
			// All records grouped under this label and key have the same scope.
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
		slices.Sort(e.procedures)
		e.procedures = slices.Compact(e.procedures)
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b entry) int { return cmp.Or(cmp.Compare(a.label, b.label), cmp.Compare(a.key, b.key)) })
	return out
}

// add includes every record in the date range, but only visible records in procedures and severity.
func (e *entry) add(r store.Record, shown bool) {
	if r.FirstSeen != "" && (e.first == "" || r.FirstSeen < e.first) {
		e.first = r.FirstSeen
	}
	e.last = max(e.last, r.LastSeen)
	if !shown {
		return
	}
	e.shown = true
	e.procedures = append(e.procedures, r.Producers...)
	if e.label == kinds.LabelFinding {
		e.severity = r.Str("severity")
	}
}

// shownRows builds the baseline rows for the next comparison.
func shownRows(entries []entry) []store.ShownRow {
	var rows []store.ShownRow
	for _, e := range entries {
		if e.shown {
			rows = append(rows, store.ShownRow{Kind: e.label, Key: e.key, Producers: e.procedures, Scope: e.scope, Severity: e.severity})
		}
	}
	return rows
}

// baseline preserves what the last render showed and which hidden entries existed when this run
// started. Recomputing visibility would hide changes caused by a new date, settings or scope,
// such as a certificate expiring overnight. A nil baseline means there is no earlier run to
// compare with.
type baseline struct {
	rows    []store.ShownRow
	byKey   map[entryKey]store.ShownRow
	started map[entryKey]bool
}

// compare returns changes in changes.csv order. Gone rows retain their previous scope and
// severity. During a passive run, missing entries observed only by target-contacting procedures are
// carried forward: those procedures have not checked them again. Derived records can still be
// reported gone. Carried rows remain in the next baseline so a later active run can report
// their removal.
func (b *baseline) compare(cur []entry, passive bool, target map[string]bool) (changes []output.Change, carried []store.ShownRow) {
	if b == nil {
		return nil, nil
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
		if _, was := b.byKey[k]; was {
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
		if passive && len(r.Producers) > 0 && slices.IndexFunc(r.Producers, func(s string) bool { return !target[s] }) < 0 {
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

// loadBaseline reads the previous output before derivation changes any records. A store with no
// records has no baseline. For older engagements without a saved baseline, it reconstructs one
// from the stored records and inputs.
func (r *Runner) loadBaseline() (*baseline, error) {
	has, err := r.st.HasRecords()
	if err != nil || !has {
		return nil, err
	}
	rows, saved, err := r.st.Shown()
	if err != nil {
		return nil, err
	}
	sig := r.kindSig(scopeKinds)
	built, err := BuildScope(r.inputs, r.cfg.Procedures, runnerSource{r})
	if err != nil {
		return nil, err
	}
	r.baseBuilt, r.baseSig = built, sig
	snap, err := r.snapshot(built.Scope, built.Inv, built.Vis)
	if err != nil {
		return nil, err
	}
	entries := entriesOf(snap)
	if saved {
		r.lastShown, r.shownSaved = rows, true // avoid saving an unchanged baseline on the first render
	} else {
		rows = shownRows(entries)
	}
	// An entry newly visible because the inputs changed counts as new. Only entries that
	// were already stored and hidden at the start can count as returned.
	started := make(map[entryKey]bool, len(entries))
	for _, e := range entries {
		if !e.shown {
			started[entryKey{e.label, e.key}] = true
		}
	}
	return newBaseline(rows, started), nil
}

func newBaseline(rows []store.ShownRow, started map[entryKey]bool) *baseline {
	byKey := make(map[entryKey]store.ShownRow, len(rows))
	for _, r := range rows {
		byKey[entryKey{r.Kind, r.Key}] = r
	}
	return &baseline{rows: rows, byKey: byKey, started: started}
}

// saveShown saves the rendered rows and any rows carried through a passive run. It writes after
// the files so a crash can repeat a change report but cannot lose one. Unchanged baselines need
// no write.
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

func targetProcedures(procedures []Procedure) map[string]bool {
	m := map[string]bool{}
	for _, s := range procedures {
		if s.Contact() == Target {
			m[s.Name()] = true
		}
	}
	return m
}
