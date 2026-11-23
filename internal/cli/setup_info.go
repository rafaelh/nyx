package cli

import (
	"context"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/keycheck"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/sanitize"
	"github.com/rafaelh/nyx/internal/setup"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// nvdTurnsOn is what the nvd key does: nyx cve is the only command that reads it, apart from the
// stages' own shared use of the file.
const nvdTurnsOn = "Increases cve requests from 5 per 30 seconds to 50"

// keyTurnsOn is the one line that says what the key of source turns on, from the stages that name
// it in their key column: those that need it, then those it adds to (a key in brackets). A key that
// only adds to stages (Cert Spotter's) also works without one. It starts with a capital letter.
func keyTurnsOn(source string, stages []run.Stage) string {
	if source == "nvd" {
		return nvdTurnsOn
	}
	var needs, adds []string
	for _, s := range stages {
		switch stageHelps[s.Name()].key {
		case source:
			needs = append(needs, s.Name())
		case "(" + source + ")":
			adds = append(adds, s.Name())
		}
	}
	var parts []string
	if len(needs) > 0 {
		parts = append(parts, "turns on "+strings.Join(needs, ", "))
	}
	if len(adds) > 0 {
		parts = append(parts, "adds to "+strings.Join(adds, ", "))
	}
	if len(needs) == 0 && len(adds) > 0 {
		parts = append(parts, "also works without a key")
	}
	line := strings.Join(parts, "; ")
	if line == "" {
		return ""
	}
	return strings.ToUpper(line[:1]) + line[1:]
}

// setupSources are the key sources setup lists, with what each turns on.
func setupSources(stages []run.Stage) []setup.Source {
	var out []setup.Source
	for _, name := range keycheck.Sources() {
		out = append(out, setup.Source{Name: name, Turns: keyTurnsOn(name, stages)})
	}
	return out
}

// setupStages are the stages setup offers to skip: those that can be skipped, in registry order,
// each with its description as nyx help stages gives it.
func setupStages(stages []run.Stage) []setup.Stage {
	var out []setup.Stage
	for _, s := range stages {
		if slices.Contains(unskippable, s.Name()) {
			continue
		}
		out = append(out, setup.Stage{Name: s.Name(), Does: stageHelps[s.Name()].does})
	}
	return out
}

// testKey tests key against source with one authenticated request to that source and nothing else.
func testKey(ctx context.Context, opts egress.Options, source string, key config.Secret) setup.TestResult {
	r := keycheck.Run(ctx, opts, source, key)
	switch r.Status {
	case keycheck.Accepted:
		return setup.TestResult{Status: setup.TestAccepted}
	case keycheck.Rejected:
		return setup.TestResult{Status: setup.TestRejected}
	case keycheck.Unknown:
	}
	return setup.TestResult{Status: setup.TestUnknown, Reason: r.Reason}
}

// Info is the config file's description, with why the threat data cannot be updated when there is
// nowhere to keep it.
func (b setupBackend) Info() setup.Info {
	info := b.Store.Info()
	if b.dir == "" {
		info.ThreatUnavailable = nowhereToKeepThreatData
	}
	return info
}

// ThreatData is the five threat-data lists in use. The credit sits on the drop_v4 row, and a source
// whose downloaded copy is unreadable gives each of its lists the warning as its note.
func (k threatKeeper) ThreatData() []setup.ThreatList {
	set := k.load()
	notes := map[string]string{}
	for _, w := range set.Warnings {
		notes[w.Source] = sanitize.Line(w.Text)
	}
	lists := make([]setup.ThreatList, len(set.Lists))
	for i, l := range set.Lists {
		lists[i] = setup.ThreatList{Source: l.Source, List: l.Name, Date: l.Updated, Entries: l.Entries,
			Downloaded: l.Downloaded, Note: notes[l.Source]}
		if l.Name == spamhaus.ListV4 {
			lists[i].Copyright, lists[i].Terms = sanitize.Line(set.Copyright), sanitize.Line(set.Terms)
		}
	}
	return lists
}

// UpdateThreatData runs the update nyx setup --update-threat-data runs, and gives each list as it
// stands after it, with what happened to it.
func (k threatKeeper) UpdateThreatData(ctx context.Context) setup.ThreatResult {
	res := k.update(ctx)
	sources := map[string]threatdata.SourceResult{}
	for _, s := range res.Sources {
		sources[s.Source] = s
	}
	byList := map[string]threatdata.ListResult{}
	for _, l := range res.Lists {
		byList[l.Source+"/"+l.List] = l
	}
	var out setup.ThreatResult
	for _, l := range k.ThreatData() {
		r := setup.ThreatListResult{ThreatList: l, Outcome: setup.ThreatCurrent}
		if lr, ok := byList[l.Source+"/"+l.List]; ok {
			r.Outcome, r.Text = threatOutcomeOf(lr.Outcome), listStatus(lr, sources[l.Source])
			if lr.Outcome == threatdata.Updated {
				r.Text = "updated " + listChange(lr)
			}
		}
		out.Lists = append(out.Lists, r)
	}
	return out
}

// threatOutcomeOf is the setup tab's outcome for an update's.
func threatOutcomeOf(o threatdata.Outcome) setup.ThreatOutcome {
	switch o {
	case threatdata.Updated:
		return setup.ThreatUpdated
	case threatdata.Skipped:
		return setup.ThreatSkipped
	case threatdata.Failed:
		return setup.ThreatFailed
	case threatdata.Current:
	}
	return setup.ThreatCurrent
}
