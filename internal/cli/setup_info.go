package cli

import (
	"context"
	"slices"
	"strings"

	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/keycheck"
	"github.com/rafaelh/nyx/internal/run"
	"github.com/rafaelh/nyx/internal/setup"
	"github.com/rafaelh/nyx/internal/spamhaus"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// nvdTurnsOn describes the NVD key's use by nyx cve.
const nvdTurnsOn = "Increases cve requests from 5 per 30 seconds to 50"

// keyTurnsOn describes stages requiring or optionally using a source's key, in that order.
// Optional-only keys, such as Cert Spotter's, are labelled accordingly. The text starts with a
// capital letter.
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

// setupSources lists credentials with their enabled features.
func setupSources(stages []run.Stage) []setup.Source {
	var out []setup.Source
	for _, name := range keycheck.Sources() {
		out = append(out, setup.Source{Name: name, Turns: keyTurnsOn(name, stages)})
	}
	return out
}

// setupStages lists skippable stages in registry order with their help descriptions.
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

// testKey limits credential checks to one authenticated source request.
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

// Info includes config metadata and any missing threat-storage explanation.
func (b setupBackend) Info() setup.Info {
	info := b.Store.Info()
	if b.dir == "" {
		info.ThreatUnavailable = nowhereToKeepThreatData
	}
	return info
}

// ThreatData reports the five lists in use. Spamhaus credit belongs to drop_v4. An unreadable
// downloaded source adds a warning to each of its lists.
func (k threatKeeper) ThreatData() []setup.ThreatList {
	set := k.load()
	notes := map[string]string{}
	for _, w := range set.Warnings {
		notes[w.Source] = w.Text
	}
	lists := make([]setup.ThreatList, len(set.Lists))
	for i, l := range set.Lists {
		lists[i] = setup.ThreatList{Source: l.Source, List: l.Name, Date: l.Updated, Entries: l.Entries,
			Downloaded: l.Downloaded, Note: notes[l.Source]}
		if l.Name == spamhaus.ListV4 {
			lists[i].Copyright, lists[i].Terms = set.Copyright, set.Terms
		}
	}
	return lists
}

// UpdateThreatData shares command update logic and converts results into list rows.
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

// threatOutcomeOf maps updater status to the setup tab's status.
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
