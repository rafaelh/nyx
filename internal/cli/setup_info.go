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
