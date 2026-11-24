package cli

// The non-interactive setup update refreshes five threat-data lists through threatdata.Update.
// It writes per-list results or one JSON envelope and returns the combined source outcome. It
// requires neither config nor a terminal.

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rafaelh/nyx/internal/clierr"
	"github.com/rafaelh/nyx/internal/config"
	"github.com/rafaelh/nyx/internal/egress"
	"github.com/rafaelh/nyx/internal/report"
	"github.com/rafaelh/nyx/internal/threatdata"
)

// updateThreatDataFlag is the name of the flag that runs the update.
const updateThreatDataFlag = "update-threat-data"

// nowhereToKeepThreatData is why there is no threat-data directory.
const nowhereToKeepThreatData = "nowhere to keep threat data: neither XDG_CONFIG_HOME nor HOME is set"

// threatKeeper shares the update directory, built-ins, clock and source client options between
// setup's UI and command.
type threatKeeper struct {
	dir     string
	builtIn *threatdata.BuiltIn
	clock   func() time.Time
	noFsync bool
	egress  egress.Options
}

func newThreatKeeper(d Deps) threatKeeper {
	return threatKeeper{dir: threatdata.Dir(d.Env), builtIn: d.ThreatBuiltIn, clock: d.Clock, noFsync: d.NoFsync, egress: d.Egress}
}

// update uses an unkeyed third-party client restricted to the two source hosts, without target
// policy.
func (k threatKeeper) update(ctx context.Context) threatdata.Result {
	o := k.egress
	o.Keys, o.Redactor = nil, config.NewRedactor()
	clients := egress.New(o).Clients(false, []string{threatdata.SpamhausHost, threatdata.IpapiHost})
	return threatdata.Update(ctx, threatdata.Options{Dir: k.dir, HTTP: clients.ThirdParty, Now: k.clock,
		NoFsync: k.noFsync, BuiltIn: k.builtIn})
}

// load is the lists in use now.
func (k threatKeeper) load() threatdata.Set { return k.builtIn.Load(k.dir, k.clock()) }

// runThreatUpdate updates both sources and writes their combined result. Signals return without
// output; atomic source writes leave each bundle complete.
func runThreatUpdate(ctx context.Context, inv *invocation) error {
	k := newThreatKeeper(inv.d)
	if k.dir == "" {
		return &clierr.Error{Code: clierr.InvalidInput, Message: nowhereToKeepThreatData,
			Hint: "set XDG_CONFIG_HOME or HOME", Input: map[string][]string{"environment": {"XDG_CONFIG_HOME", "HOME"}}}
	}
	res := k.update(ctx)
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	outErr := threatOutcome(res, inv.sh.json)
	return endLookup(outErr, func() error {
		if inv.sh.json {
			return writeThreatEnvelope(inv.d.Stdout, res)
		}
		return writeThreatLines(inv.d.Stdout, res)
	})
}

// threatOutcome returns nil, PARTIAL for one failed source, or a shared code/UPSTREAM_ERROR
// when both fail. Failed sources become targets. Network, timeout or rate-limit failures make
// the outcome transient.
func threatOutcome(res threatdata.Result, jsonMode bool) *clierr.Error {
	var failed []threatdata.SourceResult
	for _, s := range res.Sources {
		if s.Outcome == threatdata.Failed {
			failed = append(failed, s)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	e := &clierr.Error{Hint: threatHint(failed), Input: map[string][]string{"source": sourceNames(failed)}}
	reasons := make([]string, len(failed))
	for i, s := range failed {
		e.Transient = e.Transient || s.Transient
		e.Targets = append(e.Targets, clierr.Target{Input: s.Source, Message: s.Reason, Code: s.Code})
		reasons[i] = s.Source + ": " + s.Reason
	}
	if len(failed) < len(res.Sources) {
		e.Code = clierr.Partial
		e.Message = fmt.Sprintf("%d of %d threat-data sources failed", len(failed), len(res.Sources))
		return e
	}
	e.Code = failed[0].Code
	for _, s := range failed[1:] {
		if s.Code != e.Code {
			e.Code = clierr.UpstreamError
		}
	}
	e.Message = "the threat data was not updated: every source failed"
	if jsonMode { // the targets are written only as text
		e.Message += ": " + strings.Join(reasons, "; ")
	}
	return e
}

func sourceNames(rs []threatdata.SourceResult) []string {
	names := make([]string, len(rs))
	for i, s := range rs {
		names[i] = s.Source
	}
	return names
}

// threatHint derives retry times from each failed source's last response.
func threatHint(failed []threatdata.SourceResult) string {
	parts := make([]string, len(failed))
	for i, s := range failed {
		parts[i] = s.Source + " can be updated " + nextUpdate(s)
	}
	return strings.Join(parts, "; ")
}

// nextUpdate formats cooldown timing, allowing immediate retry when no response arrived.
func nextUpdate(s threatdata.SourceResult) string {
	if s.NextUpdate.IsZero() {
		return "now"
	}
	return "after " + threatTime(s.NextUpdate)
}

// threatTime formats update timestamps as UTC RFC3339.
func threatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// optionalTime formats known timestamps and returns nil for unset ones.
func optionalTime(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := threatTime(t)
	return &s
}

// The update's envelope. Every key is always there.
type threatEnvelope struct {
	Data threatData `json:"data"`
	Meta threatMeta `json:"meta"`
}

type threatData struct {
	Sources []threatSource `json:"sources"`
	Lists   []threatList   `json:"lists"`
}

type threatMeta struct {
	Errors   []errorLine `json:"errors"`
	Warnings []string    `json:"warnings"`
	Hint     *string     `json:"hint"`
}

type threatSource struct {
	Source        string     `json:"source"`
	Outcome       string     `json:"outcome"`
	LastContacted *string    `json:"last_contacted"`
	NextUpdate    *string    `json:"next_update"`
	Copyright     *string    `json:"copyright"`
	Terms         *string    `json:"terms"`
	Error         *errorLine `json:"error"`
}

type threatList struct {
	List       string `json:"list"`
	Source     string `json:"source"`
	OldUpdated string `json:"old_updated"`
	NewUpdated string `json:"new_updated"`
	OldEntries int    `json:"old_entries"`
	Entries    int    `json:"entries"`
	Added      int    `json:"added"`
	Removed    int    `json:"removed"`
}

// threatSourceError builds the same source error for result fields and meta.errors.
func threatSourceError(s threatdata.SourceResult, red *config.Redactor) errorLine {
	return newErrorLine(&clierr.Error{Code: s.Code, Message: s.Reason, Hint: "can be updated " + nextUpdate(s),
		Input: s.Source, Transient: s.Transient}, red)
}

// writeThreatEnvelope emits one compact JSON update result.
func writeThreatEnvelope(w io.Writer, res threatdata.Result) error {
	red := config.NewRedactor()
	env := threatEnvelope{Meta: threatMeta{Errors: []errorLine{}, Warnings: []string{}}}
	env.Data.Sources = make([]threatSource, len(res.Sources))
	for i, s := range res.Sources {
		out := threatSource{Source: s.Source, Outcome: string(s.Outcome),
			LastContacted: optionalTime(s.LastContacted), NextUpdate: optionalTime(s.NextUpdate)}
		if s.Source == threatdata.Spamhaus {
			out.Copyright, out.Terms = &s.Copyright, &s.Terms
		}
		if s.Outcome == threatdata.Failed {
			e := threatSourceError(s, red)
			out.Error = &e
			env.Meta.Errors = append(env.Meta.Errors, e)
		}
		env.Data.Sources[i] = out
	}
	env.Data.Lists = make([]threatList, len(res.Lists))
	for i, l := range res.Lists {
		env.Data.Lists[i] = threatList{List: l.List, Source: l.Source, OldUpdated: l.OldUpdated, NewUpdated: l.NewUpdated,
			OldEntries: l.OldEntries, Entries: l.Entries, Added: l.Added, Removed: l.Removed}
	}
	return lineEncoder(w).Encode(env)
}

// listStatus explains unchanged lists: current, skipped with cooldown times, or failed with a
// reason. Replaced lists return "".
func listStatus(l threatdata.ListResult, source threatdata.SourceResult) string {
	switch l.Outcome {
	case threatdata.Current:
		return "already current"
	case threatdata.Skipped:
		return "skipped: last contacted " + threatTime(source.LastContacted) + "; can be updated after " + threatTime(source.NextUpdate)
	case threatdata.Failed:
		return "failed: " + source.Reason
	case threatdata.Updated:
	}
	return ""
}

// listChange formats added/removed counts for a replaced list.
func listChange(l threatdata.ListResult) string { return fmt.Sprintf("(+%d, -%d)", l.Added, l.Removed) }

// writeThreatLines prints old/new dates and counts for replaced lists, or status for unchanged
// ones, followed by Spamhaus credit.
func writeThreatLines(w io.Writer, res threatdata.Result) error {
	sources := map[string]threatdata.SourceResult{}
	for _, s := range res.Sources {
		sources[s.Source] = s
	}
	var b strings.Builder
	srcWidth, listWidth := 0, 0
	for _, l := range res.Lists {
		srcWidth, listWidth = max(srcWidth, len(l.Source)), max(listWidth, len(l.List))
	}
	for _, l := range res.Lists {
		fmt.Fprintf(&b, "%-*s  %-*s  ", srcWidth, l.Source, listWidth, l.List)
		entries := fmt.Sprintf("%d entries", l.Entries)
		if l.Outcome == threatdata.Updated {
			fmt.Fprintf(&b, "%s -> %s  %s %s\n", l.OldUpdated, l.NewUpdated, entries, listChange(l))
			continue
		}
		fmt.Fprintf(&b, "%s  %s  %s\n", l.NewUpdated, entries, listStatus(l, sources[l.Source]))
	}
	for _, s := range res.Sources {
		if s.Source == threatdata.Spamhaus && s.Copyright != "" {
			fmt.Fprintf(&b, "Spamhaus DROP data %s; terms: %s\n", s.Copyright, s.Terms)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// loadThreat reads active lists once, warning only for sources the command uses. Invalid
// downloads always emit warnings, including --quiet. Staleness goes to JSON warnings or a
// deferred human hint printed by Execute.
func (inv *invocation) loadThreat(em report.Emitter, warnings *report.Warnings, read func(source string) bool) threatdata.Set {
	set := newThreatKeeper(inv.d).load()
	for _, w := range set.Warnings {
		if read(w.Source) {
			report.Say(em, "warning")(w.Text)
		}
	}
	for _, n := range set.Stale {
		switch {
		case !read(n.Source):
		case warnings != nil:
			warnings.Emit(report.Event{Type: "warning", Fields: map[string]any{"message": n.Text}})
		default:
			inv.staleHints = append(inv.staleHints, n.Text)
		}
	}
	return set
}
