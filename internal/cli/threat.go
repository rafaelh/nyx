package cli

// nyx setup --update-threat-data: setup's one non-interactive use. It updates the five threat-data
// lists (Spamhaus's three DROP lists and ipapi.is's two abuse lists) through threatdata.Update,
// writes one line per list (or, under --json, one envelope) and ends with the outcome of the two
// sources. It reads no config file and needs no terminal.

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

// threatKeeper is what the update and the setup tab need to read and update the threat data: the
// directory it is kept in, the built-in copies, the clock, and the options of the client that asks
// the two sources.
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

// update runs one update. Its client is third-party only, with no policy, no keys and no host but
// the two sources'.
func (k threatKeeper) update(ctx context.Context) threatdata.Result {
	o := k.egress
	o.Keys, o.Redactor = nil, config.NewRedactor()
	clients := egress.New(o).Clients(false, []string{threatdata.SpamhausHost, threatdata.IpapiHost})
	return threatdata.Update(ctx, threatdata.Options{Dir: k.dir, HTTP: clients.ThirdParty, Now: k.clock,
		NoFsync: k.noFsync, BuiltIn: k.builtIn})
}

// load is the lists in use now.
func (k threatKeeper) load() threatdata.Set { return k.builtIn.Load(k.dir, k.clock()) }

// runThreatUpdate is nyx setup --update-threat-data: it updates both sources, writes the result
// and ends with the error their outcome calls for. A signal ends it with the signal's error and
// nothing written, though each source then holds its previous copy or its complete new one.
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

// threatOutcome is the error an update ends with: nil when no source failed, PARTIAL when one did,
// and when both did, an error that covers them with their code if they share one, else
// UPSTREAM_ERROR. Each failed source is one of its targets, which the human error writes. It is
// transient when any failure was a network failure, a timeout or a 429.
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

// threatHint says when each failed source can next be updated: an hour after it last answered, or
// now when it sent no response.
func threatHint(failed []threatdata.SourceResult) string {
	parts := make([]string, len(failed))
	for i, s := range failed {
		parts[i] = s.Source + " can be updated " + nextUpdate(s)
	}
	return strings.Join(parts, "; ")
}

// nextUpdate is "after <time>" for a source that sent a response, and "now" for one that did not.
func nextUpdate(s threatdata.SourceResult) string {
	if s.NextUpdate.IsZero() {
		return "now"
	}
	return "after " + threatTime(s.NextUpdate)
}

// threatTime is t as the update writes every time: RFC 3339, in UTC.
func threatTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// optionalTime is t as the envelope gives it, or nil when it is not set.
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

// threatSourceError is the error of a failed source as the envelope gives it, in a source and in
// meta.errors.
func threatSourceError(s threatdata.SourceResult, red *config.Redactor) errorLine {
	return newErrorLine(&clierr.Error{Code: s.Code, Message: s.Reason, Hint: "can be updated " + nextUpdate(s),
		Input: s.Source, Transient: s.Transient}, red)
}

// writeThreatEnvelope writes the update's envelope: one JSON object on one line.
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

// listStatus is what a list that was not replaced says: already current, skipped (and when it was
// last contacted and can next be updated) or failed (and why). For a list that was replaced it is
// empty.
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

// listChange is how a replaced list changed: "(+5, -2)".
func listChange(l threatdata.ListResult) string { return fmt.Sprintf("(+%d, -%d)", l.Added, l.Removed) }

// writeThreatLines writes one line per list, the source and list in columns, and then Spamhaus's
// credit. A replaced list gives its old and new date, its entries and what was added and removed;
// any other gives its date and entries, then why it was not replaced.
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

// loadThreat reads the threat data a command checks addresses against, once, from the threat-data
// directory and the built-in copies. read says whether the command reads a source (threatdata.Spamhaus
// or threatdata.Ipapi); a source it doesn't read gives no warning and no hint.
//
// A downloaded copy that is unreadable is a warning event, which prints even under --quiet and goes
// to meta.warnings under --json. A stale source is a warning in the envelope under --json, whatever
// --quiet says, and otherwise a hint that Execute writes once the command has returned.
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
