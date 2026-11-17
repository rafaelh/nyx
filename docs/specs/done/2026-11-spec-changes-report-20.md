# Spec 20: what changed since the last run

## Goal

After a re-run the user sees exactly what is new and what disappeared, without diffing CSV files
by hand.

## Behaviours

1. A change is a difference between what the output files would show when the run starts and what
   they show when it ends, for the kinds written to output files: `new` (shown at the end, absent
   at the start), `returned` (shown at the end, on record but not shown at the start) and `gone`
   (shown at the start, not shown at the end). Candidates count as their own kind. Internal and
   evidence kinds are not listed.
2. `changes.csv` has one row per change: `change`, kind, key, scope and, for findings, severity,
   with the standard `current`, `first_seen` and `last_seen` columns. It is replaced each run and
   removed when a run has no changes. On a first run (no records when the run starts) no
   `changes.csv` is written and no change events are emitted.
3. The console summary ends with a "since last run" block: counts of new (including returned)
   hostnames, addresses, web services, open ports, candidates and findings, and of gone findings,
   followed by the new high and medium findings as a separate list. It is omitted on a first run.
4. `--json` emits one `change` event per row after the summary event, in addition to the `found`
   events already emitted during the run.
5. The baseline is the state when this invocation starts, so a resumed run after an interrupt
   compares against the interrupted run's end state. An interrupted run writes `changes.csv` for
   the work it completed before exiting 130.
6. Findings can be new or gone with no contact: a certificate crosses its expiry date, a setting
   or the binary changes. A `--passive` run never reports target-derived records as gone, because
   the stages that observe them did not run.

# Design

**Status: review before building (wave 3).** The mechanism is generic over kinds, so this design
is complete, but its summary block and passive rule name kinds and stages other specs add. Build
it last, and at review re-check the items marked *Review*. On 2026-11-14 it was re-checked
against the seven specs built so far: the baseline table now keeps the scope and severity a
`gone` row shows, and the candidate and deriver rules are written as built. **Depends on:** Spec 21
(`run.BuildScope`), Spec 15 (`candidate_rank`), and in practice every spec that adds a kind.

## Decisions

- **A change is a difference between two "shown" states of a record**, taken when the run starts
  and each time the files are written. A record's state is `absent`, `on record` (stored but not
  current or not shown) or `shown` (current and shown by the decision the
  files use). `new` is absent to shown, `returned` is on record to shown, `gone` is shown to
  anything else.
- **Which kinds are listed is a property of the kind**: `Kind.Change` is the label used in
  `changes.csv` (`hostname`, `address`, `web service`, `url`, `open port`, `third party`,
  `code mention`, `finding`, …); kinds without one (evidence and internal kinds) are skipped.
  Candidates are their own label: as built, a candidate is a record of a kind in
  `kinds.CandidateKinds` whose `Visibility.Category` is `candidates`, which is the test
  `candidates.csv` uses, and Spec 8 adds its two types to that list. A candidate's rank is an
  attribute, so `candidate_rank` has no label and a changed rank is not a change. *Review:* give
  a label to each kind the other specs added that has an output file. Of the kinds built so far:
  `third_party` is `third party`; `dns_claim` shares the `resolution` label, and a claim and a
  resolution with one key are one `resolutions.csv` row, so they are one entry in the diff;
  `web_posture`, `provider_range` and `candidate_rank` have none.
- **The baseline is what the last render showed, saved, not recomputed.** Recomputing it when a
  run starts would use today's date, settings, binary and scope, and so absorb exactly the changes
  behaviour 6 asks for (a certificate that expired overnight would already be in the baseline).
  Every render, including the one an interrupt triggers, replaces a `shown` table in the state
  database (`kind`, `key`, `stages`, `scope`, `severity`) in one transaction. The last two are
  kept because a `gone` row must show them and the store cannot give them back: it keeps a
  record's attributes only from current observations, so a finding that is no longer derived has
  lost its severity, and the scope may have changed since. A run reads it once, before its first
  derivation, and diffs every later render against that copy. A resumed run therefore compares
  against where the interrupted run stopped. If the store has no records the run is a first run
  and nothing below happens; an engagement last written by a binary without the table gets its
  baseline computed once from the stored records instead.
- **An entity's state follows the files**, not `Visibility.Shown`, which is true for every
  entity: a hostname is shown when its category is `hosts` and it is not wildcard-only, and a
  candidate when its category is `candidates`.
- **`changes.csv` is an ordinary output file** whose rows come from `Snapshot.Changes`, which the
  runner fills on every render (including the one an interrupt triggers), so it is replaced each
  run, removed when empty, and written atomically like the rest. Columns: `change`, `kind`,
  `key`, `scope`, `severity`.
- **Passive rule**: in a `--passive` run a record is not reported `gone` when every stage
  observing it at the baseline was a target-contact stage. Findings are exempt from the rule:
  they are re-derived with or without contact, so a finding that stops being derived is gone.
  The same holds for any record a deriver stores (`newDerivers()` in `internal/run/derive.go`):
  its observer is the deriver's pseudo-stage, which is not a target-contact stage, so the rule
  as written already reports it gone. A test pins that with a derived record.
- **Reporting**: the `summary` event gains `changes` (counts per label and change, and the new
  high and medium findings); the console prints the "since last run" block from it; `--json`
  emits one `change` event per row after the summary. *Review:* the six labels the block counts.

## Changes

- `internal/kinds/kinds.go`, `table.go` and the per-kind files: `Change` labels.
- `internal/store/store.go`: the `shown` table (created if missing), `SaveShown`, `Shown`.
- `internal/run/changes.go`: baseline and diff. `runner.go`: take the baseline, fill
  `Snapshot.Changes`, summary fields, `change` events.
- `internal/output/changes.go`; one line in `Default()`. `internal/report/report.go`: the block.
- `README.md`: the file, the block, the event.

## Tests

- `internal/run`: the diff over the three states, the first-run rule, the passive rule and its
  findings exemption.
- `internal/cli/changes_test.go` (fake stages and the fixed clock): a first run writes no file and
  emits no events; a second run lists new, returned and gone rows with scope and severity; a run
  with no changes removes the file; a certificate crossing its expiry date with no contact, a changed setting and a new exclusion
  each show their changes; a `--passive` run does not report a web service gone after a scope change; the
  console block and its omission on a first run; `change` events follow the summary.
- `internal/cli/crash_test.go`: an interrupted run writes `changes.csv` for completed work and
  exits 130; the resumed run's baseline is the interrupted run's end state.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **A record that is no longer current has no attributes (Spec 3, follow-up 1; Spec 12).** This
  is why the baseline keeps `scope` and `severity`. If the store is changed first to keep a
  record's last attributes, read them from the record and drop the two columns.
- **Deferred checks (Spec 6).** A budgeted stage's deferred checks are neither failed nor
  retired, so the records they observed stay current and are never reported `gone`. A test pins
  that with a deferring run.
- **The summary as built (Specs 6 and 15).** The summary now ends with the candidate list and
  the `Deferred to the next run` block. The "since last run" block comes after both.
- **`Kind` is not comparable (Spec 3).** `Kind.Change` is one more field on it. Compare `Name()`.
- **Console text (Spec 22).** If Spec 22 has merged, the block is part of the summary on stdout
  and its findings carry the severity badge in place of `[high]`.

## Out of scope

History across more than one run; diffing attribute values of a record that stayed shown.

# Implementation

## Develop

- **Store** (`internal/store/store.go`): a `shown` table (`kind`, `key`, `stages`, `scope`, `severity`),
  created with `CREATE TABLE IF NOT EXISTS` on every open so an older engagement gains it, plus
  `SaveShown` (replace in one transaction and set the meta key `shown_saved`), `Shown` (rows and whether
  a baseline was ever saved: a saved empty baseline is not "never saved") and `HasRecords`.
- **Kinds**: `Kind.Change` is the label (`resolution` for `resolution` and `dns_claim`, `address`,
  `unresolved name`, `web service`, `url`, `open port` for `open_port` and `reported_port`, `finding`,
  `email posture`, `third party`, `code mention`, and `historical address`, which has a label of its own
  because its key can equal a resolution's). Entity kinds are labelled by `Visibility.ChangeLabel` from
  their summary category: `hostname`, `candidate`, `excluded`, `netblock`.
- **Diff** (`internal/run/changes.go`): `entriesOf` groups the records of the labelled kinds into entries
  the way the files do (a current record the Visibility shows; a hostname that is not wildcard-only; a
  netblock an ASN input brought in; a candidate or excluded value once however many records carry it).
  `baseline.diff` compares the saved `shown` rows with the entries now. The runner loads the baseline
  once, after `run_start` and before the first derivation, and `render` diffs against it every time,
  fills `Snapshot.Changes`, writes the files, then saves the new `shown` rows (after the files, so a crash
  between the two repeats a change and never loses one; the save is skipped when nothing differs).
- **Output**: `changes.csv` (`internal/output/changes.go`, last in `Default()`), sorted new, returned,
  gone, then kind and key.
- **Reporting**: the `summary` event gains `changes` (`counts` per label and change, and `findings`, the
  new high and medium findings) on a run that has a baseline; `change` events follow it; the console's
  "Since last run" block comes after the candidate list and the deferred block.
- **Tests**: the diff, the first-run rule, the passive rule with its findings exemption and a derived
  record's pseudo-stage, the entry rules and the sort are `internal/run/changes_test.go`; the table is
  `internal/store/shown_test.go`; `changes.csv` is `internal/output/output_test.go`; the block and its
  omission are `internal/report/report_test.go`; each behaviour end to end, including a certificate
  crossing its expiry with no contact, a changed setting, a new exclusion, the passive rule against an
  active control, a deferring run, a baseline worked out from the stored records and the event order,
  is `internal/cli/changes_test.go`; the interrupted-then-resumed pair is `TestSignals_InterruptedRunWritesChanges`
  in `internal/cli/crash_test.go`. The first-run tests, and the nil-baseline unit test, pass against
  the stubs because they pin behaviour that already held (no file, no events).
- **Mutation checks.** `## Tests` marks none, so these were chosen by hand and each undone by hand:
  removing the passive guard (fails `TestDiff_PassiveRule` and the passive cli test), dropping the
  carried rows (fails the same two), removing the first-run rule (fails the first-run and the
  interrupted-run tests), counting shown entries as on record (fails the exclusion and passive tests),
  and never saving the baseline (fails the exclusion and passive tests, which need it to compare).
- **Deviations from the plan.**
  - `returned` is decided per entry, not per stored record: an entry is returned only when it was on
    record and *not shown* under the scope built from the stored records when the run starts. A record
    that was on record under another label (a hostname an exclusion now makes `excluded`) is `new`, and
    an entry shown under the start scope that the baseline lacks came from an input added since (an
    exclusion is merged before the run starts), so it is `new` too. Reading "on record" per record, as
    first built, reported that exclusion as `returned`.
  - The start scope is built with `BuildScope` from the stored records (a read-only build, like an
    export's), once per run that has records, after `run_start`.
  - Labels beyond those the design lists: `netblock` (shown when an ASN input brought it in, as
    `scope.csv` does), `excluded`, `unresolved name`, `email posture`, `historical address`.
  - `scope` is the placement for hostnames, candidates, excluded names and netblocks, `in-scope` for
    other kinds shown only while a host or address is in scope, and blank for the rest.
  - A `--passive` run carries the baseline rows it left out of the changes into the baseline it saves, so
    the next run that makes contact reports them gone if they still are; saved as built, they would
    have been dropped and never reported.
  - `docs/plans/2026-11-build-order.md` does not exist in this checkout, so the build order was not read.

## Known limitations

- **Behaviour 1.** A candidate is identified by its value alone, so a root and a hostname with one
  value that are both candidates are one entry, though `candidates.csv` lists two rows. A hostname that
  only a wildcard answers is never listed (it is not shown), so one that becomes real is `returned`
  or `new` when it does. `provider-hosts.csv`, `storage-unattributed.csv` and `scope.csv`'s inputs are
  derived or are not records, and are not listed.
- **Behaviour 3.** The block always has the same seven lines (zeros included) rather than only the
  non-zero ones.
- **Behaviour 6.** A record that a deriver stores is reported gone in a passive run (as the design
  says). A record only target-contact stages observed is never reported gone in a passive run, even
  when a scope change has hidden it for a reason that needed no contact; it is reported on the next
  active run. A record shown at the baseline with no observing stage at all is reported gone.
- A run that fails in `loadBaseline` (an unreadable store, an input that cannot be parsed) ends before
  any stage runs and renders nothing, as `passes` would have for the same input error.

## Pre-existing failures

- `TestHelp_Colour` fails on `main` without these changes.
- `golangci-lint` cannot start here (built with Go 1.26, the module targets 1.27), so the lint half of
  the edit hook did not run; `go vet` and `gofmt` did.

## Simplify

- **Fixed.**
  - One order for changes: `output.CompareChanges` and the exported `output.ChangeNew`, `ChangeReturned`
    and `ChangeGone` replace `run`'s own rank map and constants; `changes.csv`'s `Order` shares the rank.
  - `Visibility.ChangeLabel` returns the scope column with the label (the label fixes an entity's
    placement; another kind is `in-scope` when it is scoped), so `entriesOf` no longer classifies each
    host twice or restates `Kind.scoped`. The labels `run` reads are constants in `kinds`
    (`LabelHostname`, `LabelNetblock`, `LabelFinding`, …).
  - `entriesOf`: dropped the dead nil-Visibility fallback and the redundant scope, first-seen and
    last-seen initialisation (an entry's scope is the same for all its records).
  - `baseline.diff` (tests only) removed; `compare` takes the target-stage set as a map, replacing
    `isTargetStage`. The passive rule's finding exemption was dropped: findings are observed only by the
    `findings` pseudo-stage, so the general rule already reports them gone (the test row of a finding
    observed by `httpprobe`, a state that cannot occur, went with it).
  - The first render of a run whose baseline was saved no longer rewrites an identical `shown` table.
  - `store.ShownRow.Equal` replaces two copies of the comparison; `SaveShown` uses `Store.update`.
  - `headlineFields` is shared by the summary's findings and its `changes.findings`; the console's two
    findings lists share `findingList`.
  - Tests: `file(t, "changes.csv")`, `csvRows`, `allKeys` and `sorted` in place of hand-rolled copies;
    the `ref` helper, a dead test clause and a redundant `last` variable removed.
- **Skipped.**
  - Deriving entries from the file registry, or moving `entriesOf` into `output`, so the showing rules
    are written once: a restructuring of the registry well beyond this change.
  - Building the start scope with `buildScope` instead of a second `BuildScope`: the netblock-limit
    error would then fire before the baseline is loaded, changing what an over-limit run renders.
  - Writing only the delta of `shown`, caching the baseline's lookup map, and skipping the final pass's
    repeat diff: small gains for more state.
  - Running `shownSchema` once in `initDB`: the fresh-database transaction keeps the new schema atomic.
  - Defaulting `Kind.Change` to `Singular`: it would tie the found-line noun to the `changes.csv` label.
  - A `table` helper on the cli harness shared by three test files: outside this change.

# Verification

## Result

Checked against the goal, behaviours 1 to 6 and `## Out of scope` by reading every changed file,
the output registry, the derivers and the kinds that have output rows, and by running the targeted
tests and `make test`. `make test` passes apart from `TestHelp_Colour`, which fails on `main` too
(pre-existing, unrelated). `docs/plans/2026-11-build-order.md` does not exist in this checkout, so
it could not be read. The goal is met: a re-run writes `changes.csv` and ends the console summary
with a "Since last run" block, so nothing has to be diffed by hand.

- **B1 met.** `entriesOf` groups the labelled kinds the way the files list them and decides shown
  as they do (current and `Visibility.Shown`; a hostname not wildcard-only; a netblock an ASN input
  brought in; one entry per candidate or excluded value). `compare` gives `new`, `returned` and
  `gone`. Candidates are their own label; `candidate_rank`, `web_posture`, `provider_range` and
  the other evidence and internal kinds have none. Two readings to note: `email_posture` sits in
  the evidence block of `table.go` but is labelled, which is right because `email-posture.csv`
  lists it; and `returned` needs the entry to be on record and not shown *under the start scope*,
  so an entry an input added since the last run made visible is `new` (README states the exclusion
  case). Known limitation 1 stands (a root and a hostname candidate with one value are one entry;
  wildcard-only hostnames, `provider-hosts.csv` and `scope.csv`'s inputs are not listed), so B1 is
  not met for those rows.
- **B2 met.** Columns `change, kind, key, scope, severity` then `current, first_seen, last_seen`;
  a gone row keeps the baseline's scope and severity and is not current. The file is an ordinary
  registry entry, so it is replaced on every render and removed when empty. A first run (no
  records) has a nil baseline: no file, no events, no `changes` field (tested end to end).
- **B3 met.** The block comes last, after the candidate list and the deferred block, with the six
  new counts (returned included) and gone findings, then the new high and medium findings with the
  same severity styling as the main list. It is omitted on a first run. It always prints all seven
  lines, zeros included (known limitation 2), which the behaviour does not forbid.
- **B4 met.** `emitChanges` follows the `summary` event, one event per row in file order, and the
  `found` events are unchanged. An interrupted run emits no summary and so no `change` events; it
  still writes the file (B5).
- **B5 met.** The `shown` table is replaced on every render, the interrupt's included, and read
  once before the first derivation. `TestSignals_InterruptedRunWritesChanges` pins exit 130, the
  file for completed work, and a resumed run that does not repeat the interrupted run's rows.
- **B6 met.** The baseline is saved, not recomputed, so a certificate that expires overnight and a
  changed `--cert-expiry-days` each show as changes with no contact (tested). In a `--passive` run
  a row whose every observing stage is a target stage is not reported gone and is carried into the
  next baseline, so the next active run reports it. Findings and derived records are observed by
  pseudo-stages and are reported gone. Known limitation 3 (a target-only record hidden by a scope
  change is reported only by the next active run) is what the behaviour asks for.

Out of scope respected: only the run's start and end states are compared, and attribute changes of
a record that stayed shown are not reported.

*Changed:* `TestDiff_PassiveRule` pinned the derived-record case with a `candidate` row observed by
`candidate-rank`, which cannot occur (a candidate entry carries the stages of its root, hostname or
netblock records, and `candidate_rank` has no label). It now also has a `third party` row observed
by the `thirdparty-cname` deriver, the one labelled kind a deriver stores, and expects it gone in a
passive run. No production code needed a fix.

## Code review

`/code-review high --fix` over the changed files. Every fix below was checked against the spec;
none changes a behaviour or a test that pins one, and `make test` passes afterwards apart from the
pre-existing `TestHelp_Colour` (confirmed failing on `main`).

- **Fixed.**
  - `Store.Shown` read the `shown_saved` meta key through `Meta`, which reports any SQL error as
    "missing", so a failed read would have rebuilt the baseline from today's state and absorbed
    overnight changes (B5, B6). It now returns the error; only a missing row means never saved.
  - `changeOrder` (the `changes.csv` sort) restated `CompareChanges`; it now calls it, so the file
    and the `change` events cannot drift apart (B2, B4). Entries are unique by kind and key, so the
    order is unchanged.
  - Nine new tests in `internal/store/shown_test.go`, `internal/report/report_test.go` and
    `internal/output/output_test.go` lacked `t.Parallel()`, which `CLAUDE.md` requires.
- **Left unfixed.**
  - The baseline's `BuildScope` and the first pass's both run at startup. Reusing the first would
    move the netblock-limit error before the baseline and change what an over-limit run renders.
  - `sinceLastRun` in `internal/report/report.go` names the labels `address`, `web service` and
    `open port` as strings, not tied to `kinds`. Fixing it means `report` importing `kinds` or the
    summary event sending the seven counts itself (a change to `summary.changes`); a design call.
  - `SaveShown` rewrites the whole table when anything differs: a performance change that needs its
    own crash-ordering tests.
  - The redundant `kinds.Lookup` in `entriesOf` and the unread date value of `shown_saved`: too
    minor to change.

# Follow-ups

1. Decide whether the console block's labels should be tied to `kinds` (import the `kinds` label
   constants in `internal/report/report.go`, or have `changesSummary` in `internal/run/changes.go`
   send the seven counts) so renaming a `Kind.Change` label cannot silently zero a line.
2. Decide whether a candidate should be keyed by type and value, so a root and a hostname candidate
   with one value are two `changes.csv` rows like their two `candidates.csv` rows (`entriesOf` in
   `internal/run/changes.go`; known limitation 1).
3. Fix `TestHelp_Colour`, which fails on `main` as well:
   `go test ./internal/cli/ -run TestHelp_Colour -count=1`.
4. Rebuild golangci-lint with Go 1.27.3 or later (`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`),
   then run `golangci-lint run ./...`; it could not run on this change.
5. Restore `docs/plans/2026-11-build-order.md`, which `CLAUDE.md` asks every build to read and
   which is missing from this checkout, or remove the instruction from `CLAUDE.md`.
6. Optionally try a live re-run by hand: `make build && ./nyx recon example.com --passive --output-dir /tmp/nyx-out`
   twice, then read `/tmp/nyx-out/example.com/changes.csv` and the "Since last run" block.
