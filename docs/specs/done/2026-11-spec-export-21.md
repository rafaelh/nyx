# Spec 21: whole-engagement export

## Goal

Everything nyx has recorded about an engagement can be exported as machine-readable lines for
other tooling, without the CSV columns having to stay stable.

## Behaviours

1. `nyx export -e <name>` writes to stdout one JSON object per line for every record in the
   engagement, current or not: `kind`, `key`, `attrs`, `current`, `first_seen`, `last_seen`, the
   stages currently observing it (empty for records that are not current), and either `scope`
   (`in-scope`, `candidate`, `excluded`) for hostnames, roots, netblocks and excluded items, or
   `shown` (`true`/`false`) for every other kind, classified with the engagement's inputs and the
   current configuration. The engagement's inputs and exclusions are exported as their own lines
   (`kind` `input` and `exclusion`). The authorisation acknowledgement, netblock approval and
   settings are not exported.
2. `--output <file>` writes to a file instead, replacing an existing file atomically; a write
   failure exits 1. `--current` limits the export to current records and `--kind <kind>`
   (repeatable) to the given kinds; both filters combine. Kind names are listed by
   `nyx export --help`, and an unknown kind exits 2.
3. Secrets are never present: the export contains no API keys.
4. `export` does not take the run lock: it reads a consistent snapshot and works while a run is in
   progress, and never writes to the engagement. It exits 1 for an engagement that does not exist
   (creating nothing) or a directory that is not a nyx engagement, found under `--output-dir`
   or `output_dir` as for a run. It makes no network requests.
5. Target-supplied text (titles, banners) is sanitised as for console output.
6. The README documents the command and says that the stable names are the stored attribute
   names kept by the state database and the export's own field and kind names; finding attributes
   are derived and may change.

# Design

**Status:** ready to build (wave 1). **Depends on:** nothing; it reads kinds generically, so later
kinds are exported without change. It was re-checked against the built specs on 2026-11-14: the
functions it moves have the names given below, and one shared list was added to the move.
**Owns for Spec 20:** `run.BuildScope`.

## Decisions

- **`export` is a cobra subcommand** in `internal/cli/export.go`. The root keeps
  `cobra.ArbitraryArgs`; `export` is not a valid domain, so nothing is ambiguous. It takes `-e`
  (required), `--output`, `--current`, `--kind`, and the root's `--output-dir` and `--config`.
- **Read-only open.** `engagement.OpenReadOnly(dir)` creates nothing and takes no lock: a missing
  directory, or one without `.nyx/state.db`, is an error (exit 1). `store.OpenReadOnly` opens
  with `mode=ro` and `query_only`, checks the application id and never runs the schema.
- **One snapshot.** Every read happens inside one read transaction (`store.View(func(Reader))`),
  which under WAL is a consistent snapshot while a run writes. `Store.Records`, `Inputs` and
  `Observations` move onto a small `Reader` type over a querier so the store and the snapshot
  share them.
- **Classification reuses the run's rules.** The scope and inventory construction in
  `Runner.buildScope`, `inventoryData` and `asnNetblocks` moves to `run.BuildScope(src)`, where
  `src` gives the inputs, the records of a kind merged in the registry's stage order, and the
  observations of a kind by stage (ASN-expanded netblocks are found that way). The runner and
  `export` both call it, so the export cannot classify differently from a run. `buildScope` also
  builds the `kinds.Visibility` from the scope and inventory; `BuildScope` returns it, since the
  export's `shown` is that same decision. The list of kinds the build reads, `scopeKinds`, is now
  also the `reads` of the `candidate-rank` deriver in `derive.go`. It moves with the code and stays
  one list, or a kind added to the build later would stop re-ranking the candidates. What stays in
  the runner: the netblock-limit approval (a write) and building the egress policy. No egress is
  created by `export`: the command makes no network requests by construction.
- **Lines** are written in kind order, then key order: `kind`, `key`, `attrs`, `current`,
  `first_seen`, `last_seen`, `stages`, and `scope` for entity kinds or `shown` otherwise. Inputs
  and exclusions come first as `kind: "input"` (`type`, `value`, `added`) and
  `kind: "exclusion"`. `--kind` accepts the names of `kinds.All()` plus `input` and `exclusion`.
- **Text safety**: every string in `attrs` and `key` passes through `sanitize.Text`, then the
  redactor built from the configured keys (the store already redacts on write).
- **`--output`** writes a temporary file beside the target and renames it.

## Changes

- `internal/cli/export.go`; `cli.go` registers the subcommand and its help (kind list).
- `internal/engagement/engagement.go`: `OpenReadOnly`. `internal/store/store.go`:
  `OpenReadOnly`, `View`, `Reader`.
- `internal/run/scopebuild.go`: `BuildScope` (moved code); `runner.go` calls it.
- `README.md`: the command, and which names are stable.

## Tests

`internal/cli/export_test.go`:

- Every record of a populated engagement is exported once with the right `scope` or `shown`,
  including not-current ones with empty `stages`; ASN-expanded netblocks are `in-scope` and merged
  `attrs` equal a run's; inputs and exclusions are lines; no
  acknowledgement, netblock approval or settings appear.
- `--current`, repeated `--kind` and both together; an unknown kind exits 2.
- `--output` replaces a file atomically; an unwritable path exits 1.
- A configured key value appears nowhere; a title with terminal escapes is sanitised.
- Export while a run holds the lock succeeds and matches a consistent state; the engagement
  directory's files are byte-identical before and after; a missing engagement and a
  non-engagement directory exit 1 and create nothing; the canaries see no traffic.

## To verify while building

Opening a WAL database read-only may create `-shm` when no run is active. If it does, open with
`immutable=1` when no `-wal` file exists, so the "never writes" test holds.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **A record that is no longer current has no attributes (Spec 3, follow-up 1).** The store keeps
  them only from current observations, so such a record is exported with empty `attrs`. The
  README says so beside the field list. Do not rebuild them from the key.
- **Derived records (Spec 15).** `finding` and `candidate_rank` records are exported like any
  other, and their `stages` name a pseudo-stage (`candidate-rank`), not a stage the user can
  `--redo`. The README's note on finding attributes covers both: they are derived and may change.
- **`Kind` is not comparable (Spec 3).** It holds `Found`. Match `--kind` values against
  `Name()`; never compare two `kinds.Named` values or use one as a map key.
- **Merge order (build-order plan).** Specs 8, 11 and 16 each add a kind to the scope build.
  Merge this spec before them, so they edit `run.BuildScope` and not the runner.

## Out of scope

Importing; formats other than JSON lines; exporting settings.

# Implementation

## Develop

`nyx export` is a cobra subcommand in `internal/cli/export.go`, registered in `Execute`. It
validates `--kind`, loads the configuration (for `output_dir` and the key redactor), opens the
engagement with `engagement.OpenReadOnly` and reads everything inside one `ReadOnly.View`. The
lines are built in memory and written after the transaction ends, to stdout or through a temporary
file beside `--output` that is synced and renamed into place.

- **Store.** `store.Reader` holds `Records`, `Inputs` and `Observations` over a querier, and the
  `Store` methods delegate to it. `store.OpenReadOnly(path)` opens with `mode=ro` and `query_only`,
  checks the application id and schema version (`checkDB`, shared with `initDB`) and returns a
  `store.ReadOnly`, which has only `View` (one read transaction handing out a `Reader`) and
  `Close`. It is its own type, not a `Store` made to look closed, so a write does not compile.
- **Engagement.** `engagement.OpenReadOnly(dir)` stats the directory and `.nyx/state.db`, creates
  nothing and returns the `ReadOnly`. `engagement.ParseInputs` was split out of `Inputs` so the
  export can group the snapshot's input rows.
- **Scope build.** `run.BuildScope(in, src ScopeSource)` in `internal/run/scopebuild.go` is the
  moved code (`buildScope`'s construction, `inventoryData`, `asnNetblocks`) and returns a `Built`
  with the `Scope`, `Inventory`, `Visibility` and the candidate names. `scopeKinds` moved with it
  and is still the `reads` of the `candidate-rank` deriver. `ScopeSource` has two methods, the
  current records of a kind and the observations of a kind by stage. The runner keeps the signature
  check, the netblock-limit approval and the egress policy, and reads through `runnerSource`, which
  keeps its record cache and, through an optional interface, its provider-range index cache.
- **Classification.** `kinds.Visibility.Placement(kind, rec)` returns the `scope.Class` that
  `category` already used for the entity kinds, and `category` now calls it. `kinds.Lookup(name)`
  gives the export a handle for each kind it walks by name, so it asks the existing `Shown`. A
  netblock is `in-scope` or `candidate`, and an `excluded` record is always `excluded`.
- **Lines.** An `exportLine` struct fixes the field order. Inputs come first (stored order, by
  type), then exclusions, then records in `kinds.All()` order and the store's key order.
  `--current` drops only not-current records; the input and exclusion lines have no currency and
  are always kept unless `--kind` leaves them out. An exclusion line has no `type`. Strings in
  `key` and `attrs` (and the input values) go through `sanitize.Text` and then the redactor.
- **Tests.** `internal/cli/export_test.go` builds one engagement with real `asn` and fake stages
  and exports it. Each behaviour has a test: every record once with `scope`/`shown`, not-current
  records with empty `attrs` and `stages`, the ASN-expanded netblock, the merge in registry order
  (stages named so that name order would give another result), inputs and exclusions, nothing
  from `meta`; `--current`, repeated `--kind` and both; an unknown kind and a missing `-e` (2);
  `--output` replacing a file by rename, and two unwritable targets (1, the old file kept, no
  temporary file left); a key that only the export's redactor can mask; a title with escape
  sequences; export during a run that holds the lock, equal to the state before it; byte-identical
  directory snapshots; a missing engagement, an empty directory, a directory with files and an
  empty `.nyx` (1, nothing created); the canaries seeing no traffic; the engagement found under
  `NYX_OUTPUT_DIR`. `store_test.go` and `engagement_test.go` cover the read-only opens, that they create
  nothing and that a `View` is one snapshot. The new tests failed on their assertions before the code existed (the command was read
  as a domain argument); `TestExport_RequiresEngagementName` passed already, by coincidence, and
  now pins the required flag.
- **To verify while building (resolved).** Opening a WAL database read-only does create `-wal` and
  `-shm` when no run is active: `TestOpenReadOnlyCreatesNothing` fails without `immutable=1`. The
  store therefore opens immutable when no `-wal` file exists.
- **Mutation checks.** `## Tests` marks none, so these were spot checks of the riskiest rules, each
  undone by hand: dropping the redactor fails `TestExport_NoSecrets`; dropping `sanitize.Text`
  fails `TestExport_SanitisesTargetText`; merging in name order instead of the registry's fails
  `TestExport_MergeFollowsRegistryOrder`; ignoring `--current` fails `TestExport_Filters`; and
  removing `immutable=1` fails `TestOpenReadOnlyCreatesNothing`.
- **README and plans.** The README has an "Exporting an engagement" section, with the stable names,
  and the exit-code row mentions export. The build-order plan marks Spec 21 and `run.BuildScope`
  built. CLAUDE.md names the new seams.

## Known limitations

- **Behaviour 4 (never writes).** The immutable open is chosen by whether `-wal` exists when the
  export starts. A run that starts in the instant between that check and the first read could be
  read while it writes, and the read could be inconsistent. The window is a few microseconds and
  no test covers it. Opening with a shared lock on the run's lock file would close it, but the
  spec says the export does not take the run lock.
- **Behaviour 4 (stale log).** A `-wal` left by a killed run is opened read-only normally. One
  manual check, on a run killed by a closed pipe, exported and left `state.db`, `-wal` and `-shm`
  byte-identical. No test covers it. While a run is active the `-shm` is shared with it, and any
  reader updates its read marks, so "byte-identical" is tested only with no run.
- **Behaviour 1.** `--current` does not apply to inputs and exclusions, which have no currency. An
  `excluded` record is always `scope: excluded`, and a netblock key that does not parse is `candidate`.
- **Behaviour 5.** Sanitising removes control characters from every string in `attrs`, so a stored
  value that legitimately contains a newline (a banner) is exported with the newline removed, as the
  CSV files show it.

## Simplify

Four reviewers (reuse, simplification, efficiency, altitude) went over the change. Fixed:

- **Read-only store.** `store.OpenReadOnly(path)` returns its own `store.ReadOnly` type, which has
  only `View` and `Close`. It replaces a `Store` faked as closed with a dummy channel, so a write is
  now a compile error rather than a silent drop. `engagement.OpenReadOnly(dir)` returns that type,
  and this removes `Engagement.Close`'s `lock == nil` case, the duplicate stat of `state.db`, both
  nil-clock fallbacks and the unused `Options`. `Store.View` was removed because nothing used it.
- **Store duplication.** `initDB` calls `checkDB` for the application id and version, and a `dsn`
  helper builds the escaped database name for both opens.
- **Placement.** `Visibility.Placement(Named, rec)` returns `scope.Class` (the export writes its
  `String()`). The `Placed*` string constants and `ShownByName` are gone. The new `kinds.Lookup(name)`
  gives a read-only handle, so the export calls the existing `Shown`.
- **Scope build seam.** It is now `run.BuildScope(in, src)`. `ScopeSource` keeps only
  `CurrentRecords` and `Observations`, and the runner's provider-range cache is an optional
  unexported interface. `Built.Inputs`, `snapshotSource.Inputs/ProviderRanges` and the exported
  `run.IndexRanges` were removed.
- **Export command.** The unused `Deps` parameter and the `outputDir` field are gone. `--output-dir`
  is the flag `config.RegisterFlags` defines, and `--config` shares its help text through
  `configFlagUsage`. The exclusion input kind is `engagement.InputExclusion`. The input and exclusion
  split no longer mutates a line after building it. `encodeLines` encodes straight into the
  buffered writer. `BuildScope` is skipped when `--kind` names only `input` and `exclusion`, and a
  kind's records are dropped from the snapshot cache once written.
- **Tests.** The export tests parse lines with the harness's `jsonLines` (`exLine` is the
  harness's `event`), and use `slices.Sorted(maps.Keys)` and `maps.Equal` in place of hand-written
  helpers and diff loops. Weak assertions are now exact: the registry-order merge checks the
  `shared.a.com` title in `web-services.csv`, the sanitised title is exact, help lists the kinds
  line exactly, and a record line has exactly 8 fields. The store and engagement tests read through
  `View`, and the runtime write-refusal assertions went with the write methods.

Skipped:

- `cleanAttrs`/`cleanValue` re-walk the attribute tree that `config.Redactor.Any` walks. A shared
  mapper would mean changing `config` or `sanitize` for one caller, and sanitising still needs a
  walk of its own.
- `render` runs `asnNetblocks` again where `BuildScope` already computed it. That predates this
  change, and it costs one indexed query per render.
- `snapshotSource.CurrentRecords` filters on each call instead of caching the current slice as the
  runner's `recordsCache` does. It is called once per scope kind.
- Temp-file-then-rename in `writeExport` duplicates the logic in `internal/output`, which is inline
  in `Render`, tied to `.nyx/tmp` and to fault points, and is not a reusable helper.
- `"exclude"` in `internal/output/output.go` was left alone, because it is outside this change.
- Streaming the lines from inside the transaction was rejected: it would hold the read snapshot
  open, and stall a running run's checkpoints, for as long as the write takes.

# Verification

## Result

All six behaviours and the goal are met. `make test` passes; `golangci-lint run ./...` reports
five issues, all in files this change does not touch (`sources_keyed_test.go`,
`sanitize_test.go`, `providerranges_test.go`).

- **Goal.** `nyx export` writes every record, input and exclusion as JSON lines whose field and
  kind names are fixed in `exportLine`/`exportInputLine`, independent of the CSV columns.
- **B1: met.** Every record of every kind in `kinds.All()`, current or not, is exported once, in
  kind then key order, with `kind`, `key`, `attrs`, `current`, `first_seen`, `last_seen` and
  `stages` (from current observations only, so `[]` for a record that is not current). Entity
  kinds (hostname, root, netblock, excluded) carry `scope` from `Visibility.Placement`, which the
  summary's `category` now also calls; every other kind carries `shown` from the existing `Shown`.
  Both come from `run.BuildScope`, the code the runner itself now calls, built from the snapshot's
  inputs and records merged in the registry order (`d.Stages`, as for a run), so ASN-expanded
  netblocks are `in-scope` and merged attributes equal the CSV's (tested with stages named against
  the registry order). Inputs and exclusions are their own lines first; nothing from `meta`
  (acknowledgement, netblock approval) or the settings is read. A netblock key that does not parse
  is `candidate`, where the summary leaves it uncounted.
- **B2: met.** `--output` writes a synced temporary file beside the target and renames it; a
  failed create, write or rename exits 1 and leaves the old file and no temporary file.
  `--current`, repeated `--kind` and both combine; `--kind` is validated against the kind names plus
  `input` and `exclusion` before anything is opened, and an unknown one exits 2. `nyx export
  --help` (and `nyx help export`) ends with the kind list. `--current` keeps the input and
  exclusion lines, which are not records and have no currency.
- **B3: met.** Every string in `key`, `attrs` and the input values passes through the redactor
  built from the configured keys (file and `NYX_KEYS_*`), on top of the store's redaction on
  write; error messages go through the same redactor.
- **B4: met** (see the change below). The export opens with `engagement.OpenReadOnly`, which
  creates nothing and takes no lock, and `store.OpenReadOnly` (`mode=ro`, `query_only`, the
  application id checked, no schema). Everything is read in one read transaction. A missing
  engagement, a plain or empty directory and an empty `.nyx` exit 1 and create nothing; the
  engagement is found under `--output-dir`, `NYX_OUTPUT_DIR` or the config file's `output_dir`.
  No egress is built, and the canaries see no traffic. The stale-log case (a `-wal` left by a
  killed run) is opened read-only under WAL and was checked by hand only during development.
- **B5: met.** `sanitize.Text` is applied to every string, map key included, before redaction; a
  banner's newline is removed, as in the CSV files.
- **B6: met.** README "Exporting an engagement" documents the command, its lines and filters, the
  empty `attrs` of a record that is not current, the derived records and their pseudo-stages, and
  says which names are stable (stored attribute names and the export's field and kind names) and
  that finding attributes are derived and may change. The exit-code table mentions export.

Changed during verification:

- **A run starting during an immutable read (B4).** With no `-wal` the database is opened
  `immutable=1`, which takes no lock. The known limitation called the window "a few microseconds",
  but it lasts for the whole read: a run that starts after the check can checkpoint into the file
  while the export reads it. `ReadOnly.View` now checks, after an immutable read, whether a `-wal`
  appeared or the file's size or modification time changed, and if so opens the database again
  (under WAL when a run still holds it) and reads again, up to three times. The export resets its
  lines on each call. `TestViewRereadsWhenARunStarts` pins it (it fails without the check). The
  first limitation under `## Known limitations` is therefore closed.
- **No completion command.** Adding the first subcommand made cobra add its default `completion`
  command to `nyx`, which the spec does not ask for and the README does not document. It is
  turned off (`CompletionOptions.DisableDefaultCmd`), and `TestExport_HelpListsKinds` checks the
  root help lists `export` and no `completion`. `nyx help <command>` remains, as cobra's help.

## Code review

`/code-review high --fix` made seven findings and applied two fixes; `make test` passes after
both.

- **Fixed (B2, `--output`).** `writeExport` set the new file to 0644 whatever the umask, so
  replacing a 0600 export widened it. The temporary file is now created with 0666 and `O_EXCL`
  (the umask decides), and a file being replaced keeps its permissions. The atomic rename is
  unchanged.
- **Fixed (no behaviour).** `initDB` read the application id and version, then `checkDB` read them
  again. Both now share `dbIDs` and `checkIDs`.

Left unfixed:

- **A run that ends between the `-wal` check and the first read (B4).** The export then opens a WAL
  database under WAL with no log present, and SQLite can create `-shm`/`-wal` beside it. The window
  is the few instructions between `os.Stat` and the first query, and the files are the ones the
  next run creates anyway. Closing it would need a different open strategy; a decision for the
  user (Follow-ups). An export still reading when a run closes leaves the run's own log files in
  place, which is SQLite declining to delete them under a reader, not the export writing.
- **`export` loads the whole configuration.** A bad unrelated setting (a missing wordlist file)
  makes `export` exit 2. B4 asks for the engagement to be found "as for a run", which this does;
  a narrower load would change `internal/config`. Left for the user.
- **An unparsable netblock key is `candidate` in the export and uncounted in the summary.** Rare,
  and already listed under `## Known limitations`.
- **`moved` treats a `-wal` stat error as a change.** Not a bug: such an error also makes the open
  choose WAL, so there is no immutable read to redo.
- **`kinds.Lookup` repeated per kind in the export loop.** A trivial cost.

# Follow-ups

1. Move or delete the untracked `config.yaml` in the repository root. It holds real API keys, was
   not part of this change and was not committed. Its place is
   `~/.config/nyx/config.yaml` (`mv /home/rafael/git/recon/config.yaml ~/.config/nyx/config.yaml`),
   and if any of its keys may have been shared, rotate them with each provider.
2. Check the stale-log case of B4 by hand once more: start a run, kill it with
   `kill -9`, then compare `sha256sum /tmp/nyx-out/<name>/.nyx/state.db*` before and after
   `nyx --output-dir /tmp/nyx-out export -e <name> > /dev/null`. No test covers it.
3. Decide whether to close the race in which a run ends between the export's `-wal` check and its
   first read (SQLite may then create `-shm`/`-wal`), in `store.OpenReadOnly`
   (`internal/store/store.go`).
4. Decide whether `nyx export` should load only `output_dir` and the keys, so an unrelated bad
   setting does not stop it (`runExport` in `internal/cli/export.go`, `config.Load` in
   `internal/config`).
