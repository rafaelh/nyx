# Spec: Procedures and jobs

## Goal

nyx names its units of work after reconnaissance: a *stage* runs *checks*. nyx may later do work
that is not reconnaissance, and these names won't fit it. So nyx uses "procedure" for what it calls
a stage today. In MITRE ATT&CK, a procedure is one concrete way of carrying out a technique. It uses
"job" for what it calls a check today. It uses "analysis" for a record nyx produces itself rather
than one a procedure observes (findings, candidate ranks, third parties from CNAMEs, and addresses
egress refused to dial), which today is a deriver or guard stored under a pseudo-stage (amended by
D6). All three changes apply wherever nyx uses the old words as its own
terms, from the command line and the `--json` output through to the user guide and the code.

Done when:

- `nyx help procedures` replaces `nyx help stages`;
- nothing nyx writes, and none of the places listed in B5, uses "stage", or "check" outside the
  allow list in B4, in nyx's sense (amended by D13).

## Behaviours

B1. `nyx help procedures` lists the procedures in run order. The list has the contact, key and
description columns, the marker for procedures `--skip` refuses, and the footer that
`nyx help stages` has today, all in the new words. `nyx help stages` fails with exit 2, as any
unknown help topic does.

B2. Every message nyx writes says "procedure" and "job" wherever it says "stage" and "check" in
nyx's sense today. This covers help, flag and completion descriptions, errors and hints, the console
log (`--debug` lines included), the summary, and `nyx setup`. For example:

- `--redo <procedure>` performs every job of one procedure again;
- the failed-jobs error reads `16 jobs failed: crtsh 2, …`;
- the console log's per-procedure line reads `crtsh done (12 jobs, 0 failed)`;
- the deadline summary reads `Stopped by the deadline: 40 jobs completed, 3 cancelled`;
- `--skip`'s description reads "Procedure to turn off";
- the setup Skip tab lists procedures.

Uses of "check" on the allow list in B4 are unchanged. So are the procedure names (`crtsh`,
`origincheck`, …), the `--redo` and `--skip` flags, and the `skip` setting's values.

B3. In the recon `--json` envelope and in `nyx recon export` record lines, every key named after
stage or check is renamed to the procedure or job equivalent, and the old key is no longer written.
This covers `failed_checks`, `meta.checks_completed`, `meta.checks_cancelled`, the `stage` key of
the `failed_checks`, `deferred` and `not_configured` rows, and export's `stages`.

Export never lists as a procedure anything that `nyx help procedures` does not list. Some records
come from an analysis rather than being observed by a procedure: findings, candidate ranks, third
parties derived from CNAMEs, and excluded addresses that egress refused to dial. Such a record names
the analysis that produced it under a key of its own, `analysis`. Every record line has
`procedures`, an empty list when no procedure observes the record now; `analysis` is written only
when an analysis produces the record now, so a record that is both observed and produced by an
analysis has both filled. The user guide calls these analyses and lists every value that key can
take. (amended by D2, D5, D6)

B4. The allow list. These uses of "check" or "checks" are ordinary English or not nyx's unit of
work, so they stay:

- "check" as a verb, or as a noun meaning a test of a value or fact. Examples: the abusive-network
  check, port-checked, `could not check`, "TCP ports to check", "the `ports` procedure checks only
  the configured port list";
- the `origincheck` procedure, its `--origincheck-max-candidates` flag and `origincheck.*` settings;
- the `port_check` and `origin_check` record kinds;
- validation of config, keys and input (`config.Check`, the key test);
- vet and lint checks, and identifiers from the Go standard library and third-party modules.

Any other use of "check" or "checks", meaning a unit of work a procedure performs and records, fails
the search in B5.

B5. Search for "stage", "stages", "deriver", "derivers", "check" and "checks", case-insensitively,
after splitting names at case changes, underscores, hyphens and dots. "stage", "stages", "deriver"
and "derivers" must not appear at all; "check" and "checks" may appear only as B4 allows. The verb
"derive" ("derived", "derives") is ordinary English and stays. The search covers:

- README.md and docs/*.md, docs/todo.md included;
- CONTEXT.md, the package docs and CLAUDE.md;
- nyx's own skills and agents under .claude/;
- Go identifiers, file and directory names, and test names;
- the state database's table, column and index names.

It does not cover docs/specs/ (finished specs or this one) or the third-party golang-* skills.

## Out of scope

- What an engagement created before the rename does under the new binary. This is undefined:
  nothing is released, so no old engagement needs to work.
- Refusing such an engagement with a clear error. Declined for the same reason.
- ATT&CK technique IDs, tactics or version anywhere, whether in help, JSON or the user guide. The
  user judged they add little.
- A `nyx procedures` subcommand. The list is a help topic only.
- Accepting the old words as aliases (such as `nyx help stages`). This is a clean cut.
- A permanent test for B5's search. The user chose a one-off search (D12): "check" as a verb can't
  be told from the unit of work mechanically.
- Bumping the schema version or migrating old state databases. That is the "refuse with a clear
  error" declined above.

# Design

## External facts

- **An unknown help topic exits 2.** `nyx help nosuch` writes
  `Error: unknown command "nosuch": the commands are …, stages (INVALID_INPUT)` and exits 2.
  *Confirmed live* (built from `a79fd35`, 2026-11-24). So B1 needs no new code to fail
  `nyx help stages`, only the topic's removal.
- **SQLite accepts the new schema names.** `jobs`, `procedure`, `producer`, `job_key`,
  `observations_job` and `producers` are not reserved words. *Confirmed live* with `sqlite3`
  (`CREATE TABLE jobs(procedure TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY(procedure,key))` and
  the rest of D3 succeed). `modernc.org/sqlite` has the same parser.
- **MITRE ATT&CK defines a procedure as a concrete implementation of a technique.** *From docs*
  (the Goal and CONTEXT.md). Nothing in the design rests on it, and no ATT&CK ID or wording goes in
  the product (out of scope).

No external API, list or data is fetched or embedded.

## Decisions

**D1. Code vocabulary.** The renames are mechanical, with `gopls rename` and `git mv`:

- `run.Stage` → `run.Procedure`, `run.Check` → `run.Job` (`Key`, `Input`, `Cost`),
  `Stage.Checks()` → `Procedure.Jobs()`.
- `ErrAbortStage` → `ErrAbortProcedure`, with the text "abort procedure".
- `internal/stages/` → `internal/procedures/`. The subpackages keep their names.
- `internal/run/stage.go` → `procedure.go`, and `stagerun.go` → `procedurerun.go`
  (`stageRun` → `procedureRun`, `stageStats` → `procedureStats`).
- `internal/cli/stages_topic.go` → `procedures_topic.go` (`stagesHelp` → `proceduresHelp`), and
  `testdata/plain/help-stages.txt` → `help-procedures.txt`.
- `defaultStages()` → `defaultProcedures()`, and `stageNames` → `procedureNames`.
- `run.Config.Stages`, `cli.Deps.Stages` and `setup.Info.Stages` → `Procedures`; `setup.Stage`
  (`internal/setup/backend.go`) → `setup.Procedure`.
- `report.StageCount` → `ProcedureCount`, and `StageReason` → `ProcedureReason`.
- `store.CheckKey` → `JobKey`, `ObsRow.CheckKey` → `JobKey`,
  `Observer{Stage, CheckKey}` → `{Procedure, JobKey}`, `Store`/`Reader.Observations(kind, stage)`
  → `(kind, procedure)`, and `writeStmts.checkObs` → `jobObs`.
- `deriver` → `analysis`: `newDerivers` → `newAnalyses`, `storeDerived` → `storeAnalysis`, and
  `deriveInput` → `analysisInput`. The file `derive.go` can keep its name, since "derive" is
  allowed.
- Test names follow, such as `TestSRV_FailureFailsOnlyTheSRVCheck` → `…SRVJob`.

Comments and string literals in every Go file are reworded too. The Goal says "through to the
code", and the B5 search reads every line of Go anyway. The optional interfaces (`WorkerCounter`,
`Retiring`, `Evidencer`, `CandidateSourcer`, `ASNExpander`, `Budgeted`, `Historical`) keep their
names. The `Record.Current` comment ("while a completed check still observes the record") is
already wrong: a record is current while any observation of it exists. It becomes exactly that.

**D2. Procedures and analyses are split by name, at read (user).** The store keeps one neutral list
per record:

- `store.Record.Stages`, `store.ShownRow.Stages` and `inventory.Host.Stages` → `Producers`: the
  sorted names of the procedures and analyses observing the record now.
- Only export splits the list. `procedures` holds the producers that are registry names, and
  `analysis` holds the producer that is an analysis name (D6). A producer that is in neither (a
  procedure since removed) is dropped.
- The other readers keep the whole list, unchanged in behaviour:
  - `historyOnly` (`derive.go`);
  - the passive carry in `changes.go`;
  - the inventory's generator test;
  - `shodan/host.go`;
  - `urls.csv`'s `found_by`, which no analysis can reach, since no analysis writes `url`.

**D3. Schema.** There is no version bump and no migration (out of scope):

```sql
CREATE TABLE jobs(procedure TEXT NOT NULL, key TEXT NOT NULL, completed_at TEXT NOT NULL,
                  PRIMARY KEY(procedure, key));
CREATE TABLE observations(kind TEXT NOT NULL, key TEXT NOT NULL, producer TEXT NOT NULL,
                          job_key TEXT NOT NULL, attrs TEXT NOT NULL, seen TEXT NOT NULL,
                          PRIMARY KEY(kind, key, producer, job_key));
CREATE INDEX observations_job ON observations(producer, job_key);
-- shownSchema:
CREATE TABLE IF NOT EXISTS shown(kind …, key …, producers TEXT NOT NULL, scope …, severity …, …);
```

`inputs`, `records` and `meta` are unchanged. The meta key `redo:<procedure>` keeps its form.
Every SQL string in `store.go` follows these names.

**D4. Analyses and guard write no jobs row (user; its own commit).**

- **Today.** `storeDerived` calls `Complete(name, "derived", obs)`, and `guard` calls
  `Complete("guard", value, obs)`. Both insert a `checks` row.
- **The new write.** The store's writer queue gets one more operation, used by analyses and
  guard. It does what a completion does without the jobs insert: it upserts the observations under
  `(producer, job_key)`, deletes the ones that pair no longer produces, refreshes `current` and
  bumps the kind versions. `Complete` (procedures only) is that plus the jobs row. Name it, for
  example, `Store.Put(producer, key string, obs []Obs)`. Analyses use job key `""` in place of
  `"derived"`, and guard keeps one key per address.
- **Why nothing visible changes:**
  - `current` depends only on observations existing (`refreshSQL`).
  - `Observers` joins observations to `jobs` and is read only for the candidate kinds (root,
    hostname, netblock, asn, organisation), which no analysis or guard writes.
  - `Completed`, `Redo`, `FinishRedo` and `Retire` are only called with procedure names.
- **Why do it.** The `jobs` table then holds only jobs.

**D5. The export record line (user).**

- `procedures` replaces `stages`. It is a sorted list, always present, and `[]` when no procedure
  observes the record now.
- `analysis` is new: a string with `omitempty`, written only when an analysis produces the record
  now.
- Field order: `kind, key, attrs, current, first_seen, last_seen, procedures, analysis, scope |
  shown`.
- Some examples:
  - A current finding has `procedures: []` and `analysis: "findings"`.
  - A third party that a procedure saw and a CNAME implies has both.
  - A non-current record has `procedures: []` and no `analysis`.

**D6. Analysis names are declared once, and "analysis" covers guard (user).**

- Today's names stay, since they are already in export: `findings`, `candidate-rank`,
  `thirdparty-cname` and `guard`.
- `internal/run` declares them once, as consts plus an exported `AnalysisNames()` (or a var) in
  run order. `newAnalyses` and `guard` use the consts, so there is no second hand-kept list.
- The definition is widened (Goal amended): an analysis is a record nyx produces itself rather than
  one a procedure observes. That wording goes in the `internal/run` package doc, CONTEXT.md and
  `docs/output.md`.
- Tests pin the invariants D2 relies on:
  - `newAnalyses()`'s names plus `guard` equal `AnalysisNames()`;
  - no analysis name is a registry name;
  - each analysis writes a different kind, and none writes a kind a procedure writes, apart from
    `third_party`. This is why a record has at most one analysis.

**D7. Envelope keys.**

- `failed_checks` → `failed_jobs`.
- `meta.checks_completed` → `meta.jobs_completed`, and `meta.checks_cancelled` →
  `meta.jobs_cancelled`.
- `stage` → `procedure` in the `failed_jobs`, `deferred` and `not_configured` rows
  (`internal/report/summary.go`, `envelope.go`).

**D8. Event recorder.** `report.Event` is internal: it is teed to `cli.Deps.Events` and never
written by `--json`. The event type `"stage"` → `"procedure"`, and its field `"checks"` →
`"jobs"`. The doc comment listing the event types (`report.go`) and the test readers follow.

**D9. Fault point.** `in-check-tx` → `in-job-tx` (`store.go`, `crash_test.go`, CLAUDE.md).

**D10. The help topic.**

- The topic is `procedures`, with the short description "The procedures, in run order, and what
  each one contacts and does".
- The heading is "Procedures, in the order each pass runs them:", and the column is `PROCEDURE`.
  The column widths come from the longest name, as today.
- The footer is today's text in the new words:
  - "Third-party procedures ask public sources and resolvers, and run under --passive. Target
    procedures contact the target's own systems: …".
  - "A procedure with a KEY needs keys.<KEY> …".
  - "--redo <procedure> performs every job of one procedure again, and --skip <procedure> turns one
    off, except the procedures marked *, which other procedures' safety depends on."
- There is no alias. `nyx help stages` fails through the existing unknown-command path (External
  facts).

**D11. Messages.** These are reworded with the same structure and values. Goldens under
`internal/cli/testdata/plain` are regenerated, and each diff is reviewed so that only the words
change.

- `recon.go`:
  - `unknown procedure %q for --redo` and `… for --skip or the skip setting`, with the hint
    `valid procedures: …`;
  - `procedure %q is named in both --redo and --skip`;
  - `procedure %q cannot be skipped: other procedures' safety depends on it`, with the hint
    `procedures that can be skipped: …`;
  - the annotations "Procedures accepted by --redo and --skip" and "Procedures --skip refuses".
- Flag descriptions:
  - `--redo`: "Re-perform every job of one procedure (see nyx help procedures)".
  - `--skip`: "Procedure to turn off for this run (…; see nyx help procedures)".
  - `--concurrency`: "Workers per procedure".
  - `--debug`: "each failed job (recon)".
- `config.go:690`: `… cannot be combined with procedure names`.
- The `Long` text of `completion.go` and `setup.go` ("the procedures to skip"; "checks addresses"
  is a verb and stays).
- `partial.go`:
  - `%d jobs failed: %s`;
  - `the deadline (--timeout %s) stopped the run: %d jobs completed, %d cancelled`;
  - `; failed jobs: `;
  - `raise --timeout: no job succeeded within %s`.
- `runner.go`:
  - `not authorised, so these procedures are left out: …`;
  - `%d jobs will be retried next run`;
  - the debug line `%s job %s failed: %s`.
- `report.go`: ` (%s jobs, %s failed)`, also in the palette sheet.
- `summary.go`: `Stopped by the deadline: %d jobs completed, %d cancelled` and
  `Failed jobs (retried on the next run; --debug shows each failure)`.
- `egress/thirdparty.go`: `host %s is not one of this procedure's sources`.
- `procedures/rdap`: `unknown job`.
- The setup Skip tab takes its descriptions from the renamed help entries.

Non-Go text that the Goal reaches is reworded too:

- the comment at `.golangci.yml:23`;
- the comment at `internal/config/builtin/sensitive_paths.yaml:7-8` ("creates new checks").

**D12. The B5 search is one-off, with an allow list (user).** There is no permanent test. The
script below removes B4's allowed phrases from each line, then splits tokens at non-alphanumerics,
lower→upper changes and acronym boundaries (`SRVCheck` → `SRV Check`). It prints each remaining
hit, for a path and for every line of a `.go`, `.md`, `.sh` or `.json` file.

- `stage`, `stages`, `deriver` and `derivers` must have **zero** hits.
- Each remaining `check` or `checks` hit is reviewed against B4. The output, with a one-word reason
  per kept hit, is saved as the verification artefact under `## Develop`/`## Result`.
- Run it at the end of `/spec-develop` and again in `/spec-verify`.

Save the script as `<scratch>/vocab.pl`, outside the repo:

```perl
#!/usr/bin/env perl
# B5 search. Reads paths on stdin; prints path:line:word (line "path" for the path itself) for each
# token stage|stages|deriver|derivers|check|checks, after removing the B4 allow-list phrases and
# splitting tokens at non-alphanumerics and case changes (fooBar, HTTPCheck).
use strict; use warnings;
my %bad = map { $_ => 1 } qw(stage stages deriver derivers check checks);
my @allow = map { qr/$_/i } (
  'port[_-]?checks?(?:ed)?', 'origin[_ ]?checks?', 'config\.Check', 'key[ -]?checks?', 'go-check',
  'health-check', 'abusive-network checks?', 'could not check', 'ports to check', 'vet and lint checks',
  'lint checks', 'mutation checks?', 'last_checked',
);
sub hits { my ($s) = @_; $s =~ s/$_/ /g for @allow; my @w;
  for my $t ($s =~ /[A-Za-z0-9]+/g) {
    $t =~ s/([a-z0-9])([A-Z])/$1 $2/g; $t =~ s/([A-Z]+)([A-Z][a-z])/$1 $2/g;
    push @w, grep { $bad{$_} } map { lc } split / /, $t;
  } return @w; }
while (my $f = <STDIN>) { chomp $f;
  print "$f:path:$_\n" for hits($f);
  next unless $f =~ /\.(go|md|sh|json)$/;
  open my $fh, '<', $f or next; while (my $l = <$fh>) { print "$f:$.:$_\n" for hits($l) } }
```

```sh
{ git ls-files ':!docs/specs' ':!.claude/skills/golang-*'; git ls-files --others --exclude-standard CONTEXT.md; } \
  | perl <scratch>/vocab.pl > <scratch>/b5.txt
grep -E ':(stage|stages|deriver|derivers)$' <scratch>/b5.txt   # must print nothing
grep -E ':(check|checks)$' <scratch>/b5.txt                      # review each against B4
```

The schema names are in Go strings in `store.go`, so this covers them. At the base commit it reports
1,476 `stage`, 691 `stages`, 49 `deriver`, 9 `derivers`, 1,431 `check` and 838 `checks`.

**D13. The Done-when is qualified with "in nyx's sense" (user).**

- nyx still writes "stage" where it echoes input (`unknown command "stages"`) or reports target
  data.
- Target vocabulary stays:
  - the built-in wordlist entry `stage` (a DNS label);
  - `sensitive_paths.yaml`'s match on `.gitlab-ci.yml`'s `stages:` key;
  - the test data in `internal/config/testdata/sensitive/` and
    `internal/cli/testdata/words-default.txt`.
- threatdata's `last_checked` is a check of a fact (B4), so it stays too.

**D14. The skill's git wording.** `.claude/skills/spec-develop/SKILL.md` says "stage the test
files with `git add` (stage only, never commit)" and "stay staged". It is reworded to "add the test
files to the index with `git add` (never commit)" and "stay in the index", because B5 bans "stage"
outright in nyx's skills.

**D15. Docs.**

- **Package docs.** `internal/run`'s package doc defines procedure, job and analysis (D6's
  wording), since CLAUDE.md says domain terms live in the owning package's doc. `store`, `report`
  and the other package docs are reworded.
- **The rest.** CLAUDE.md, README.md, docs/*.md (todo.md and release-preparation.md included),
  CONTEXT.md and `.claude/agents/*` are reworded.
- **`docs/output.md`'s export section** documents:
  - `procedures`, and `analysis` with every value and what each produces;
  - that a non-current record has neither filled;
  - that attributes merge from the procedures in registry order. An analysis's attributes merge
    first, because unlisted producers sort first in `Records`, so a procedure wins a field it also
    sets.
- **The stability notes record this as a deliberate one-off break.** `docs/exit-codes.md`'s
  stability section and CLAUDE.md's stable-interface note both get it, as CLAUDE.md already does
  for the `nyx cve` default selection: `failed_checks`, `meta.checks_*`, the rows' `stage` and
  export's `stages` were renamed before the first release.
- **`docs/commands.md`** names `meta.jobs_completed` and `meta.jobs_cancelled`.
- **CONTEXT.md** is committed with the change, because B5 covers it.

**D16. Order.** Each commit passes `make test` on its own, so a golden diff never hides a behaviour
change:

1. `git mv` and `gopls rename` for the Go identifiers, files and directories (D1), with no
   user-visible text changed.
2. The schema and store names (D3).
3. D4, alone.
4. The JSON keys, the export split and the analysis names (D5–D7).
5. The help topic, messages, events, fault point and goldens (D8–D11).
6. The docs, package docs, CLAUDE.md, skills and CONTEXT.md (D14, D15), then the B5 search (D12).

## Files

- `internal/run/`:
  - `stage.go` → `procedure.go`, and `stagerun.go` → `procedurerun.go`;
  - `derive.go` (the analyses and their names), `runner.go` (guard, `storeAnalysis`, messages,
    events) and `changes.go`;
  - `scopebuild.go`, `result.go`, and every `_test.go`.
- `internal/stages/**` → `internal/procedures/**`: package docs, comments and identifiers, and
  `rdap.go`'s message.
- `internal/store/store.go`: the schema, SQL, `Put`, renames and package doc. Plus `store_test.go`
  and `shown_test.go`.
- `internal/cli/`:
  - `cli.go` (`defaultProcedures`), `recon.go`, `export.go` (the split and `exportLine`), `help.go`
    and `stages_topic.go` → `procedures_topic.go`;
  - `partial.go`, `completion.go` and `setup.go`;
  - the tests: `harness_test.go`, `export_test.go`, `envelope_test.go`, `crash_test.go`,
    `srv_test.go`, `logcolours_test.go`, `risk_misc_test.go` and others;
  - `testdata/plain/*.txt` goldens: `help-stages.txt` → `help-procedures.txt`, plus help-recon,
    help-root, help-help, help-cve, help-export, help-completion, help-setup, log-*, summary-*.
- `internal/report/report.go`, `summary.go`, `envelope.go`, `sheet.go` and their tests.
- `internal/output/output.go` and `internal/inventory/inventory.go` (`Producers`).
- `internal/config/config.go`, plus the comment in `internal/config/builtin/sensitive_paths.yaml`.
- `internal/egress/thirdparty.go` (the message), and the comments elsewhere in egress.
- `internal/setup/backend.go`, `model.go`, `view.go`, and `internal/configedit/store.go`.
- `internal/testkit` (the fake procedures).
- `.golangci.yml` (the comment).
- `CLAUDE.md`, `README.md`, `docs/*.md` and `CONTEXT.md`.
- `.claude/skills/spec-develop/SKILL.md`, and any `.claude/agents/*.md` line the search flags.

## Tests

Every test follows the harness conventions (`t.Parallel()`, `h.setKey`, the fixed clock). The
renamed tests keep their assertions; only the words change.

- **B1.**
  - The golden `help-procedures.txt` has the heading, the `PROCEDURE` column, the `*` marker and
    the reworded footer.
  - `nyx help stages` exits 2 with `INVALID_INPUT`, and the error lists `procedures` among the
    commands and not `stages`.
  - The root help's topic list and `nyx help` completion offer `procedures`, not `stages`.
  - No external dependency, batch, crash or re-run applies: the topic is pure rendering.
- **B2.**
  - Regenerated goldens (help-*, log-first-run, log-debug, log-second-run, summary-*), with their
    diffs reviewed so that only the words change.
  - An explicit assertion for each example message: the `--redo`/`--skip` descriptions, `N jobs
    failed: …`, `<procedure> done (N jobs, 0 failed)` and `Stopped by the deadline: N jobs
    completed, M cancelled`.
  - The unknown-procedure errors for `--redo` and `--skip`.
  - The setup Skip tab, through the setup harness, lists procedures and shows the new
    descriptions.
  - **A batch with one failing item:** the existing failed-jobs test has one procedure failing
    jobs while the others complete. It asserts the per-procedure counts in the new words.
  - **External dependency errors:** the existing egress and source-error tests are renamed. The
    rename adds no external call.
- **B3.**
  - **The envelope:** `failed_jobs`, `meta.jobs_completed`, `meta.jobs_cancelled` and `procedure`
    appear in the `failed_jobs`, `deferred` and `not_configured` rows, and no old key appears
    anywhere (search the raw stdout).
  - **Export**, one engagement with real and fake procedures:
    - a hostname line has `procedures` filled and no `analysis`;
    - a current finding has `procedures: []` and `analysis: "findings"`;
    - a `candidate_rank` line has `analysis: "candidate-rank"`;
    - a `third_party` that a procedure observes and a CNAME implies has both;
    - an `excluded` line from a refused dial has `analysis: "guard"`;
    - a non-current record has `procedures: []` and no `analysis`;
    - no line has a `stages` key;
    - every `procedures` value is a name `nyx help procedures` lists.
  - **D6 invariants** (unit tests in `internal/run`):
    - the names `newAnalyses` uses plus `guard` equal `AnalysisNames()`;
    - no analysis name is in `defaultProcedures()`;
    - the analyses' `writes` kinds are distinct.
  - **A doc test** that `docs/output.md`'s export section names every `AnalysisNames()` value.
  - **D4 store tests:**
    - `Put` leaves no `jobs` row;
    - its records are current and merge attributes as before;
    - a second `Put` with fewer observations makes the dropped ones not current;
    - `Observers` never returns an analysis or `guard`.
  - **Re-run:**
    - a second run of the same engagement re-derives findings without adding `jobs` rows;
    - export's `procedures`/`analysis` are the same after the re-run;
    - `--redo <procedure>` still re-performs that procedure's jobs and leaves analysis
      observations alone.
- **Crash and interrupt.**
  - `crash_test.go` uses `NYX_FAULT=in-job-tx` and the other points. Resume completes, and the
    output files are atomic, as today.
  - The existing tests that job keys and output never contain an API key (`store.JobKey`
    redaction, the `--debug` failed-job line) are renamed and must still pass.
- **B4 and B5.** No automated test (D12). The search output, with every kept `check` hit justified,
  is the evidence.

**For a mutation check in `/spec-develop`:**

- **Export's procedure filter (B3).** Make it pass every producer, and the export test must fail.
  This is a stable interface.
- **D4's `Put`.** Make it also insert a jobs row, or skip the sweep of dropped observations, and
  the store tests must fail. This is data in every engagement.
- **Job-key redaction.** Bypass `JobKey`'s redaction, and the secret-leak tests must fail. This is
  security.

## Conventions

- **CLAUDE.md.** In particular:
  - Australian English;
  - conventional commit prefixes (`refactor:` for D16 steps 1–3, `feat:` for the interface renames
    in step 4, `docs:` for step 6);
  - the hard invariants, which this change must not touch (the egress boundary, the passive
    boundary);
  - the stable-interface note, which D15 updates;
  - the testing rules (`t.Parallel()`, the harness, goldens, doc tests that read whole sections).
- `.claude/hooks/go-check.sh` runs gofmt, vet and lint after each Go edit.
- Spec structure: `docs/specs/` and the `.claude/skills/spec-*` workflow.

# Follow-ups

- `docs/console-and-json.md` is linked from README.md, docs/exit-codes.md, docs/cve.md, docs/ip.md
  and CLAUDE.md but does not exist, so the renamed envelope keys have no page that documents them.
- CONTEXT.md defines **Procedure** twice, with two wordings. D15 rewords its analysis entry; which
  procedure definition to keep is the author's call.
- Engagements created before this change, the developer's own included, fail with
  `no such table: jobs` (`UNEXPECTED_ERROR`). Delete or recreate them after upgrading.

# Implementation

## Develop

Base commit: a79fd353c264888a4a8fac6f34e15a58b0c162f0

Implemented in the six commits D16 asks for, each passing `go test ./...` on its own (the only failure
is the one under "Known failure", which predates the change).

1. `d1d37f8` renamed the Go identifiers, files, directories and comments. `gopls rename` did the types
   (`run.Stage`/`Check`/`ErrAbortStage`, the three `Stages` fields to `Producers`); a token-based rewriter
   did the rest of the `stage`/`deriver` identifiers and comments; five workers then reworded the
   remaining `check` identifiers and comments by hand against B4. String literals were left alone.
2. `0de0a9f` renamed the schema (D3). The SQL strings and the tests' queries follow.
3. `0d70f61` added `Store.Put` (D4): an `op` flag skips the `jobs` insert. Analyses use job key `""`.
4. `39dfcfe` renamed the envelope keys (D7), split export's `procedures`/`analysis` (D5), and declared
   the analysis names once in `internal/run/analysis_names.go` (D6).
5. `f642379` changed every user-visible string (D8-D11), the help topic, the event type and field, the
   fault point, and regenerated the goldens. Each golden diff was read: only words change, plus the
   one-cell widening of the help command column (`nyx help procedures` is the widest command).
6. `0f005e7` reworded the docs, CLAUDE.md, CONTEXT.md, skills, the package docs and the two non-Go
   comments (D14, D15).

Deviation from the skill's order: the mechanical renames (steps 1 and 2) were done before any test was
written, because the test writers need the new names to compile and a rename has no new behaviour to
pin; the existing tests are its safety net. Steps 3 to 6 were test-first: tests written by the
`spec-test-writer` agent, shown failing on their assertions, then added to the index. Step 5's tests
were the existing tests' string literals reworded by three workers, plus new tests for the topic.

How each behaviour is pinned:

- B1: `TestProceduresTopic_OldNameIsUnknown`, `TestHelp_PlainJoin` (golden `help-procedures.txt`), the
  root help and completion tests.
- B2: the reworded log, summary, partial, skip and help tests and goldens;
  `TestProceduresTopic_FlagDescriptions`, `TestProceduresTopic_FailedJobsInTheNewWords`,
  `TestProceduresTopic_SetupSkipTabListsProcedures`.
- B3: `TestEnvelope_ProcedureAndJobKeys`, `TestExport_ProceduresAndAnalysis`,
  `TestExport_ProducerFieldOrder`, `TestExport_ProducersUnchangedByASecondRun`,
  `TestAnalysisNames_*` (run and cli), `TestAnalysisDocs_ExportSectionNamesEveryAnalysis`, the
  `TestPut_*` store tests and `TestAnalysisRerun_*`.
- B4, B5: no automated test (D12); the search output is under "Result" below.

Changes to tests the writers froze, each forced by the spec's own words:

- `TestHelp_CommandRowsWrap` expected the summary column to be as wide as `nyx help [command]`; the
  topic name `procedures` makes `nyx help procedures` the widest row, so the column is one cell wider.
- `TestSummaryTerminalOtherLinesWrap` wrapped a 700-job deadline line at 60 columns; "jobs" is shorter
  than "checks", so the line now fits (59 cells). The assertion uses 70000 jobs instead.

Deviation from D12 ("zero" `stage` hits): 17 `stage`/`stages` lines remain, all justified: the old
key names quoted in the deliberate-break notes of CLAUDE.md and docs/exit-codes.md (4), tests that
assert the old names are gone or echoed as unknown input (10), and fake target hostnames
`*.stage.example.com` in a HackerTarget fixture (3, D13).

The skipped clause of the tests (a procedure never writes an analysis's kind, apart from
`third_party`) is covered by a source scan, `TestAnalysisNames_NoProcedureWritesAnAnalysesKind`,
because `run.Procedure` can't say which kinds it writes.

### Mutation checks

Each break was made by hand and undone by hand (the file restored from a scratch copy, not git).

- Export's procedure filter passes every producer (`case true:`): `TestExport_ProceduresAndAnalysis`,
  `TestExport_ProducerFieldOrder`, `TestExport_EveryRecordOnce` and
  `TestExport_ProducersUnchangedByASecondRun` fail.
- `Put` also writes a jobs row (the `noJob` guard removed): `TestPut_LeavesNoJobsRow`,
  `TestPut_ObserversNeverReturnAnAnalysisOrTheGuard`, `TestPut_BumpsKindVersionAndCompletesNothing`,
  `TestAnalysisRerun_GuardWritesNoJobsRow` and `TestAnalysisRerun_FindingsRederivedWithoutJobsRows`
  fail. `Put` skips the sweep of dropped observations: `TestPut_DropsWhatItNoLongerProduces` fails.
- `JobKey` returns its argument unredacted: **no test failed**. The store's tests only checked that
  `JobKey` agrees with `Completed`, which holds for the identity function too. I added
  `TestRedactedJobKeyHidesTheSecret` (the stored key and `JobKey`'s result never hold the secret), and
  it fails with the break.

### Changes the simplify step made to frozen tests

Refactors of the tests' helpers (`diallerProcedure`, `missingInOrder`, `run.AnalysisNames()` in place of a
copied list) and the removal of `TestAnalysisRerun_ExportUnchangedByASecondRun`, a weaker copy of
`TestExport_ProducersUnchangedByASecondRun`. `run.AnalysisNames()` is now built from `newAnalyses()` plus the
guard, so the test that kept two lists in step became `TestAnalysisNames_NoDuplicate`.

### Known failure

`TestAbusiveDocs_GiveTheSnapshotDates` fails on the base commit and with this change, 20 of 20 runs on
each (`go test ./internal/cli -run TestAbusiveDocs_GiveTheSnapshotDates -count=20`, base checked in a
scratch worktree): the docs don't give the built-in Spamhaus asndrop list's date, 2026-11-24. It is in
docs/todo.md. It isn't fixed here.

## Known limitations

- Engagements created before this change fail with `no such table: jobs` (out of scope, as the spec
  says).
- B5/D12 asks for zero `stage` hits; 17 remain, justified above.

## Simplify

Four reviewers (reuse, simplification, efficiency, altitude) read the change. `go test ./...` passes
apart from the known failure, and `make lint` reports no issues.

Fixed:

- `AnalysisNames()` is built from `newAnalyses()` plus the guard, so D6's "no second hand-kept list"
  holds and `TestAnalysisNames_AreTheAnalysesAndTheGuard` became `TestAnalysisNames_NoDuplicate`.
  The cli name test no longer repeats the run package's "lacks" loop.
- Export's `splitProducers` used to rebuild the registry's names and `AnalysisNames()` for every
  record. The exporter now computes both once, and `snapshotSource.order` uses the same names.
- `analysis_rerun_test.go` uses `run.AnalysisNames()` and `h.completed` instead of its own copy of
  the four names, a hand-rolled prefix test and a four-slot `IN` clause.
  `TestAnalysisRerun_ExportUnchangedByASecondRun` and its helper are gone: it was a weaker copy of
  `TestExport_ProducersUnchangedByASecondRun`.
- The two `dialler` fakes are now one `diallerProcedure`, and the two export field-order loops share
  `missingInOrder`.
- Rename leftovers: the store's writer `op` and `Records` name the `producer` column `producer`, and
  `applyComplete` (which applies `Put` too) is `apply`. The `changes.go` entry field, `Shown`'s
  local and three comments say producers, not procedures, since analyses are among them.
  `findings`' private `analysis` type, a cache for one `DeriveAll`, is `calc`, so it isn't confused
  with `run`'s analyses.
- Stale comments: `deriveInput`, "one synthetic procedure and job" (derive.go, candidaterank.go,
  risk_misc_test.go), and the summary test's note about the word "jobs" replaced. The rule that a
  record has at most one analysis is stated once, in the `run` package doc, and the other two places
  point to it. Comment lines the rename pushed past 100 columns are rewrapped.

Skipped:

- Replacing `TestAnalysisNames_NoProcedureWritesAnAnalysesKind`'s source scan with a runtime check
  in `procedureRun` that fails a job whose observations have an analysis's kind. It's sounder, but
  it changes behaviour beyond a cleanup; the scan stays as D6 asked.
- Making `run.New` refuse a registry with a duplicate name or an analysis's name: new behaviour, and
  the cli test covers the real registry.
- Renaming the `sr` receiver and the `c`/`chk` job variables: names only, spread over every
  procedure, and B5 doesn't ban them.
