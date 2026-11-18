# Spec 24 (2 of 3): recon and export under the agent contract

## Goal

An agent can run recon to a deadline, read the run's outcome from the exit code and one JSON
object, and resume a run it cut short without losing progress or going round in circles.

Depends on Spec 23 (command tree and shared CLI contract), which is built. Spec 20 (changes
report), also built, added the "since last run" block that the envelope must carry (D7).

## Behaviours

B1. `nyx recon --timeout D` sets a deadline for the run. It is a flag only, with no default, no
    config key and no `NYX_*` variable. A value that is not a positive duration exits 2. With it,
    recon aims to exit by the deadline: it stops starting checks, and cancels the ones in flight,
    a reserve before the deadline, so that its files and summary are written before the deadline
    passes. The reserve is a tenth of the timeout, at least 2 seconds, at most 60 seconds and
    never more than half the timeout. If writing the files and summary takes longer than the
    reserve, recon finishes writing them and exits after the deadline. A cancelled check is not
    done and not failed, and runs on the next run. A run that finishes its work before the
    deadline is unaffected. (amended by D2)

B2. A run the deadline ended prints its summary or envelope and exits 7.
    - Its `PARTIAL` error says the deadline stopped the run, how many checks completed in this
      run, how many the deadline cancelled and which stages those were in. A check is completed
      when it ran and finished in this run, whether it succeeded or failed. A check a stage
      abandoned without running it is failed (B4) but not completed.
    - The hint is the caller's own invocation, shell-quoted, with `--redo` and its value removed
      and every other argument kept, and the error is marked transient.
    - When no check succeeded in this run, the hint says to raise `--timeout` instead, and the
      error is not marked transient. (amended by D5 and D9)

B3. `nyx recon --json` writes one compact `{data, meta}` object to stdout when the run ends, and
    no event lines.
    - `data` holds the engagement's name and directory and everything the human summary shows:
      counts, failed checks per stage, deferred work per stage, high and medium findings,
      high-confidence candidates (the first 20, as the summary lists them, and their total),
      unconfirmed risky ports, the stages' notes and, on a run that has an earlier one to
      compare with, what changed since it (the counts and the new high and medium findings). A
      candidate's sources are a list.
    - `data` also lists each stage that did not run and why (`skipped`, `passive-only`,
      `no authorisation`, or the stage's own reason such as `no key`), `[]` when every stage ran.
    - The envelope also says whether the deadline ended the run, and how many checks completed
      and how many were cancelled. (amended by D7)
    - `meta.warnings` lists every warning the run raised, `[]` when there are none. Under `--json`
      a warning never goes to stderr.
    - Every key appears on every run, `null` or `[]` when empty. Figures per stage or per category
      are lists of objects with fixed keys, never objects keyed by a stage or category name.
    - stdout is empty on every exit other than 0 and 7, and stderr is empty on exit 0 apart from
      `--debug` lines.
    - Human mode shows the same things as today, log on stderr and summary on stdout. Its summary
      adds the completed and cancelled counts when the deadline ended the run.

B4. A run in which any check failed prints its summary or envelope and exits 7.
    - That includes a check a stage abandoned when it stopped for the run on a 401, 403, 429 or
      spent quota, and a check that panicked.
    - The `PARTIAL` error names each stage with failed checks and how many. Its hint is the
      invocation as in B2. It is marked transient unless every failure was a rejected key.
    - These do not make a run partial: a `not-configured` stage, work a per-run cap deferred, a
      result truncated by a page cap, and failures recorded by earlier runs for stages that did
      not run this time.

B5. When several outcomes apply, one is reported, in this order: a signal, a fatal error (exit 1),
    the netblock limit (exit 2), the deadline (exit 7), failed checks (exit 7). The error of a run
    the deadline ended also names its failed checks; its hint follows B2, and it is transient when
    B2 makes it so. (amended by D9)

B6. Engagement problems get the exit code of their kind.
    - An engagement locked by another run exits 1 with the error code `LOCKED`, marked
      transient. (amended by D10)
    - An output directory that is not a nyx engagement, including one from the Python version,
      exits 2 naming the directory, with a hint to choose another `-e` (today it exits 1).
    - `nyx recon -e <name>` with no inputs, for an engagement that does not exist, exits 3
      (`NOT_FOUND`) and creates nothing. Its hint lists up to ten existing engagements in the
      output directory and says how many more there are.

B7. `nyx recon export` keeps writing JSON lines, with no envelope, cap or paging, and takes no
    `--timeout` because it makes no network calls. `--json` changes only the format of its
    errors. An engagement that does not exist exits 3 with the hint of B6, a directory that is not
    a nyx engagement exits 2, and a failure to write the export exits 1.

B8. The recon example in `nyx --help` and in `nyx recon --help` passes `--timeout` as well as
    `--json`, and the root help lists `--timeout` among recon's everyday flags.

B9. The keys of the recon envelope are a stable interface, as Spec 23 makes the error format.
    README and CLAUDE.md say so. README lists in one place every way nyx departs from
    `docs/agent-tools`:
    - recon has no default `--timeout`;
    - export writes JSON lines with no envelope, cap or paging;
    - API keys may come from the config file;
    - a stage whose key is missing is `not-configured` instead of a usage error;
    - `--authorized` is an alias;
    - `--quiet` with `--debug` is rejected;
    - SIGHUP exits 129;
    - recon can finish slightly after its deadline (B1);
    - requests are paced by token buckets, not a sliding window;
    - a failed request is not retried within the run: its check is retried on the next run;
    - HTTP connections are not reused. (amended by D13)

## Out of scope

- A reserve measured from how long the engagement's last write took. Declined: the fixed share
  is less code, and a late finish is the fallback.
- A hard stop at the deadline (exit 1 `TIMEOUT` with stale files). Declined: a slightly late
  exit 7 with current files is the better outcome.
- Every stage's state in the envelope. Declined: only the stages that did not run are listed.
- Splitting long checks (one permutations check per root can take minutes) so that they finish
  under a short deadline.
- A default deadline for recon. Declined: runs take hours, so the deadline is opt-in.
- Keeping the JSON event lines, or a flag that brings them back. Declined: one envelope; the files
  and `nyx recon export` are the detailed record.
- Letting in-flight checks finish at the deadline. Declined: the run must end by the deadline.
- Deferred work making a run partial. Declined: a per-run cap is a setting the caller chose.
- Making export a list verb, or adding a verb for querying an engagement. Declined for now: export
  stays a bulk dump.
- Environment-only API keys. Declined: `keys.<source>` in the config file stays.
- Reading recon's inputs from stdin.

# Design

Settled 2026-11-17 against the code at `b06b6d7` and the design of Spec 23. Revised 2026-11-18
against `df027c6`, where Spec 23 is built (`internal/clierr`, `internal/cli/classify.go`,
`failure.go`, `recon.go`) and so is Spec 20 (changes report: the summary's `changes` field, the
`change` events and the baseline in `internal/run/changes.go`). "S23 Dn" below is a decision of
Spec 23; each one this design leans on is now named by the code that implements it. Where the
code differs from a decision here, follow the code and keep the behaviour.
`docs/plans/2026-11-build-order.md` was removed while Spec 23 was built, so nothing here updates it.

The user decided the reserve and the late finish (D2), the rule for "raise `--timeout`" (D9), the
envelope's keys, `not_configured` and the list type of `sources` (D7), the `LOCKED` code (D10)
and the eleven departures (D13). An architecture review then moved the deadline from the runner
to the command (D2, D4), changed what counts as completed (D5), made the test tap pass through
JSON (D14), and added the error precedence of D4, the redaction of warnings (D7), the guard on
retire and redo (D4) and the stage names in the `PARTIAL` message (D9). The revision of
2026-11-18 added the envelope's `changes` key and the removal of the `change` events (D7), which
Spec 20 made necessary; their shape follows the rules of B3 and has not been put to the user.

## External facts

| Fact | Tag |
|---|---|
| `golang.org/x/time/rate` v0.16.0 `Limiter.Wait` returns `would exceed context deadline` while the context is still live, when the context carries a deadline the wait would pass (`rate.go`, `wait`). The runner would record that as a failed check. | from source |
| `miekg/dns` v1.1.73 `Client.ExchangeContext` is `DialContext` then `ExchangeWithConnContext` (`client.go:461`). The latter uses the context only to shorten the read and write deadlines it sets on the connection (`client.go:198-222`), so cancelling the context does not end a read: it blocks for `Client.Timeout`. Both methods are exported. | from source |
| Closing a `net.Conn` from another goroutine makes a blocked `Read` return at once. Setting a deadline from outside would race the deadlines `ExchangeWithConnContext` sets itself. | from docs |
| `context.AfterFunc` and `context.WithCancelCause` are in the standard library of the pinned toolchain. With `WithCancelCause` the first cancel sets the cause and later ones do not change it. | from docs |
| `time.ParseDuration` accepts a number and a unit, combined (`30s`, `1m30s`, `1.5h`), and rejects a bare number other than `0`. | from docs |
| A keyed source's 401 means the key was refused, and its 403 means the key is refused or not entitled to the endpoint; neither is cured by waiting. GitHub is the exception: it answers 403 for a rate limit. | assumed (vendor documents, not checked with real keys); D6 says what rests on it |
| Writing the files and summary of a typical engagement takes less than the reserve of D2. Nothing in the code measures it, and all 23 or so files are rewritten and synced each time. | assumed; B1 says what happens when it is wrong |
| An agent harness kills a tool call after a fixed time (Claude Code: two minutes), per `docs/agent-tools/0004`. One permutations check per root sends about 4,900 lookups at 50 a second, so it cannot finish under such a deadline. | from docs (the harness), from source (the check) |

## Decisions

D1. **`--timeout` is a recon flag that takes any text and is checked with the other values.**
    It is declared with a pass-through `pflag.Value` whose `Type()` is `duration`, as
    `config.numberFlag` does for the numeric settings (S23 D7), and `runRecon` checks it and adds
    any problem to the same `clierr.Problems` as its other checks, instead of the parse ending. The check: `time.ParseDuration` succeeds and the result is above zero. The problem
    reads `timeout: invalid value "abc": not a positive duration`, with the hint
    `--timeout 30m`. It is not a setting: it is not in `settingTable`, so `NYX_TIMEOUT` is
    ignored and a `timeout:` key in the config file is an unknown key. `export` has its own
    flag set, so `nyx recon export --timeout 5s` is an unknown flag.

D2. **The deadline is a timer that cancels, owned by the recon command** (user decision: a
    fixed reserve, and a late finish when the write overruns).
    - The clock starts when the recon command starts, read from `time.Now()` (monotonic), not
      from `Deps.Clock`, which tests fix.
    - `reserve(d) = min(max(d/10, 2s), 60s, d/2)`, a pure function with a unit test. Checks get
      `d - reserve`: 27s of 30s, 9m of 10m, 1h59m of 2h, 200ms of 400ms.
    - recon derives `ctx, cancel := context.WithCancelCause(invocationCtx)` and arms
      `time.AfterFunc(d - reserve - elapsed, func() { cancel(errDeadline) })`, with
      `errDeadline` an unexported sentinel of `cli`. It stops the timer when the run returns.
    - It is not `context.WithDeadline`: the rate limiter would fail waiting checks before the
      context ended (first external fact), and `egress/http.go:422` lets a parent's
      `DeadlineExceeded` fall through to a "no service" result. A plain cancel has neither
      problem.
    - The runner knows nothing of the deadline. It already returns an error that wraps
      `context.Cause(ctx)` (`interrupted` in `runner.go`), and recon tests
      `errors.Is(err, errDeadline)`.
    - Nothing stops the write when the reserve runs out. recon finishes and exits 7 late.

D3. **A cancel ends work in flight at once.** Two reads ignore the context today and hold a
    cancelled check for up to three seconds. Both fixes are in `internal/egress`.
    - DNS (`dns.go`, which calls `ExchangeContext` for UDP and again over TCP): dial with
      `Client.DialContext`, register
      `stop := context.AfterFunc(ctx, func() { conn.Close() })`, then call
      `ExchangeWithConnContext`, for the UDP exchange and for the TCP retry of a truncated
      answer. One helper serves both. The existing `ctx.Err()` test after a failed exchange
      then returns the context's error.
    - TCP (`tcp.go`, `dialAndRead`, which reads for `BannerWait`): the same `context.AfterFunc`
      around the banner read, and
      `ctx.Err()` returned when the context ended during it.
    - `runStage`'s producer loop tests `ctx.Err()` at the top of each check a stage yields and
      stops producing. `permutations` and `storage` enumerate without looking at the context.

D4. **`Runner.Run` returns `(Result, error)`.** This replaces today's error-only return (S23 D9)
    and keeps its error values.
    - `Result` holds `Summary report.Summary` (D7), `Completed` and `Succeeded` (D5),
      `Cancelled []report.StageCount` (per stage, registry order) and `KeyRejected int` (D6).
      The number of failed checks is the sum of `Summary.FailedChecks`; it is not kept twice.
    - `nil` error: the run did all its work. A final pass that executed no check returns `nil`
      even when the context ended during its render, so a deadline or a signal that lands after
      the work is done changes nothing (B1; S23 D10).
    - An error that wraps `context.Cause(ctx)`: the context ended the run. The `Result` is
      still filled in. Before returning, the runner flushes, rebuilds the scope, renders the
      files and emits the counts, so the summary and the findings include the evidence of the
      stage that was cut short. The render also compares against the baseline and saves it, as
      every render does since Spec 20, so `changes` counts the work done before the deadline and
      the next run compares against where this one stopped. If the rebuild meets the netblock
      limit, that error is returned instead (B5: the netblock limit comes before the deadline).
    - `*NetblockLimitError` or any other error: the `Result` is zero. The files are still
      rendered first, as today.
    - An error from that render or flush replaces a netblock or context error (B5: a fatal
      error comes first). Today `Run` discards it (`_, _ = r.render()`, `runner.go:210`).
    - `runStage` keeps its early return when the context has ended. It must not fall through
      to `FinishRedo` or `Retire`: the producer stopped early, so the set of valid checks is
      incomplete and a sweep would delete evidence of checks that were never listed.
    - The runner no longer emits `summary`, `candidate` or `change` (`emitSummary`,
      `emitChanges`), and recon no longer emits `run_end`; recon writes the result (D7, D9).

D5. **Completed, succeeded and cancelled are counted where `Stage.Run` returns.** A worker
    that called `Stage.Run` adds one to the stage's *cancelled* when the context had ended by
    the time it returned, and otherwise one to *completed*, and to *succeeded* when the error
    is nil. The enumeration failure counts as completed. A check failed by a stage abort
    without running (`stage aborted earlier in this run`) is failed, and is in neither count.
    The runner's `attempted`, which the stage lines use, is left as it is. Why not `attempted`:
    it includes the checks an abort failed, so one rejected key would make every run look like
    progress.

D6. **A refused key is its own sentinel.** `run.ErrKeyRejected = fmt.Errorf("key rejected: %w",
    ErrAbortStage)`, beside `run.ErrQuota` (`stage.go:61`), which already wraps `ErrAbortStage`
    the same way for a spent allowance.
    - `httpsrc.get` returns it for a keyed 401 or 403. A keyed 429 stays a plain
      `ErrAbortStage`, and the spent statuses (`GetQuota`'s 429, `GetCredits`' 402 and
      HackerTarget's spent reply) stay `ErrQuota`.
    - `github` returns it for a 401 only. Its 403 and 429 that do not lift stay a plain
      `ErrAbortStage`, because GitHub uses 403 for rate limits.
    - The runner's `aborted map[string]bool` becomes `map[string]error`, and `recordFailure`
      takes a `rejected bool`: true for the check that returned `ErrKeyRejected` and for each
      check failed afterwards by an abort whose cause was one. `Result.KeyRejected` is their
      total.
    - A `PARTIAL` error for failed checks is transient when the failed total is above
      `KeyRejected` (B4).
    - The warning `quota spent or key rejected; N checks will be retried next run` is
      unchanged.
    - Why 403 counts: a key that is refused and a key with no credits or no access to the
      endpoint are alike in that waiting does not help. If a vendor turns out to use 403 for a
      rate limit, give it GitHub's treatment.

D7. **The summary is a typed value and the envelope is built from it** (user decisions: the
    keys, `not_configured`, `sources` as a list).
    - `report.Summary` is the envelope's `data`. Its fields, in this order, are the keys:

      | Key | Value |
      |---|---|
      | `engagement` | the engagement's name |
      | `directory` | its directory, as an absolute path |
      | `counts` | `[{category, n}]`, sorted by category |
      | `failed_checks` | `[{stage, n}]`, sorted by stage name, as the summary prints them |
      | `deferred` | `[{stage, n}]`, sorted by stage name |
      | `not_configured` | `[{stage, reason}]`, registry order: each stage whose gate is closed when the run ends |
      | `findings` | `[{severity, category, target, detail}]`: every current high and medium finding, in `findings.Headline` order; `detail` is `null` when empty |
      | `candidates` | `[{kind, value, sources, evidence_count, confidence, promote}]`: the first 20 current high-confidence candidates, best first; `sources` is a list, split from the stored `;`-joined text |
      | `candidates_total` | the number of current high-confidence candidates |
      | `unconfirmed_risky_ports` | a number |
      | `notes` | `[string]` |
      | `changes` | `null` on a first run (no baseline), as the human block is then left out; otherwise `{counts, findings}`: `counts` is `[{kind, change, n}]` for each kind and change with `n` above zero, sorted by kind then change; `findings` is the new high and medium findings, in the row shape of `findings` |

    - `report.Meta`, in this order: `count` (always 1, the single-record shape of
      `docs/agent-tools/0003`), `deadline_exceeded`, `checks_completed`, `checks_cancelled`,
      `warnings`.
    - `report.Envelope{Data Summary; Meta Meta}`. `Envelope.Map(func(string) string)` returns a
      copy with every string mapped, the warnings included. recon maps it once through
      `sanitize.Text` and the redactor, as `export` does for its lines, before either writer.
    - `report.WriteEnvelope(w, env)` writes one compact line with `SetEscapeHTML(false)`. It
      turns each nil list into `[]`, so every key appears on every run.
    - `report.WriteSummary(w, depth, env)` writes the human summary: today's text from the
      typed value (a candidate's sources joined with `;` as now, and `and N more in
      candidates.csv` from `candidates_total`), the "Since last run" block when `changes` is not
      null (today's `sinceLastRun`, which always prints its seven lines, zeros included, so it
      looks up a missing kind and change as 0), plus the line
      `Stopped by the deadline: N checks completed, M cancelled` after the notes when
      `deadline_exceeded` is true.
    - The runner fills `Summary` at the end of a run, on both paths of D4 that return a
      `Result`, from what `emitSummary`, `rankedCandidates`, `notes` (`runner.go`) and
      `changesSummary` and `headlineFields` (`changes.go`) compute today. `not_configured` comes
      from `r.gate(s)` for each stage.
    - Deleted: `report.JSONEmitter` and `NewJSON`; the `summary`, `candidate`, `change` and
      `run_end` event types, and `emitChanges`; `Event.Time` and `timestamp`, which only the
      JSON lines used; the `summary` case and method of `Console`, with `sinceLastRun` and
      `findingList` moving to `summary.go`. The events that remain (`run_start`, `stage`,
      `found`, `count`, `warning`, `debug`) drive the human log. Each row of a change is in
      `changes.csv` and in `nyx recon export`, as the out-of-scope list says of the event lines.

D8. **Under `--json` the emitter collects warnings and writes nothing.** `report.Warnings` is
    an `Emitter` that keeps the message of each `warning` event in order; the runner already
    writes the same text once per run. recon puts it inside `report.WithRedactor` and copies
    its list into `meta.warnings`. With `--debug`, the DEBUG lines still go to stderr through
    `report.Only("debug", console)`, as today. The human-mode emitter is the console, as today.
    The `--json` flag's help becomes `Print one JSON object with the run's outcome on stdout
    when the run ends`.

D9. **recon picks the outcome after the engagement has closed** (user decision: "raise
    `--timeout`" when no check succeeded). In this order (B5):
    1. `Run` returned an error that is not the deadline: return it. S23 turns a cancel into
       `INTERRUPTED`, a `*NetblockLimitError` into `INVALID_INPUT` and anything else into
       `UNEXPECTED_ERROR`. Nothing is written to stdout.
    2. `eng.Close` failed: return that error (exit 1), with stdout empty. So the human summary
       is written after the close, where today it is printed before it.
    3. The invocation's own context has ended (a signal arrived during the deadline's
       wrap-up): write nothing and return the context's error, so the outcome is
       `INTERRUPTED` with an empty stdout.
    4. Write the summary (human) or the envelope (`--json`) to stdout.
    5. The deadline ended the run: return `PARTIAL`.
       - Message: `the deadline (--timeout 30m) stopped the run: 412 checks completed, 6
         cancelled (permutations 2, crawl 4)`, then `; failed checks: crtsh 2, shodan 14` when
         any failed. The timeout is shown as the caller typed it.
       - `Succeeded > 0`: the hint is the caller's invocation, shell-quoted, with `--redo <v>`
         or `--redo=<v>` removed after the `recon` token. It is built by `netblockHint` in
         `classify.go`, generalised so that it can drop `--redo` without inserting
         `--allow-large-netblocks`; transient.
       - `Succeeded == 0`: the hint is `raise --timeout: no check succeeded within 30m`; not
         transient, whatever the failures were (B5 as amended).
    6. Otherwise, some check failed: return `PARTIAL` with the message `16 checks failed:
       crtsh 2, shodan 14`, the same invocation hint, and transient per D6.
    7. Otherwise return nil.

    `input` is `null` for every `PARTIAL` error.

    **This amends S23 D10.** `Execute` (`cli.go`) turns any error a command returns into
    `INTERRUPTED` once a signal is recorded, or once the caller's own context was cancelled. An
    error whose code is `PARTIAL` is now exempt: a command
    returns it only after writing its result, so `INTERRUPTED` never comes with a non-empty
    stdout. Accepted limit, the twin of S23 D10's for export: a second signal that lands while
    the envelope is being written exits at once with part of it on stdout.

D10. **Engagement errors are classified once, by `engagement.Probe`** (user decision: the code
     `LOCKED`).
     - `engagement.Probe(dir) (State, error)`: `Exists` (it has `.nyx/state.db`), `Foreign` (not
       a directory, or a directory with entries and no `.nyx`, which is what the Python
       version left) or `Absent` (missing, empty, or `.nyx` with no `state.db`). An error is a
       failure to read the directory, and is `UNEXPECTED_ERROR`.
     - `engagement.List(outputDir) []string`: the names of the subdirectories that `Exist`,
       sorted. An output directory that cannot be read gives none.
     - recon probes during validation, before `engagement.Open`, replacing its
       `engagement.Exists` test and the `engagement <name> does not exist in <dir>` problem it
       adds today (S23 D8). `Probe` subsumes `Exists`, which goes; `Open` and `OpenReadOnly`
       keep sharing `statePath`.
       - `Foreign`: a problem named `engagement`, collected with the others (exit 2). Message
         `<dir> exists but is not a nyx engagement`; hint `choose another engagement name with
         -e, or move <dir> away`.
       - `Absent`, `-e` given and no inputs: `NOT_FOUND` (exit 3) when validation found no
         problem, and nothing is created. Message `no engagement named "acme" in <output-dir>`;
         `input` `{"engagement":["acme"]}`; hint `engagements in <output-dir>: a, b, c and 4
         more; or give domains, --org, --asn or --cidr to start one`, with up to ten names, or
         `no engagements in <output-dir>; give domains, --org, --asn or --cidr to start one`.
         When validation did find problems, they are reported alone as exit 2.
     - `engagement.Open` can still return `*NotEngagementError` or `*LockedError` when the
       directory changed after the probe. The first maps as `Foreign` does. The second is
       `clierr.Locked` (`LOCKED`, added to the code table under exit 1), transient, with the
       hint `another run holds this engagement; wait for it to finish, or use another -e`.
     - Every other failure to open, read or write an engagement stays `UNEXPECTED_ERROR`.

D11. **export uses the same probe** (B7). `Absent` is `NOT_FOUND` with D10's hint, `Foreign` is
     `INVALID_INPUT`, and a failure to read the snapshot or to write the export is
     `UNEXPECTED_ERROR`. Today both an absent and a foreign directory reach `OpenReadOnly`'s
     untyped `is not a nyx engagement (no .nyx/state.db)` error, exit 1; it stays as the
     fallback for a directory that changed after the probe. Its lines and flags do not change.

D12. **Help** (B8). `timeout` joins `reconEveryday` in `recon.go`, the names of recon's
     everyday-flags annotation (S23 D14), and recon's `Example` lines pass it, the first one as
     `nyx recon example.com --json --timeout 30m`, since the root help shows only each command's
     first example (`firstExample` in `help.go`). Root and command help are both rendered from
     those, so no other change is needed. The flag's
     help: `Stop by this deadline, e.g. 30m or 2h, and exit 7; run again to carry on
     (default: none)`.

D13. **Documents** (B9; user decision: eleven departures).
     - README, "Console and JSON": the envelope with each key of D7, that the keys are a
       stable interface (adding one is compatible; renaming, removing or retyping one is a
       breaking change), and that the event lines are gone.
     - README, every other mention of a `--json` event, rewritten for the envelope or the log:
       the `warning` event of the authorisation notice, the `found` event's fields for a third
       party, `deferred` and `unconfirmed_risky_ports` and `notes` in the `summary` event, the
       `candidate`, `change` and `run_end` events, the `changes` field ("What changed since the
       last run"), and "stdout is empty (but for a recon `--json` run's earlier event lines)"
       under "Errors".
     - README, a section on the deadline: the reserve, the late finish, what a cancelled check
       is, the two hints, and that a single permutations or crawl check can take minutes, so a
       short `--timeout` may never finish one.
     - README, exit codes: 7 for recon, `LOCKED` under 1, 3 and 2 for the engagement cases of
       B6 and B7, and exit 0 no longer covering failed checks.
     - README, one list titled for departures from `docs/agent-tools`, with the eleven items
       of B9.
     - README, migration: an old output directory now exits 2.
     - CLAUDE.md: the flow line (`internal/report` writes the console log, the summary and
       the `--json` envelope), the envelope's keys beside the other stable interfaces, and the
       convention that "CSV columns and `--json` event fields" may change freely, which now
       covers CSV columns only.

D14. **Tests keep reading events, through a tap.** About 165 of the 528 tests in
     `internal/cli` read the event lines, most through `world.run` (`world_test.go:196`), which
     always passes `--json`.
     - `cli.Deps.Events report.Emitter` is optional. When set, recon sends every event to it
       as well, from inside `report.WithRedactor`, so it sees what the console would.
     - The harness sets a recorder that marshals each event to a JSON line (type plus fields)
       and `harness.events()` parses those lines as it parses stdout today. The round trip
       matters: `event.num` reads a `float64`, and the runner's fields are Go `int`s, so a
       recorder that kept the maps would make every `num(...) != 0` assertion pass without
       testing anything. A guard test runs one known failed check and expects
       `num("failed") == 1`.
     - `lastState`, `stateOf`, `stageEvents`, `messages`, `warnings`, `warns` and the `found`
       helpers then work unchanged in either mode.
     - `summaryEvent()` and the helpers on it (`summaryFindings`, `summaryTargets`, `countOf`,
       `summaryTotal`, `summaryNum`, `deferredOf`, `deferredHosts`) read `data` from the
       envelope on stdout instead, adapting to its lists. So do the tests that read the
       summary's `changes` field directly (`changes_test.go`).
     - The `candidate` and `change` events are gone, so the tests that read them through the
       tap read `data.candidates`, `data.changes` or `changes.csv` instead.
     - Rejected: running the shared tests in human mode and parsing stage lines from stderr,
       because one run could not then give the envelope too; and rewriting the 161 tests
       against the files.

## Files

New:
- `internal/report/summary.go`: `Summary`, its row types and `WriteSummary` (D7).
- `internal/report/envelope.go`: `Envelope`, `Meta`, `Map`, `WriteEnvelope`, `Warnings` (D7, D8).
- `internal/cli/timeout_test.go`, `envelope_test.go`, `partial_test.go`,
  `engagement_errors_test.go`.

Changed:
- `internal/cli/recon.go`: the `--timeout` flag and its check (D1); `reserve`, the timer and
  `errDeadline` (D2); the probe and `NOT_FOUND` (D10); the emitter (D8, D14); the outcome (D9);
  the help annotation and examples (D12).
- `internal/cli/cli.go`: `Deps.Events` (D14); `newEmitter` without the JSON lines (D8); the
  `PARTIAL` exemption in `Execute` (D9).
- `internal/cli/classify.go`: `netblockHint` generalised for the `PARTIAL` hint (D9).
- `internal/cli/export.go`: the probe and the error codes (D11).
- `internal/clierr/clierr.go`: `Locked` and its row in the exit table (D10).
- `internal/run/runner.go`: `Run` returns `(Result, error)`, the wrap-up and the error
  precedence (D4); the counters (D5); `aborted` as a map of causes and `recordFailure`'s flag
  (D6); the producer's context test (D3); `Summary` built from what `emitSummary` and
  `rankedCandidates` compute today (D7).
- `internal/run/changes.go`: `changesSummary` gives the typed `changes` value, and
  `emitChanges` goes (D7).
- `internal/run/stage.go`: `ErrKeyRejected` (D6).
- `internal/report/report.go`: the deletions of D7.
- `internal/egress/dns.go`, `tcp.go`: connections closed on cancel (D3).
- `internal/stages/httpsrc/httpsrc.go`, `internal/stages/github/github.go`: `ErrKeyRejected`
  (D6).
- `internal/engagement/engagement.go`: `Probe`, `State`, `List`, replacing `Exists` (D10).
- `internal/cli/harness_test.go`, `risk_helpers_test.go` and the helper functions named in D14.
- `README.md`, `CLAUDE.md` (D13).

## Tests

Behaviour tests drive `cli.Execute` through the harness. Each test of a non-zero exit checks
both streams: one error on stderr, and stdout empty unless the exit is 7. Deadline tests use
small timeouts (`--timeout 400ms` gives checks 200ms) and fake stages whose checks block on the
context.

- **B1** (mutation check: a cancelled check is neither done nor failed).
  - `--timeout 0`, `-5s`, `abc` and `30` each exit 2 with the value in `input`; one call with a
    bad `--timeout` and a bad `--concurrency` reports both; nothing is created or contacted.
    `NYX_TIMEOUT=1ms` changes nothing, a `timeout:` key in the config file is rejected, and
    `recon export --timeout 5s` is an unknown flag.
  - A unit test of `reserve` over 400ms, 3s, 10s, 30s, 10m and 2h.
  - A stage with two quick checks and four that block: exit 7 within the timeout plus a
    margin; the two are in `checks`; the four are in neither `checks` nor `failures`; the
    files are written. A second run without `--timeout` runs exactly the four and exits 0.
  - A real third-party stage at a low `--rate-per-source`, so checks are waiting on the
    limiter when the timer fires: no row in `failures` (this is what `WithDeadline` would
    break).
  - A run whose work finishes before the timer exits 0 with `deadline_exceeded` false.
  - A `Retiring` stage, and a stage with a pending `--redo`, cut during enumeration: evidence
    recorded by an earlier run is still current afterwards (mutation check).
  - `internal/egress`: with `BannerWait` and `DNSTimeout` at five seconds, a banner read
    against a silent listener, a UDP lookup against a silent server and the TCP retry of a
    truncated answer each return within half a second of the cancel, with the context's error.
  - A child process, as `crash_test.go` does: a `--timeout` run exits 7 by the deadline plus a
    wide margin (the suite runs under `-race`), `assertOutputsIntact` passes, and the re-run
    finishes the rest.
- **B2.** The exact message and counts in both modes, with the stages of the cancelled
  checks. The hint with `--redo x` and with `--redo=x` removed, an argument that needs quoting
  (`--org 'Acme Pty'`) and a shared flag before the command; running the hint's arguments
  completes the run. "Raise `--timeout`", not transient, in three cases: a timeout too small
  to start a check, every started check cancelled, and one check that always fails with the
  rest cancelled. Checks failed by a stage abort are not in the completed count. In human mode
  the summary on stdout has the `Stopped by the deadline` line and stderr has the error, hint
  and retry lines.
- **B3** (mutation check: a key in the envelope is masked).
  - The exact bytes of the envelope of a fixed fake run: one line, compact, the keys of D7 in
    order. A run that found nothing: every key present, `[]` for each list, `null` for an empty
    `detail` and for a first run's `changes`. A unit test encodes the zero `Envelope` to the
    same shape.
  - A re-run that finds a new hostname and a new high finding: `changes.counts` has the
    hostname and finding rows and `changes.findings` the finding; the human summary's "Since
    last run" block is unchanged. A deadline-ended re-run's `changes` counts what it completed.
  - No event lines on stdout. stderr is empty on exit 0; with `--debug` it holds only DEBUG
    lines and stdout is byte-for-byte the same.
  - A warning is in `meta.warnings` and not on stderr; a warning that carries an escape
    sequence and a key value comes out stripped and masked; so does a finding's `detail`.
  - `not_configured` gives `skipped`, `passive-only`, `no authorisation` and `no key` for four
    stages, in registry order, and `[]` when all ran.
  - 23 high-confidence candidates: 20 listed, `candidates_total` 23, `sources` a list.
    `directory` is absolute when `--output-dir` is relative.
  - stdout is empty under `--json` on exits 1, 2, 3 and 130.
  - Human mode: the existing summary and log tests pass unchanged.
- **B4** (mutation check: the transient flag).
  - One failing check among others: exit 7, the envelope printed, the others completed, the
    error naming the stage and its count; the same in human mode. A re-run with the fault
    gone exits 0.
  - A keyed source answering 401, and 403: not transient. The same with a second stage failing
    for another reason: transient. A keyed 429, a spent quota, GitHub's 403, a 500 and a
    panicking check: transient.
  - Exit 0 for: a `not-configured` stage, work a budget deferred, a result a page cap
    truncated, and a failure recorded by an earlier run for a stage that is skipped this time.
- **B5** (mutation check: a signal leaves stdout empty). A signal during the deadline's
  wrap-up: `INTERRUPTED`, stdout empty. An output file whose row function fails, with an
  over-limit `--cidr`: exit 1. The netblock limit met during the deadline's wrap-up: exit 2.
  The deadline with failed checks: exit 7, one error naming both. The deadline with no success
  and a failure that would be transient: not transient. A signal after the result is written
  leaves exit 7 standing (a unit test of the exemption in `Execute`).
- **B6.** A test holds the engagement's lock: exit 1, `LOCKED`, transient, the hint. A
  directory with a file and no `.nyx`: exit 2 naming it, with and without inputs, reported
  together with a bad flag, and the directory unchanged. `-e nope` with no inputs: exit 3 and
  nothing created, with the directory absent and present but empty; the hint with none, three
  and twelve engagements (ten names, sorted, `and 2 more`); `input` in the JSON error.
- **B7.** export of an absent engagement: exit 3 with the hint; of a foreign directory: exit
  2; with `--output` naming a directory: exit 1. `--json` changes the error's format and not
  one byte of the lines.
- **B8.** `--timeout` is among recon's flags in `nyx --help`, and the recon example in both
  helps passes `--timeout` and `--json`.
- **B9.** The unit test of the code-to-exit table covers `LOCKED`. The B3 byte test is the pin
  on the keys. README and CLAUDE.md are checked by reading.

The four cases, across the behaviours:
- **An error from an external dependency.** B4's statuses from the fake sources; B1's cancel
  during a limiter wait, a banner read and a DNS read.
- **One item failing in a batch.** B4: the other checks complete and the failure is reported.
- **A crash or interrupt part-way.** B1's child process, B5's signal cases, B3's masking of a
  key in the envelope and in a `PARTIAL` error. The existing crash tests still pass.
- **A re-run.** After the deadline (the cancelled checks run, the completed ones do not), after
  failed checks (they are retried), after `NOT_FOUND` (the same error, nothing created), and
  the hint's own arguments (B2).

Existing tests to change:
- The tests that assert event order or the JSON stream itself: `candidates_test.go`
  `TestCandidates_JSONEvents`, `behaviour_test.go` `TestJSONMode` and its
  `run_start`/`summary`/`run_end` count, `logcolours_test.go` `TestLog_JSON` (the same stream
  with and without `--debug`), and the `candidate` event assertions in `candidates_test.go:163`
  and `rdap_test.go:687`. Rewrite them against the envelope.
- `changes_test.go`: its `change` event assertions (`:86`, `:169`, `:372`) and its reads of
  the summary's `changes` field (`:89`, `:172`, `:205`) move to `data.changes` and
  `changes.csv`; a first run's check that the field is absent becomes `changes` being `null`.
- `error_contract_test.go` `TestContract_FailedRunKeepsEarlierEventLines` pins what this spec
  removes: rewrite it to expect an empty stdout.
- `providerranges_test.go:206` filters on an event type `finding` that never existed, so it
  asserts nothing. Make it read `data.findings`.
- Every test whose run has a failed check and expects exit 0 now gets 7: the key-rejection
  and quota tests in `sources_keyed`, `sources_unkeyed`, `discovery`, `github`, `reverseip`,
  `rdap`, `identifiers`, `shodan_host` and `logcolours`,
  `TestContract_PanicInACheckFailsOnlyThatCheck` in `error_contract_test.go`, and any
  `mustRun` over a failing source.
- `report_test.go`: the JSON renderer tests go; the summary tests call `WriteSummary`.
- The tests of a locked engagement, of an old directory and of export's missing engagement
  change their exit codes.

## Conventions

- `CLAUDE.md`: Australian English; no spec numbers in code, comments, test names or file
  names; only `internal/egress` does network I/O (D3 stays inside it); a stage never sees
  `net/*` types; conventional commit prefixes; `README.md` is the behaviour contract.
- `docs/agent-tools/0002` (exit 7, one place picks the exit), `0003` (the envelope, every key
  every time, compact, warnings in `meta`), `0004` (the deadline) and `0007` (a walk that
  cannot finish exits 7 with what it has and a hint that carries on). Where this design
  departs from them, B9's list says so.
- `CLAUDE.md` (which took these over from the removed build-order plan): behaviour tests in
  new `internal/cli/<feature>_test.go` files; new struct fields appended at the end. Run the
  suite as `XDG_CONFIG_HOME=$(mktemp -d) make test`.

## Handed to later specs

- **Spec 25 (CVE lookup):** the `PARTIAL` exemption of D9 covers every command, so its command
  must test its context before writing to stdout, or a signal during its run would exit 7. Its
  envelope and its `--timeout` (with a default) are its own; `report.Envelope` is recon's.
- **Any later spec that adds to the summary** appends a field to `report.Summary`, which is
  also a key appended to the envelope.

Specs 7, 14, 16, 19 and 20, which this section once handed work to, are built: their tests and
README text are in "Existing tests to change" and D13.

# Implementation

## Develop

Built on 2026-11-18 against `df027c6`. Four packages were built by workers from this spec and
checked against the tree afterwards; the runner, report and recon changes were made together.

- `internal/egress`: `dns.go` dials with `Client.DialContext` and reads through `exchange`, which
  closes the connection from a `context.AfterFunc`; the TCP retry of a truncated answer uses the same
  helper. `tcp.go` does the same around the banner read.
- `internal/engagement`: `State` (`Absent`, `Exists`, `Foreign`), `Probe` and `List` replace `Exists`.
  `clierr.Locked` is `LOCKED` under exit 1.
- `internal/report`: `Summary` and its row types, `Envelope`, `Meta`, `Envelope.Map`, `WriteEnvelope`,
  `WriteSummary` (the old event-based summary) and `Warnings`. `JSONEmitter`, `NewJSON`, the
  `summary`, `candidate`, `change` and `run_end` events, `Event.Time` and the console's summary are gone.
- `internal/run`: `Runner.Run` returns `(Result, error)`; `result.go` builds the `Summary`
  (`result`, `notConfigured`, `rankedCandidates`, `changesSummary`, `headlineRows`). `wrapUp` flushes,
  rebuilds the scope, renders and counts after a cut, with the error precedence of the design. The
  per-stage counters (`completed`, `succeeded`, `cancelled`, `rejected`) are kept under `r.mu`;
  `aborted` holds the error that aborted a stage; `ErrKeyRejected` is returned by `httpsrc.get` for a
  keyed 401 or 403 and by `github` for a 401. The producer stops at the top of each yielded check once
  the context has ended.
- `internal/cli`: `--timeout` is a pass-through `timeoutFlag` (`deadline.go`) checked with the other
  problems; `reserve`, the timer and `errDeadline` are in `deadline.go` and `recon.go`; `partial.go`
  builds the `PARTIAL` error; `engagement_errors.go` holds `engagementNotFound`, `foreignProblem` and
  `openError`; `invocationHint` in `classify.go` is `netblockHint` generalised; `Execute` exempts
  `PARTIAL` from `INTERRUPTED`; `newEmitter` returns the console log or, under `--json`, the
  warning collector; `Deps.Events` is the tests' tap. `export.go` probes before it opens.
- `README.md` and `CLAUDE.md`: the envelope and its keys, the deadline section, the exit codes, the
  list of departures, the migration note, and the harness's tap.

How each behaviour is tested (behaviour tests in `internal/cli` through the harness unless noted):

- B1: `TestTimeout_InvalidValues`, `TestTimeout_IsNotASetting`, `TestReserve` (internal),
  `TestTimeout_CutChecksAreNeitherDoneNorFailed`, `TestTimeout_FinishedBeforeTheDeadlineIsUnaffected`,
  `TestTimeout_CheckWaitingOnTheLimiterIsNotAFailure`, `TestTimeout_CutEnumerationKeepsEarlierEvidence`
  (a Retiring stage, then a pending redo), `TestTimeoutInAChildProcess`; in `internal/egress`
  `cancel_test.go` (a silent UDP server, the TCP retry, a silent banner, each within half a second of
  the cancel, and the cases that must not change).
- B2: `TestPartial_DeadlineMessageAndHint` (both modes, the exact message, the summary line),
  `TestPartial_DeadlineHint` (`--redo x`, `--redo=x`, a shared flag first, quoting; the hint is run),
  `TestPartial_RaiseTimeoutWhenNothingSucceeded` (three cases), `TestPartial_AbortedChecksAreNotCompleted`.
- B3: `TestEnvelope_EveryKeyOnEveryRun`, `TestEnvelope_ExactBytes`,
  `TestEnvelope_NoEventLinesAndDebugOnlyAddsDebugLines`, `TestEnvelope_WarningsAreInMetaMaskedAndStripped`,
  `TestEnvelope_FindingTextIsStrippedAndMasked`, `TestEnvelope_NotesAreStrippedAndMasked`,
  `TestEnvelope_NotConfigured`, `TestEnvelope_DirectoryIsAbsolute`,
  `TestEnvelope_CandidatesAreCappedAndSourcesAreAList`, `TestEnvelope_ChangesSinceTheLastRun`,
  `TestEnvelope_StdoutIsEmptyOnOtherExits`; in `internal/report` the exact bytes, the zero envelope,
  `Map` and `WriteSummary` unit tests. The existing summary and log tests pass with the console
  summary now written by `WriteSummary`.
- B4: `TestPartial_FailedCheck` (both modes, a re-run with the fault gone), `TestPartial_TransientByCause`,
  `TestPartial_KeyedSourceStatuses` (a real `httpsrc.Get` against 401, 403, 429, 500), `TestPartial_ExitsZeroFor`
  (four cases), and the migrated keyed-source tests (`TestKeyed_*`, `TestGitHub_*`, the quota tests).
- B5: `TestPartial_SignalDuringWrapUpLeavesStdoutEmpty`, `TestPartial_NetblockLimitComesBeforeTheDeadline`,
  `TestPartial_FatalErrorComesBeforeTheNetblockLimit`, `TestPartial_SignalAfterTheResultKeepsExit7`,
  and the deadline with failed checks in `TestPartial_DeadlineMessageAndHint`.
- B6 and B7: `engagement_errors_test.go` (a held lock, a foreign directory in four argument shapes, `-e`
  for a missing engagement with the output directory absent and empty, the hint with three, ten and
  twelve engagements, export's three cases, `--json` leaving the lines unchanged), and
  `engagement.TestProbe`, `TestList`.
- B8: `TestTimeout_InHelp`. B9: `clierr.TestExitCodes` (`LOCKED`) and `TestEnvelope_ExactBytes`; README and
  CLAUDE.md by reading.

The tests for the runner, report and recon changes were written after that code and seen to fail
only by mutation (below); those for egress, engagement and export were seen to fail on their
assertions first, against stubs.

Mutation checks, made after the simplification by editing a copy of the tree by hand (the live files
were not touched), each run against `TestTimeout_|TestEnvelope_|TestPartial_|TestEngagementErrors|
TestTimeoutInAChildProcess`:

- B1, a cancelled check is neither done nor failed: recording it done failed
  `TestTimeout_CutChecksAreNeitherDoneNorFailed` and `TestTimeoutInAChildProcess`; recording it failed
  failed those two and `TestPartial_DeadlineMessageAndHint` and
  `TestTimeout_CheckWaitingOnTheLimiterIsNotAFailure`; removing the early return of a cut stage (so it
  goes on to the sweep) failed `TestTimeout_CutEnumerationKeepsEarlierEvidence`.
- B3, a key in the envelope is masked: dropping the redactor from the mapping initially passed. Only a
  stage's note reaches the envelope without already being redacted by the store, so
  `TestEnvelope_NotesAreStrippedAndMasked` was added; it and `TestEnvelope_FindingTextIsStrippedAndMasked`
  now fail when the mapping is dropped.
- B4, the transient flag: always transient failed `TestPartial_TransientByCause` and
  `TestPartial_KeyedSourceStatuses`, as did `>=` for `>`; a transient deadline error with no success
  failed `TestPartial_RaiseTimeoutWhenNothingSucceeded`.
- B5, a signal leaves stdout empty: dropping the check after the deadline's wrap-up failed
  `TestPartial_SignalDuringWrapUpLeavesStdoutEmpty`; dropping the `PARTIAL` exemption in `Execute`
  failed `TestPartial_SignalAfterTheResultKeepsExit7`.

Deviations from the design:

- **The harness synthesises a `summary` event from the envelope.** D14 has the summary helpers read
  `data` from the envelope. `h.events()` instead appends a `summary` event made from the envelope
  (`summaryOf`, in the old shape), so the roughly 100 tests that read the summary map keep working;
  the tests that are about the envelope read it typed through `h.envelope()`.
- **The world's sources answer with valid empty results by default.** Every failed check now makes a
  run partial, so the shared world (`newWorldWith`) serves empty answers for crt.sh, wayback,
  commoncrawl and the range publishers; a test that wants a failure sets its own handler. That
  default AWS list names 203.0.113.0/24, which some tests use for servers, so `serveAWSElsewhere`
  moves it. This is why many existing tests changed by more than an exit code.
- **A cancel-cut enumeration is not recorded as a failure.** `enumFail` records nothing once the
  context has ended, or a cut stage would leave a failed row for a check that is only unlisted.
- **`--json`'s help** reads `Print one JSON object with the run's outcome on stdout when the run
  ends (recon), and any error as one JSON line on stderr`: the error clause stays true for export.
- **The not-found hint of export** is the list alone (`engagements in <dir>: a, b and 2 more`), without
  recon's "or give domains ... to start one".
- **D9 step 3** (the invocation's context ended) applies only to a run the deadline ended. A run that
  did all its work and then met a signal exits 0 with its result, as the nil-error rule of D4 says.
- **The messages are as written in the design**, so a single failure reads `1 checks failed` and
  `1 checks completed`.
- `--concurrency abc` cannot be used in the export tests (it has no such flag): they use `--kind nope`.

External facts: none differed. `golangci-lint` cannot run here (built with Go 1.26, the module
targets 1.27), so the hook's lint step errors on every edit and no lint result exists; `gofmt` and
`go vet` for the four targets are clean.

## Known limitations

- **B1, B2, B3:** only a check that had called `Stage.Run` when the context ended is counted as
  cancelled (D5). Checks a stage had not yet sent, and stages the run never reached, are in neither
  count, so the message names only the stages that had checks in flight.
- **B1:** the late finish (writing the files takes longer than the reserve) has no test of its own;
  it follows from nothing stopping the write.
- **B6:** `Probe` returns an error, and so `UNEXPECTED_ERROR`, for a path it cannot read, such as
  one beneath a regular file.
- **B3:** the envelope's `directory` is `filepath.Abs` of the engagement directory, so a symlinked
  working directory shows the path the process sees, not the one typed.
- One web test (`TestProbeIP_OutOfScopeAndExcludedIPsAreNotProbed`) failed once in the first full
  `-race` run, while other edits to the tests were being made, and passed in nine runs alone and in
  two full runs after. It was not reproduced.

## Simplify

Fixed:
- recon and export share one `probeEngagement` helper (`engagement_errors.go`) in place of two
  copies of the probe-then-classify block.
- recon sums the cancelled checks with `sumCounts`, as `partialError` does. `partialError` sets
  `Transient` once on each path instead of overwriting it.
- The runner reads a stage's abort error once through `abortErr`, which replaces `isAborted` and
  `abortedByRejection`. `abortFail` takes that error and decides on rejection itself.
- `report`: the dead `ConsoleOptions.Summary` and `SummaryDepth` fields are removed, along with the
  stale `Console` doc. `Warnings.Emit` uses the package's `str`. The envelope's two identical
  stage mappers are one. `writeLabelled` sanitises each label once.
- `engagement.List` stats each entry's state database instead of running `Probe` (and a full
  `ReadDir`) on every sibling. `Probe` checks emptiness with `Readdirnames(1)`.
- Tests: the duplicate helpers are gone (`foundBy` replaced by `finder`, `failsWith` by `erring`,
  `sumStrip` by `stripEscapes`, `splitHint` by `shellSplit`). One `h.partialFailed` holds the
  "n checks failed" assertion that four helpers and two inline checks used to repeat. `sweep` and
  `sweepPartial` share `sweepArgs`. The two signal tests in `partial_test.go` cancel the caller's
  context (which `Execute` treats as an interrupt) instead of sending SIGINT and sleeping 200ms.

Skipped:
- Making `engagement.Open` and `OpenReadOnly` classify through `Probe` with typed errors: the change
  reaches beyond this diff into the engagement package's open paths.
- Replacing the field-by-field `Envelope.clone` with a generic string walk, or sanitising where
  strings enter the `Summary`. The `nonNil` guarantee is kept in both the builder and
  `WriteEnvelope`, and `WriteSummary` keeps its second sanitise (pinned by
  `TestWriteSummary_Sanitises`). D7 set this shape, and the repetition is defence in depth.
- Replacing `Execute`'s PARTIAL exemption from the signal override with a "result written" flag:
  D9 chose the code-based rule.
- Rewriting the harness `recorder` and `summaryOf` shim so tests read the typed envelope, and
  making the recorder marshal lazily. That means 13 assertions in 8 files, for a small saving.
- Skipping `wrapUp`'s second render when the cancel lands after the last render: the window is
  narrow, and the change alters the wrap-up path.
- Per-stage atomic counters in place of `r.count` under the runner lock: negligible next to network
  I/O.
- Shorter deadlines in `TestTimeoutInAChildProcess` (3s) and
  `TestTimeout_CheckWaitingOnTheLimiterIsNotAFailure` (1s): both need a check in flight when the
  timer fires, so a smaller margin under `-race` risks flakes for a few hundred milliseconds.
- Deleting `engagement.State.String`: the `%v` in the Probe tests' failure messages uses it.

`go test ./...` passes apart from `TestHelp_Colour`, which also fails on `HEAD` (see Follow-ups).
`go vet` is clean for all four targets.

# Verification

## Result

Checked on 2026-11-18 against the working tree on top of `df027c6` (68 files). I read the diff of
every non-test file, the new behaviour tests, README and CLAUDE.md, and tried the error paths with a
built binary against a scratch output directory. I made no live run.

- **Goal: met, with the B2 caveat below.** An agent can give `--timeout`, read the exit code (0, 7 or
  the error's code) and the one `{data, meta}` object, and run the hint to carry on. Cancelled checks
  are recorded neither done nor failed, and a cut enumeration never reaches the retire or redo sweep.
- **B1: met.** `--timeout` is a pass-through flag checked with the other problems (`0`, `-5s`, `abc`,
  `30` and `""` exit 2, with the value in `input`). It is not in `settingTable`, `NYX_TIMEOUT` is
  ignored, a `timeout:` key is rejected, and export has no such flag. `reserve` matches the formula.
  The timer cancels with `errDeadline` rather than using a context deadline, so a check waiting on the
  rate limiter is cancelled, not failed (tested). DNS and banner reads end within half a second of a
  cancel (`internal/egress/cancel_test.go`). The late finish is met by reading, since nothing stops
  the write, but it has no test (Known limitations).
- **B2: partly met.** The message, the hint without `--redo` (shell-quoted, `--timeout` kept), the
  transient flag and "raise `--timeout`" when nothing succeeded are as specified and tested.
  "Cancelled" counts only checks that had called `Stage.Run` when the cancel landed (D5). Checks
  still queued, and stages the run never reached, are in neither count, so the message can name fewer
  cancelled checks and stages than the deadline actually stopped (Known limitations). A check a stage
  abandoned is failed but not completed, as specified.
- **B3: met.** One compact line holds the keys of D7 and `meta` in order. Every list is `[]` when
  empty, `detail` and a first run's `changes` are `null`, and there are no event lines. Warnings go
  only to `meta.warnings`, and the envelope is sanitised and redacted. `not_configured` comes from the
  stage gates, `directory` is absolute, and the candidates are capped at 20 with `candidates_total`.
  stdout is empty on exits 1, 2, 3 and 130, and `--debug` adds only DEBUG lines to stderr. The human
  summary adds `Stopped by the deadline: N checks completed, M cancelled`. A symlinked working
  directory shows the path the process sees (Known limitations); `directory` is still absolute.
- **B4: met.** Any failed check this run exits 7, including checks a stage abandoned on 401, 403, 429
  or a spent quota, and a panic. The error names each stage with its count. It is not transient only
  when every failure was a refused key (`run.ErrKeyRejected` from `httpsrc.get` for a keyed 401 or 403,
  and from `github` for a 401). A `not-configured` stage, a budget deferral, a page cap and a failure
  recorded by an earlier run for a skipped stage all exit 0.
- **B5: met.** The precedence is: a signal (the `PARTIAL` exemption in `Execute` applies only after
  the result is written), the render or close error, the netblock limit (also when the deadline's
  wrap-up meets it), the deadline, then failed checks. A deadline error also names the failed checks.
  A signal during the deadline's wrap-up leaves stdout empty and gives `INTERRUPTED`.
- **B6: met.** `LOCKED` exits 1 and is transient. A foreign directory exits 2 naming it, reported with
  the other problems. `-e <name>` with no inputs for a missing engagement exits 3, creates nothing, and
  its hint lists up to ten engagements and how many more. A path `Probe` cannot stat (such as one
  beneath a regular file) is `UNEXPECTED_ERROR`, as D10 says (Known limitations). B6 does not cover
  that case.
- **B7: met.** export uses the same probe (absent exits 3, foreign exits 2, a write failure exits 1),
  takes no `--timeout`, and with `--json` its lines are unchanged.
- **B8: met.** `timeout` is in `reconEveryday`, and recon's first example is
  `nyx recon example.com --json --timeout 30m` in both helps.
- **B9: met.** README has the envelope's keys and their stability, a Deadline section, the exit codes
  (7, `LOCKED`, 3 and 2), the eleven departures in one list and the migration note. CLAUDE.md
  lists the envelope's keys among the stable interfaces and narrows the free-to-change convention to
  CSV columns. `clierr.TestExitCodes` covers `LOCKED`.
- **Out of scope:** nothing out of scope was built. No default deadline, no event lines, no hard stop,
  no export envelope.

Corrected during verification:
- The `input` of the `NOT_FOUND` and foreign-directory errors held the derived engagement name (for
  `-e 'Nope Two'`, `nope-two`), not the value as typed, which README's "Errors" section promises (B6,
  B7). `probeEngagement` and `engagementNotFound` now take the typed value. For a name derived from
  the first input, the foreign problem's `input` is that input, as before this spec. A case in
  `TestEngagementErrors_NotFoundCreatesNothing` pins this for recon and export.

The design deviations listed under Develop all keep the behaviours. One example: D9 step 3 applies
only to a deadline run, because D4 has a run that finished its work exit with its result.
`go test ./...` passes apart from `TestHelp_Colour`. I confirmed that it fails the same way on a clean
export of `df027c6`.

## Code review

`/code-review high --fix` reviewed every file that differs from `main`. It applied two fixes, both
within the spec:

- **Problems before a probe failure (B1, B6, B7).** recon and export returned a failure to stat the
  engagement directory straight away (`UNEXPECTED_ERROR`), ahead of the usage problems already
  collected. For example, `--output-dir <a file> --timeout abc` exited 1 without reporting the bad
  `--timeout`. Both commands now report every usage problem first (exit 2), and the probe's error
  only when there is none.
- **The input of a late foreign directory (B6).** `openError`, for a directory that turned foreign
  between the probe and `Open`, now names the value as typed as its input, as the probe's problem
  does.

Left unfixed:
- The `--quiet` help (`Write only warnings and errors to stderr; the summary is still printed`) does
  not say that under `--json` warnings go only to `meta.warnings` and `--quiet` changes nothing.
  README says so. No behaviour is wrong, and the wording is the user's to choose.

After the fixes, `XDG_CONFIG_HOME=$(mktemp -d) make test` (the vet for all four targets and
`go test -race ./...`) passes apart from `TestHelp_Colour`, which fails before this change too.

# Follow-ups

1. Update any script or agent skill of your own that reads nyx's JSON event lines, or that treats
   exit 0 as "ran, perhaps with failed checks". A `--json` run now writes one `{data, meta}` object,
   and a run with failed checks exits 7. Search them with `grep -rn 'run_end\|"summary"\|"candidate"'`
   and check every exit-code test.
2. Run a large engagement with a deadline and time the final write: `time nyx recon -e <large
   engagement> --json --timeout 2h`. The gap between the moment checks stop and the exit is the
   write. If it nears 60 seconds, the reserve's cap in `internal/cli/deadline.go` (`reserve`) is too
   low, and the measured reserve declined under Out of scope is the fix.
3. With real keys, check what each keyed source answers for a wrong key and for spent credits. For
   example, set `NYX_KEYS_SHODAN=wrong` and run `nyx recon example.com --passive --json --debug`, then
   read the DEBUG lines and the `PARTIAL` error's `transient`. D6 assumes no source outside GitHub
   uses 403 for a rate limit. If one does, give it GitHub's treatment in
   `internal/stages/httpsrc/httpsrc.go` (`get`).
4. Decide whether a spec should split the long checks. One permutations check per root, and one
   crawl check per service, can outlast an agent-sized deadline, so such a run never gets past them
   (`docs/specs/`, via `/spec-define`).
5. Decide whether "cancelled" should also count the checks a deadline stopped before they started
   (queued checks, and stages the run never reached). Today the count and the stage names in the
   `PARTIAL` message cover only checks in flight (`internal/run/runner.go`, the worker loop in
   `runStage`; Known limitations, B2).
6. Look into `nyx recon -e <name> --redo rdap`, which looks up nothing when no earlier stage does work
   in that run. rdap's `Checks` skips every address that `View.Registered` calls registered, and the
   redo leaves those records current. A spec of its own (`internal/stages/rdap`). Two rdap tests work
   round it by passing an extra root on the redo run.
7. Fix `TestHelp_Colour`, which fails on `df027c6` and still does: the root help does not colour bool
   flags such as `--passive[=true|false]`. Run it with
   `go test ./internal/cli/ -run TestHelp_Colour -count=1`. Until it is fixed, `make test` fails.
8. Choose whether to reword the `--quiet` help (`internal/cli/help.go`). Under `--json`, `--quiet`
   changes nothing, because warnings go only to `meta.warnings` (see Code review).
9. Install a `golangci-lint` built with Go 1.27 or later, for example
   `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`. Then run
   `golangci-lint run ./...`. The one installed here was built with 1.26, so neither this change nor
   the hook's lint step has been linted. The linter note in Spec 23's follow-ups is the same item.
