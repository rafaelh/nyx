# Spec 24 (2 of 3): recon and export under the agent contract

## Goal

An agent can run recon to a deadline, read the run's outcome from the exit code and one JSON
object, and resume a run it cut short without losing progress or going round in circles.

Depends on Spec 23 (command tree and shared CLI contract).

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
      unconfirmed risky ports and the stages' notes. A candidate's sources are a list.
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

Settled 2026-11-17 against the code at `b06b6d7` and against the design of Spec 23, which is
**not built yet**: there is no `internal/clierr`, no `classify.go`, no `failure.go` and no `recon`
command in the code. Build Spec 23 first. "S23 Dn" below is a decision of that spec; where the
code as built differs from it, follow the code and keep the behaviour.

The user decided the reserve and the late finish (D2), the rule for "raise `--timeout`" (D9), the
envelope's keys, `not_configured` and the list type of `sources` (D7), the `LOCKED` code (D10)
and the eleven departures (D13). An architecture review then moved the deadline from the runner
to the command (D2, D4), changed what counts as completed (D5), made the test tap pass through
JSON (D14), and added the error precedence of D4, the redaction of warnings (D7), the guard on
retire and redo (D4) and the stage names in the `PARTIAL` message (D9).

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
    It is declared with a pass-through `pflag.Value` whose `Type()` is `duration`, as S23 D7 does
    for numbers, so a bad value joins S23's collected `clierr.Problems` instead of ending the
    parse. The check: `time.ParseDuration` succeeds and the result is above zero. The problem
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
      context ended (first external fact), and `egress/http.go:391` reads a parent's
      `DeadlineExceeded` as a "no service" result. A plain cancel has neither problem.
    - The runner knows nothing of the deadline. It returns an error that wraps
      `context.Cause(ctx)`, as S23 D9 already says, and recon tests
      `errors.Is(err, errDeadline)`.
    - Nothing stops the write when the reserve runs out. recon finishes and exits 7 late.

D3. **A cancel ends work in flight at once.** Two reads ignore the context today and hold a
    cancelled check for up to three seconds. Both fixes are in `internal/egress`.
    - DNS (`dns.go`): dial with `Client.DialContext`, register
      `stop := context.AfterFunc(ctx, func() { conn.Close() })`, then call
      `ExchangeWithConnContext`, for the UDP exchange and for the TCP retry of a truncated
      answer. One helper serves both. The existing `ctx.Err()` test after a failed exchange
      then returns the context's error.
    - TCP (`tcp.go`): the same `context.AfterFunc` around the banner read, and
      `ctx.Err()` returned when the context ended during it.
    - `runStage`'s producer loop tests `ctx.Err()` at the top of each check a stage yields and
      stops producing. `permutations` and `storage` enumerate without looking at the context.

D4. **`Runner.Run` returns `(Result, error)`.** This replaces the error-only return of S23 D9
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
      stage that was cut short. If the rebuild meets the netblock limit, that error is returned
      instead (B5: the netblock limit comes before the deadline).
    - `*NetblockLimitError` or any other error: the `Result` is zero. The files are still
      rendered first, as today.
    - An error from that render or flush replaces a netblock or context error (B5: a fatal
      error comes first). Today `runner.go:193` keeps the netblock error.
    - `runStage` keeps its early return when the context has ended. It must not fall through
      to `FinishRedo` or `Retire`: the producer stopped early, so the set of valid checks is
      incomplete and a sweep would delete evidence of checks that were never listed.
    - The runner no longer emits `summary`, `candidate` or `run_end`; recon writes the result
      (D7, D9).

D5. **Completed, succeeded and cancelled are counted where `Stage.Run` returns.** A worker
    that called `Stage.Run` adds one to the stage's *cancelled* when the context had ended by
    the time it returned, and otherwise one to *completed*, and to *succeeded* when the error
    is nil. The enumeration failure counts as completed. A check failed by a stage abort
    without running (`stage aborted earlier in this run`) is failed, and is in neither count.
    The runner's `attempted`, which the stage lines use, is left as it is. Why not `attempted`:
    it includes the checks an abort failed, so one rejected key would make every run look like
    progress.

D6. **A refused key is its own sentinel.** `run.ErrKeyRejected = fmt.Errorf("key rejected: %w",
    ErrAbortStage)`.
    - `httpsrc.get` returns it for a keyed 401 or 403. A keyed 429 stays a plain
      `ErrAbortStage`.
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

    - `report.Meta`, in this order: `count` (always 1, the single-record shape of
      `docs/agent-tools/0003`), `deadline_exceeded`, `checks_completed`, `checks_cancelled`,
      `warnings`.
    - `report.Envelope{Data Summary; Meta Meta}`. `Envelope.Map(func(string) string)` returns a
      copy with every string mapped, the warnings included. recon maps it once through
      `sanitize.Text` and the redactor, as `export` does for its lines, before either writer.
    - `report.WriteEnvelope(w, env)` writes one compact line with `SetEscapeHTML(false)`. It
      turns each nil list into `[]`, so every key appears on every run.
    - `report.WriteSummary(w, depth, env)` writes the human summary: today's text from the
      typed value (a candidate's sources joined with `;` as now), plus the line
      `Stopped by the deadline: N checks completed, M cancelled` after the notes when
      `deadline_exceeded` is true.
    - The runner fills `Summary` at the end of a run, on both paths of D4 that return a
      `Result`. `not_configured` comes from `r.gate(s)` for each stage.
    - Deleted: `report.JSONEmitter` and `NewJSON`; the `summary`, `candidate` and `run_end`
      event types; `Event.Time` and `timestamp`, which only the JSON lines used; the `summary`
      case and method of `Console`. The events that remain (`run_start`, `stage`, `found`,
      `count`, `warning`, `debug`) drive the human log.

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
         or `--redo=<v>` removed, built by the hint builder S23 puts in `classify.go`;
         transient.
       - `Succeeded == 0`: the hint is `raise --timeout: no check succeeded within 30m`; not
         transient, whatever the failures were (B5 as amended).
    6. Otherwise, some check failed: return `PARTIAL` with the message `16 checks failed:
       crtsh 2, shodan 14`, the same invocation hint, and transient per D6.
    7. Otherwise return nil.

    `input` is `null` for every `PARTIAL` error.

    **This amends S23 D10.** `Execute` turns any error a command returns into `INTERRUPTED`
    once a signal is recorded. An error whose code is `PARTIAL` is now exempt: a command
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
     - recon probes during validation, before `engagement.Open`, replacing the `state.db` test
       of S23 D8.
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
     `UNEXPECTED_ERROR`. `OpenReadOnly` keeps its untyped errors as the fallback for a
     directory that changed after the probe. Its lines and flags do not change.

D12. **Help** (B8). `timeout` joins the names in recon's everyday-flags annotation (S23 D14),
     and recon's `Example` lines pass it: `nyx recon example.com --json --timeout 30m`. Root
     and command help are both rendered from those, so no other change is needed. The flag's
     help: `Stop by this deadline, e.g. 30m or 2h, and exit 7; run again to carry on
     (default: none)`.

D13. **Documents** (B9; user decision: eleven departures).
     - README, "Console and JSON": the envelope with each key of D7, that the keys are a
       stable interface (adding one is compatible; renaming, removing or retyping one is a
       breaking change), and that the event lines are gone.
     - README, a section on the deadline: the reserve, the late finish, what a cancelled check
       is, the two hints, and that a single permutations or crawl check can take minutes, so a
       short `--timeout` may never finish one.
     - README, exit codes: 7 for recon, `LOCKED` under 1, 3 and 2 for the engagement cases of
       B6 and B7, and exit 0 no longer covering failed checks.
     - README, one list titled for departures from `docs/agent-tools`, with the eleven items
       of B9.
     - README, migration: an old output directory now exits 2.
     - CLAUDE.md: the flow line (`internal/report` writes the console log, the summary and
       the `--json` envelope), and the envelope's keys beside the other stable interfaces.

D14. **Tests keep reading events, through a tap.** 161 of the 444 tests in `internal/cli` read
     the event lines, most through `world.run`, which always passes `--json`.
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
       envelope on stdout instead, adapting to its lists.
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
- `internal/cli/cli.go`: `Deps.Events` (D14); `newEmitter` without the JSON lines (D8).
- `internal/cli/failure.go`: the `PARTIAL` exemption (D9).
- `internal/cli/export.go`: the probe and the error codes (D11).
- `internal/clierr/clierr.go`: `Locked` and its row in the exit table (D10).
- `internal/run/runner.go`: `Run` returns `(Result, error)`, the wrap-up and the error
  precedence (D4); the counters (D5); `aborted` as a map of causes and `recordFailure`'s flag
  (D6); the producer's context test (D3); `Summary` built from what `emitSummary` and
  `rankedCandidates` compute today (D7).
- `internal/run/stage.go`: `ErrKeyRejected` (D6).
- `internal/report/report.go`: the deletions of D7.
- `internal/egress/dns.go`, `tcp.go`: connections closed on cancel (D3).
- `internal/stages/httpsrc/httpsrc.go`, `internal/stages/github/github.go`: `ErrKeyRejected`
  (D6).
- `internal/engagement/engagement.go`: `Probe`, `State`, `List` (D10).
- `internal/cli/harness_test.go`, `risk_helpers_test.go` and the helper functions named in D14.
- `README.md`, `CLAUDE.md` (D13).
- `docs/plans/2026-11-build-order.md`: mark this spec, and add the seams it owns:
  `report.Summary` and the envelope, `run.Result`, `run.ErrKeyRejected`, `Deps.Events`,
  `engagement.Probe` and `List`, `clierr.Locked`, and the `PARTIAL` exemption.

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
    `detail`. A unit test encodes the zero `Envelope` to the same shape.
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
  leaves exit 7 standing (a unit test of the exemption in `failure.go`).
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
- The tests that assert event order or the JSON stream itself: `candidates_test.go:385-415`,
  `behaviour_test.go` `TestJSONMode` and its `run_start`/`run_end` count,
  `logcolours_test.go:680-726` (the same stream with and without `--debug`), and the
  `candidate` event assertions in `candidates_test.go` and `rdap_test.go`. Rewrite them
  against the envelope.
- `providerranges_test.go:203` filters on an event type `finding` that never existed, so it
  asserts nothing. Make it read `data.findings`.
- Every test whose run has a failed check and expects exit 0 now gets 7: the key-rejection
  and quota tests in `sources_keyed`, `sources_unkeyed`, `discovery`, `github`, `reverseip`,
  `rdap`, `identifiers`, `shodan_host` and `logcolours`, and any `mustRun` over a failing
  source.
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
- `docs/plans/2026-11-build-order.md`: behaviour tests in new `internal/cli/<feature>_test.go`
  files; new struct fields appended at the end. Run the suite as
  `XDG_CONFIG_HOME=$(mktemp -d) make test`.

## Handed to later specs

- **Spec 25 (CVE lookup):** the `PARTIAL` exemption of D9 covers every command, so its command
  must test its context before writing to stdout, or a signal during its run would exit 7. Its
  envelope and its `--timeout` (with a default) are its own; `report.Envelope` is recon's.
- **Spec 20 (changes report)** adds a summary line: now a field appended to `report.Summary`,
  which is also a key appended to the envelope.
- **Specs 7, 14, 16, 19 and 20**, designed before this one: `h.events()` reads the tap and
  keeps working; a summary assertion reads the envelope; a run with a failed check exits 7;
  README text about a `--json` event (`found`, `summary`, `warning`) is rewritten for the
  envelope or the log.

# Follow-ups

- Update any script or agent skill file of your own that reads nyx's JSON event lines, or that
  treats exit 0 as "ran, perhaps with failed checks": the first now gets one object, and the
  second gets exit 7.
- Run a large engagement with `--timeout` and time the final write. If it nears 60 seconds,
  the reserve's cap is too low, and the measured reserve declined above is the fix.
- With real keys, check what each keyed source answers for a wrong key and for spent credits.
  D6 assumes a 403 is never a rate limit outside GitHub.
- One permutations check per root, and one crawl check per service, can outlast an agent-sized
  deadline, so such a run never gets past them. Splitting those checks is a spec of its own.
- The linter note in Spec 23's follow-ups still applies.
