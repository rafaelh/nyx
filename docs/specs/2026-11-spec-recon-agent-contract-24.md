# Spec 24 (2 of 3): recon and export under the agent contract

## Goal

An agent can run recon to a deadline, read the run's outcome from the exit code and one JSON
object, and resume a run it cut short without losing progress or going round in circles.

Depends on Spec 23 (command tree and shared CLI contract).

## Behaviours

B1. `nyx recon --timeout D` sets a deadline for the run. It is a flag only, with no default, no
    config key and no `NYX_*` variable. A value that is not a positive duration exits 2. With it,
    recon exits by the deadline: it stops starting checks, and cancels the ones in flight, early
    enough to write its files and summary before the deadline passes. A cancelled check is not
    done and not failed, and runs on the next run. A run that finishes its work before the
    deadline is unaffected.

B2. A run the deadline ended prints its summary or envelope and exits 7.
    - Its `PARTIAL` error says the deadline stopped the run, how many checks completed in this
      run and how many the deadline cancelled. A check is completed when it finished in this run,
      whether it succeeded or failed.
    - The hint is the caller's own invocation, shell-quoted, with `--redo` and its value removed
      and every other argument kept, and the error is marked transient.
    - When every check the run started was cancelled, the hint says to raise `--timeout` instead,
      and the error is not marked transient.

B3. `nyx recon --json` writes one compact `{data, meta}` object to stdout when the run ends, and
    no event lines.
    - `data` holds the engagement's name and directory and everything the human summary shows:
      counts, failed checks per stage, deferred work per stage, high and medium findings,
      high-confidence candidates, unconfirmed risky ports and the stages' notes.
    - The envelope also says whether the deadline ended the run, and how many checks completed
      and how many were cancelled.
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
    B2 or any of those failures makes it so.

B6. Engagement problems get the exit code of their kind.
    - An engagement locked by another run exits 1, marked transient.
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
    - SIGHUP exits 129.

## Out of scope

- A default deadline for recon. Declined: runs take hours, so the deadline is opt-in.
- Keeping the JSON event lines, or a flag that brings them back. Declined: one envelope; the files
  and `nyx recon export` are the detailed record.
- Letting in-flight checks finish at the deadline. Declined: the run must end by the deadline.
- Deferred work making a run partial. Declined: a per-run cap is a setting the caller chose.
- Making export a list verb, or adding a verb for querying an engagement. Declined for now: export
  stays a bulk dump.
- Environment-only API keys. Declined: `keys.<source>` in the config file stays.
- Reading recon's inputs from stdin.
