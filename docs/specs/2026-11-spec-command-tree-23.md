# Spec 23 (1 of 3): command tree and shared CLI contract

## Goal

Everything nyx does today runs as `nyx recon`, leaving the root free for other commands. An agent
learns every command from one `nyx --help`, and can act on any outcome from the exit code and one
error on stderr, as `docs/agent-tools` sets out.

This is the first of three specs. Spec 24 (recon and export under the agent contract) and Spec 25
(CVE lookup) depend on it and can be built in parallel once it has merged.

## Behaviours

B1. `nyx recon [domain...] [flags]` does what `nyx [domain...] [flags]` does today, and
    `nyx recon export` does what `nyx export` does today, with the same inputs, flags, settings,
    config file, engagements and files, except where B5 to B14 change it.

B2. An old-form call exits 2 with a hint that is the caller's own arguments, shell-quoted, with
    `recon` inserted after `nyx`. A call is old-form when its first argument, the shared flags of
    B5 aside, is not a command and contains a dot, or is a flag that only recon or export takes
    and no command name follows the flags (`nyx example.com`, `nyx -e acme`,
    `nyx --passive example.com`, `nyx --json example.com`). When a command name does follow, the
    call is a misplaced flag under B5. `nyx export …` gets the hint `nyx recon export …`. An
    old-form call writes nothing to stdout, creates nothing and contacts nothing. (amended by D2)

B3. A bare `nyx` and `nyx help` print the root help, exactly as `nyx --help` does, and exit 0;
    `nyx help <command>` prints that command's own help. Any other unknown first word exits 2
    naming the valid commands, and prints no help. (amended by the user on 2026-11-17, during
    the build: B3 first had a bare `nyx` exit 2 and no `help` command)

B4. `nyx --help` writes to stdout and exits 0.
    - It opens with examples that pass `--json`.
    - It then shows every registered command with its everyday flags, one example and the valid
      values of each fixed-set flag it shows (recon's stage names, export's kinds).
    - recon's everyday flags are its inputs (positional domains, `-d`, `--org`, `--asn`,
      `--cidr`), `-x`, `--exclude-file`, `-e`, `--passive`, `--authorised`, `--redo`, `--skip`,
      `--allow-large-netblocks`, `--config`, `--output-dir` and the shared flags of B5. Every
      other recon flag is a tuning setting, listed only in `nyx recon --help`, and the root help
      says so. export's everyday flags are all of its flags.
    - It ends with one line listing the exit codes.
    - Each command's own `--help` also opens with examples and ends with the exit-codes line.
    - A command added later adds its own entry to the root help.

B5. Every command takes `--json`/`-J`, `--quiet`/`-q` and `--debug`, before or after the command
    name (`nyx --json recon example.com` runs recon). `--json` implies `--quiet`. `--json --debug`
    is allowed; `--quiet --debug` exits 2 on every command. None of the three is a setting: there
    is no config key or `NYX_*` variable for them. Any other flag placed before the command is a
    usage error that says flags follow the command, and its hint is the caller's own arguments,
    shell-quoted, with the command moved to directly after `nyx`
    (`nyx --passive recon example.com` gets `nyx recon --passive example.com`). What
    `nyx recon --json` and `nyx recon export` print on stdout when they succeed is not changed by
    this spec. (amended by D2)

B6. `nyx --version` prints the version and exits 0. Every HTTP request nyx makes carries
    `nyx/<version>` as its User-Agent (`nyx/devel` for a build with no version), in place of
    today's fixed `nyx/1`.

B7. A flag must be spelt in full: an abbreviation (`--pass` for `--passive`) is an unknown flag.
    `--authorized` stays the one alias.

B8. A problem with a flag, a setting, the config file or a file named on the command line is a
    usage error: exit 2 before anything is contacted, created or written. Checks of values and
    combinations report every problem they find in one error, with each failing value echoed; an
    unknown flag or command may be reported on its own.

B9. Every non-zero exit writes one error to stderr, and stdout is empty unless the exit is 7.
    - In human mode the error is `error: <message> (<CODE>)`, then `hint: <next step>` when there
      is one, then `retry: may succeed after a wait` when it is transient, with no timestamp or
      level.
    - Under `--json` it is one compact line of JSON with exactly the keys `error`, `code`, `hint`,
      `input` and `transient`; `hint` and `input` are `null` when there is nothing to say.
    - `--json` applies even when the arguments fail to parse: `nyx recon --bogus --json` gets a
      JSON error.
    - Two exceptions. In human mode, exit 7 from a call with several targets adds one
      `error: <input>: <message> (<CODE>)` line for each target that failed. And until Spec 24,
      the event lines a `nyx recon --json` run printed before it failed stay on stdout; the
      failure itself is the error on stderr and no longer an `error` event.

B10. Exit codes mean the same for every command:

    | Code | Meaning | Error codes |
    |---|---|---|
    | 0 | Success | none |
    | 1 | System error | `NETWORK_ERROR`, `TIMEOUT`, `RATE_LIMITED`, `UPSTREAM_ERROR`, `AUTH_FAILED`, `UNEXPECTED_ERROR` |
    | 2 | Usage error | `INVALID_INPUT` |
    | 3 | Not found | `NOT_FOUND` |
    | 7 | Partial result | `PARTIAL` |
    | 130, 143, 129 | SIGINT, SIGTERM, SIGHUP | `INTERRUPTED` |

    Exceeding the netblock limit without `--allow-large-netblocks` therefore exits 2, no longer
    3. Its error shows the address total, and its hint is the caller's own invocation,
    shell-quoted, with `--allow-large-netblocks` added and `--redo` and its value removed. It is
    the one usage error raised after a run has started work. Until Spec 24, recon and export keep
    exit 1 for the cases that spec reclassifies.

B11. A signal ends the command with its own exit code (130, 143 or 129, where today all three
     give 130), an `INTERRUPTED` error and an empty stdout. recon saves completed work as it does
     today. A second signal exits at once with the same code, and the error is still written
     exactly once.

B12. An unexpected failure exits 1 as `UNEXPECTED_ERROR`, with its stack trace on stderr only
     under `--debug`. A panic inside one recon check is that check's failure: the run carries on,
     and the check is retried on the next run.

B13. No command prompts. recon no longer asks for authorisation on a terminal: the stages that
     contact target systems run only with `--authorised` or an acknowledgement stored for the
     engagement, and otherwise are `not-configured (no authorisation)` with the existing warning,
     on a terminal as anywhere else. No command reads stdin unless an argument is `-`, and none
     loads a `.env` file.

B14. The exit codes, the error codes and the five keys of the error are a stable interface: adding
     one is compatible, and renaming or removing one is a breaking change. README and CLAUDE.md
     say so.

## Out of scope

- Keeping `nyx example.com` working as an alias, silent or with a warning. Declined: a clean break
  keeps the root free and avoids a second spelling.
- recon's tuning settings in the root help. Declined: they stay in `nyx recon --help`.
- `--timeout`, which Specs 24 and 25 add to their own commands.
- recon's `--json` envelope and exit 7 for recon, which are Spec 24's.
- Reading recon's inputs from stdin.

# Design

Settled 2026-11-16 against the code at `21455a6`. The user decided D2 (which rule wins), D7 and
the root help's level of detail in D14. An architecture review then changed D6, D8, D9, D10, D11
and D14 and added the last paragraph of D4; none of its findings went against a user decision.

## External facts

| Fact | Tag |
|---|---|
| pflag v1.0.10 looks a long flag up by its exact name (`flag.go`, `parseLongArg`), and cobra's `EnablePrefixMatching` is off by default. `nyx --pass example.com` already fails with `unknown flag: --pass`, exit 2. B7 needs only a test. | confirmed live |
| cobra v1.10.2 `stripFlags` (`command.go:691`) assumes an unknown `--flag` takes a value and swallows the next argument, so cobra alone reads `nyx --passive recon x` as an unknown flag on the root. The pre-scan of D2 is needed. | from source |
| cobra adds a `help` command to a root that has subcommands, during `ExecuteC` (`InitDefaultHelpCmd`, `command.go:1263`), so it is in `root.Commands()` by the time a help function runs. | from source |
| cobra adds `-v` to `--version` unless a `version` flag is already defined (`command.go:1238`). Today's long-only definition stays. | from source |
| viper v1.21.0 reads a bound flag by its type name (`viper.go:1179`): `int` goes through `cast.ToInt`, which turns `abc` into `0` without an error. Any type name it does not list is read as the raw string. | from source |
| pflag shows a custom value's `Type()` as the placeholder in help, and `(default N)` unquoted unless the default is `0`, `false` or empty (`flag.go:574-633`). | from source |
| mapstructure fills the struct before it reports unused keys, so `UnmarshalExact` leaves usable values behind when its only complaint is an unknown key. | assumed (read by the reviewer, not checked here); D6 says what to do if it is wrong |
| An unrecovered Go panic prints the runtime's dump and exits 2, the same code as a usage error. | from docs |
| A shell reports 128 plus the signal number: SIGHUP 129, SIGINT 130, SIGTERM 143, on Linux and macOS. | from docs |
| The build's version string (`v0.0.0-20261116071529-21455a61bc0f+dirty` today) holds only characters that are valid in a User-Agent product token. | confirmed live (the string), from docs (RFC 9110 tokens) |
| Today: `nyx --json --bogus` writes an `error` and a `run_end` event to stdout; `--quiet --debug` and a missing `-e` on export are reported in cobra's own words; `--ports 99999 --concurrency 0 --redo nope bad_domain` reports the two settings and stops before the stage and the domain. | confirmed live |

## Decisions

D1. **Keep cobra; the tree is `nyx` → `recon` → `export`.** The root owns the persistent flags
    `--json`/`-J`, `--quiet`/`-q` and `--debug`, plus `--version` (long only) and `--help`.
    `recon` takes every flag today's root takes, the hidden `--palette` included, and `export`
    is its child with its own flags. The root keeps `SilenceErrors`, `SilenceUsage` and
    `CompletionOptions.DisableDefaultCmd`, and its own `help [command]` command through
    `SetHelpCommand`, which prints the root help or the named command's (B3 as amended). A
    command's run function never returns an error
    through cobra (as today: `RunE` returns nil and the result is captured), so whatever
    `ExecuteContext` returns is cobra's or pflag's own and is a usage error. cobra's
    `MarkFlagRequired` and `MarkFlagsMutuallyExclusive` go; D6 replaces them. `-h` stays as the
    shorthand of `--help`. Why: replacing cobra would rewrite flag parsing and help for no gain.

D2. **A pure pre-scan classifies the arguments before cobra sees them** (user decision on the
    overlap of B2 and B5). `classify(args, root)` reads the command names and flag sets from
    the cobra tree and returns one of the outcomes below.
    - Shared tokens are skipped: `--json`, `--quiet`, `--debug` (with or without `=value`),
      `--help`, and `-J`, `-q`, `-h` alone or clustered. `--version` is valid only when no
      command is given.
    - The first other token decides. A command name (`help` included): hand the arguments to
      cobra. None: `--version` if asked for, else the root help. Not a flag: `export` or a word
      with a dot is old-form, anything else is an unknown command.
    - A flag: look it up in every command's flag set to learn whether it takes a value, and walk
      on to the first positional. If that is a command name, the error is "flags follow the
      command" and the hint moves the command to directly after `nyx`. Otherwise the call is
      old-form when recon or export takes the flag and no other command does, and an unknown
      flag when no command takes it. A flag that several commands take, with no command given,
      is the usage error `no command given`, hint `nyx --help`.
    - `nyx -e recon` is old-form: `recon` there is the value of `-e`.
    - JSON mode for errors comes from a raw scan of the arguments before a bare `--`: `--json`,
      `--json=<true value>`, `-J`, or a cluster of shared shorthands that contains `J`. So
      `nyx recon --bogus --json` gets a JSON error.
    - Hints name the program `nyx`, whatever `argv[0]` was, and quote each argument with one
      POSIX quoting function (unquoted when it is only safe characters, else single-quoted with
      `'\''` for a quote).

D3. **One error type, in a new leaf package `internal/clierr`** with no I/O. `cli`, `config`,
    `input` and `store` import it; `run` does not.
    - `Error{Code, Message, Hint, Input any, Transient bool, Targets []Target}`.
    - Constants for every error code in B10, and one table from code to exit code. A signal's
      exit code is the only one not read from the table.
    - `Problem{Name, Value, Message, Hint}` and `Problems`, a collector that is an `error` and
      becomes one `INVALID_INPUT` error: the messages joined by `; `, the distinct hints joined
      by `; ` (default `nyx <command> --help`), and `input` a JSON object from each name to the
      list of its failing values. It is always a list, so the shape does not depend on how many
      failed.
    - `PanicError{Value, Stack}`.
    - `Targets` holds the per-target lines of B9's exit 7. No command exits 7 in this spec, so a
      unit test of the writer pins the layout and Spec 25 is its first user.
    Why a package of its own: Spec 25's NVD code must classify its failures with these codes and
    cannot import `cli`.

D4. **`Execute` alone picks the exit code and writes the error.** Commands return an error and
    print none.
    - An error that is not a `clierr.Error` is `UNEXPECTED_ERROR`, exit 1. Until Spec 24 that
      covers a locked engagement, a directory that is not an engagement, and store and file
      failures.
    - Human mode: `error: <message> (<CODE>)`, then `hint: …`, then
      `retry: may succeed after a wait`, then one `error: <input>: <message> (<CODE>)` per
      target. Only `error:` keeps today's colour on a terminal. Each line goes through
      `sanitize.Text`.
    - `--json`: one compact line from a struct with the keys in the order `error`, `code`,
      `hint`, `input`, `transient`; `hint` and `input` are `null` when empty; no HTML escaping.
    - A `sync.Once` guards the write, for the second signal of D10.
    - Both modes redact API keys. The redactor starts from the `NYX_KEYS_*` variables, read
      before the configuration is loaded, and the command replaces it with the full one once
      `config.Load` succeeds.

    | Case | Message | Hint | `input` |
    |---|---|---|---|
    | A flag several commands take, and no command | `no command given` | `nyx --help` | `null` |
    | Unknown command | names it and lists the commands | `nyx --help` | `{"command":[…]}` |
    | Old-form | says nyx now takes a command | the corrected invocation | `{"argument":[<first argument>]}` |
    | Flag before the command | `flags follow the command` | the corrected invocation | `{"flag":[…]}` |
    | Unknown flag or other parser error | the parser's message | `nyx <command> --help` | `{"flag":[…]}` when pflag's typed error names it, else `null` |
    | Validation | every problem | the valid values, where a set is fixed | name to values |
    | Netblock limit | the address total and the limit | D9 | `null` |
    | Signal | `interrupted by SIGTERM` | recon: completed work is saved, run the same command again | `null` |
    | Panic | `unexpected failure: <value>` | `add --debug for the stack trace`, when it was not given | `null` |

D5. **The `error` event and a `run_end` with a non-zero code are gone.** `cli.fail` and the
    `error` case of `report.Console` are deleted. A successful `--json` run still ends with
    `run_end` and `exit_code` 0. Event lines printed before a failure stay on stdout, as B9
    allows until Spec 24, and nothing is added after them. The "interrupted; completed work is
    saved" warning event becomes the hint of the `INTERRUPTED` error.

D6. **Validation is collected into one error** (B8). `Execute` starts the `Problems` of every
    command with the `--quiet` and `--debug` check and hands it to the command.
    - recon adds: `config.Load`, `input.Parse`, the engagement name, "no inputs", the `--redo`
      stage and the `--skip` rules (left out when the settings did not load).
    - export adds: a missing `-e`, each unknown `--kind`, `config.Load`, the engagement name,
      and an `--output` whose directory does not exist.
    - `config.Load` and `input.Parse` return `clierr.Problems`. A setting's name is its key
      (`rate.per_host`); an input's is `domain`, `org`, `asn`, `cidr`, `exclude`,
      `domains-file` or `exclude-file`; cli's own are the flag name without dashes.
    - `config.Load` no longer returns at a config file it cannot read or at an unknown key. It
      records the problem and validates the rest. If the decoded settings turn out to be
      unusable after a decode error (the assumed fact above), it returns what it has recorded.
    - The valid stages and kinds move from the message to the hint.

D7. **Numeric setting flags accept any text, and `config.Load` validates them** (user decision).
    `RegisterFlags` declares them with one pass-through `pflag.Value`, as `portsFlag` already
    does for ports. Its `Type()` is `integer` or `float`, never `int`: viper would cast `int`
    and turn `abc` into `0`. Help shows `integer` where it showed `int`, and the defaults as
    before. `--concurrency abc` is then reported as `concurrency: invalid value "abc": not an
    integer`, with every other problem.

D8. **Nothing is created for a usage error.** `nyx recon -e <name>` with no inputs, where
    `<output-dir>/<name>/.nyx/state.db` does not exist, is a problem found before
    `engagement.Open`, which would otherwise create `.nyx` even in an existing empty directory.
    An engagement that exists and has no stored inputs keeps the check after opening. Spec 24
    turns the first case into exit 3.

D9. **`Runner.Run` returns only an error, and `run`'s exit-code constants are deleted.** It
    returns nil, a `*NetblockLimitError`, an error that wraps `context.Cause(ctx)` when the
    context ended the run (so Spec 24 can tell a deadline from a cancel), or any other error.
    cli turns `NetblockLimitError` into `INVALID_INPUT`: the hint is the caller's arguments,
    shell-quoted, with `--allow-large-netblocks` put directly after the `recon` token and
    `--redo <v>` or `--redo=<v>` removed. The outputs are still rendered first, as today.

D10. **`Execute` handles signals, for every command.** `Deps.HandleSignals` becomes
     `Deps.Signals <-chan os.Signal` (nil means none); `DefaultDeps` subscribes to SIGINT,
     SIGTERM and SIGHUP.
     - The first signal is recorded and cancels the context. If the command then returns an
       error, the outcome is `INTERRUPTED` with exit 130, 143 or 129, whatever else failed. A
       command that had finished its work returns nil and exits 0.
     - A second signal writes the error if it is not yet written and calls `os.Exit` with the
       first signal's code. This is the one exit outside `main`, a deliberate exception to
       `docs/agent-tools/0002`, because B11 asks for an exit at once.
     - A context the caller cancelled, with no signal recorded, counts as SIGINT. The test is
       `errors.Is(ctx.Err(), context.Canceled)` on `Execute`'s own context, so a deadline is
       never read as an interrupt. Kept because it defines what `Execute` returns to a caller
       that cancels, and nine tests use it.
     - export checks the context once, after reading the snapshot and before writing.
     - recon sets the interrupt hint on the invocation, so both paths print it. `INTERRUPTED`
       is not transient.
     - Accepted limit: a second signal that lands while export is writing to stdout exits with
       part of the export already written.

D11. **A panic never reaches the runtime's own exit** (B12). First-party code starts goroutines
     in four places, and each is covered.
     - `Execute` recovers on the main goroutine: `PanicError`, `UNEXPECTED_ERROR`, exit 1. Under
       `--debug` the stack is written to stderr before the error, so the error stays the last
       line. recon's deferred `eng.Close` still runs.
     - The check workers in `Runner.runStage` recover around each call of `Stage.Run`, inside
       the loop, so a worker survives its check's panic. The panic is that check's ordinary
       failure, recorded as `panic: <value>` and retried on the next run; under `--debug` its
       stack follows as DEBUG lines.
     - The loop that enumerates `Stage.Checks` recovers too and records the panic as the
       `(enumeration)` failure the runner already has, once per run. The work channel is still
       closed and the workers waited for.
     - The store's writer recovers around each batch in `commit`, sets the store's sticky error
       and still releases the batch's barriers, so `Flush` returns the error.
     - The two lookups the email stage starts with `wg.Go` recover into their own error slot.
     - The signal goroutine of D10 runs no code that can panic.

D12. **No prompt and no stdin** (B13). `acknowledge` becomes "if `--authorised`, store the
     acknowledgement"; `ackPrompt`, `Deps.Stdin` and `Deps.StdinIsTTY` are deleted. The runner's
     gate and its warning are unchanged. Nothing loads a `.env` file today; a test pins that.

D13. **The User-Agent is `nyx/<version>`** (B6). `egress.Options.UserAgent` replaces the
     `nyx/1` constant at both call sites, and cli sets it from `Deps.Version`, `nyx/devel` when
     there is none.

D14. **The root help is rendered from the cobra tree** (user decision: one line per everyday
     flag). There is no second list of commands, so a command added to the tree is in the help.
     - Each command carries its examples in cobra's `Example` field and, in `Annotations`, the
       names of its everyday flags (absent means all of them), the lines naming the valid
       values of its fixed-set flags, and an optional note. The walk skips hidden commands.
     - Root help: the examples, each with `--json`; the three shared flags and the sentence
       that only they may come before the command; then for each command its use line, short
       description, one example, one line per everyday flag (pflag's own layout) and its
       valid-value lines; recon's note that its tuning settings are in `nyx recon --help`;
       `--version` and `--help`; one exit-codes line.
     - recon's everyday flags are the list in B4. Its valid values are the stage names for
       `--redo` and `--skip` and the four stages `--skip` refuses; export's are the kinds.
     - A command's own help: its examples, its long description, its usage and every flag
       (without cobra's own examples block), today's footer for recon and the kinds for export,
       then the exit-codes line.
     - The exit-codes line: `Exit codes: 0 success, 1 system error, 2 usage error, 3 not found,
       7 partial result, 130/143/129 interrupted (SIGINT/SIGTERM/SIGHUP)`.

D15. **The test harness runs recon.** `harness.exec` and `execCtx` put `recon --output-dir <dir>`
     before the arguments, so the existing behaviour tests keep their calls; `execRoot` passes
     the arguments as given, for the tests of the tree itself.

## Files

New:
- `internal/clierr/clierr.go`, `clierr_test.go`: D3.
- `internal/cli/classify.go`: the pre-scan, the quoting function and the two hint builders (D2,
  D9).
- `internal/cli/failure.go`: the error writer and the signal handling (D4, D10).
- `internal/cli/help.go`: the root help, a command's help and the exit-codes line (D14).
- `internal/cli/recon.go`: the recon command, moved out of `cli.go` (`newCommand`, `runCommand`,
  `helpFooter`, `validateSkip`, `acknowledge`).
- `internal/cli/command_tree_test.go`, `error_contract_test.go`, `help_internal_test.go`.

Changed:
- `internal/cli/cli.go`: `Deps` (D10, D12), `Execute` (the root command, pre-scan, recover, one
  exit), `newEmitter` unchanged. `defaultStages` stays here.
- `internal/cli/export.go`: a child of recon; its own checks (D6); the context check (D10); its
  errors returned, not printed.
- `internal/run/runner.go`: `Run` and `passes` return an error (D9); the recovers of D11; the
  message of `NetblockLimitError` loses its "Re-run with" sentence, which is now the hint.
- `internal/config/config.go`: the pass-through flag value (D7); `Load` returns `Problems` and
  carries on past a file problem (D6); a function that returns the `NYX_KEYS_*` values (D4).
- `internal/input/input.go`: `Parse` returns `Problems` (D6).
- `internal/store/store.go`: the writer's recover (D11).
- `internal/stages/risk/email.go`: the two lookups recover (D11).
- `internal/egress/egress.go`, `http.go`, `thirdparty.go`: `Options.UserAgent` (D13).
- `internal/report/report.go`: the `error` case goes (D5).
- `internal/cli/harness_test.go` (D15) and the tests listed under "Existing tests to change".
- `README.md`: every invocation as `nyx recon …`; the exit-code table of B10; the error format
  and the statement of B14; the authorisation section without the prompt; large netblocks as
  exit 2 with the hint; console and JSON; export as `nyx recon export`; under migration, that
  `nyx example.com` now exits 2 with the corrected command.
- `CLAUDE.md`: the flow line, the package doc line of `cli`, `Deps`, and the exit codes, error
  codes and five keys as a stable interface (B14).
- `docs/todo.md`: remove the two items this spec delivers.
- `docs/plans/2026-11-build-order.md`: rows for Specs 23 to 25 and the seams this spec owns
  (`clierr`, the help annotations, the hint builders, `Deps.Signals`, `Options.UserAgent`).

## Tests

Behaviour tests drive `cli.Execute` through the harness. Each test of a non-zero exit also
checks that stdout is empty and that stderr holds exactly one error.

- **B1.** The existing suite passes through `recon` (D15). `recon export` gives the same lines
  as `export` did.
- **B2** (mutation check). A table of the four examples, `nyx export -e acme`, `nyx -e recon`
  and an argument that needs quoting (`--org 'Acme Pty'`), in both modes: exit 2, the exact
  hint, no file or directory created under the output directory or the working directory, and
  no hit on the network canaries.
- **B3.** Bare `nyx`, bare `nyx --json`, `nyx help` and `nyx -h` print exactly what `nyx --help`
  prints and exit 0; `nyx help recon` is `nyx recon --help`; `nyx frob` and `nyx help frob`
  exit 2 with the message and hint, and no help text on either stream.
- **B4.** The root help starts with examples that each pass `--json`; holds every command of
  the tree, each everyday flag of B4, the stage names and the kinds; leaves out a tuning flag
  that `nyx recon --help` has; and ends with the exit-codes line. Each command's help starts
  with examples and ends with that line. An internal test adds a command to the tree and finds
  it in the root help.
- **B5.** Each shared flag before and after `recon` and `recon export`; `--quiet --debug` exits
  2 on both; `NYX_JSON`, `NYX_QUIET` and `NYX_DEBUG` change nothing and a `json:` key in the
  config file is rejected; `nyx --passive recon a.com` gets the error and hint of D2.
- **B6.** `--version`; loopback fakes for a third-party source and a target see
  `nyx/<version>`, and `nyx/devel` with no version.
- **B7.** `--pass` and `--authoris` are unknown flags on recon and `--cur` on export;
  `--authorized` works.
- **B8** (mutation check). One call with a bad number, an unknown `--redo`, an unskippable
  `--skip`, a bad domain, a missing domains file and `--quiet --debug`: one error that names
  all six, `input` with each value, nothing created, no canary hit. A config file with an
  unknown key plus a bad flag reports both. `recon -e new` with no inputs creates nothing,
  with the directory absent and with it present and empty. export with no `-e` and an unknown
  `--kind` reports both.
- **B9.** The exact human layout and the exact JSON line (five keys, their order, compact,
  `null` for an empty hint and input); `nyx recon --bogus --json` and `--json` before the
  command; a recon `--json` run that fails after starting keeps its earlier event lines and
  has no `error` or `run_end` event; an API key in an error is masked in both modes, also when
  the configuration failed to load (mutation check); terminal-acting characters are stripped
  in human mode. A unit test pins the per-target lines of exit 7.
- **B10.** A unit test of the code-to-exit table. The netblock limit: exit 2, the total in the
  message, the exact hint with `--redo x` and `--redo=x` removed and with a shared flag before
  the command, the outputs rendered; running the hint's arguments succeeds.
- **B11** (mutation check). In child processes, as `crash_test.go` does: each of the three
  signals gives its own code, one `INTERRUPTED` error in each mode, an empty stdout in human
  mode, the completed checks saved and a re-run that finishes the rest; two signals exit at
  once with the first one's code and still one error. In-process, through `Deps.Signals`: a
  signal before export writes gives an empty stdout.
- **B12** (mutation check on the worker recover). A fake output file whose row function panics:
  exit 1, `UNEXPECTED_ERROR`, a stack on stderr only with `--debug`, and the engagement not
  left locked. A fake stage that panics on three checks with `--concurrency 1`: the run
  finishes, the other checks complete, the three are failed and retried on the next run. A
  stage whose enumeration panics: the run carries on. A store test: a panicking callback sets
  the sticky error and `Flush` returns instead of hanging.
- **B13** (mutation check). With stdout and stderr as terminals and no `--authorised`: no
  prompt, the target stage is `not-configured (no authorisation)`, the warning is written and
  the target canaries see nothing; with `--authorised`, and again on a later run without it,
  the stage runs. A child process whose stdin is a pipe that never closes still finishes. A
  `.env` in the working directory that sets `NYX_OUTPUT_DIR` and a key changes nothing.
- **B14.** The unit tests of B9 and B10 are the pin; the README and CLAUDE.md text is checked
  by reading.

The four cases, across the behaviours:
- **An error from an external dependency.** This spec adds no external call. The sources recon
  already uses keep their own tests, which now run through `recon`.
- **One item failing in a batch.** B8 (every problem reported) and B12 (one check panics, the
  rest complete).
- **A crash or interrupt part-way.** B11, the redaction tests of B9, and the existing crash
  tests, which pass through `recon` unchanged.
- **A re-run.** After a usage error nothing exists, so the same call gives the same error (B2,
  B8); after the netblock limit (B10); after a signal (B11); after a panicking check (B12).

Existing tests to change: the six that assert an `error` event and the one that asserts a
non-zero `run_end` (`behaviour`, `sources_unkeyed`, `sources_keyed`, `logcolours`, `skip`); the
prompt tests in `behaviour`, `logcolours` and `skip`, which become "never prompts" tests or go;
the netblock exit 3; `TestSignals` in `crash_test.go`; the tests that call `cli.Execute`
directly (`export_test.go`, `version_test.go`); the root `--help` assertions; the `error` cases
of `report_test.go`; the tests of `config` and `input` that match error text; and
`run.ExitInterrupted` in `risk_misc_test.go`.

## Conventions

- `CLAUDE.md`: Australian English; no spec numbers in code, comments, test names or file names;
  only `internal/egress` does network I/O (this spec adds none); `golang.org/x/sys/unix` stays
  on its allowlist (signals in `internal/cli`); conventional commit prefixes; `README.md` is the
  behaviour contract and must stay accurate.
- `docs/agent-tools/0001` to `0005` are the contract this spec implements. Where this design
  departs from them it says so (D10's exit).
- `docs/plans/2026-11-build-order.md`: behaviour tests in new `internal/cli/<feature>_test.go`
  files; settings appended at the end of each block. This spec is not in its waves yet; add it.
- Run the suite as `XDG_CONFIG_HOME=$(mktemp -d) make test` (see the tooling note in the build
  order file).

## Handed to later specs

- **Spec 24:** `--timeout` and the deadline (it reads `context.Cause` from D9); the recon
  `--json` envelope, which removes the event lines D5 leaves; exit 7 for recon; the error codes
  of a locked engagement and of a directory that is not an engagement, which are
  `UNEXPECTED_ERROR` here; exit 3 for the case of D8, with its listing hint; `--timeout` in
  recon's everyday flags and examples.
- **Spec 25:** the first use of `Error.Targets` and of exit 7; `Deps.Stdin`, added back when
  `-` needs it; `keys.nvd`; its command needs only `AddCommand`, an `Example` and annotations
  to be in the root help and the pre-scan.
- **Specs 7, 14, 16, 19 and 20**, designed before this one: their tests call `h.exec`, which
  now runs recon, so they need no change; their README examples must read `nyx recon …`, and a
  failure they assert as an `error` event is now the error on stderr.

# Implementation

## Develop

Built on 2026-11-17 against `309c8fa`. `internal/clierr` holds the error, the codes, their exit
codes and `Problems`. In `internal/cli`, `classify.go` is the pre-scan, the quoting and the two hint
builders; `failure.go` is the error writer and the signal watcher; `help.go` builds the tree and
renders both kinds of help from it; `recon.go` holds the recon command moved out of `cli.go`; and
`cli.go` holds `Deps` and `Execute`, which alone picks the exit code. `config.Load` and
`input.Parse` return `clierr.Problems`; numeric setting flags are a pass-through `numberFlag`
(`integer` or `float`). `Runner.Run` returns only an error, the check workers and the enumeration
loop recover panics into check failures (a panic's stack follows as DEBUG lines), the store's writer
recovers into its sticky error, and the email stage's three `wg.Go` lookups recover.
`egress.Options.UserAgent` replaces `nyx/1`. The `error` event and a failed run's `run_end` are gone.

How each behaviour is tested (behaviour tests in `internal/cli`, through the harness, whose `exec`
now runs `recon --output-dir <dir>` and whose `failed` helper checks the exit code, an empty stdout
and exactly one error in either layout):

- B1: the existing suite, through `recon`; the export tests through `recon export`.
- B2: `TestTree_OldFormCallsGetTheCorrectedCommand` (both modes, the exact hint, quoting, nothing
  created in the output or working directory, no canary hit, the same error twice).
- B3 (as amended): `TestTree_HelpIsBareNyxAndTheHelpCommand`, `TestTree_UnknownCommand`.
- B4: `TestTree_RootHelpIsTheWholeReference`, `TestTree_CommandHelpOpensWithExamplesAndEndsWithExitCodes`,
  `TestRootHelp_CommandAddedLater` (internal: a command added to the tree, and the pre-scan knows it),
  and the updated `TestHelp_Colour` and `TestHelp_StagesTopic`.
- B5: `TestTree_SharedFlagsBeforeAndAfterTheCommand`, `TestTree_QuietWithDebugIsAUsageError`,
  `TestTree_SharedFlagsAreNotSettings`, `TestTree_FlagBeforeTheCommand`.
- B6: `TestVersionFlag`, `TestTree_UserAgentIsTheVersion` (a source and a target),
  `egress.TestUserAgentOption`.
- B7: `TestTree_FlagsAreSpeltInFull`.
- B8: `TestContract_EveryProblemInOneError` (six problems in one call, a config file problem with a
  flag's, export's), `TestContract_NewEngagementWithoutInputsCreatesNothing`,
  `config.TestNumericFlagsTakeAnyText`, `config.TestLoadReportsFileProblemsWithTheRest`,
  `input.TestParseProblemsNameTheirArgument`, `clierr.TestProblemsUsage`.
- B9: `TestContract_ErrorLayout` (the exact human and JSON layouts, `null` hint and input),
  `TestContract_JSONModeWhenParsingFails`, `TestContract_FailedRunKeepsEarlierEventLines`,
  `TestContract_KeysAreMaskedInTheError`, `TestContract_TerminalCharactersStripped`, and the
  internal `TestFailureWriter_TargetLines` and `TestFailureWriter_OnceAndRedacted`.
- B10: `clierr.TestExitCodes`, `TestContract_NetblockLimit` (the hint with `--redo x`, `--redo=x`
  and a shared flag before the command, the outputs rendered, the hint run), and the netblock tests
  in `behaviour_test.go` now at exit 2.
- B11: `TestSignals` and `TestSignals_SecondExitsAtOnce` in child processes (both modes),
  `TestContract_SignalBeforeExportWrites` and `TestContract_CancelledContextIsAnInterrupt`
  in-process.
- B12: `TestContract_PanicIsAnUnexpectedFailure` (a panicking output file, with and without
  `--debug`, not left locked), `TestContract_PanicInACheckFailsOnlyThatCheck` (three panicking
  checks; a panicking enumeration), `store.TestWriterPanicSetsTheStickyError`.
- B13: `TestContract_NoPrompt`, `TestStdinIsNotRead` (a child whose stdin pipe never closes),
  `TestContract_DotEnvIsNotLoaded`.
- B14: the unit tests of B9 and B10; README ("Exit codes", "Errors") and `CLAUDE.md` state it.

The tests were seen to fail on their assertions against stubs first.

Deviations from the design:

- **B3 was amended by the user during the build.** A bare `nyx` and `nyx help` print the root help
  and exit 0, and `nyx help <command>` is that command's help. `help` is a visible command set
  through `SetHelpCommand`; the root help lists it with the two topics under `Help:`. D2's
  bare-call error now applies only to a flag several commands take with no command given.
- **D10: `DefaultDeps` does not subscribe to signals.** `cli.NotifySignals()` does, and `main` (and
  the crash test's child) set `Deps.Signals` from it. A subscription in `DefaultDeps` would have
  taken over SIGINT for every test process that calls it for its stage list.
- **D10: a signal already waiting when a command starts is taken before any work.** This makes the
  in-process export test deterministic and changes nothing a caller can see.
- **D6: the `--skip` rules are checked even when the settings fail to load.** `config.Load` now
  returns the settings that did load (an unparsable `skip` is left empty), so leaving the rules out
  was not needed, and B8 reports more.
- **D6's assumed fact was not relied on.** After an unknown key, `config.Load` decodes again
  without `UnmarshalExact`, so the rest is checked whatever mapstructure leaves behind.
- **The `--quiet` with `--debug` problem's input** is `{"quiet":["true"]}`.
- **`docs/plans/2026-11-build-order.md` was not updated:** the user removed `docs/plans/` while the
  spec was being built.

Mutation checks, each made by hand on the final code, run, and undone from the saved text:

| Behaviour | Code broken | Caught by |
|---|---|---|
| B2 | a word with a dot no longer counts as the old form | `TestTree_OldFormCallsGetTheCorrectedCommand` |
| B8 | recon returns at the first settings problem | `TestContract_EveryProblemInOneError` |
| B9 | the human error is not redacted | `TestContract_KeysAreMaskedInTheError` |
| B9 | no keys are masked once the configuration fails to load | `TestContract_KeysAreMaskedInTheError` |
| B11 | SIGTERM and SIGHUP exit 130 | `TestSignals`, `TestContract_SignalBeforeExportWrites` |
| B11 | a second signal does not exit | `TestSignals_SecondExitsAtOnce` |
| B12 | the worker does not recover a check's panic | `TestContract_PanicInACheckFailsOnlyThatCheck` (the test binary panics) |
| B13 | a terminal on stdout stores the acknowledgement | `TestContract_NoPrompt` |

## Known limitations

- B11 (D10's accepted limit): a second signal that lands while export writes to stdout exits with
  part of the export written.
- B9: until Spec 24, a recon `--json` run that fails keeps the event lines it printed on stdout, so
  stdout is not empty on that exit.
- B10: a locked engagement, a directory that is not an engagement, an engagement `export` cannot
  find and store or file failures are `UNEXPECTED_ERROR` until Spec 24 gives them codes.
- B2: whether a flag before no command is old-form depends on which commands take it; a flag both
  recon and a later command take is "no command given", exercised only by the internal test.
- `nyx --help recon` prints recon's help, as cobra resolves the command first; the spec does not
  say which help it should be.
- Tests: the `internal/cli` web tests (`TestWebPlumbing_*`, `TestWebPosture_*`, `TestRedirect_*`,
  `TestTLS_*`, `TestCrawl_*`) fail intermittently on `main` as well as here, more often when the
  whole suite runs.

## Simplify

Fixed:

- **Settings and the key redactor load in one place.** `invocation.loadSettings` replaces the
  copies in recon and export. `config.Load` reads `NYX_KEYS_*` through one helper, `envKeys`, which
  `EnvKeyValues` also uses, and keeps those keys on its early return. So callers no longer append
  `EnvKeyValues()` themselves.
- **Error input is masked by `config.Redactor.Any`,** which gained a `map[string][]string` case.
  cli's own `redactInput` is gone.
- **One panic-to-error helper.** `run.RecoverInto` is used by `runCheck` and by the email stage's
  goroutines, so a panic there now carries its stack under `--debug` like any other check. The
  stage's own `recoverInto` is gone.
- **The User-Agent is set once,** in `withDefaults`, for every command, not inside recon.
- **`engagement.Exists`** replaces recon's hard-coded `.nyx/state.db` path. `Open` and
  `OpenReadOnly` share the path through `statePath`.
- **Smaller tidy-ups:**
  - `slices.Contains` replaces `clierr.contains`.
  - `helpOf` serves both `helpHint` and `parseError`.
  - `visibleCommands` serves both `classify` and `unknownCommand`.
  - `flagOf` handles `NotExistError` and `ValueRequiredError` in one branch.
  - One signal table gives each signal's code and name.
  - The `--palette` sheet uses `helpDepth`.
  - recon's stage names are worked out once.
  - recon's footer is a constant.
  - export builds its kinds line once.
  - `input.Parse` reuses `named` for domains and files.
  - The error writer is given stderr's depth directly; the override to none under `--json` was
    never read.
- **Tests:**
  - The harness checks the JSON error's compactness and key order by encoding the decoded error
    again and comparing, not with regular expressions.
  - `checkInterrupted` lost its unused signal parameter.
  - The `mixedStage` alias is gone.
  - The harness no longer guards a nil `Signals`.

Skipped:

- **`--quiet --debug` is checked only by recon and export.** `nyx help`, the topics and a bare
  `nyx` accept the pair and exit 0. Moving the check to the root would change what those calls
  do, so it is left for verification against B5 rather than made here.
- **Merging `clierr.PanicError` with run's `checkPanic`.** Their messages differ
  (`unexpected failure:` against `panic:`), and `run` is kept free of `clierr` by design.
- **The enumeration's recover in `produce`.** Rewriting it with `RecoverInto` made it longer.
- **Marking the help command with an annotation** instead of matching its name in `help.go`. The
  name checks are few and work.
- **Helpers for repeated test set-up** (the untouched-directory checks, appending `--json`). Kept
  as written, for readability in each test.
- **`CLAUDE.md` still points at `docs/plans/2026-11-build-order.md`,** which was removed. Whether to
  restore the plan or drop the pointer is the user's call.
- **Efficiency.** No reviewer found a regression. `EnvKeyValues` reading the environment twice and
  the duplicated `"nyx/devel"` default in egress were too small to matter.

# Verification

## Result

Verified on 2026-11-17 against the working tree on `main` (base `309c8fa`), by reading the code,
driving a built binary through the edge cases of B2 to B5, and running
`XDG_CONFIG_HOME=$(mktemp -d) make test`, which passed before and after the changes below.

The goal is met: everything nyx did runs as `nyx recon` (export as `nyx recon export`), one
`nyx --help` lists every command, and every outcome is an exit code and one error on stderr.

- **B1** met. The existing suite passes through `recon` (the harness's `exec`), and the export
  tests through `recon export`.
- **B2** met. All four examples, `nyx export -e acme` and `nyx -e recon` get the caller's own
  arguments with `recon` inserted, shell-quoted, exit 2, in both modes; the pre-scan runs before
  cobra, so nothing is printed, created or contacted.
- **B3** (as amended) met. A bare `nyx`, `nyx --json`, `nyx help` and `nyx -h` print the root help;
  `nyx help recon` is byte-for-byte `nyx recon --help`; `nyx frob` and `nyx help frob` exit 2 naming
  the commands, with no help printed.
- **B4** met. The root help opens with `--json` examples, renders every runnable command from the
  tree with one example, the everyday flags of B4 and the stage and kind lists, says recon's tuning
  settings are in `nyx recon --help`, and ends with the exit-codes line; each command's help opens
  with examples and ends with that line. The two help topics print their own text, as before.
- **B5** met after a fix. The shared flags work before and after the command, are not settings, and
  any other flag before the command gets "flags follow the command" with the moved hint. `--quiet`
  with `--debug` exited 2 only for recon and export: a bare `nyx`, `nyx help`, any `--help`, the
  topics and `--version` printed and exited 0. Fixed (see below).
- **B6** met. `--version` prints the version; `Options.UserAgent` carries `nyx/<version>`, or
  `nyx/devel`, to sources and targets alike.
- **B7** met. Abbreviations are unknown flags; `--authorized` is the one alias.
- **B8** met. recon and export collect every problem (settings, config file, inputs, files,
  engagement name, `--redo`, `--skip`, `--kind`, `--output`, the shared pair) into one error with
  each value in `input`; `recon -e <new>` with no inputs is refused before `engagement.Open`.
- **B9** met, with the exception B9 itself allows: a recon `--json` run that fails keeps the event
  lines it printed. Both layouts are exact, JSON mode comes from a raw scan so parse errors are JSON
  too, keys are masked (also when the configuration fails to load), and human lines are sanitised.
- **B10** met. One code-to-exit table; the netblock limit is `INVALID_INPUT`, exit 2, with the
  total and the corrected call as hint; the cases Spec 24 reclassifies stay exit 1.
- **B11** met except one edge. Each signal gives its own code and one `INTERRUPTED` error, stdout is
  empty in human mode, completed work is saved and a second signal exits at once. A second signal
  that lands while export is writing to stdout leaves part of the export written (D10's accepted
  limit, which `## Out of scope` does not record as agreed by the user).
- **B12** met. Panics on the main goroutine, in a check, in a stage's enumeration, in the store's
  writer and in the email stage's goroutines are recovered; a check's panic fails only that check.
- **B13** met. No prompt, no `Deps.Stdin`, nothing loads `.env`; the acknowledgement is stored only
  with `--authorised`.
- **B14** met. `README.md` ("Exit codes", "Errors") and `CLAUDE.md` state the stable interface, and
  the unit tests of B9 and B10 pin it.

Changed during verification:

- **`--quiet` with `--debug` is refused on every call (B5).** The pre-scan's raw scan now finds
  `--quiet` (and `q` in a cluster), and the root help and version paths check the pair before
  printing; the help command, every `--help` and the topics check it through one `showHelp` gate,
  which makes the usage error the outcome and prints nothing. `TestTree_QuietWithDebugIsAUsageError`
  gained nine cases covering those paths.
- **`CLAUDE.md`** named the export command as `nyx export`; it now says `nyx recon export`.

# Follow-ups

- Update any script, alias or agent skill file of your own that calls `nyx <domain>` or
  `nyx export`: both now exit 2 with the corrected command in the hint.
- The web tests of `internal/cli` are flaky on `main` too (see Known limitations); worth a look of
  their own.
