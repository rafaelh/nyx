# Spec 22: log colours and line format

## Goal

Someone watching a run can tell progress from problems at a glance, and can redirect the log apart
from the summary. Console output follows `docs/log-colors.md` except where this spec says
otherwise.

## Behaviours

B1. **Streams.** During a run in human mode, stdout carries only the end-of-run summary. The run
    header, stage lines, `+` found lines, count lines and warnings are log lines on stderr. The
    authorisation prompt and the run-ending `error:` line stay on stderr with no timestamp or
    level. On a coloured stderr the `error:` prefix takes the palette's semantic error colour and
    the rest of the line has none. A run that ends without a summary (interrupted, stopped by the
    netblock limit, or ended by an error) writes nothing to stdout. (amended by D16)

B2. **Line layout.** On an uncoloured stream a log line is `HH:MM:SS | LEVEL | message`, with the
    level padded to 5, so the message follows the first 19 characters. On a coloured stream the
    separators are `│`, the level is a 7-cell badge, the timestamp and separators take the
    palette's chrome colours, and the message follows the first 21 cells. The time is the run's
    clock shown in the local time zone (`TZ`). The second and later lines of a multi-line message
    are indented by that many spaces (19 or 21), with no timestamp or level. No message of a run
    has more than one line today, so the palette sheet (B12) shows one.

B3. **Levels.** The run header, found lines, count lines and the lines of stages that are running,
    done, done-previously or not-configured are INFO. The line of a failed stage is ERROR. Every
    warning is WARN and is shown without any flag: for example a truncated result, a spent quota,
    addresses skipped because their owner is unknown, technology detection being off, or an
    interrupted run, and any warning a later spec adds. A warning whose text has already been
    written in this run is not written again, on the console or as a `--json` event. Per-check
    failure lines are DEBUG only: they are never also written as WARN lines. (amended by D9)

B4. **Stages skipped for lack of authorisation.** When a run leaves stages out because
    authorisation was not confirmed, it writes one WARN line that names them and says that
    `--authorised` confirms authorisation. The line names exactly the stages whose stage line
    reads `not-configured (no authorisation)`, so a stage left out by `--skip` is not named. It is
    written once, right after the run header and before any stage line, so an interrupted run
    still shows it. When no stage is in that state, as under `--passive`, there is no line.

B5. **Flags.** By default INFO and above are written; with `--quiet` (`-q`) WARN and above; with
    `--debug` DEBUG and above. `--quiet` together with `--debug` is rejected with exit 2. Both are
    flags only: there is no config setting or `NYX_*` variable for either. `--verbose` is
    removed and is rejected like any unknown flag.

B6. **Message text.** The header, stage and count messages keep today's text (count lines keep
    their two-space indent) and carry no colour. The only colour inside any message is the
    severity badge on a finding's line.

B7. **Found lines.** The message is `+`, a space and the record as today. A finding with a
    severity carries a badge directly after the `+`, and its `[severity]` suffix is gone. The badge
    is the severity exactly as recorded (`high`, `medium`, `low`) padded to 8. On a coloured stream
    it has one more space each side (10 cells) and the palette's severity style: `high` as HIGH,
    `medium` as MEDIUM, `low` as LOW. On an uncoloured stream it is the padded word alone, with no
    brackets. A finding with no severity has no badge. A severity the palette does not know takes
    the DEBUG style; it never fails.

B8. **Summary.** A completed run writes the summary to stdout, with `--quiet` or without. Its
    content is as today with two changes: each listed finding shows the severity badge of B7 in
    place of `[high]`, and the failed-checks heading reads
    `Failed checks (retried on the next run; --debug shows each failure)`. On a coloured stream
    headings are bold, and there is no colour besides the badges.

B9. **Colour decision.** A stream is coloured only when it is a terminal, `NO_COLOR` is unset or
    empty and `TERM` is not `dumb`. stdout and stderr are decided separately, so
    `nyx example.com 2> run.log` on a terminal writes a plain log and a coloured summary.
    `FORCE_COLOR` and `CLICOLOR_FORCE` force nothing. An uncoloured stream has no escape bytes.

B10. **Palette and colour depth.** Colours are those of the tables in `docs/log-colors.md`. They
    are written as 24-bit colour when `COLORTERM` is `truecolor` or `24bit`, as the nearest
    256-colour entries when `TERM` contains `256color`, and otherwise in 16 colours. The
    16-colour form of each style is fixed in the palette, not computed: the bright colour of the
    style's hue on black, so that badges keep their meaning (the nearest 16-colour entries would
    make most of them grey on black). These variables choose only the depth on a stream B9 has
    already decided to colour; they never turn colour on. At every depth each badge's foreground
    differs from its background. (amended by D4)

B11. **`--json`.** stdout stays one JSON event per line. Warning events, including the one for B4,
    are in the stream without any flag, and `--quiet` changes nothing. Per-check failures are no
    longer warning events. stderr is empty unless `--debug` is given, which writes only the DEBUG
    lines to stderr (coloured or not by B9) and leaves stdout unchanged.

B12. **`--palette`.** A hidden flag that prints the palette sheet to stdout and exits 0: every
    entry of every table in `docs/log-colors.md` (the level, outcome, severity and HTTP status
    badges, the HTTP method and chrome colours, the semantic text colours), one sample log line
    per level, and one two-line message showing the continuation indent, all through the formatter
    a run uses. It follows B9 and B10, and under `--json` the sheet is uncoloured. Any inputs given
    with it are ignored: it needs no scope, contacts nothing and creates no engagement directory.

B13. **Message handling.** Target-supplied text is sanitised and secrets are redacted as today.
    Lines are never wrapped to the terminal width and never redrawn.

B14. **Docs.** README and `--help` describe `--quiet` and `--debug`, the two streams and the
    colour rule, and no longer mention `--verbose`. The README's authorisation section describes
    the warning of B4.

B15. **OTX and Anubis.** The `otx` and `anubis` stages are removed: neither service answers an
    unkeyed client any more, so with warnings shown by default each would report a problem on
    every run. They are no longer run, listed in `--help`, or accepted by `--redo` and `--skip`,
    and the README no longer names them as sources. An engagement that already holds their
    results keeps them. (added by D18)

## Out of scope

- Unit labels in the summary's `Deferred to the next run` block. It keeps a bare number per stage
  and the README names each unit. (D19)
- Changing what `and N more in candidates.csv` counts. N stays the high-confidence candidates
  beyond the 20 listed. (D19)
- Giving OTX an API key instead of removing it. (D18)

- The `{data, meta}` envelope, error codes and the other agent-tools rules. `--json` keeps its
  event stream, with warnings and errors as events on stdout.
- Catching unexpected internal failures and hiding their stack trace unless `--debug` is given. A
  Go panic keeps printing its own trace, as today: nyx catches no panics, and checks run on
  worker goroutines, so this is its own change.
- DEBUG lines for each check as it runs or for each outbound request.
- Outcome badges or coloured state words on stage lines: the level badge carries the status.
- A flag that adds detail to the summary. The ranked-candidates spec is amended to list high
  candidates only; the rest are in `candidates.csv`.
- Repeating INFO and WARN lines on stderr under `--json --debug`: they would duplicate the stdout
  events.
- Making each stage skipped for lack of authorisation a WARN line: one line per run names them all.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one. Each is settled in
`## Decisions`: the deferred block's units and the reading of "and N more" in D19, the medium
candidate list in D17, the two warning paths in D8 and D9, OTX and Anubis in D18, and the text
that names `--verbose` in D8 and `## Files`.

- **Units in the deferred block (Spec 6, follow-up 5).** The summary's `Deferred to the next run`
  block shows a bare number per stage, in that stage's own unit (names for `permutations`,
  requests for `sensitive-paths`; Specs 4, 7 and 13 add addresses, hostnames and searches). The
  README names the units. B8 keeps the summary's content as today, so decide here whether the
  block should label them. The place is `Console.summary` in `internal/report/report.go`, and a
  label needs the unit from the stage (one more method beside `run.Budgeted`).
- **The medium candidate list (Spec 15).** As built, `--verbose` adds the medium candidates to
  the summary. Removing `--verbose` (B5) removes that list and its tests, which is what Spec 15's
  amended behaviour 4 and this spec's `## Out of scope` already say.
- **"and N more" (Spec 15, follow-up).** The line under the candidate list is printed only when
  there are more than 20 high candidates, and N counts those. Behaviour 4 of Spec 15 can also be
  read as every candidate not listed. Decide which while the summary is being rewritten.
- **Summary lines already on stdout (Specs 6 and 15).** The candidate list and the deferred block
  are asserted on stdout today and stay there (B1, B8). Tests that assert stage lines, `+` lines
  and warnings on stdout move to stderr.
- **Two warning paths (Spec 1).** Stages warn through `View.Warn` from `Checks` and through
  `run.Warnf(ctx, …)` from `Run`. Both are shown only with `--verbose` today, and both become
  WARN lines (B3).
- **OTX and Anubis (Spec 1, follow-up 1).** OTX no longer answers anonymous requests, so its
  stage warns and aborts on its first check, and Anubis answers with a Cloudflare challenge, so
  it fails one check per root, on every run. Once warnings show without a flag (B3) the OTX line
  is printed on every run, and Anubis is listed under the failed checks every time. Decide
  whether to keep, key or drop each stage before this spec is built, or with it.
- **Text that names `--verbose`.** B14 covers the README and `--help`. In the code, the doc
  comments of `View.Warn` and `run.Warnf` in `internal/run/stage.go` say "shown only with
  `--verbose`" and need the same change; no stage's message string names the flag.

# Design

Decided 2026-11-14. D4, D9, D10 (the wording), D16, D18 and D19 are the user's answers; the rest
follow from the spec, the code or `docs/agent-tools/0003-output.md`. An adversarial review
changed D1, D7, D9, D10, D13 and D20.

## External facts

- **OTX refuses anonymous clients.** *Confirmed live* (2026-11-14):
  `GET https://otx.alienvault.com/api/v1/indicators/domain/example.com/passive_dns` answers 429
  with `{"detail": "Anonymous access to this endpoint is limited. Please authenticate."}`.
- **Anubis is behind a Cloudflare challenge.** *Confirmed live* (2026-11-14): `jldc.me` answers
  301 to `jonlu.ca`, which answers 403 with a challenge page.
- **cobra v1.10.2 flag groups.** *Confirmed live* (read in the module source):
  `Command.MarkFlagsMutuallyExclusive` is checked by `ValidateFlagGroups` before `RunE`, and
  returns `if any flags in the group [debug quiet] are set none of the others can be; [debug
  quiet] were all set`. `ExecuteContext` returns it, so `Execute` exits 2 through `fail`.
- **pflag v1.0.10.** *Confirmed live* (source): an unknown flag fails with
  `unknown flag: --verbose`; `FlagSet.MarkHidden` keeps a flag out of the usage text.
- **Go loads `time.Local` from `TZ` once per process.** *Confirmed live* (source,
  `time/zoneinfo_unix.go`). `t.Setenv("TZ", …)` inside a test therefore changes nothing, which is
  why D13 passes the zone in.
- **The xterm 256-colour table.** *From docs*: indices 16 to 231 are a 6×6×6 cube with levels 0,
  95, 135, 175, 215, 255 (index = 16 + 36r + 6g + b); 232 to 255 are greys 8 + 10i. Indices 0 to
  15 depend on the terminal's theme.
- **SGR codes.** *From docs* (`docs/log-colors.md` for 24-bit; ECMA-48 and xterm for the rest):
  `38;2;r;g;b` and `48;2;r;g;b` for 24-bit, `38;5;n` and `48;5;n` for 256 colours, 30 to 37 and
  90 to 97 for the 16 foregrounds, 40 to 47 for backgrounds, `1` bold, `0` reset.
- **Nearest 256-colour entries of the palette.** *Confirmed live* (computed with a script, squared
  RGB distance over indices 16 to 255). Foreground/background: DEBUG 146/236, INFO 111/236, WARN
  222/236, ERROR 210/236, CRIT 255/131, PASS 150/235, DRY RUN 116/236, MEDIUM 216/236. Foreground
  only: GET 117, POST 141, PATCH and PUT 179, DELETE 168, TIMESTAMP 102, SEPARATOR 239. No badge
  has the same index for both. The same script showed that the nearest of the 16 xterm colours is
  white or grey on black for WARN, ERROR, MEDIUM, PASS and DEBUG (D4).
- **The colour rule.** *From docs* (`docs/agent-tools/0003-output.md`, "Human mode"): colour only
  when the stream is a terminal, `NO_COLOR` is unset or empty and `TERM` is not `dumb`; decided
  once per stream and passed down.

## Decisions

D1. **A pure `internal/palette` package holds the palette as data.** Base styles (24-bit
    foreground and background, bold, and the 16-colour SGR pair of D4), the four badge categories
    mapping labels to styles with their widths (level 5, outcome 7, severity 8, http_status 3),
    the foreground-only styles (http_method, chrome) and the four semantic text colours. It
    offers: a `Depth` (none, 16, 256, 24-bit), a badge for a category label, a badge for a record
    value (text exactly as recorded, style found case-insensitively in the category, DEBUG style
    when unknown), foreground-only text, and bold. On depth none a badge is the label padded to
    the category width with no side spaces and no escapes. Nothing else in the code holds a
    colour value. The document's synonym table and its "unknown name is an error" lookup are not
    built: nyx only prints level names it holds as constants and record values, which never use
    synonyms. This is a deliberate gap against the checklist in `docs/log-colors.md`.

D2. **nyx writes its own escape codes; lipgloss and termenv are removed.** Only `report.go`
    uses them. The fixed 16-colour table (D4) and byte-exact tests of the sequences need direct
    control, and the amount of code is small. Run `go mod tidy` afterwards; it should also drop
    `charmbracelet/x/term` and `go-colorful`. Each styled span is followed by `ESC[0m`. A 24-bit
    badge is `ESC[38;2;r;g;b;48;2;r;g;bm`, with `1;` first when bold, as in the example in
    `docs/log-colors.md`.

D3. **The colour decision is one pure function, called once per stream.**
    `palette.Detect(isTerminal bool, getenv func(string) string) Depth` returns none unless the
    stream is a terminal, `NO_COLOR` is empty and `TERM` is not `dumb`; then 24-bit when
    `COLORTERM` is exactly `truecolor` or `24bit`, 256 when `TERM` contains `256color`, else 16.
    It reads no other variable. `cli.Deps` gains `StderrIsTTY` (in `DefaultDeps`,
    `term.IsTerminal` on `os.Stderr`; nil means false). `Execute` calls `Detect` for stdout and
    for stderr with `os.Getenv` and passes the two depths down.

D4. **16 colours use a fixed table** (user decision, amends B10). Badges, as SGR foreground;
    background: DEBUG `37;40`, INFO `94;40`, WARN `93;40`, ERROR `91;40`, CRIT `1;97;41`, PASS
    `92;40`, DRY RUN `96;40`, MEDIUM `33;40`. Foreground only: GET `96`, POST `95`, PATCH and PUT
    `33`, DELETE `91`, TIMESTAMP `90`, SEPARATOR `90`. The semantic text colours are the
    foregrounds of PASS, ERROR, WARN and INFO. MEDIUM and LOW differ only as yellow against
    bright yellow, because 16 colours have no orange.

D5. **256 colours are computed.** The nearest entry among indices 16 to 255 by squared RGB
    distance from the 24-bit value. Indices 0 to 15 are skipped because their colour depends on
    the theme. The expected indices are in `## External facts`.

D6. **Events carry no level; the console assigns one.** `run_start`, `found` and `count` are INFO.
    `stage` is INFO, or ERROR when its state is `failed`. `warning` is WARN. A new event type
    `debug` (one field, `message`) is DEBUG. The console takes a minimum level (INFO; WARN with
    `--quiet`; DEBUG with `--debug`), a log writer with its depth (stderr) and a summary writer
    with its depth (stdout). `summary` always goes to the summary writer whatever the level.
    `error` goes to the log writer as `error: <message>` with no prefix (D16). `candidate`,
    `run_end` and unknown types print nothing, as today. `JSONEmitter` drops `debug` events, so
    stdout under `--json` is the same with or without `--debug`.

D7. **`--json --debug` is a tee, filtered by event type.** stdout gets the `JSONEmitter`. stderr
    gets a console behind a filter that passes only `debug` events (`report.Only("debug", …)`),
    not a console with a low minimum level: a level threshold would also write the summary and a
    second copy of the error. The redactor wraps the tee, so DEBUG lines are redacted like
    everything else. Without `--debug`, `--json` builds no console at all.

D8. **Warnings no longer depend on a flag.** `run.Config.Verbose` is removed. `Runner.warn` always
    emits a `warning` event, so `View.Warn`, `run.Warnf`, the spent-quota warning and "reading
    records" all show by default. `failCheck` emits a `debug` event with today's text
    (`<stage> check <key> failed: <message>`) instead of a warning. The interrupted warning stays
    in `cli.go`. The doc comments of `View.Warn` and `run.Warnf` say "a WARN line, shown by
    default". The authorisation prompt is unchanged.

D9. **A warning is written once per run** (user decision, amends B3). `View.Warn` is called from
    `Checks`, which the runner calls on every pass, so the ports and httpprobe warnings would
    otherwise repeat at least twice. `Runner.warn` keeps the set of messages already emitted this
    run and drops a repeat (a `sync.Map`, as `guarded` is). A message whose text differs, such as
    the ports warning with a new count, is written.

D10. **The authorisation warning comes from the runner, right after `run_start`.** The part of
    `gate` that runs before `Configured` (skipped, passive-only, no authorisation) moves to a
    helper that both `gate` and this line use, so the names are exactly the stages whose line
    reads `not-configured (no authorisation)`, and `Configured` is not called to build it. The
    names are in registry order. Wording (user decision):
    `not authorised, so these stages are left out: httpprobe, crawl, takeover, sensitive-paths, ports; --authorised confirms authorisation`.
    With the default registry and no `--skip` it names those five. It is an ordinary `warning`
    event, so `--json` carries it (B11). No stage in that state means no event.

D11. **Flags.** `--quiet` (`-q`) and `--debug` are plain bools in `cli.options`, registered in
    `newCommand` beside `--json`, not through `config.RegisterFlags`, so they have no setting and
    no `NYX_*` variable. `cmd.MarkFlagsMutuallyExclusive("quiet", "debug")` gives the exit 2.
    `--verbose` and `options.verbose` are deleted. `--palette` is registered and marked hidden.
    Help text: `--quiet`: "write only warnings and errors to stderr; the summary is still
    printed"; `--debug`: "also write each failed check to stderr"; `--json`: unchanged. The help
    footer gains a short "Console" paragraph: the log is on stderr, the summary on stdout, and
    colour is used only on a terminal, never with `NO_COLOR` set or `TERM=dumb`.

D12. **`--palette` is handled first in `runCommand`**, before `config.Load`, input parsing and
    `engagement.Open`, so a broken config, missing scope or stray inputs do not matter and nothing
    is created or contacted. It writes the sheet to stdout at stdout's depth (none under
    `--json`) and returns 0. The sheet is plain text built by `report` from the palette data and
    the run's line formatter: a bold heading per table of `docs/log-colors.md`; under it one line
    per entry with the badge (or the coloured text, for the foreground-only and semantic
    entries) and its name; then one log line for each of DEBUG, INFO, WARN, ERROR and CRIT; then
    one two-line message. The sheet's log lines use the clock like any other line.

D13. **One formatter makes both forms of a log line.** Plain: `HH:MM:SS | LEVEL | message` with
    the level padded to 5. Coloured: the timestamp in chrome TIMESTAMP, ` │ ` in chrome SEPARATOR,
    the 7-cell level badge, ` │ ` again, then the message. The message is split on `\n` after it
    has been sanitised; later lines get 19 or 21 spaces. `sanitize.Text` removes `\n` from every
    event field, so only the sheet's sample has two lines, and a test says so to stop anyone
    splitting before sanitising. The time is `clock().In(loc)`. `cli.Deps` gains `Location`
    (nil means `time.Local`), because `TZ` cannot be changed inside a test process.

D14. **Found lines and the severity badge.** The message is `+ ` then, when the event has a
    severity, the record-value badge of the severity category and a space, then the record text as
    today (`text`, else `category: value`). Uncoloured: `+ high     takeover: …`. The same badge
    replaces `[high]` in the summary's finding lines. The green `+`, the bold stage name, the
    coloured state word, the coloured header tags and the grey count line all lose their styling
    (B6); their text is unchanged.

D15. **Summary.** Written to stdout as today, with the severity badges, the new failed-checks
    heading, and headings in bold (`ESC[1m…ESC[0m`) when stdout is coloured. No heading has a
    colour.

D16. **The `error:` line** (user decision, amends B1). `error: <message>` on stderr, with
    `error:` in the semantic error colour (ERROR's foreground, no background, not bold) at
    stderr's depth and the message uncoloured. Under `--json` errors stay events on stdout.

D17. **The medium candidate list goes with `--verbose`.** The runner stops building it, the
    `summary` event loses `medium_candidates`, and the console loses the "Candidates of medium
    confidence" block. This is what the ranked-candidates spec's amended behaviour 4 says.

D18. **`otx` and `anubis` are removed** (user decision, adds B15). Their `Stage` entries, fetch
    functions and parsers go, with their tests, README mentions and the comment in
    `defaultStages`. Nothing is migrated: the store already reads observations of a stage that is
    not registered, so an existing engagement keeps the hostnames they found. Their two entries
    stay in the `families` table of `internal/candidates` with a comment, so stored evidence from
    them still counts as passive DNS and not as a family of its own. A config whose `skip` list
    names either now fails with the existing "unknown stage" error; the README says so.

D19. **The summary's content is otherwise untouched** (user decisions). The deferred block keeps
    bare numbers, and `and N more in candidates.csv` keeps counting the high-confidence
    candidates beyond the 20 listed.

D20. **The harness pins the terminal environment.** It gains `stderrTTY` and a location (UTC by
    default), and sets `NO_COLOR` to empty, `TERM` to `xterm` and `COLORTERM` to empty with
    `t.Setenv`, so a developer's shell cannot change a result. It gains a helper that returns the
    messages of the plain `| DEBUG |` lines on stderr. `world.run` always passes `--json`, so
    tests that assert the text of a check failure through `messages(w, "warning", …)` pass
    `--debug` and read that helper instead. Console assertions on stage, `+`, count and warning
    lines move from `h.stdout` to `h.stderr`. Each `--verbose` is dropped, or replaced by
    `--debug` where the test wants a check failure. Assertions that there is no warning without
    `--verbose` are inverted. Tests that use `otx` as their example stage use `hackertarget`.

## Files

- `internal/palette/palette.go`, `palette_test.go` (new): D1 to D5.
- `internal/report/report.go`: the console (D6, D13 to D16), `JSONEmitter` dropping `debug`,
  `Only` and a tee (D7). `internal/report/sheet.go` (new): the palette sheet (D12).
  `internal/report/report_test.go`: rewritten for the new console; the medium-candidate cases go.
- `internal/run/runner.go`: `Config.Verbose` removed, `warn` and its once-per-run set, the `debug`
  event in `failCheck`, the authorisation warning and the helper shared with `gate`, the summary
  without `medium_candidates`. `internal/run/stage.go`: the two doc comments.
- `internal/cli/cli.go`: `Deps.StderrIsTTY` and `Deps.Location`, the two depths, the flags, the
  emitter wiring, `--palette`, the help text, the comment in `defaultStages` and the comment on
  `--version` that names `--verbose`.
- `internal/stages/subdomains/subdomains.go`, `sources_unkeyed.go`: `otx` and `anubis` removed.
  `internal/candidates/candidates.go`: a comment on the two kept entries.
- Tests: `internal/cli/harness_test.go` and `world_test.go` (D20, and the two hosts out of the
  source list); `internal/cli/logcolours_test.go` (new); and the existing files that assert
  console text on stdout, pass `--verbose` or name `otx` or `anubis`: `behaviour_test.go`,
  `budget_test.go`, `candidates_test.go`, `dnsroot_test.go`, `lists_test.go`, `ports_test.go`,
  `providerranges_test.go`, `risk_misc_test.go`, `risk_paths_test.go`, `skip_test.go`,
  `sources_keyed_test.go`, `sources_unkeyed_test.go`, `version_test.go`, `web_archive_test.go`,
  `web_test.go`. `TestNonTTYNoANSI` in `behaviour_test.go` now sees escapes on a terminal stdout
  only through the bold summary heading.
- `go.mod`, `go.sum`: `go mod tidy` after D2.
- `README.md`: the console section (two streams, levels, `--quiet`, `--debug`, the colour rule),
  the `--json` paragraph (no `medium_candidates`, warnings without a flag, `--debug` on stderr),
  the authorisation section (B4), the two places that say a failure is "reported with
  `--verbose`" or "named by `--verbose`" (now `--debug`), the ranked-candidates paragraph, and
  the source lists without OTX and Anubis ("one of these five" becomes three).
- `docs/plans/2026-11-build-order.md`: the console seam marked built, `otx` and `anubis` out of
  the registry order, and the carried items marked settled.

## Tests

Unit tests in `internal/palette` and `internal/report`; behaviour tests in
`internal/cli/logcolours_test.go` unless a file is named. **(mutation)** marks a behaviour for a
mutation check.

- **B1 (mutation).** A completed run: stdout is exactly the summary; the header, stage, `+`,
  count and warning lines are on stderr. Stdout is empty for an interrupted run, a run stopped by
  the netblock limit and a run ended by an error, and each has its `error:` line or interrupted
  WARN line on stderr. The `error:` line has no timestamp; on a coloured stderr only its prefix
  is styled. The prompt is on stderr with no prefix.
- **B2.** Byte-exact plain and coloured lines from the formatter (unit), including the 19 and 21
  cell offsets and a two-line message. One cli test sets the location to a fixed `+11:00` zone
  and expects `20:00:00` for the harness clock of 09:00 UTC.
- **B3.** A run with a failing stage, a `View.Warn`, a `run.Warnf` and a spent quota: levels as
  listed, warnings present with no flag. One check failing among several: the others complete,
  the stage line and summary count it, and its line appears only with `--debug`, as DEBUG, never
  as WARN. A `View.Warn` raised on every pass is written once per run on the console and once as
  a `--json` event; a warning whose text changes is written again.
- **B4 (mutation).** Unauthorised default-style registry: one WARN line naming exactly the stages
  whose line reads `not-configured (no authorisation)`, after the header and before the first
  stage line. A Target stage in `--skip` is not named. No line under `--passive`, with
  `--authorised`, or when every Target stage is skipped. A run interrupted in its first stage
  still shows it. A second run of the same unauthorised engagement shows it again; after
  `--authorised` it is gone. Under `--json` it is a `warning` event.
- **B5.** Default, `--quiet`, `-q` and `--debug` each show the right levels. `--quiet --debug`
  exits 2. `--verbose` exits 2 as an unknown flag. `NYX_QUIET=1` and `NYX_DEBUG=1` change
  nothing, and `quiet: true` in a config file is rejected as an unknown key.
- **B6, B7.** Header, stage and count messages equal today's text after the prefix. A found line
  for a high, medium and low finding, plain and coloured (badge widths 8 and 10, styles by
  depth); a record with no severity has no badge; an unknown severity gets the DEBUG style and
  does not fail. No escape in a coloured log line other than chrome, the level badge and the
  severity badge.
- **B8.** `--quiet` still prints the summary. Finding lines carry the badge, the failed-checks
  heading has the new text, headings are bold on a coloured stdout and nothing else is styled.
  The existing summary tests (deferred block, candidate list and its `and N more` line) keep
  passing on stdout.
- **B9 (mutation).** `palette.Detect` over the matrix: terminal or not, `NO_COLOR` unset, empty
  and set, `TERM=dumb`, and `FORCE_COLOR` and `CLICOLOR_FORCE` set on a non-terminal (no colour).
  cli: stderr not a terminal and stdout a terminal gives a log with no `ESC` byte and a styled
  summary, and the reverse. No `ESC` byte anywhere with `NO_COLOR=1`.
- **B10.** Unit: the depth chosen from `COLORTERM` and `TERM`; neither turns colour on for a
  non-terminal. The exact sequences of one badge at each depth, the 256 indices listed in
  `## External facts`, the 16-colour table of D4, and for every badge at every depth a
  foreground that differs from its background.
- **B11 (mutation).** Every stdout line under `--json` parses as JSON, with and without `--debug`
  and `--quiet`, and the event lists are equal across the three. Warnings are events with no
  flag. A failing check gives no `warning` event; with `--debug` stderr holds only DEBUG lines
  (no summary, no `error:` copy), and without it stderr is empty. An API key in a check's
  failure message is redacted in the DEBUG line.
- **B12.** `--palette` exits 0, prints every label of every table, five level lines and a
  continuation line indented 19 (plain) or 21 (coloured); creates no engagement directory; the
  network canaries see nothing; inputs, a missing scope and an invalid config file are ignored;
  it is absent from `--help`; under `--json` on a terminal it has no `ESC` byte.
- **B13 (mutation).** Escape sequences, OSC titles, newlines and bidi controls in a found value,
  a warning and a check-failure message never reach either stream, coloured or not (unit and
  cli). A configured key in any of them is redacted. A very long message is one line.
- **B14.** `--help` names `--quiet`, `--debug`, the two streams and the colour rule, and not
  `--verbose` or `--palette`. The README is checked by reading.
- **B15.** `otx` and `anubis` are not in `--help`'s stage list; `--redo otx` and `--skip anubis`
  exit 2; a passive run requests neither host. An engagement directory seeded with a completed
  `otx` check and its hostname still lists that hostname after a run.

The four failure cases: no behaviour here calls an external dependency, so there is no vendor
error to cover (the removed stages are covered by B15). One item failing in a batch is the B3
failing-check test. A crash or interrupt part-way is covered by B1 and B4 (interrupted runs) and
B11 and B13 (no secret on either stream); the existing `crash_test.go` children keep passing, and
none of them reads console text. A re-run is covered by B4 (the warning on every unauthorised
run) and by the existing resume tests, whose `done-previously` lines move to stderr.

## Conventions

- `CLAUDE.md`: Australian English; no spec numbers or IDs in code, comments, test names or file
  names; only `internal/egress` does network I/O (the palette and report packages import neither
  `net` nor `os/exec`); CSV columns and `--json` fields may change if the README stays accurate.
- `docs/plans/2026-11-build-order.md`: this spec owns the console seam; behaviour tests go in a
  new `internal/cli/<feature>_test.go`; specs that merge later write their `+` lines through the
  log formatter and assert them on stderr.
- `docs/log-colors.md` and `docs/agent-tools/0003-output.md` ("Human mode"): the palette, the
  line format and the colour rule.

## Handed to later specs

- Specs 4, 7 and 20 add `+` lines or summary lines through the formatter built here. Specs 8, 10,
  11, 13, 16 and 17 read "shown with `--verbose`" in their designs as "a WARN line", written once
  per run for the same text (D9).
- Any spec whose tests use `otx` or `anubis` as an example stage uses another source (D18).

# Implementation

## Develop

Built bottom up, tests first at each layer, each shown failing on its assertions against a stub.

- **`internal/palette`** (new, pure): the four badge tables, the eight base styles with their fixed
  16-colour pairs (D4) and computed nearest 256-colour indices (D5), the foreground-only groups
  (`http_method`, `chrome`, `semantic`), `Detect` (D3), `Depth.Badge` (canonical label),
  `Depth.Value` (record value as recorded, style looked up case-insensitively, DEBUG for unknown),
  `Depth.Text` and `Depth.Bold`. `palette_test.go` pins the detection matrix (B9, B10), the exact
  sequences of one badge at every depth, the 256 indices and the 16-colour table, and that every
  badge keeps its foreground apart from its background at every depth. The computed 256 indices
  matched `## External facts` on the first run.
- **`internal/report`**: lipgloss and termenv are gone (`go mod tidy` also dropped their
  dependencies). `report.Line` is the one formatter for both layouts (B2, D13). `Console` takes
  `ConsoleOptions` (log writer and depth, summary writer and depth, minimum level, clock,
  location) and assigns levels by event type (D6). `Only` and `Tee` give the `--json --debug`
  wiring (D7). `debug` events are kept off stdout under `--json` (D6); `JSONEmitter` drops them itself (the
  simplify pass moved this into `newEmitter`; verification moved it back). `sheet.go` writes the palette sheet (D12).
  `report_test.go` was rewritten: byte-exact plain and coloured lines (the coloured one is the
  example in `docs/log-colors.md`), the 19 and 21 offsets, continuation lines, levels and the
  minimum level, found-line badges, the `error:` line, sanitising (B13), the summary (B8) and the
  sheet.
- **`internal/run`**: `Config.Verbose` is gone. `warn` always emits and keeps a `sync.Map` of texts
  already emitted (D8, D9). `failCheck` emits a `debug` event. `gateByRun` is the part of `gate`
  before `Configured`, which `warnUnauthorised` also uses, right after `run_start` (D10). The
  summary has no `medium_candidates` (D17).
- **`internal/cli`**: `Deps.StderrIsTTY` and `Deps.Location`, the two depths from `palette.Detect`
  with `os.Getenv`, `--quiet`/`-q`, `--debug`, hidden `--palette` handled first in `runCommand`,
  `MarkFlagsMutuallyExclusive`, the Console help paragraph, and `newEmitter` building the
  console, the JSON emitter or the tee.
- **`otx` and `anubis`** are removed from `internal/stages/subdomains` (B15). Their entries stay
  in the candidate families table, with a comment.
- **Tests**: the harness pins `NO_COLOR`, `TERM` and `COLORTERM`, defaults the location to UTC and
  gains `stderrTTY`, `logLines`, `logMsgs` and `debugLines` (D20).
  `internal/cli/logcolours_test.go` holds one or more behaviour tests for each of B1 to B15 as
  listed in `## Tests`. B4 is also cross-checked against the real registry, where the warning's
  names must equal the stages whose `stage` events read `no authorisation`. Existing tests were
  migrated: console assertions moved to stderr, `--verbose` was dropped or became `--debug`, the
  "no warning without `--verbose`" assertions were inverted, and the `otx` and `anubis` cases were
  removed or now use `hackertarget` or `urlscan`.
- **Deviation:** `TestPorts_WorkerBounds` was already flaky on main (it failed 4 runs in 6 there).
  The fake server stopped counting a connection only when the client's close reached it, so the
  next connect was counted on top of it. The helper in `ports_test.go` now stops counting once
  the banner is written. With one extra port worker added by hand, the test still fails on every
  run.
- No external fact turned out different.
- **Mutation checks** (each a hand edit, then a hand revert checked byte for byte against a copy):
  - B1: the console's log writer set to stdout. Six `TestLog_` tests fail.
  - B4: the warning names every stage left out for any reason. `TestLog_AuthorisationWarning`
    fails.
  - B4: the `warnUnauthorised` call removed. `TestLog_AuthorisationWarning` and
    `TestLog_AuthorisationWarningMatchesTheStageLines` fail.
  - B9: `Detect` honours `FORCE_COLOR` and ignores `TERM=dumb`. `TestDetect` and
    `TestLog_ColourDecision` fail.
  - B11: the `debug` filter removed from the JSON stream. This first survived, because every mode
    then carried the same `debug` events. `TestLog_JSON` now asserts that stdout has no `debug`
    event, and it fails.
  - B11: the whole console teed onto stderr, not just the `debug` events. `TestLog_JSON` fails.
  - B13: `str` no longer sanitises. `TestConsoleSanitises` and `TestLog_MessageHandling` fail.

## Known limitations

- B2: no message of a run has more than one line, so the continuation indent is exercised only
  by the formatter's unit tests and the palette sheet.
- B10 and B12: the document's synonym table and its erroring lookup are not built (D1), so the
  sheet has no synonyms to show. A label the palette does not know takes the DEBUG style.
- B12: cobra checks flags before `--palette` runs, so `--palette --quiet --debug` or an unknown
  flag still exits 2. Inputs, the scope and the config file are ignored, as specified.
- B9: `Execute` reads the colour variables with `os.Getenv`, not through `Deps`, so the cli tests
  that set them use `t.Setenv` and cannot run in parallel.

## Simplify

Fixed:
- `report.Line` builds plain and coloured lines the same way, through `Depth.Text` and
  `Depth.Badge`. The indent comes from `palette.Width(palette.Level)`, so the `%-5s` and the
  hand-counted offsets (19 and 21) are gone. `Level.Label` reads the palette's Level table.
- The palette works out each table's width from its widest label instead of storing it.
  `Style` embeds `fgStyle`, and a single `fgParams` writes the foreground SGR for both
  badges and text. `foregroundOf` is gone.
- The foreground-only groups are an ordered slice with a typed `Group` and a `Groups()`
  accessor. The sheet and both sheet tests now iterate the palette instead of listing groups
  and levels by hand.
- `JSONEmitter` no longer drops debug events itself. `newEmitter` wraps it in a new
  `report.Except("debug", …)`, so all the `--json`/`--debug` routing is in one place, and the
  no-op `console.Summary = io.Discard` is gone. `Only` and `Except` share one filter type.
- `NewConsole` and `Sheet` no longer apply their own nil defaults for clock and location
  (`Execute` already does). `Sheet` takes the time to show.
- `rankedCandidates` filters for high confidence before it sorts and builds maps.
- Tests: `logLines` in the harness parses with `logLayout`, which moved there from
  `logcolours_test.go`, so one regexp pins the plain layout. `rest2` became `stripSGR` with the
  regexp at package level. Dropped a summary assertion about `medium_candidates`, a field
  nothing emits any more.

Skipped:
- Merging the `stripEscapes` test helpers from `palette_test` and `report_test` into one shared
  helper: they live in different packages and are a few lines each.
- Unexporting `Style`/`Styles()` (only `TestDepthTables` uses them): it would mean moving that
  test into an internal test file for no change in behaviour.
- Passing the environment to `Detect` through a `Deps.Getenv`: viper reads `NYX_*` from the
  process environment anyway, so the tests would still need `t.Setenv` (see Known limitations).
- Dropping the `depths` struct, and checking the console's level before it formats the message:
  both are minor, and nothing on that path is hot.

# Verification

## Result

Checked against the goal, B1 to B15 (as amended by D4, D9, D16 and D18) and `## Out of scope` by
reading every changed file, `docs/log-colors.md`, `docs/agent-tools/0003-output.md` and the
build-order plan, by running `make test` (passes; `go mod tidy` makes no further change), and by
running the built binary with `--palette` and `--help`. The goal is met: a run's log is on stderr
as levelled, timestamped lines, the summary alone is on stdout, and the WARN and ERROR badges set
problems apart from INFO progress. Console output follows `docs/log-colors.md` except for the
synonym table and the erroring lookup (D1), which the design left out but which `## Out of scope`
does not list (Follow-ups).

- **B1 met.** `newEmitter` gives the console stderr for the log and stdout for the summary. The
  prompt is written to stderr with no prefix, and the `error:` line bypasses the formatter with only
  its prefix in the semantic error colour at stderr's depth. The runner emits `summary` only for an
  `ExitOK` run, so an interrupted run, the netblock limit and an error write nothing to stdout
  (tested for all three).
- **B2 met.** `report.Line` builds both layouts; the indent is worked out from the timestamp, the
  level width and the separators (19 plain, 21 coloured). The time is `Clock().In(Location)`, with
  `Deps.Location` defaulting to `time.Local`. Known limitation 1 is what the behaviour itself says:
  only the sheet shows a two-line message.
- **B3 met.** Levels are assigned by event type in `Console.Emit`. `Runner.warn` always emits and
  drops a text already emitted this run (a `sync.Map`), so the dedupe holds for the console and
  `--json` alike. `failCheck` emits a `debug` event and never a warning.
- **B4 met.** `gateByRun` is the part of `gate` before `Configured`, and `warnUnauthorised` uses it
  right after `run_start`, so the names are exactly the `no authorisation` stages, in registry
  order, and a skipped stage is not named. It is cross-checked against the real registry.
- **B5 met.** `--quiet`/`-q` and `--debug` are plain flags outside `config.RegisterFlags`, made
  exclusive by cobra (exit 2). `--verbose` is gone and fails as an unknown flag; `NYX_QUIET`,
  `NYX_DEBUG` and the config keys do nothing or are rejected.
- **B6, B7 met.** Header, stage and count text is unchanged and unstyled. A found line carries
  `Depth.Value(Severity, …)`: the recorded text padded to 8 (10 cells coloured), the style looked up
  case-insensitively, DEBUG for an unknown value.
- **B8 met.** The summary goes to stdout with `--quiet` too, with the badges, the new failed-checks
  heading and bold headings only on a coloured stdout.
- **B9, B10 met.** `palette.Detect` is called once per stream with `os.Getenv`; the matrix,
  the exact sequences at each depth, the computed 256 indices (equal to `## External facts`), the
  fixed 16-colour table of D4 and foreground differing from background are unit-tested.
- **B11 met.** Under `--json` stdout is `Except("debug", JSON)`; `--debug` tees a console behind
  `Only("debug", …)` onto stderr, inside the redactor. The event lists are equal with and without
  `--debug` and `--quiet`.
- **B12 met.** `--palette` is handled first in `runCommand`, before the config, the inputs and
  `engagement.Open`, and prints every entry of the enumerated tables, five level lines and a
  two-line message through `report.Line`. Known limitation 3 (flags are still validated by cobra,
  so `--palette --quiet --debug` exits 2) does not conflict with "inputs are ignored": flags are not
  inputs. The synonym table is not on the sheet (known limitation 2), which B12's own list of
  tables does not ask for.
- **B13 met.** Every event field passes through `sanitize.Text` before formatting and the redactor
  wraps every emitter; lines are not wrapped or redrawn.
- **B14 met after one fix.** `--help` has the new flags and a Console paragraph and no `--verbose`
  or `--palette`. *Fixed:* the README's console section still said "`--verbose` no longer exists",
  and B14 says the README no longer mentions it; the sentence is removed.
- **B15 met.** The two stages, fetchers and parsers are gone, `--redo otx` and `--skip anubis` exit
  2, a passive run requests neither host, and stored hostnames from them stay listed. Their entries
  stay in the candidate family table with a comment.

Out of scope respected: the deferred block keeps bare numbers, `and N more` counts high candidates
beyond 20, there is no `{data, meta}` envelope, no panic handling, no per-request DEBUG lines and
no outcome badges on stage lines. The `ports_test.go` helper change (the deviation) is test-only and
fixes a counting race; it does not touch the port worker bound.

## Code review

`/code-review high --fix` over the changed files. `make test` passes after its fixes.

Fixed:
- `NewConsole` defaults a nil `Clock` to `time.Now` and a nil `Location` to `time.Local`, so a
  caller other than `Execute` cannot panic on the first log line (B2; no change to a run).
- `Level.Label` reads a table built once and returns `""` for a level outside DEBUG to CRIT instead
  of panicking (B2).
- `JSONEmitter` drops `debug` events itself, as D6 says, so no other use of it can put a failed
  check on the JSON stream (B11). This undoes the simplify pass's `report.Except`; `Only` is now its
  own small type. `TestLog_JSON` still pins the behaviour, and the unit test of `Only` and `Tee`
  was adjusted only for the removed `Except`.
- The README's list of INFO stage lines now includes `done-previously` (B3, B14).

Left unfixed:
- `palette.Styles()` is exported only for `palette_test`. Moving it to an `export_test.go` changes
  no behaviour.
- `--palette -q --debug` exits 2 from cobra's flag-group check. B12 ignores inputs, and flags are
  not inputs; moving the check would change behaviour the spec does not ask for.
- `golangci-lint` reports an unused `newRangeHosts` in `internal/cli/providerranges_test.go` and two
  staticcheck warnings in `internal/cli/sources_keyed_test.go`. They predate this change.

# Follow-ups

1. Anyone with `otx` or `anubis` in a config file's `skip` list must remove it: nyx now rejects
   the name as an unknown stage (D18). Check `$XDG_CONFIG_HOME/nyx/config.yaml` (or
   `~/.config/nyx/config.yaml`) and any `--config` files in use.
2. Decide whether nyx should build the synonym table and the erroring lookup of
   `docs/log-colors.md` ("Lookup rules"), or whether to record the gap. D1 left them out, but
   `## Out of scope` does not, so the goal's "follows `docs/log-colors.md`" is met except for them.
   Either add a line to `## Out of scope` here or note the gap in `docs/log-colors.md` (it is
   shared, so it may be better left as it is).
3. Eyeball the palette on the terminals and themes you use: `make build && ./nyx --palette`, and
   again with `TERM=xterm-256color ./nyx --palette` and `COLORTERM=truecolor ./nyx --palette`.
   Only byte-exact tests have checked the colours so far.
4. Clear the existing lint warnings this change did not introduce: `golangci-lint run ./...`
   (an unused `newRangeHosts` in `internal/cli/providerranges_test.go`, two staticcheck warnings
   in `internal/cli/sources_keyed_test.go`).
