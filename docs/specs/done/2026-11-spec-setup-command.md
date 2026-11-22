# Spec: Setup command

## Goal

A user who has just installed nyx, or who later needs to add, rotate or remove a key, can store their
API keys, output directory and common settings, and confirm the keys work, without reading the
README's Configuration section or opening the config file. The next `nyx recon` or `nyx cve` uses
those values.

## Behaviours

- B1. `nyx setup` opens a full-screen terminal UI that edits one config file: the one given by
  `--config`, or the default path. It is in the root help with an example. With no `--config` and
  no default path (neither `XDG_CONFIG_HOME` nor `HOME` is set), setup exits 2 and says to pass
  `--config`. Any positional argument exits 2.
- B2. It lists every key source (`securitytrails`, `shodan`, `virustotal`, `whoisxml`, `censys`,
  `chaos`, `github`, `certspotter`, `nvd`) with what each turns on (for `certspotter`, that it also
  works without one), and `output_dir`, `concurrency`, `rate.per_host`, `rate.per_source`,
  `rate.dns`, `wordlist`, `sensitive_paths` and `skip`, each showing its file value, or its default
  when the file doesn't set it. An unset `output_dir`, and any relative path already in the file, is
  shown as resolving against the directory nyx is later run from, with the current result as an
  example.
- B3. A set key of 12 or more characters is shown masked with its last 4 characters; a shorter one
  shows only "set"; an unset key, or one that is empty in the file, shows "not set". While a key is
  typed, one mask character is shown per character; pasting is accepted.
- B4. No key, in full or beyond its last 4 characters, appears on screen, in any error or test
  reason, on stderr under `--debug`, or in the terminal after setup exits.
- B5. You can enter or replace a key, or clear it, which removes it from the file. A key is stored
  without surrounding whitespace, and an entered key that is empty after trimming counts as clearing
  it. Keys for sources nyx doesn't know are kept untouched and not listed.
- B6. A setting or key source whose name in the file differs only in case (`keys.Shodan`,
  `Concurrency`) is shown as that setting and replaced in place, leaving one entry. If the file holds
  two case variants of one name, that setting is marked invalid until it is edited or cleared, and
  saving it leaves one entry.
- B7. Non-key values are checked as they are entered, with the same rules and messages that
  `nyx recon` gives for the file; an invalid value isn't accepted. Clearing a setting removes it from
  the file so its default applies, and a value entered empty after trimming counts as clearing it.
  A relative `output_dir`, `wordlist` or `sensitive_paths` that is entered is saved as an absolute
  path, expanded against the directory setup runs from; a leading `~/`, or `~` alone, is kept as
  typed. (amended by D18)
- B8. `skip` is edited by toggling stages from the stage list, with each stage's one-line
  description as in `nyx help stages`; stages that can't be skipped aren't offered. Each `skip` entry
  in the file that is unknown or can't be skipped is listed with its message and can be removed on
  its own; the other entries are kept.
- B9. A key can be tested, including an entered, unsaved key: one authenticated request to that
  source only, never to a target. It shows "accepted" when the source accepts the key, "rejected"
  when the source says the key is invalid, and "could not check: <reason>" for a rate limit,
  exhausted credits, a network failure or any other answer. A reason taken from a source's answer is
  shown with terminal control characters removed and cut to one line. A test gives up after 15
  seconds with "could not check: timed out"; the UI stays usable while it runs, and quitting
  abandons it. A result is shown only while the key it tested is unchanged: editing or clearing the
  key removes it, and an answer for a key that has since changed is discarded.
- B10. Edits are held until you save; a value changed and changed back counts as unchanged.
  Quitting (Ctrl+C in the UI is a quit) with unsaved changes asks: save, discard, or go back.
  Quitting with no changes writes nothing. Setup exits 0 after a save, a discard or no change.
  SIGTERM or SIGHUP exit with their usual exit code and leave the file as it was, or as fully saved
  if a save was already under way.
- B11. On every exit (save, discard, quit, SIGTERM, SIGHUP, an unexpected error) the terminal is
  returned to the state it was in before setup started, and any error message is printed after that,
  so it stays visible.
- B12. Saving changes only the edited values and keeps every other setting, comment and their order;
  a cleared value's own comment goes with it, and a `keys:` block left empty is removed. It creates
  the file and any missing directories; a created directory and the saved file are readable only by
  their owner, and saving tightens an existing file's broader permissions. A crash during save leaves
  either the old or the new file, never a partial one. If the config path is a symlink, the file it
  points to is updated and the link stays.
- B13. After a save, `nyx recon` run from the directory setup was run from, with no `NYX_*`
  variables and no flags, uses exactly the values setup showed, and with no `NVD_API_KEY`, `nyx cve`
  sends the `nvd` key setup saved. Every key and path is stored exactly as entered (after B5's
  trimming and B7's absolute paths), whatever characters it contains.
- B14. If a save fails, setup stays open with the edits kept, shows the reason and the file path,
  and the file on disk is unchanged.
- B15. If the file changed on disk since setup opened, last saved or reloaded it, saving warns and
  offers to reload (discarding setup's edits) or overwrite. If a reload finds the file unreadable,
  unparseable or holding an unknown key, setup stays open with its edits kept, shows the problems and
  the path, and still offers to overwrite.
- B16. A missing file, at the default path or at `--config`, opens with every value at its default
  and is created on save. An unreadable or unparseable file, or one with an unknown key, makes setup
  exit 2 with the problems `nyx recon` reports for the file alone (as if no `NYX_*` variable were
  set), with an error naming the file's full path; the UI doesn't open. A file that parses but holds
  an invalid value (including a `wordlist` or `sensitive_paths` file that can't be read, or a `skip`
  stage that doesn't exist or can't be skipped) opens with that value marked invalid and its message
  shown; saving is blocked until it is fixed or cleared.
- B17. `NYX_*` variables and `NVD_API_KEY` are ignored entirely: they don't change what's shown, and
  an invalid one doesn't stop setup.
- B18. If stdin or stdout isn't a terminal, setup exits 2 with error code `INVALID_INPUT`, an error
  naming the config file path and a hint to edit it by hand; under `--json` that error is the usual
  JSON error. `nyx setup --help` prints help and exits 0 even when piped.
- B19. When no config file exists at the default path, a default path exists, and `--config` isn't
  given, `nyx recon` (a run, not `nyx recon export`) and `nyx cve` print one hint line on stderr
  suggesting `nyx setup`. It is not printed under `--json` or `--quiet`, or when the command fails
  with a usage error, and changes nothing else: exit code, stdout and events are as before.
- B20. A footer always shows the available keystrokes. A terminal too small to draw the UI shows a
  message asking for a larger one in its place.
- B21. The README documents `nyx setup`, its exit-2 cases in the exit-code table, the no-config
  hint, and that `NYX_*` variables and `NVD_API_KEY` still override what setup saves.

## Out of scope

- Editing settings other than those in B2: they stay hand-edited in the file.
- A line-prompt fallback when there is no terminal: setup exits 2 instead (B18).
- Showing or editing values from `NYX_*` variables: setup edits the file only (B17).
- Warning before a key test that spends a query credit: the test is just sent.
- Narrowing the no-config hint to users with no keys in the environment: it shows whenever there is
  no file (B19).
- The no-config hint for `nyx ip` (it reads no configuration) and `nyx recon export` (it reads an
  engagement that already exists).
- A help topic for setup beyond its command help.

# Design

## External facts

Probed on 2026-11-22 with a fake key and, where the user had one, a real key. Only status codes
and masked, shortened bodies were seen.

- **Bubble Tea v2** (`charm.land/bubbletea/v2` v2.1.1, released 2026-10-28) — *confirmed from
  source*:
  - It builds with `CGO_ENABLED=0` for darwin/linux on amd64/arm64.
  - `WithContext`, `WithoutSignalHandler`, `WithoutCatchPanics`, `WithInput`, `WithOutput`,
    `WithEnvironment`, `WithColorProfile` and `WithWindowSize` exist.
  - A cancelled context ends `Run` with `ErrProgramKilled`, after `shutdown` restores the terminal.
    `Kill()` restores it from another goroutine.
  - Output counts as a terminal only when it is a `term.File`, and the window size is read only
    then.
  - Without `WithoutSignalHandler` it traps SIGINT and SIGTERM itself.
  - Its panic catcher writes the panic value and stack straight to `os.Stderr`, and with
    `TEA_DEBUG` set it writes `bubbletea-panic-*.log` in the working directory.
  - With `WithoutCatchPanics`, nothing recovers a panic in a Cmd goroutine, including the Cmds
    inside `tea.Batch`/`tea.Sequence`.
  - `exec.go` imports `os/exec`, used only by `ExecProcess`.
- **Bubbles v2** (`charm.land/bubbles/v2` v2.2.1, released 2026-08-24) — *confirmed from source*:
  - `textinput` runs typed and pasted runes through a sanitiser (tab and newline become a space,
    control characters are dropped).
  - Its `EchoPassword` draws one mask per terminal cell, not per character.
  - Its Ctrl+V binding reads the clipboard through `atotto/clipboard`, which runs `xclip`/`pbpaste`.
  - `key` and `help` have no such side effects. It requires `charm.land/lipgloss/v2` ≥ v2.0.5.
- Newer releases of these modules (bubbletea v2.1.2, bubbles v2.2.2, lipgloss v2.1.x) are under
  two weeks old and are not used.
- **yaml.v3 Node re-encode** (`go.yaml.in/yaml/v3` v3.0.6) — *confirmed live*:
  - It keeps comments and order.
  - It drops blank lines, re-indents to `SetIndent`, and reflows folded scalars.
  - Plain scalars resolve with `strconv.ParseInt(s, 0, 64)`, so `010` reads as 8, `0x10` as 16 and
    `1_000` as 1000.
  - An explicit `!!str` tag makes the encoder quote only when the value would otherwise resolve to
    a non-string.
  - `!!str` with invalid UTF-8 fails to encode.
  - A header comment with no blank line after it attaches to the first key's `HeadComment`.
- **viper** v1.21.0 — *confirmed from source*:
  - It lower-cases map keys while it reads them, so with two case variants of a block one wins at
    random.
  - A scalar `skip: a,b` becomes a list through its weak-slice hook.
  - Whether it accepts a literal dotted top-level key (`rate.per_host:`) is *assumed*. D8's
    mismatch check covers it either way.
- **Key-test endpoints**, each with the answer it gave:

  | Source | Request | Fake key | Real key |
  |---|---|---|---|
  | securitytrails | `GET api.securitytrails.com/v1/ping`, header `APIKEY` | 401 "Please check user credentials" (*confirmed live*) | The user's key also got 401 here and on `/v1/domain/example.com/subdomains` and `/v1/account/usage`, so it is invalid. A valid key gets 200 (*from docs*). |
  | shodan | `GET api.shodan.io/api-info?key=` | 401 (*confirmed live*) | The user's key got 401 here and on `/account/profile` and `/shodan/host/count`, so it is invalid; 200 for a valid key is *from docs*. `GET /shodan/host/8.8.8.8` answers 200 even to a fake key (*confirmed live*), so it can never test a key. |
  | virustotal | `GET www.virustotal.com/api/v3/domains/example.com`, header `x-apikey` | 401 `WrongCredentialsError` (*confirmed live*) | 200 (*confirmed live*). Spends one lookup from the daily quota (*from docs*). |
  | whoisxml | `GET user.whoisxmlapi.com/user-service/account-balance?apiKey=` | 401 "Access restricted. Check the credits balance or enter the correct API key" (*confirmed live*) | The user's key got the same 401 here, and 403 "insufficient credits balance, incorrect API key, or your IP address is not added to the IP allowlist" on the reverse-WHOIS preview (*confirmed live*). The source never says clearly that a key is bad. 200 for a valid key is *from docs*. |
  | censys | `POST api.platform.censys.io/v3/global/search/query`, Bearer, body `{"query":"cert.names: \"example.com\"","page_size":1}` (the stage's own request) | 401 "Access credentials are invalid" (*confirmed live*) | Not available. 200 is *from docs*, and the stage already parses this endpoint. It spends a query credit. The server authenticates before it routes, so a fake key can't confirm a path; this is why the stage's request is used rather than an account path. |
  | chaos | `GET dns.projectdiscovery.io/dns/example.com`, header `Authorization` (no scheme) | **400** `{"valid":false,"message":"invalid pdcp_api_token…"}` (*confirmed live*) | Not available; 200 is *assumed*. |
  | github | `GET api.github.com/rate_limit`, Bearer | 401 "Bad credentials" (*confirmed live*) | Not available; 200 is *from docs*. It doesn't count against the rate limit. |
  | certspotter | `GET api.certspotter.com/v1/issuances?domain=example.com`, Bearer | 401 `bad_credentials` (*confirmed live*). **The message echoes the key's leading part.** | Not available; 200 is *from docs*. |
  | nvd | `GET services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228`, header `apiKey` | 404 with header `message: Invalid apiKey.` (*confirmed live*) | 200 (*confirmed live*). |
- **429 and 402.** A 429 means rate limited and a 402 means credits exhausted. Both are *from
  docs*, and `httpsrc` already treats them this way.

## Decisions

- **D1. TUI library: Bubble Tea v2 + Bubbles** (user's choice).
  - Use `charm.land/bubbletea/v2` v2.1.1 and `charm.land/bubbles/v2` v2.2.1, using only its `key`
    and `help` packages.
  - `charm.land/lipgloss/v2` v2.0.6 comes in only through `help`.
  - The rejected alternatives were Bubble Tea core with hand-written widgets, tview/tcell (heavier,
    its own styling, last released Aug 2025) and huh (too rigid for per-row asynchronous results).
  - The boundary test checks only first-party direct imports, so the libraries' own `os/exec` and
    `x/sys/unix` use doesn't trip it. nyx never calls `ExecProcess`.
- **D2. Program wiring.**
  - `tea.NewProgram` gets these options:
    - `WithInput(raw stdin)` and `WithOutput(raw stdout)`. These are the `Deps.Stdin`/`Deps.Stdout`
      from before `newInvocation` wraps stdout in the `marginWriter` (`cli.go:225-226`), kept on
      `invocation` as `rawIn`/`rawOut`. Given the wrapped writer, Bubble Tea sees no terminal and
      draws a 0×0 window.
    - `WithContext(runCtx)`, `WithoutSignalHandler()` and `WithoutCatchPanics()`.
    - `WithEnvironment(Deps.Env)`.
    - `WithColorProfile` mapped from `inv.st.out.Depth`, so `NO_COLOR` and `TERM=dumb` behave as in
      the rest of nyx and there is one colour detector.
  - Tests that give a buffer also pass `WithWindowSize`.
  - The view sets the alt screen, so nothing of the UI stays in the terminal after exit (B4, B11).
- **D3. Packages.**
  - `internal/setup`: the Bubble Tea model (tabs, rows, dialogs, the text field, change tracking,
    the key-test Cmd). It does no I/O itself; it gets injected functions for check, save, reload
    and test.
  - `internal/configedit`: the YAML document (lookup, case variants, set/clear, encode) and `Save`.
    It is pure apart from `Save` and reading the file.
  - `internal/keycheck`: the nine sources' test requests and their classification, over
    `egress.ThirdPartyHTTP`.
  - `internal/cli/setup.go`: the command, its checks, and the wiring of `Deps` into the model and
    the Program.
- **D4. Text entry: a hand-written field** (user's choice). It is a rune buffer with a cursor, and
  takes typed runes, `tea.PasteMsg` (bracketed paste), backspace/delete, left/right, home/end and
  clear.
  - It stores runes exactly as typed or pasted, so B13 holds.
  - A key field draws one `•` per rune (B3). A setting field draws the text after
    `sanitize.Line`, but stores it unsanitised.
  - Bubbles' `textinput` is not used: it rewrites input, masks by cell width, and has a
    clipboard binding that runs a program.
- **D5. Layout: tabs Keys | Settings | Skip** (user's choice).
  - A tab's title gets `*` when it holds unsaved changes and `!` when it holds an invalid value.
  - The header shows the config file's path and the number of unsaved changes.
  - Each tab scrolls so the selected row stays visible. The Skip tab has 37 rows, which don't fit
    in the minimum size.
  - Descriptions are cut to one line with `…` at the width, measured with `layout.Measure`.
  - The minimum size is 60×16. Below it, the view is only "make the terminal at least 60×16"
    (B20).
  - The footer is `bubbles/help` over the active key map (B20).
- **D6. Keystrokes.**
  - **Moving:** tab/shift+tab switch tabs; ↑/↓ (and k/j) move.
  - **Editing:** enter edits a row or toggles a skip stage; in the field, enter accepts and esc
    cancels.
  - **Row actions:** t tests a key; x or delete clears the value, or removes a skip problem entry.
  - **Saving and quitting:**
    - ctrl+s saves; q, esc or ctrl+c quits (B10).
    - The quit dialog offers s save, d discard and esc back.
    - The conflict dialog offers r reload, o overwrite and esc back.
- **D7. Reading the file (B16, B17).**
  - `config.Load` is refactored so that parsing and checking a file's bytes is
    `config.Check(data []byte, path string, env Env) (Settings, error)`. It uses
    `viper.ReadConfig` with the same `settingChecker`, and `Load` calls it.
  - Setup's env is `Deps.Env` without `NYX_*` and `NVD_API_KEY`. `HOME` and `XDG_CONFIG_HOME` are
    kept, for the default path and for `~`.
  - **Missing file** (`fs.ErrNotExist`, at the default path or at `--config`): every value is at
    its default and the file is created on save.
  - **Unreadable or unparseable file, or an unknown key:**
    - Setup exits 2 with the whole problem set `Check` and the skip check give, as recon would
      give it for the file alone.
    - The message names the path through `filepath.Abs`.
    - A problem named `config` makes the error fatal; problems named by setting only mark rows
      invalid.
- **D8. Shown values are the decoded ones.**
  - Each row shows the value `config.Check` decoded, so `concurrency: 0x10` shows as `16`, the value
    recon uses (B13).
  - Case variants (B6) are matched case-insensitively at every level: for `keys.Shodan`, and for
    whole blocks (`Keys:`/`keys:`, `Rate:`/`rate:`).
  - Two variants of an entry or a block mark that setting invalid ("set twice in the file, as `X`
    and `Y`").
  - As a safety net, any setting whose node text doesn't decode to what `Check` gave is marked
    invalid. This covers viper picking one block at random, or a literal dotted key.
- **D9. Validation as values are entered (B7).**
  - An entered value is put into a copy of the document, which is serialised and run through
    `Check`. Problems named by that setting's key reject it and show the same message recon gives.
  - Invalid UTF-8 is refused when it is entered (it can't be stored as `!!str`).
  - The wordlist and sensitive-path files are read at that point too, so an unreadable file is
    rejected.
- **D10. Save encoding: yaml.v3 Node re-encode** (user's choice).
  - The encoder uses `SetIndent(2)`; blank lines are lost on the first save.
  - Every scalar setup writes is tagged `!!str`, numbers included, so it reads back exactly as
    shown (B13).
  - **Replacing:** a case variant is replaced in place, and two variants collapse to one at the
    first's position (B6).
  - **Clearing** removes the entry and its own comments (head, line, foot). The head comment of the
    document's first entry is the exception: it moves to the document, since it is usually the
    file's header.
  - **Removing a block:** a `keys:` block left empty is removed, and so is any other block left
    empty (`rate:`).
  - **Untouched:** unknown key sources are left as they are.
  - `skip` is written as a block sequence once it is edited.
- **D11. Save mechanics (B12, B14).**
  - **Symlinks:** the target is found with an `os.Readlink` loop (at most 40 hops, a relative link
    resolved against its own directory), so a dangling link creates its target and the link stays.
  - **Directories:** missing ones are created with `0700`.
  - **Writing:**
    1. Write a temp file with `0600` and `O_EXCL` beside the target.
    2. `fault.Point("in-config-save")`.
    3. Write, then fsync unless `Deps.NoFsync`.
    4. Rename, then fsync the directory.
  - The saved file is always `0600`, which tightens a broader one.
  - **On error:** the temp file is removed, the file is unchanged, and the model keeps its edits
    and shows the reason and path.
- **D12. Change tracking and conflicts (B10, B15).**
  - Each field keeps its original value. It is changed when the current value differs: string
    equality, and set equality for `skip`.
  - The bytes read at open, save or reload (or "absent") are kept. Before writing, the file is read
    again and compared with `bytes.Equal`. A difference opens the conflict dialog.
  - **Reload:** if the file now fails D7's fatal checks, the edits are kept, the problems and path
    are shown, and overwrite is still offered.
- **D13. Skip (B8).**
  - **Reading:** entries are read as `parseSkip` does: trimmed and lower-cased, and a scalar
    `a,b` is split on commas. `DNS` in the file matches the `dns` toggle.
  - **`none`:**
    - Alone it means empty, and is dropped once a stage is toggled.
    - Beside stage names it is one problem on the whole list, with recon's message.
  - Unknown and unskippable entries get per-entry messages from a function split out of
    `validateSkip` (`recon.go:303-320`), which the cli passes to setup.
  - The offered stages are `Deps.Stages` without the unskippable ones, each with its `stageHelps`
    description.
- **D14. Paths.**
  - An entered relative `output_dir`, `wordlist` or `sensitive_paths` is saved as
    `filepath.Join(Deps.Getwd(), v)`. `Deps.Getwd` is new, and defaults to `os.Getwd`.
  - `~` and `~/…` are kept as typed.
  - An unset `output_dir`, or a relative value in the file, is shown as "relative: resolves against
    the directory nyx runs from, e.g. <cwd>/<v>".
  - `wordlist` and `sensitive_paths` defaults show `config.Builtin*Label()`.
- **D15. Keys in memory and on screen (B3, B4).**
  - The model holds keys as `config.Secret`, so a `%v` of its state prints `****`.
  - The view shows:
    - a key of 12 or more runes as `••••` plus its last 4 runes, after `sanitize.Line`;
    - a shorter one as `set`;
    - an empty or unset key as `not set`.
  - Every key value from the file, including unknown sources, and every value typed this session is
    added to the failure writer's redactor (`inv.fw.setRedactor`) before any error can be written.
- **D16. Key test (B9).**
  - **Request:** `keycheck.Check(ctx, http, source, key)` runs as a Cmd with a 15 s context. The
    request's own `Timeout` is 20 s, so the context decides.
    - `errors.Is(err, context.DeadlineExceeded)` gives "could not check: timed out".
  - **Client:** each test builds `egress.New(Deps.Egress` with `Keys{source: key}` and
    `Redactor: config.NewRedactor(key))`. It calls `.Clients(false, []string{that source's host})`,
    so egress itself allows only that source. There is no `Policy` and never a target.
  - **Tracking results:**
    - Each test carries the field's edit generation, and a result for an older one is discarded.
    - Editing or clearing removes a shown result.
    - `t` is ignored while that key's test is running.
    - Quitting cancels the context.
  - **Reason:** the source's message (a JSON `message`, `messages` or `error.message`, the NVD's
    `message` header, else `HTTP <n>`).
    - It goes through `sanitize.Line` and is cut to one line.
    - Every run of 5 or more characters of the key is masked, since Cert Spotter echoes part of it.
- **D17. Endpoints and classification.**
  - The endpoints are the table in External facts. For SecurityTrails and WhoisXML the free ones
    are kept (user's choice): the stage endpoints answered the user's keys the same way.
  - **Common answers:** 200 is accepted, 429 is "could not check: rate limited", 402 is "could not
    check: out of credits", and anything else is "could not check: HTTP <n>: <message>".
  - **Rejected,** per source:
    - 401, or 401/403 where that source means a bad key (securitytrails, shodan, virustotal,
      censys, github, certspotter);
    - for chaos, also 400 with `"valid":false`;
    - for the NVD, the status rules exported from `internal/cve`, which `cve/client.go` then uses
      too, so the two can't disagree (as `origin` is shared). There, 403 without "apikey" means
      rate limited.
  - WhoisXML's 401/403 is "could not check: <its message>", because it never clearly says the key
    is bad.
  - A network error gives "could not check: <egress's scrubbed error>".
- **D18. An empty entered setting clears it** (user's choice; amends B7). This is the same rule as
  B5 for keys, instead of `output_dir`'s "must not be empty".
- **D19. Signals (B10, B11).**
  - **First signal:** `watchSignals` cancels `runCtx`, the Program ends with the terminal restored,
    and `Execute` then writes the interrupt error and returns 143 or 129.
  - In raw mode Ctrl+C is a key, which starts the quit flow. An external SIGINT gives 130.
  - **Second signal:** `invocation` gains `beforeHardExit`, guarded by `inv.mu`. Setup sets it to
    `p.Kill()`, and the second-signal path (`cli.go:250-255`) calls it before `os.Exit`.
  - **During a save:** the save runs synchronously inside `Update`, so a first signal lets it
    finish. The atomic rename covers a second signal or a crash.
- **D20. Panics (B4, B11).** `WithoutCatchPanics` (see External facts).
  - The root model's `Update`, `View` and `Init` recover a panic, kill the Program (restoring the
    terminal) and return a `*clierr.PanicError` through `Execute`: redacted, with the stack only
    under `--debug`.
  - Every Cmd, including those from sub-models and `Init`, is wrapped in `safe(cmd)` before any
    `tea.Batch`. `safe` turns a panic into a message that re-panics inside `Update`.
- **D21. Terminal checks and their order (B1, B18).**
  - `Deps.StdinIsTTY` is new and defaults to `term.IsTerminal(os.Stdin.Fd())`.
  - The checks run in this order, each exiting 2:
    1. a positional argument;
    2. no `--config` and no default path;
    3. stdin or stdout not a terminal (`INVALID_INPUT`, naming the path, with the hint "edit
       <path> by hand; see the README's Configuration section"), as a JSON error under `--json`;
    4. D7's file problems.
  - `--help` is cobra's, and works when piped.
- **D22. No-config hint (B19).**
  - `recon` (a run) and `cve` set `inv.hintNoConfig` when there is no `--config`, the default path
    is not empty, and `os.Stat` on it gives `fs.ErrNotExist`.
  - `Execute` writes the one line straight to stderr after the command returns and before any
    error line. It does so only when the error code isn't `INVALID_INPUT`, and not under `--json`
    or `--quiet`.
  - It isn't an event, so events and stdout are unchanged.
  - It comes at the end because recon can still fail with `INVALID_INPUT` mid-run: an empty scope
    (`recon.go:247`) or the netblock limit (`recon.go:265`).
  - The text is: `hint: no config file at <path>; run nyx setup to store API keys and settings`.
- **D23. What each key turns on (B2).**
  - Built in cli from `stageHelps`' key column: the stages naming the source, with bracketed ones
    as "adds to".
  - Cert Spotter's line says it works without a key.
  - The NVD's line is fixed: "nyx cve: 50 requests per 30 s instead of 5".
  - Setup gets the result as data, so no code outside cli names a stage.
- **D24. Shared flags.** `--json` changes only the error format. `--quiet` and `--debug` are
  accepted, and nothing goes to stderr while the UI runs.
- **D25. README (B21).**
  - Add a `nyx setup` section and the exit-2 cases in the table.
  - Document the hint, and that `NYX_*`/`NVD_API_KEY` override what setup saves.
  - Correct "No prompts, no stdin", and the matching `Deps.Stdin` comment (`cli.go:75`).
  - List the key-test hosts in the Passive boundary section.
  - Note that a test may spend a query, for VirusTotal and Censys.

## Files

- `go.mod`, `go.sum`: add bubbletea v2.1.1 and bubbles v2.2.1 (lipgloss v2.0.6 comes in
  indirectly).
- `internal/config/config.go`: split `Check` out of `Load`; export what setup needs (the
  defaults as text, the built-in labels, `expandHome` semantics for display).
- `internal/configedit/` (new): `doc.go` (document, lookup, set/clear, encode), `save.go`
  (symlinks, permissions, atomic write, fault point), with their tests.
- `internal/keycheck/` (new): `keycheck.go` (source table, `Check`, `Host`, classification,
  reason masking), with its tests.
- `internal/cve/client.go`: export the NVD status rules for keycheck to share.
- `internal/setup/` (new): `model.go`, `tabs.go`, `field.go`, `dialogs.go`, `view.go`,
  `safe.go`, with their tests.
- `internal/cli/setup.go` (new): the command, Example, help annotations, checks, wiring.
- `internal/cli/help.go`: `AddCommand` for setup.
- `internal/cli/cli.go`: `Deps.StdinIsTTY` and `Deps.Getwd`, `rawIn`/`rawOut`, `beforeHardExit`,
  the hint in `Execute`, and the `Deps.Stdin` comment.
- `internal/cli/recon.go`: split the per-name skip check out of `validateSkip`; set the hint flag.
- `internal/cli/cve.go`: set the hint flag.
- `internal/cli/stages_topic.go`: the per-source "turns on" text from `stageHelps`.
- `internal/cli/setup_test.go`, `crash_test.go`, `pty_linux_test.go` (new): tests.
- `README.md`: D25.

## Tests

Tests marked **[mutation]** pin behaviours where a bug would do the most harm. `/spec-develop` runs
a mutation check on them.

- **B1:**
  - The harness runs `nyx setup` with `--config`, and with the default path. Root help lists
    `setup` with an example.
  - With `HOME` and `XDG_CONFIG_HOME` unset and no `--config`, it exits 2 with the `--config`
    message.
  - `nyx setup x` exits 2.
- **B2:**
  - A model test checks each tab's rows: nine sources with their "turns on" text and Cert
    Spotter's no-key note; the eight settings with file value or default.
  - An unset `output_dir` and a relative `wordlist` show the cwd example (`Deps.Getwd` faked).
  - `concurrency: 0x10` shows `16` (D8).
- **B3** **[mutation]:**
  - Model tests: a 12-rune key shows `••••` plus its last 4; an 11-rune key shows `set`; an empty
    or absent key shows `not set`.
  - Typing and pasting a wide-character key show one `•` per rune.
  - A key holding ESC shows a sanitised last 4.
- **B4** **[mutation]:**
  - A harness run with keys in the file, a typed key and `--debug`: the key's text beyond its last
    4 characters must appear in no view frame, stdout, stderr or error.
  - The same after a forced panic in `Update` and in a Cmd, and with a fake source that echoes the
    key in its 401 body.
  - `fmt.Sprintf("%v", model)` contains no key.
- **B5:**
  - Entering, replacing and clearing a key, then saving: the file holds the trimmed key, or no
    entry. Whitespace only counts as a clear.
  - An unknown source `keys.foo` survives a save byte for byte and isn't listed.
- **B6:**
  - Documents with `keys.Shodan`, with `Concurrency`, with `Keys:` plus `keys:`, and with
    `Rate:` plus `rate:`. Each case variant shows as its setting and is replaced in place.
  - With two variants the setting is marked invalid, and after an edit one entry is left.
- **B7:**
  - Each setting rejects a bad value with the exact message `config.Check` gives for the file. A
    table test runs both and compares.
  - An empty value clears (D18).
  - A relative path is saved as absolute; `~` and `~/x` are saved as typed.
  - An unreadable wordlist file is rejected.
  - Invalid UTF-8 is refused.
- **B8:**
  - The stages offered exclude the unskippable ones, each with its description cut to one line.
  - `skip: [dns, foo, resolve]` lists `foo` (unknown) and `resolve` (can't be skipped), each
    removable on its own, and keeps `dns`.
  - A scalar `skip: DNS,ports` and `none` alone are read correctly; `none` beside a stage is one
    whole-list problem.
- **B9:**
  - keycheck tests against an httptest fake per source, with `SourceBaseURLs`:
    - accepted, and each source's rejected form (chaos's 400, the NVD's 404 with its `message`
      header);
    - 429, 402 and another status;
    - WhoisXML's ambiguous 401/403;
    - a network error (a closed port);
    - a fake that never answers, giving "timed out" after 15 s (clock-free: a short-context test
      seam);
    - an echoed key, masked;
    - control characters in the message, stripped.
  - **[mutation]** The test sends exactly one request, only to that source's host. The harness's
    canaries see nothing else, and no target is contacted.
  - Model tests:
    - a result for an older generation is discarded;
    - editing the key removes the shown result;
    - `t` during a running test is ignored;
    - quitting cancels the test's context, and the fake sees it.
- **B10:**
  - Model tests:
    - an edit followed by changing the value back counts as no change;
    - quit with changes opens the dialog, and save, discard and back each do the right thing;
    - Ctrl+C is a quit;
    - with no change, nothing is written (the file's mtime and bytes are unchanged).
  - Exit codes are 0 after save, discard and no change.
  - Child tests over a pty (Linux): SIGTERM gives 143 and SIGHUP gives 129, with the file
    unchanged.
  - A save in progress when the first signal arrives completes. This uses a save seam that blocks
    until signalled, in-process.
- **B11:** a Linux-only pty child test (`x/sys/unix` in a `_test.go`: `/dev/ptmx`, `TIOCSPTLCK`,
  `TIOCGPTN`).
  - The termios after exit equal the termios before it for:
    - save, discard and quit;
    - SIGTERM, SIGHUP and a second signal;
    - a forced panic.
  - The last output leaves the alt screen and shows the cursor.
  - An error message comes after the restore sequences.
  - macOS has no pty test; this is recorded in Conventions.
- **B12** **[mutation]:**
  - configedit golden tests: the README's sample config, and a commented file with a header.
    - Other settings, comments and order are kept.
    - A cleared value's comment goes with it; the header stays when the first entry is cleared.
    - An empty `keys:` (and `rate:`) block is removed.
  - Save tests:
    - a new file is `0600` and its new directories `0700`;
    - an existing `0644` file becomes `0600`;
    - a symlink, a relative symlink and a dangling symlink each update the target and keep the
      link.
  - A child test calls `configedit.Save` directly and is killed with SIGKILL at `in-config-save`.
    The file is then the old one or the new one, never partial, and no temp file is left at the
    destination.
- **B13** **[mutation]:**
  - A round trip of keys and paths with `: `, `#`, quotes, a leading `-`, `yes`, `0123`, `0x10`,
    unicode and a tab.
  - After the save, `config.Load(nil, path, cleanEnv)` gives exactly the values setup showed.
  - `nyx cve` with no `NVD_API_KEY` then sends the saved key to the fake NVD.
- **B14** **[mutation]:** a save into a read-only directory, and a rename failure through a seam.
  Setup stays open with its edits, and shows the reason and path; the file's bytes are unchanged.
- **B15:**
  - The file is changed on disk after open, after save and after reload. Save opens the conflict
    dialog; reload discards the edits; overwrite writes them.
  - **[mutation]** A changed file is never written without the dialog.
  - A reload of an unparseable file, or one with an unknown key, keeps the edits, shows the
    problems and path, and still offers overwrite.
- **B16:**
  - A missing file at the default path, and at `--config`, opens at the defaults and is created on
    save.
  - An unreadable file, an unparseable one and one with an unknown key each exit 2 with the whole
    problem set, naming the absolute path, before the UI opens.
  - Invalid values (a number, a missing wordlist file, an unknown skip stage) open marked invalid,
    and saving is blocked until each is fixed or cleared.
- **B17:** `NYX_CONCURRENCY=abc`, `NYX_KEYS_SHODAN=x` and `NVD_API_KEY=y` set in the harness env
  change nothing that is shown, and setup still opens.
- **B18:**
  - With stdin or stdout not a terminal, setup exits 2 with `INVALID_INPUT`, naming the path, with
    the hint. Under `--json` it is the JSON error, with its five keys.
  - `nyx setup --help`, piped, exits 0.
- **B19:**
  - `recon` and `cve` print the hint when the default file is absent.
  - It is not printed:
    - under `--json`, `--quiet` or `--config`;
    - when the file exists;
    - on an `INVALID_INPUT` (a bad flag, an empty scope).
  - It is printed for `cve` but not for `nyx ip` or `nyx recon export`.
  - Exit code, stdout and the recorded events are the same with and without it.
- **B20:**
  - The footer lists the active keys on each tab and in each dialog.
  - At 59×16 and 60×15 the view is only the size message; at 60×16 the UI draws.
  - The Skip tab scrolls so the selection stays visible.
- **B21:** a README check, as for the existing commands, that `nyx setup` is in the command list and
  the exit-code table.
- **The real Program wiring:** one in-process harness test with `StdinIsTTY` forced true,
  keystrokes as Stdin and `WithWindowSize`. It edits, saves and quits, and checks the file and an
  exit of 0.

## Conventions

- CLAUDE.md:
  - the hard invariants (only egress does network I/O; the third-party client contacts only the
    declared source; no first-party `os/exec`);
  - the stable error interface (`INVALID_INPUT`, the five JSON error keys);
  - `config.Secret` and redaction;
  - the config `Env` rule (no `os.Getenv`);
  - output written to a temp file and renamed;
  - Australian English, with US input accepted;
  - no spec IDs in code.
- Tests:
  - `t.Parallel()` and `h.setenv`;
  - child-process tests under `TestChildProcesses`;
  - the pty test is Linux-only and skips elsewhere, because macOS ptys need different ioctls.
- `docs/todo.md`: the shared atomic-write helper is still deferred. `configedit.Save` is the
  third such writer, and the todo's "Shared helpers" item should now name it.

# Implementation

## Develop

Built as the design says, in four groups, each tests first (stubs, then failing assertions, then
code): `config.Check` with `internal/configedit`, `internal/keycheck` with the NVD status rules
exported from `internal/cve`, the `internal/setup` Bubble Tea model, and the cli wiring.

- **Config and configedit.** `config.Load` now calls a shared `check`, and `config.Check` is its file-only
  form. `configedit` holds the YAML document (`Doc`), `Save`, and a `Store` that implements the file side
  of `setup.Backend` (open, per-value check, save with conflict detection, overwrite). Tests: golden and
  round-trip tests for B5, B6, B12 and B13, a table test that each setting's message equals
  `config.Check`'s (B7), save tests for permissions, symlinks and the read-only directory and rename seam
  (B12, B14), conflict tests (B15), and a SIGKILL child test at `in-config-save` (B12).
- **keycheck.** The nine requests of the External facts table, with classification, a masked and
  one-line reason and a one-request-to-one-host test (B9). `cve.Meaning` is the NVD's status rules, shared
  with `cve/client.go`.
- **setup.** The model, field, dialogs, view and `Run`, behind `setup.Backend` (`internal/setup/backend.go`,
  written first as the contract between the groups). Tested by driving `Update` with a fake Backend, and
  through a real Program with a buffer and a window size (B2, B3, B4, B8, B9, B10, B15, B16, B20, D20).
- **cli.** `cli/setup.go` does the exit-2 checks in D21's order, builds the Store and runs the editor;
  `invocation` gained `rawIn`, `rawOut`, `beforeHardExit` and the hint; `Deps` gained `StdinIsTTY`,
  `Getwd` and `WindowSize`; `skipProblem` was split out of `validateSkip`. The behaviour tests drive
  `cli.Execute` with the keys as scripted stdin through the real Program (B1, B4, B10, B13, B14, B15,
  B16, B17, B18, B19, the wiring test), and `pty_linux_test.go` runs the real child on a
  pseudo-terminal for B10 and B11 (save, discard, quit, SIGTERM, SIGHUP, SIGINT, a second signal while a
  save is stuck at `in-config-save`, a forced panic). README: B21's check is `setup_readme_test.go`.
- **Deviations from the plan.**
  - `configedit.Store` implements most of `setup.Backend` (D3 had configedit pure apart from `Save`).
    It imports `setup` for the contract types.
  - `Deps.WindowSize` is new: the window size a test gives a buffer, for `WithWindowSize`.
  - The harness gives every run an empty default config file, so existing tests do not see the no-config
    hint; the one test that asserted an empty config directory (`TestIP_WritesNoFiles`) compares with
    what the harness put there. `TestTree_RootHelpIsTheWholeReference` exempts `nyx setup`'s example
    from "passes `--json`", and the plain help goldens gained `setup`.
  - keycheck treats only a 401 as "rejected" for securitytrails, shodan, virustotal, censys, github and
    certspotter: no probe showed any of them use 403 for a bad key, so a 403 reads "could not check:
    HTTP 403: …". Chaos is 401, or 400 with `"valid":false`.
  - A failed save's notice shows the reason alone on its first line and `file: <path>` on the next
    (`configedit.SaveError.Reason`), because the path made the first line too long to show the reason.
  - `.golangci.yml`'s forbidigo exclusion now covers the two new child-process test files.
  - The info-helper tests (`setup_info_internal_test.go`, `setup_readme_test.go`, the hint tests) were
    written beside their code, not watched failing first; they pin new behaviour and the
    mutation checks below cover the ones marked.
- **External facts that differed.**
  - viper does apply a literal dotted key (`rate.per_host: 9`); the D8 safety net marks the row invalid.
  - A hand-written `output_dir: ~` is YAML null, so the loader uses the default `.`; setup writes `"~"`
    quoted, which does mean home.
  - Bubble Tea draws about every 17 ms, so a script that sends keys faster than that shows only the last
    frame; the tests pace their key presses.
- **Mutation checks**, on the final code (after the simplify pass), each by hand and each killed
  (`go test -count=1` over the packages named, the original restored by hand afterwards):
  - B3: 11 runes masked (`TestKeysTab_MaskedKeys`); last five runes shown (six setup tests).
  - B9: a 429 sent again (`TestRun_OneRequestToItsHostOnly`, `TestCheck_CommonAnswers`). Letting `Run`
    allow all nine hosts survives, because only egress's own allow-list can see it; a test pins that a
    client that allows another host refuses the request.
  - B12: file left `0644`, directories `0755`, temp file kept on failure (the save tests).
  - B13: values not tagged `!!str` (`TestDoc_AwkwardValuesReadBackExactly` and five more); a key not
    trimmed (`TestSetup_EditSaveAndQuit`, four setup tests).
  - B14: a rename error swallowed (`TestSave_AFailedRenameShowsReasonAndPathAndLeavesTheFile` and three more).
  - B15: the store's conflict check off (`TestSetup_ChangedFileAsksBeforeWriting`,
    `TestStore_SaveReturnsErrConflictWhenTheFileChanged`); the model overwriting with no dialog
    (`TestConflict_NeverWritesWithoutTheDialog` and five more).
  - B11: a second signal that does not give the terminal back, and a Program kill that is not
    registered (both `TestChildProcesses/SetupOnAPty/second signal`).
  - B17: NYX_* and `NVD_API_KEY` left in setup's environment (`TestSetup_FileProblemsExitTwo`,
    `TestStore_IgnoresNYXVariablesAndTheNVDKey`, `TestFileOnlyEnv_DropsTheOverrides`).
  - B18, B19, B1: the stdin check, the hint under `--json`, the hint on a usage error, and positional
    arguments accepted (`TestSetup_NoTerminalExitsTwo`, `TestNoSetupHint_NotPrinted`,
    `TestSetup_ArgumentExitsTwo`).
  - Two first attempts did not build and were corrected, not counted.

## Known limitations

- **B9.** A panic inside a key-test Cmd is forced only in the `internal/setup` tests (a fake Backend), not
  through `cli.Execute`: no egress hook panics on that path.
- **B9.** A 403 from six sources reads "could not check", not "rejected" (see the deviation above).
- **B4.** `OnSecret` also registers the typed buffer once it has 4 runes, so the redactor masks any
  occurrence of those prefixes in an error, which can mask four innocent characters of a message.
- **B11.** No macOS pty test; the Linux one is the only check that the terminal is restored under signals.
- **B15.** Overwrite on a file setup cannot open (unparseable, unknown key, more than one YAML
  document) replaces it with just the edits.
- **B6.** Editing a setting under two case variants of a block (`Keys:` and `keys:`) merges the second
  block into the first.
- **B2.** A setting setup does not list (for example `crawl.max_depth: x`) that is invalid has no row,
  so setup does not mark it; it is fatal only when another problem makes the whole file fatal.
- **B16.** A file with more than one YAML document exits 2, though viper reads the first, because a
  save would drop the rest.

## Simplify

Four reviewers (reuse, simplification, efficiency, altitude) ran over the whole change.

Fixed:

- `config` now owns knowledge that was copied elsewhere.
  - `SettingText` replaces the second key-to-text switch in configedit, and `DefaultText` is built on it.
  - `SkipNames` replaces configedit's copy of the skip normalisation, whose `none` field nothing read.
  - `FileOnlyEnv` replaces the two copies of the NYX_*/NVD_API_KEY filter. Before, the filter ran twice.
  - `ErrorText` replaces configedit's `reason`, so both packages word an OS error the same way.
- configedit:
  - `Store` dropped its mutex: every method runs on the model's goroutine.
  - `relative` reuses the path that `value` already works out.
  - `maps.Keys` replaces a hand-written iterator.
  - `Check` no longer reads the wordlist or sensitive-path file when another setting is accepted.
- setup:
  - `keyRow.testing` and `settingRow.origProblem` held derivable state and are gone.
  - `scrub` caches its redactor until a key is seen or typed, so a keystroke no longer builds dozens of redactors.
  - Panic scrubbing is in one helper, used by `root.fail` and `Run`.
  - Removed: `Init`'s recover around `return nil`, the inner `safe` around the key-test Cmd (`root.Update` already wraps every Cmd), and the `keymap` type, whose `help.KeyMap` interface nothing used.
  - `cursorAt` replaces the identical `bodyCursor`.
  - `header` uses `plural`, and `tooSmall` uses `wrap`.
  - The five accessors in the test helpers are now one generic `nth`.
- cli:
  - `slicesClone` gave way to `slices.Concat`.
  - `secrets.add` skips values it already holds and rebuilds the failure redactor only for a new one.
  - `invocation.rawIn` duplicated `Deps.Stdin` and is gone.
  - "Also works without a key" now follows from a key that only adds to stages, so certspotter is not named.
- keycheck:
  - `Host` and `Check` were only used by tests and are no longer exported.
  - `Run` looks the source up once and passes it on.
- cve: `Meaning` lower-cases the body only for a 403 or 404.

Skipped:

- One table of settings in `config` that would derive `setup.SettingKeys`, `number` and `isPath`.
  `SettingText` removes the worst of the duplication, and the table is a wider redesign.
- One table in egress of where each source's key goes, shared by the stages and keycheck. It would
  change every keyed stage, well outside this change. The whoisxml difference (stage body field,
  test query parameter) is noted for a follow-up.
- A `KeySourcer` stage interface in place of the bracketed key column. `stageHelps` predates this
  change.
- A shared atomic-write helper for configedit, export and output: their rules differ (mode, link
  following, directory sync).
- Holding back each typed prefix from `secrets` until the edit ends. A replaceable "typing" slot
  would forget a longer value after a backspace, so every prefix is still kept.
- Reusing the startup `config.Load` for the `Open` snapshot, and the second read after a save or
  overwrite. Each happens once per action.
- Building the row items once per frame instead of three times. The cached redactor removes most of
  the cost.

# Verification

## Result

The implementation meets the goal: a user can store, rotate, clear and test their keys, the output
directory and the common settings from one full-screen editor, and the next `nyx recon` or `nyx cve`
reads exactly what it saved. `make test` (the cross-target vet and `go test -race ./...`) and
`make lint` (0 issues) pass. By hand, the built binary exits 2 with the documented message and hint
for no terminal (as text and as the five-key JSON error), no default path, and an argument;
`nyx setup --help` exits 0 when piped; and `nyx cve` with a malformed ID (a usage error) prints no
hint. No bug was found that needed a fix before the code review, so nothing was changed up to that
point.

- **B1.** Met. `--config` and the default path, the root help entry with its example, the no-path
  and argument exits, and D21's check order are tested through the harness.
- **B2.** Met for the settings it lists. The nine sources, each with its "turns on" text (built from
  `stageHelps`, so no code outside cli names a stage), Cert Spotter's no-key note, the NVD's fixed
  line, the eight settings with their file value or default, decoded values (`0x10` shows `16`) and
  the cwd example are tested. The "B2" known limitation is about B16: see there.
- **B3, B4.** Met. Masking at 12 runes, `set`, `not set`, one bullet per rune typed or pasted, a
  sanitised last four, the `%v` of the model and field, the failure redactor fed before anything can
  fail, and a scrubbed panic are tested. The "B4" known limitation over-redacts (four innocent
  characters of a message may be masked); it never shows more of a key, so B4 holds.
- **B5.** Met: trimming, whitespace-only as a clear, and an unknown source kept byte for byte.
- **B6.** Met. A case variant is shown and replaced in place; two variants mark the setting invalid
  and a save leaves one entry. Two spellings of a whole block (`Keys:` and `keys:`) mark every
  setting in it invalid, as D8 says, so all nine key rows must each be edited or cleared before a
  save; the save then merges the blocks into the first, which is the "one entry" B6 asks for. The
  "B6" known limitation is that merge, and is not a gap.
- **B7.** Met, with D18's amendment. The table test compares every setting's message with
  `config.Check`'s; relative paths are made absolute, `~` and `~/x` kept, an unreadable wordlist and
  invalid UTF-8 refused. Numbers typed in unusual forms (`+5`, `010`, `1_000`) were checked by hand
  to read back as the loader reads them, so B13 holds for them too.
- **B8.** Met: the unskippable stages are left out, descriptions are cut to one line, unknown and
  unskippable entries are removable one at a time, and a scalar list, `none` alone and `none` beside
  a stage read as recon reads them.
- **B9.** Met. One request to the tested source's host only (egress's own allow-list holds that one
  host), each source's accepted and rejected forms, 429, 402, other statuses, WhoisXML's ambiguous
  answers, network errors, the 15 s timeout, echo masking, sanitising, and the generation rules are
  tested. The "403 is could not check" known limitation is consistent with B9: no probe showed any of
  the six sources using 403 for a bad key, so "rejected" is kept for an answer that says so. A panic in
  a key-test Cmd is forced only in the `internal/setup` tests; the same `safe` wrapper covers the real
  path, and the model returns no batched Cmds that could escape it.
- **B10, B11.** Met on Linux. Change tracking, the quit dialog, Ctrl+C, no write without changes,
  exit 0, 143 and 129 with the file unchanged, a save that completes under the first signal, and the
  termios, alt screen and error order after save, discard, quit, signals, a second signal and a panic
  are tested on a real pty. There is no macOS pty test ("B11" known limitation): B11 is unchecked on
  macOS (see Follow-ups).
- **B12.** Met, except in the case below under B15. Comments and order kept, a cleared value's
  comments removed, the header kept, empty blocks removed, `0600`/`0700`, tightening, symlinks
  (absolute, relative, dangling, chains, loops) and the SIGKILL at `in-config-save` are tested.
- **B13.** Met: the round trip with `: `, `#`, quotes, `-`, `yes`, `0123`, `0x10`, unicode and a tab,
  `config.Load` with a clean environment, and `nyx cve` sending the saved key.
- **B14.** Met: a read-only directory and a failed rename keep the edits, show the reason and the
  path, and leave the file's bytes.
- **B15.** Partly met. The conflict dialog after open, save and reload, reload discarding the edits,
  overwrite writing them, never writing a changed file without the dialog, and a reload of a broken
  file keeping the edits and still offering overwrite are tested. But an overwrite of a file setup
  cannot open replaces it with only the edits ("B15" known limitation). For an unparseable or
  unreadable file there is nothing to keep, but a file that only holds an unknown key parses, and an
  overwrite then drops every other setting and comment in it, which B12 does not allow. Keeping them
  would keep the unknown key, which setup cannot then reopen, so which way to go is a decision for
  the user (see Follow-ups).
- **B16.** Partly met. A missing file at either path, the exit-2 cases with the whole problem set and
  the absolute path, and invalid listed values (a number, a missing wordlist, an unknown skip stage)
  marked and blocking the save are tested. Two gaps, both known limitations: an invalid value in a
  setting setup does not list (`crawl.max_depth: x`) is neither marked nor shown, so setup saves a
  file `nyx recon` still refuses without saying why; and a file with more than one YAML document
  exits 2, though recon reads its first document and B16 asks setup to open it. The first cannot be
  fixed inside the spec (B16 would block saving on a value setup cannot edit, and Out of scope leaves
  such settings hand-edited); both are listed in Follow-ups.
- **B17.** Met: `NYX_*` and `NVD_API_KEY` are dropped before the file is read and change nothing.
- **B18.** Met: the `INVALID_INPUT` error names the path with the hand-edit hint, as text and JSON,
  and piped `--help` exits 0.
- **B19.** Met: printed for `recon` and `cve` when the default file is absent; not under `--json`,
  `--quiet`, `--config`, an existing file or a usage error; not for `nyx ip` or `nyx recon export`;
  exit code, stdout and events unchanged.
- **B20.** Met: the footer per tab and dialog, the size message at 59×16 and 60×15, and Skip-tab
  scrolling are tested.
- **B21.** Met: the README's command list, Setup section, exit-code table, hint, overrides, key-test
  hosts and the query a test may spend; `setup_readme_test.go` checks it.
- **Conventions.** Met: only egress does network I/O (the boundary test passes), no first-party
  `os/exec`, keys are `config.Secret`, no `os.Getenv`, Australian English, no spec IDs in code, the
  tests are parallel and the child tests sit under `TestChildProcesses`, and `docs/todo.md` names
  `configedit.Save` as the third atomic writer.

## Code review

`/code-review high --fix` went over every file of the change. It reported five problems and fixed
four. Each fix was checked against the spec.

Fixed and kept:

- **Partly masked keys (B4).** `secrets.add` in `internal/cli/setup.go` built the failure writer's
  redactor in arrival order. The values include each prefix of a key as it is typed, so the shortest
  prefix was masked first, and an error holding the whole key showed `****` and the rest of it. The
  values are now sorted longest first, as the editor's own `scrub` already did.
- **The hint and a panic (B19).** `writeNoConfigHint` in `internal/cli/cli.go` called `toError` to
  look for a usage error, which under `--debug` writes a panic's stack, so `Execute` wrote it a
  second time with the hint in between. A panic now skips that check. The hint still comes before
  the error line, and nothing else changes.
- **A relative `--config` (B1).** `runSetup` now resolves it against `Deps.Getwd` (which is
  `os.Getwd` in production, so a real run behaves as before), the same directory the editor
  resolves relative paths against.

Fixed by the review and then undone by hand:

- **`NaN` and `Inf` as rates.** `posFloat` in `internal/config/config.go` accepts `rate.*: nan` and
  `inf`, which setup's Check therefore accepts too. This is older than this change and is how
  `nyx recon` reads the file. Rejecting them would change recon's behaviour, which the spec doesn't
  ask for, so the fix was reverted (see Follow-ups).

Left unfixed:

- **Ctrl+C in the quit and conflict dialogs (B10).** A second Ctrl+C there does nothing; only the
  listed keys (`s`/`d`/`esc`, `r`/`o`/`esc`) work. D6 gives the dialogs exactly those keys, and
  whether Ctrl+C should go back or discard and quit is a design choice for the user.

The review added no tests. After these changes, `make test` and `make lint` pass.

# Follow-ups

1. Decide what an overwrite should keep when the file has an unknown key but still parses (B12,
   B15). Today `Store.Overwrite` in `internal/configedit/store.go` writes only the edits and drops
   every other setting and comment. The alternative is to apply the edits to the parsed document,
   which keeps the unknown key, so setup then can't reopen the file it just saved.
2. Decide how setup should treat an invalid value in a setting it doesn't list, such as
   `crawl.max_depth: x` (B16). Today it is neither shown nor marked, and setup saves a file that
   `nyx recon` still refuses. One option is to show it as a notice that doesn't block saving, from
   `Store.snapshot` in `internal/configedit/store.go`, which today drops problems whose name is not a
   listed setting.
3. Decide whether a config file with more than one YAML document should open in setup, since
   `nyx recon` reads its first document. Today `configedit.Parse` refuses it and setup exits 2,
   because a save would drop the other documents.
4. Decide what Ctrl+C means in the quit and conflict dialogs (go back, or discard and quit), and add
   it to `quitKey` and `conflictKey` in `internal/setup/model.go`.
5. Decide whether `rate.per_host`, `rate.per_source` and `rate.dns` should reject `nan` and `inf`.
   If so, add `math.IsNaN(f), math.IsInf(f, 0)` to the "not a number" case of `posFloat` in
   `internal/config/config.go`, and add a case to `TestCheck_AgreesWithLoad` in
   `internal/config/check_test.go`.
6. Check terminal restoration on macOS by hand, as no test covers it: run `nyx setup`, then in turn
   save, discard, quit, `kill -TERM <pid>` and `kill -HUP <pid>` from another terminal. After each,
   confirm that `stty -a` matches what it showed before, and that the shell prompt and cursor are
   normal.
7. Replace the SecurityTrails and Shodan keys, which every key-checking endpoint refused in the
   probe. Then confirm with `nyx setup`, pressing `t` on each row, that they read `accepted`.
8. Check the WhoisXML account (credits, the key and the IP allowlist) at
   https://user.whoisxmlapi.com, since the key got WhoisXML's ambiguous 401/403. Then test it with
   `t` in `nyx setup`.
9. Once keys are available for Censys, Chaos, GitHub and Cert Spotter, test each with `t` in
   `nyx setup`. Their "accepted" answers come from the docs or are assumed. If one reads
   `could not check: HTTP <n>` for a good key, update its entry in `sources` in
   `internal/keycheck/keycheck.go`.
10. Look into three flaky tests, none touched by this change, each seen failing once under load:
    `go test ./internal/iplookup/ -run TestActive_NoHostnameUsesTheAddress -count=50` and
    `go test ./internal/cli/ -run TestCVE_Pacing -count=50`. The third, keycheck's network-error
    test, now drops the connection instead of closing the port; recheck it with
    `go test ./internal/keycheck/ -run TestCheck_NetworkError -count=200`.
