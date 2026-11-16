# Spec 17: GitHub code search for mentions of in-scope roots

## Goal

Public repositories that mention an in-scope root domain are recorded as locations, and hostnames
in the matched code become hostname observations, so forgotten internal hostnames surface.

## Behaviours

1. A `github` stage, keyed on `keys.github` and available under `--passive`, performs one code
   search per in-scope input root for the quoted root domain, reading results up to
   `github.max_results` (default 500; GitHub serves at most 1,000). A root's search completes
   once; new mentions appear only with `--redo github` or when the cap changes. Roots added to
   scope later are searched in later passes.
2. Each match is a row in `code-mentions.csv`: repository, file path and the match's URL, all
   sanitised, plus the hostnames found in the returned fragment that are under an in-scope root.
   Those hostnames are recorded as hostnames. No fragment text is written. Personal-account
   repositories are recorded like any other; the README says so.
3. Nothing is inferred about secrets, credentials or tokens, and no finding is produced. The
   README says the stage queries GitHub about the domain, not the target, and records only
   locations.
4. When GitHub's rate limit resets within 60 seconds, the stage waits and continues; an interrupt
   during the wait exits 130 promptly with completed roots kept. Otherwise, and on a 401 or any
   other 403 or 429, the stage stops for this run as for other keyed sources. Keys never appear in
   output.
5. Rows whose match is gone after `--redo github` are marked not current. The README adds
   `github` to the keyed-sources list, the passive-boundary list of third parties and the output
   table; without a key the stage is `not-configured (no key)`.

# Design

**Status:** ready to build (wave 2). Spec 1 has merged, and the design was re-checked against
the built specs on 2026-11-14 with no correction. **Depends on:** Spec 1 (`KeyPrefix`, `Accept`,
`Warnf`, `CleanName`).

## Decisions

- **One stage, `github`**, in `internal/stages/github`, keyed, source `api.github.com`. One check
  per in-scope input root, keyed `<root>|max=<n>`, so changing `github.max_results` (default 500,
  minimum 1, maximum 1,000) searches again.
- **Request**: `GET /search/code?q="<root>"&per_page=100&page=<n>` with
  `Authorization: Bearer <key>` and `Accept: application/vnd.github.text-match+json`, which is
  what makes GitHub return fragments. Pages are read until the cap, the total, or an empty page.
- **Rate limits are handled in the stage**, so it calls `ThirdParty.Do` and reads the headers
  itself instead of `httpsrc.Get`: on a 403 or 429 with `retry-after`, or with
  `x-ratelimit-remaining: 0` and `x-ratelimit-reset`, it computes the wait; 60 seconds or less
  means wait on a timer that also selects on the context (an interrupt returns at once and the
  check is simply not completed) and retry the same page; anything else, and any 401, returns
  `run.ErrAbortStage`. A root already completed is kept either way.
- **Records**: kind `code_mention`, keyed by the match's `html_url`, with `root`, `repository`,
  `path`, `url`, `hostnames` (`;`-joined), shown while `root` is in scope and counted as
  `code mentions`. Hostnames are extracted from `text_matches[].fragment` with a hostname
  pattern, cleaned, and kept when under an in-scope root (the check input carries the scope);
  each is also a `hostname` observation. The fragment itself is never stored.
- **`code-mentions.csv`**: `repository`, `path`, `url`, `hostnames`, `root`. Because a redo
  replaces the check's observations, a match that is gone goes not current.

## Changes

- `internal/stages/github/`. `internal/cli/cli.go`: registered after the subdomain sources.
- `internal/kinds/codemention.go`. `internal/output/codementions.go`; one line in `Default()`.
- `internal/config/config.go`: `github.max_results`. `README.md`: keyed sources, boundary list,
  output table, the statement of what is and is not recorded.

## Tests

`internal/cli/github_test.go`, with a loopback fake:

- No key: `not-configured (no key)`. With one: rows for each match, hostnames under an in-scope
  root recorded and resolved, other hostnames ignored, no fragment text in any file or the
  database.
- The cap stops paging; changing it searches again; a completed root is not searched again; a
  root added later is searched.
- A reset within 60 seconds waits and continues; an interrupt during the wait exits 130 with the
  completed roots kept; a longer reset, a 401 and a plain 403 stop the stage.
- `--redo github` marks vanished matches not current; the key appears nowhere; `--passive` runs
  the stage; nothing becomes a finding.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Failures every source shares (Spec 1).** The stage calls `ThirdParty.Do` itself, so it does
  not get `httpsrc.Get`'s mapping. It must repeat the two parts that still apply: a truncated
  body is a transient error, and any status other than 200 that the rate-limit rule does not
  handle is one too.
- **Paged sources (Spec 2, follow-up 3).** Cert Spotter, Censys and `shodan-dns` each hand-roll
  their page cap and truncation warning, with two rules between them. The behaviours here ask
  for no truncation warning. If one is added, use the rule Censys and `shodan-dns` share (warn
  only when the source reports more than was read) and do not add a third.
- **In-scope input roots (Spec 1, follow-up 4).** Several stages already walk `v.Inputs().Roots`
  and keep the in-scope ones. Add `View.InScopeRoots()` (the in-scope input roots, sorted) in
  `internal/run/stage.go` and use it here. The existing loops move to it in one later change,
  because Specs 9, 16 and 19 are editing three of those files.
- **`Evidencer` (Spec 15).** The key carries `max=`, but the stage records only names under an
  in-scope root, so it finds no candidate and needs none.
- **The check key does not carry the scope (Specs 2 and 3)**, as for `shodan-dns` and `dnsroot`.
  A hostname in a fragment that is under another root the user adds later was ignored, so it is
  recorded only after `--redo github`. The README says so.
- **A record that is no longer current has no attributes (Spec 3, follow-up 1).** The key is the
  match's URL, so a `code-mentions.csv` row whose match is gone shows `url` and blank
  `repository`, `path`, `hostnames` and `root`. The URL names the repository and the path, so
  that is accepted; do not add a key-parsing fallback. The README says a not-current row keeps
  only its URL.
- **Hostname cleaning (Spec 1).** `httpsrc.CleanName` strips `*.` before it validates. The
  hostname helpers are merged in one change after Specs 4, 10, 13 and 17.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.

## Out of scope

Secrets detection; cloning or reading file contents; GitLab and paste sites.

# Implementation

## Develop

Built as the design had it: `internal/stages/github` (one check per in-scope root, keyed
`<root>|max=<n>`), `kinds.CodeMention` (`internal/kinds/codemention.go`, `HostAttr: "root"`,
counted as `code mentions`), `internal/output/codementions.go` (one line in `Default()`),
`github.max_results` (`--github-max-results`, default 500, 1 to 1,000: the upper bound is a check
after `posInt`), `View.InScopeRoots()` in `internal/run/stage.go`, the stage registered after
`chaos` and before `shodan`, and the README (keyed sources, the boundary list, the output table, a
new "GitHub code search" section). The stage calls `ThirdParty.Do` itself. A 401, or a 403 or 429
that has no `Retry-After` and no `X-RateLimit-Remaining: 0` with a reset, or whose wait is over 60
seconds, wraps `run.ErrAbortStage`. A shorter wait is a timer that also selects on the context, and
the same page is asked again. Any other status, a truncated body, and a body that is not JSON or has
no `items` are transient errors, as `httpsrc.Get` would map them.

Tests are in `internal/cli/github_test.go`, with a loopback `api.github.com` added to the world's
source list. They pin: no key; the request shape (quoted root, `per_page=100`, bearer key, the
text-match `Accept`, in-scope roots only and in sorted order); rows, hostnames recorded and resolved,
other names ignored, no fragment text in any file or the database, no finding, `--passive`; the
sanitising of repository and path; the cap, the total and an empty page ending paging; the cap being
part of the check; a completed root, a root added later and `--redo github`; vanished matches going
not current with only the URL kept; a mention hidden once its root is excluded; waits for
`Retry-After` and `X-RateLimit-Reset` on a 403 and a 429, retrying the same page; an interrupt during
the wait (exit 130, completed roots kept, the next run asks only the waiting root); eight kinds of
stop (reset over 60 seconds, 401, plain 403, a 403 with quota left, plain 429, and so on), each
keeping the completed root and not asking the rest; four transient failures; the key appearing
nowhere; the registry order, help and `--skip`; and the README. Existing tests that list every
output file and every summary category were updated for the new file and category.

Choices the design left open:

- A hostname equal to an in-scope input root is not listed in a row's `hostnames` or recorded:
  every match mentions the root it was searched for, and `admin@example.com` would otherwise put it
  in every row. Subdomains are kept.
- Hostnames are found by splitting the fragment into runs of `[A-Za-z0-9_*.-]`, cleaning each with
  `httpsrc.CleanName` and keeping those the scope classifies as in scope. Underscores are part of a
  run, so `a_b.example.com` is skipped and not read as `b.example.com`.
- A wait is at least one second, and one page is waited for at most five times in a row; after that
  the stage stops, so a limit that never lifts cannot loop.
- A not-current row is listed without asking the showing rule, since it has no `root` attribute and
  its key's host is `github.com`, which would hide it.
- A stage is `failed` only when every check failed, so a stop partway shows as `done` with a failed
  count, and a WARN line says how many checks will be retried. The tests assert the count.
- The `Retry-After` and `X-RateLimit-*` header names are matched without regard to case, through
  `egress.ThirdPartyResponse.HeaderValue`.

Mutation checks: `## Tests` marks none, so three guards were broken by hand and restored by hand.
Removing the 60-second limit made `TestGitHub_StopsTheStage` hang until the test timeout (it really
waited an hour), which detects the break but not on an assertion. Letting candidates through the
in-scope check on hostnames failed `TestGitHub_RowsHostnamesAndNoFragmentText`. Not stopping on a
401 failed `TestGitHub_StopsTheStage`.

## Known limitations

- Behaviour 2: a file that mentions two in-scope roots is one record (the key is its URL), so its
  row shows the `root` and `hostnames` of the search that was merged last. If that root is later
  excluded while the other stays in scope, the row is hidden. Hostnames are recorded either way.
- Behaviour 4: a wait of exactly 60 seconds is not tested (the tests wait one second and
  refuse 61 seconds and an hour). A wait from `X-RateLimit-Reset` uses the local clock.
- Behaviour 1: GitHub's own limit is that a search returns at most 1,000 results, and no warning is
  written when a root has more than `github.max_results`, as the behaviours ask for none.
- The request and the response shape were written from GitHub's documentation and a fake; no real
  token was used, so GitHub's secondary rate limits and the live `text_matches` shape are untested.
- `golangci-lint` could not run (the installed v1 is built with an older Go than the module); gofmt
  and `go vet` for all four targets pass.

## Simplify

Four reviewers (reuse, simplification, efficiency, altitude) went over every changed file. `make test`
passes after the fixes.

Fixed:

- README: the passive-boundary sentence had two phrases pasted twice. It is now the original
  sentence with "GitHub's code search" added once. The Limits bullet no longer repeats that the key is
  never written (the API keys bullet already says it), and the keyed-sources line is rewrapped.
- The stage's own case-insensitive `header()` loop is gone. `egress.ThirdPartyResponse` gains
  `HeaderValue`, matching `egress.Response.HeaderValue`, and `resetWait` takes the response.
- `searchResult.Items` is a plain slice, not a pointer (nil still means no `items`). `culprit` is
  renamed `match`. The cap is applied once per page, by slicing the page to `max - read`, instead of
  a counter checked in both loops.
- `CodeMentionAttrs.URL` is removed: it repeated the record key, which is what the CSV writes. No
  release has used the attribute, so nothing breaks on resume.
- `hostnames` skips tokens with no dot before parsing them, and builds its result with
  `slices.Sorted(maps.Keys(...))`.
- `View.InScopeRoots` no longer runs `slices.Compact`, since input roots are already unique.
  `maxGitHubResults` is unexported (only `config` uses it).
- Tests: one `ghRefuse` helper replaces the three hand-written "set headers, then `http.Error`"
  handlers. `ghLeaks` is replaced by the shared `leaks` (github's key is added to its list, so the
  base64 form is checked too). `ghAskedAfter` is inlined. `ghPage` derives a fixture's URL when it is
  empty. A map-literal lookup inside a loop is now a loop over pairs. The `X-RateLimit-Reset` wait
  cases use a reset one second away, so each waits exactly the one-second floor instead of up to
  two seconds.

Skipped:

- Keying a mention by `<root>|<url>` and restoring its root from the key (as `ThirdPartyOf` does) so
  that not-current rows go through the showing rule: this changes behaviour the README states (a
  file that mentions two roots is one row). It is already Follow-up 2.
- Moving the 401, status and truncation mapping into an `httpsrc` variant that hands 403/429 back to
  the caller, and per-source pacing in egress so the stage stays under GitHub's limit instead of
  reacting to it: both change shared infrastructure well beyond this change.
- One worker or a shared "not before" time so that parallel roots stop sending requests that are
  bound to be refused: this changes how the stage waits, so it is a design decision, not a cleanup.
- Cutting the four end-to-end wait subtests to one and unit-testing `resetWait`: the behaviour tests
  pin each header on each status.
- Dropping `input.roots` in favour of `n != in.root`: excluding every in-scope root from `hostnames`
  is a recorded choice above.
- Moving `subdomains`, `shodan-dns`, `email` and `dnsroot` to `View.InScopeRoots`, and folding
  `countOf` with the other summary-total helpers in `internal/cli` tests: both mean editing files
  outside this change.
- The `ghFake` header table as plain values instead of `func() map[string]string`: the functions are
  there so the reset time is read when each subtest starts.
- The upper bound after `posInt`: this is the only setting with a maximum, so it does not yet need a
  helper.

# Verification

## Result

Checked against the code on 2026-11-16. `make test` passes (vet for the four targets, then
`go test -race ./...`). `golangci-lint` could not run: the installed binary was built with Go 1.26
and the module targets Go 1.27.3. The registry order (`github` after `chaos`, before `shodan`) and
the output file's place match `docs/plans/2026-11-build-order.md`.

- **Goal: met.** Each in-scope input root is searched on GitHub with a key, each match is a
  `code_mention` record shown in `code-mentions.csv`, and the in-scope hostnames in the fragments
  are recorded as hostnames and then resolved like any other. Not run against the live API.
- **B1: met** (after the change below). Keyed on `keys.github`, third-party so it runs under
  `--passive`; one check per root from `View.InScopeRoots()`, keyed `<root>|max=<n>`, so a root
  completes once, a new cap searches again, `--redo github` repeats it and a root added later is
  searched (the root list is read on each pass). `github.max_results` is 500 by default and bounded
  to 1 to 1,000 by flag, file and environment.
- **B2: met, with the reading in `## Known limitations`.** One row per match with sanitised
  repository, path and URL, and the `;`-joined hostnames under an in-scope root (the root itself
  left out, a recorded choice); each is a `hostname` observation. No fragment text reaches a file or
  the database (tested). A file mentioning two roots is one row. Personal-account repositories are
  recorded alike, and the README says so.
- **B3: met.** No finding is produced; the stage writes only locations. The README states that the
  stage queries GitHub about the domain, not the target, and records only locations.
- **B4: met, with one guard.** A 403 or 429 with `Retry-After`, or `X-RateLimit-Remaining: 0` and a
  reset, within 60 seconds is waited out on a timer that also watches the context, and the same page
  is asked again; an interrupt exits 130 with completed roots kept (tested). A longer wait, a 401,
  and any other 403 or 429 wrap `run.ErrAbortStage`. The guard: a page refused six times in a row
  stops the stage even if each reset was short. Under GitHub's 10-a-minute search limit and the
  default 10 workers this should not happen; it now appears in the README. Keys appear nowhere
  (tested in all forms, including after waits and stops).
- **B5: met.** After `--redo github` a vanished match is not current and its row keeps only the URL;
  the README adds `github` to the keyed sources, the passive-boundary third parties and the output
  table; without a key the stage is `not-configured (no key)`.

Changed while verifying:

- **Paging past GitHub's 1,000th result (B1).** Paging stopped only at the cap, the total or an
  empty page. GitHub can serve a page shorter than 100 results, so with `github.max_results` near
  1,000 and a large total the stage asked for page 11, which GitHub refuses (422). That was a
  transient error: the root's results were all dropped, and the check failed again on every run.
  Paging now also stops after page 10 (`lastPage` in `internal/stages/github/github.go`). Pinned by
  `TestGitHub_StopsAtGitHubsLastPage`, which fails with the guard removed.
- README: the GitHub "Limits" bullet now says a page is waited for at most five times in a row and
  that reading stops at GitHub's tenth page.

## Code review

`/code-review high --fix` reported ten findings and applied four. I kept all four. `make test` passes
afterwards.

Kept:

- **Escapes next to a name (B2).** A token right after `%XX`, `\xXX`, `\uXXXX`, `\n`, `\r` or `\t`
  kept the escape's tail, so `https%3A%2F%2Fsso.example.com` recorded `2fsso.example.com`, a name
  the text never gave, and it was then resolved. The tail is now dropped (`unescaped` in
  `github.go`); an escaped backslash (`\\files.example.com`) is left as it is. The test of rows and
  hostnames gained a fragment with each form. The original assertions still hold.
- **A file two roots match (B2).** `hostnames` had `omitempty`, so a search that found no names left
  the field out and the store kept the other search's hostnames beside this search's root. The
  stage always writes the field, so it no longer has `omitempty` (the JSON name is unchanged). The
  row now matches the README's "from the root searched last".
- **`Evidence` method.** The check key carries `max=`, and `CLAUDE.md` requires a stage like that to
  implement `run.Evidencer`. The design said the stage needs none, since it records only in-scope
  names. But a name it recorded becomes a candidate if its root is dropped from the inputs later,
  and a changed cap would then count it twice. `Evidence` returns `github` and the root. This
  changes no behaviour in B1 to B5.
- **Build-order doc.** Specs 13 and 17 are struck and marked built, "Ready now" lists only 19 and 14,
  and the built registry paragraph places `github` and `identifier-pivot`.

Left unfixed:

- **`incomplete_results` is not read.** A search GitHub timed out on completes with what it served.
  Retrying or warning would add behaviour the spec does not ask for (no truncation warning, B1).
  Follow-up 2.
- **A 403 with no rate-limit headers stops the stage.** GitHub's documentation says that for a
  secondary limit with no `Retry-After` a client should wait at least a minute. B4 says any other 403
  stops the stage, so this is as specified. Follow-up 1 covers checking it live.
- **Not-current rows skip the showing rule.** This is accepted in the design: such a row has no
  `root`. Already in `# Implementation`.
- **`View.InScopeRoots` is not yet used by the four older loops.** The design defers that to one
  later change, because other specs are editing those files.
- **`search` repeats `httpsrc.get`'s status handling, and the 1,000 ceiling is in both `config` and
  the stage.** The first is the design's decision (the stage reads rate-limit headers itself). The
  second is a small duplication across a package boundary, not worth a shared constant.

# Follow-ups

1. **Run the stage once with a real token** against a domain you own, with an `--output-dir` outside
   the repo: `NYX_KEYS_GITHUB=<token> nyx --passive --github-max-results 1000 --output-dir <dir>
   <domain>`. Check that the `Accept: application/vnd.github.text-match+json` request returns
   `text_matches` with fragments the stage reads, and what GitHub's secondary limit sends (a
   `Retry-After`, or a 403 with no headers, which currently stops the stage) when several roots run
   at once.
2. **Decide whether `incomplete_results: true` should matter.** Today such a search completes with
   what GitHub served and is not repeated without `--redo github`. The options are to warn or to
   leave the check incomplete so it is retried (`search` and `Run` in
   `internal/stages/github/github.go`).
3. **Decide whether a file that mentions two roots should keep both.** A record per root and URL
   would change the key. See Known limitations, behaviour 2.
4. **Run `golangci-lint run --new-from-rev=main ./...`** with a golangci-lint v2 built with Go 1.27.3
   or later (`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`). The
   installed one was built with Go 1.26 and refuses this module, so the linter did not run on this
   change.
