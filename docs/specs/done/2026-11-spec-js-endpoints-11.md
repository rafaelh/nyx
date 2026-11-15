# Spec 11: JavaScript endpoint extraction

## Goal

The API hostnames and paths referenced inside an in-scope site's own JavaScript are recorded as
URLs and hostnames, so the services behind a single-page application are discovered. Nothing found
inside a script is ever requested.

## Behaviours

1. The crawl records which URLs it saw in a `<script src>` element. A `jsparse` stage (target
   contact, skipped under `--passive` and until authorisation) performs one check per such URL
   whose host is in scope, not excluded, not wildcard-only and not served by a SaaS platform.
   Scripts on any other host, CDNs included, are not fetched. The check is one GET of the script
   URL; a redirect is followed only to the same in-scope host; a non-2xx response completes with
   nothing; a timeout is a transient failure.
2. At most `jsparse.max_scripts` (default 50) scripts are fetched per script origin, in URL order;
   the rest are not fetched and a `--verbose` warning says how many were skipped.
3. From the script body nyx records, in `urls.csv` with `found_by` including `jsparse` and no
   status: absolute URLs and protocol-relative references whose host is under an in-scope root;
   and quoted paths beginning with `/`, at least two characters long, without whitespace,
   backslashes or template placeholders (`${`, `{{`), joined to the script's own origin.
   Hostnames under an in-scope root are recorded as hostnames. Hostnames outside scope are
   ignored, as the crawl does. Examples: `/api/v1/users` and `//api.example.com/v2` are recorded;
   `/.js`, `/\d+/g`, `/ ` and `//comment` are not.
4. At most 500 URLs are recorded per script, in order of appearance; reaching the cap produces a
   `--verbose` warning.
5. A response with a `text/html` content type or a body starting with `<` completes with nothing.
   Scripts are read up to 4 MiB (larger than the usual target-response limit, because bundles are
   large); a longer body completes with the URLs found in the part read and a `--verbose` warning
   that it was truncated. The README states the limit.
6. No stage requests a URL recorded from a script. The README's passive-boundary list of requested
   paths adds "same-site script files referenced by crawled pages" and says the URLs found in them
   are recorded, never requested.
7. When a re-crawl no longer references a script, the URLs found only in that script are marked
   not current.
8. Existing engagements gain script records only when the crawl runs again (`--redo crawl`); the
   README says so.

# Design

**Status:** ready to build (wave 2). Spec 1 has merged, and the design was re-checked against
the built specs on 2026-11-14 with no correction. **Depends on:** Spec 1 (`run.Warnf`). **Shares
with Spec 13:** `crawl.go` (each adds one emit in `observations()`); nothing in the probe.

## Decisions

- **Scripts are a kind**, `script` (key: the normalised script URL; `url`, `host`, `service`),
  shown while its host is in scope. The crawl emits one for every `script[src]` it sees, in
  addition to the `url` record it writes today. The crawl's check key does not change, so existing
  engagements gain scripts only when the crawl runs again.
- **`jsparse`** (`internal/stages/web/jsparse.go`, target contact) yields one check per `script`
  whose host is a probe hostname (in scope, resolved, not wildcard-only), not excluded and not
  `SaaSServed`. Per script origin it takes the first `jsparse.max_scripts` (default 50, minimum 1)
  and warns from `Checks` about the rest. Scripts already parsed are taken first, then others in
  URL order: each completed check also emits a `script_parsed` marker (key: the URL), so a script
  that was fetched is never pushed past the cap, and so never retired, by a new script that sorts
  before it. Key: `<url>|p=<parser hash>`. The stage is
  `Retiring`, so when a re-crawl stops referencing a script its check is retired and the URLs only
  it observed go not current (behaviour 7), and a parser change re-reads scripts.
- **Egress cannot be asked for an arbitrary path.** A new constructor `egress.Script(url)` builds
  a request that the policy allows only if the URL is in `Policy.Scripts`, a set the runner builds
  from current `script` records, exactly as sensitive paths are allowed by list index. Host scope,
  exclusion and port rules apply as for any target request. Script responses are read up to
  4 MiB; `Response.Truncated` is set when the cap cut the body.
- **Redirects**: `egress.Redirect` is used only when the target is on the same host; anything else
  completes with nothing. Non-2xx completes with nothing; a timeout is a transient error.
- **Extraction is pure**: `web.ExtractEndpoints(body, origin)` returns candidate URLs in order of
  appearance from string literals: absolute `http(s)://` URLs, `//host/path` references, and
  quoted paths starting with `/` that are at least two characters with no whitespace, backslash,
  `${` or `{{`, and whose first segment is not empty and not just an extension. The stage keeps
  those whose host is in scope, records at most 500 as `url` observations without a status, and
  records their hosts as `hostname` observations. `text/html` or a body starting with `<` yields
  nothing.
- **Nothing recorded here is requested**: the crawl queues only links from pages it fetched, and
  `egress.Script` accepts only crawl-recorded script URLs.

## Changes

- `internal/kinds/script.go` (`script`, `script_parsed`). `internal/stages/web/crawl.go`: emit `script`.
- `internal/stages/web/jsparse.go`, `endpoints.go`. `internal/cli/cli.go`: after `crawl`.
- `internal/egress/http.go`, `egress.go`: `Script`, `Policy.Scripts`, the 4 MiB cap, `Truncated`.
- `internal/run/runner.go`: `script` in `scopeKinds`; `Policy.Scripts` in `buildScope`.
- `internal/config/config.go`: `jsparse.max_scripts`. `README.md`: boundary list, limit, stage.

## Tests

- `internal/stages/web`: the extraction table, including every example in behaviour 3, the 500
  cap and template placeholders.
- `internal/egress`: `Script` is refused for a URL not in the policy set, a candidate host, an
  excluded host and under `--passive`; the 4 MiB cap and `Truncated`.
- `internal/cli/jsparse_test.go`: same-host scripts are fetched once, CDN and SaaS-hosted ones
  never; the per-origin cap and its warning; a parsed script stays within the cap, and its URLs stay
  current, when new scripts sort before it; URLs appear in `urls.csv` with `found_by` including
  `jsparse` and no status; in-scope hosts become hostnames; an HTML answer and a non-2xx record
  nothing; a truncated bundle records what was read and warns; a script dropped by a re-crawl
  retires its URLs; **canary:** no URL found in a script is ever requested.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **`Evidencer` (Spec 15).** A stage whose check key carries a setting and which can find
  candidates must implement it. This key carries the parser hash, but the stage records only
  names under an in-scope root, so it finds no candidate and needs none. If that ever changes,
  it must implement `Evidencer` and drop the hash from the item.
- **The check key does not carry the scope (Specs 2 and 3)**, as for `shodan-dns` and `dnsroot`.
  A URL or hostname under a root the user adds later was ignored when its script was read, so it
  is recorded only after `--redo jsparse`. The README says so beside the `--redo crawl` note.
- **Merge order (build-order plan).** Spec 21 moves the scope and inventory construction to
  `run.BuildScope`. If it has merged, `script` joins the kinds that function reads and
  `Policy.Scripts` is built beside it, not in `runner.go`.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.
- **Console text (Spec 22).** If Spec 22 has merged, the `--verbose` warnings of behaviours 2, 4
  and 5 are WARN lines, shown without a flag.

## Out of scope

Source maps, inline scripts, executing JavaScript, secrets detection.

# Implementation

## Develop

Built as designed. `script` and `script_parsed` are in `internal/kinds/script.go`. The crawl emits a
`script` for every `<script src>` of a page it fetched (`crawler.scriptRef`, bounded like the URLs
by `urlsPerPage` times the page limit). `egress.Script(url)` builds a request with its own body cap;
`do` refuses it unless the URL is in `Policy.Scripts`, then applies the ordinary host, exclusion,
port, passive and authorisation rules. `Response.Truncated` is set by reading one byte past the cap,
for every target request, so an ordinary 1 MiB cut is now reported too. A redirect built with
`egress.Redirect` from a script response keeps the 4 MiB cap. The runner builds `Policy.Scripts` from
the current script records (`Runner.setScripts`). Simplify took `script` out of `scopeKinds`, which
the design had asked for, because neither `BuildScope` nor the candidate ranking reads it: when only
scripts change, `buildScope` copies the last policy with a fresh `Scripts`. `BuildScope` itself is
unchanged: the policy is still built in the runner.

`web.ExtractEndpoints` (`endpoints.go`) is one regular expression over the body: an absolute
`http(s)://` URL anywhere in the text, or a whole quoted literal that starts with `/`. A literal is
matched by its own quotes, so an apostrophe in a comment cannot desynchronise it. `jsparse.go` has
the stage: `Checks` takes the per-origin cap (scripts with a `script_parsed` marker first), warns
with `View.Warn`, and keys each check `<url>|p=<parser hash>` (the hash covers the pattern, both
caps and a `parserVersion` constant); `Run` follows a same-host redirect (stopping at a repeat or
after `maxHops`), completes with nothing for a non-2xx, a refusal, a redirect elsewhere and HTML,
and fails the check on a timeout. Every completed check emits the `script_parsed` marker.
`jsparse.max_scripts` is the setting (`--jsparse-max-scripts`, default 50, at least 1).

Behaviours and their tests (`internal/cli/jsparse_test.go` unless named):

1. Fetch rules: `FetchesSameHostScriptsOnce`, `NeverFetchesCDNOrSaaSScripts` (CDN, SaaS, excluded and
   an unknown IP literal), `RedirectsAndFailures` (same-host redirect followed, cross-host not, 404
   and 500 complete and are not repeated, a timeout fails and is retried, a loop ends),
   `NotUnderPassive`, and in `internal/egress/script_test.go` the refusals: a URL not listed, a
   candidate host, an excluded host, a passive run, no authorisation.
2. Cap: `PerOriginCapAndWarning` (per origin, URL order, the count in the warning),
   `DefaultCapIsFifty` (50, and 0 exits 2), `ParsedScriptStaysWithinTheCap`, and the setting row in
   `internal/config/lists_test.go`.
3. Extraction: the table in `internal/stages/web/endpoints_test.go` (every example of the
   behaviour, placeholders, extensions, quotes, order and repeats) and `RecordsURLsAndHostnames`.
4. 500 cap: `URLCap` (the first 500 in order, one warning naming that script only).
5. HTML and 4 MiB: `HTMLAnswerRecordsNothing`, `TruncatedBundle`, and `TestScript_BodyCapAndTruncated`
   (just under, exactly, one over and far over the cap; the ordinary cap still 1 MiB).
6. Never requested: `CanaryNothingFoundInAScriptIsRequested` (three runs, a `--redo jsparse` and a
   `--redo crawl`; every site's request log is checked, as are the harness canaries).
7. `ReCrawlThatDropsAScriptRetiresItsURLs` (a URL only the dropped script found goes not current, one
   a kept script also found stays current).
8. README only: the passive-boundary bullet, a JavaScript endpoints section, the setting, the
   `--redo crawl` and `--redo jsparse` notes and the `urls.csv` row.

Also changed for the new stage: the registry-order test (`jsparse` after `crawl`, a target stage),
`TestSkip_NoPromptWhenEveryTargetStageIsSkipped` (`jsparse` is a target stage, so it must be skipped
too), and `TestCrawl_FetchesAndRecords` (`/app.js` is now fetched once, by `jsparse`). The two
crawl-limit tests pass `--skip jsparse` so that they stay about the crawl's own requests.

Deviations from the design:

- A script whose host is an in-scope IP literal is fetched too, not only a probe hostname. The
  behaviour says "in scope, not excluded", and `sensitive-paths` also covers IP-literal services.
- The extractor drops any candidate with `${` or `{{`, absolute URLs included, where the behaviour
  names only quoted paths. It also drops a host with no dot that is not an address (`//comment`).
- "Just an extension" is a first segment matching `^\.[A-Za-z0-9]+$`, so `/.well-known/...` is kept.
- `Truncated` is set for every target request, not only scripts.
- The 500-URL warning is given when URLs were left out, not at exactly 500.
- Scripts are joined to the origin of the final response, after a same-host redirect.

Mutation checks (the spec marks none, so these are the safety-critical behaviours; each edit was made
by hand, the named test failed, and the edit was undone by hand):

- The `Policy.Scripts` check removed in `egress`: `TestScript_AllowedOnlyForAListedURL` fails.
- The same-host test of a redirect removed: `TestJSParse_RedirectsAndFailures` fails.
- `Retiring` taken off the stage: `TestJSParse_ReCrawlThatDropsAScriptRetiresItsURLs` fails.
- The HTML guard removed: `TestJSParse_HTMLAnswerRecordsNothing` fails.
- The truncation warning removed: `TestJSParse_TruncatedBundle` fails.
- Parsed scripts no longer taken first: `TestJSParse_ParsedScriptStaysWithinTheCap` fails.
- The cap applied to all scripts instead of per origin: `TestJSParse_PerOriginCapAndWarning` fails.

Tests that already passed against the stubs, so pinned existing behaviour: the registry order (the
stub was registered) and `TestJSParse_NotUnderPassive` (the stub did nothing). The canary passed too
until the stage fetched scripts; it has force only since then, and the first mutation above is what
it and the egress test stand against.

External facts: none were listed, and none turned out different.

## Known limitations

- Behaviour 3: a URL written with escaped slashes (`"https:\/\/api.example.com\/v1"`, as in JSON
  inside a script) is not recognised, because a backslash ends a candidate. A literal split across
  concatenation (`"/api/" + id`) records only its first part. A single-brace template
  (`"/users/{id}"`) is recorded as the encoded path, since only `${` and `{{` are filtered.
- Behaviour 3: an absolute URL with a template placeholder is dropped, so its host is not recorded
  as a hostname either, even when the placeholder is only in the path.
- Behaviour 3: absolute URLs are found anywhere in the text, comments included, not only inside string
  literals.
- Behaviour 1: the scope a check uses is the one at the time the check is made, so a root added later
  is applied to scripts already read only after `--redo jsparse` (the README says so).
- Behaviour 7: a re-crawl retires a script's URLs only when the crawl runs again. Scripts of an
  engagement crawled before this stage existed are found only after `--redo crawl` (behaviour 8).

## Simplify

Fixed:

- `kinds.Script` is no longer in `scopeKinds`, so the Develop note above about that no longer holds.
  `BuildScope` never read it, and having it there rebuilt the whole scope and re-ranked candidates
  whenever the crawl saw a script. `buildScope` now tracks the script `KindVersion` on its own. When
  only scripts have changed, it copies the last policy with new `Scripts` (`Runner.setScripts`).
- `egress`:
  - `Script` and `resolveFrom` share `targetOf`: the userinfo refusal and the default port are
    defined once.
  - The body cap comes from `target.bodyCap()`.
  - Stale comments are fixed: the `(stub)` on `Truncated`, the 1 MiB note on `Body`, the
    `MaxTargetBody` doc, and the read-error comment.
- `jsparse`:
  - The per-origin cap splits URLs into read and unread in one pass. Before, it cloned, sorted
    stably, then sorted again. It also yields inside the origin loop.
  - `scriptInput` no longer carries a host that can be derived from the URL.
  - `fetchScript` returns unnamed results and drops a redundant redirect-target check.
  - The `maxHops` doc now names all three stages that use it.
- `ExtractEndpoints` joins quoted paths and `//host` references with the package's `resolve`, not
  by hand.
- The crawl resolves each `<script src>` or asset reference once, for both `storageRef` and
  `scriptRef`. It keeps scripts in one set, emitted sorted, instead of a set and a list.
- Tests:
  - `warnings()` reuses `messages`.
  - An `== false` check is folded into the preceding condition.
  - A wrapper closure that added nothing is removed.

Skipped:

- Replacing the `script_parsed` marker with a `View` method over completed check keys. The design
  chose the marker, and the change would widen `View`.
- A `View` method shared by probe and jsparse for which hosts a web stage may fetch, and one helper
  for the three redirect loops (probe, crawl, jsparse). Both are follow-ups that touch stages
  outside this change.
- Dropping `ScriptAttrs.URL` and `Service`. They match how the other kinds are shaped (`URLAttrs`
  also repeats its key).
- Switching `sensitive-paths`' `bodySize` to `Response.Truncated`. It is outside this change and
  would alter how a body of exactly 1 MiB is reported.
- Efficiency:
  - A literal prefilter in front of the endpoint regular expression (about 155 ms against 18 ms for
    a 4 MiB bundle). Network time dominates, and it would add a second matching path.
  - Preallocating the body buffer from `Content-Length`.
  - Memoising host parsing per match. All are minor.
- Removing the one-use `plural` helper and the single `MaxScriptBody` alias (it follows the
  `MaxTargetBody` pattern). Deduplicating the two tests that serve a changing root page.
- Deleting `TestExtractEndpoints_SpecificationExamples`. It deliberately pins the specification's
  own examples in one place.

# Verification

## Result

Checked against the code on 2026-11-15. `make test` passes (vet for the four targets, then
`go test -race ./...`). `golangci-lint` could not run: the installed binary was built with Go 1.26
and the module targets Go 1.27.3.

- **Goal: met.** Scripts a crawled page loads from an in-scope host are read once each, and the
  URLs and hostnames under an in-scope root that they name are recorded. Egress can request a
  script only by a URL the crawl recorded (`Policy.Scripts`, checked in `targetHTTP.do` after the
  passive and authorisation refusals and before the host rules), and no stage reads `url` records
  to request them: `output` is their only reader. A hostname a script names is resolved and
  probed at `/` like any other in-scope hostname; that is the ordinary handling of an in-scope
  name, not a request for a URL found in the script.
- **B1: met.** The crawl emits a `script` for every `<script src>` on a fetched page, on any host.
  `jsparse` is a `Target` stage (gated by `--passive` and authorisation before `Checks` is called),
  and yields one check per script whose host is a probe hostname (in scope, resolved, not
  excluded, not wildcard-only) or an in-scope, non-excluded IP literal, and not `SaaSServed`. The
  IP-literal case is a reading the behaviour's wording supports. One `egress.Script` GET; a
  redirect is followed only when its target has the same host (and egress still applies the host
  policy); non-2xx, a refusal and a redirect elsewhere complete with nothing; a timeout fails the
  check, which is retried. Other connection failures (refused, DNS) complete with nothing, which
  the behaviour does not address.
- **B2: met.** Per origin, the first `jsparse.max_scripts` (default 50, at least 1; flag, config
  key and env) in URL order, with scripts already read kept first so a re-crawl never pushes them
  out. The warning (a WARN line, since Spec 22 has merged) names the count, the origin and the
  setting, once per run.
- **B3: met** (after the change below). Absolute and protocol-relative URLs, and quoted paths with
  the stated rules, joined to the script's origin; filtered with `Scope.WebHostInScope`, the
  crawl's own test; recorded in `urls.csv` with `jsparse` in `found_by` and no status; in-scope
  hosts other than the script's own recorded as hostnames. Every example in the behaviour is
  pinned. Readings: absolute URLs are found anywhere in the text, comments included (the behaviour
  does not limit them to literals); a single-brace template (`/users/{id}`) is recorded, since
  only `${` and `{{` are named; a literal split by `+` records its first part.
- **B4: met, with one reading.** At most 500 in-scope URLs per script, in order of appearance. The
  warning is given when URLs were left out, not when exactly 500 were found and none dropped.
- **B5: met.** `text/html` (parameters ignored) or a body whose first character after a byte order
  mark and whitespace is `<` completes with nothing. Script bodies are read to 4 MiB
  (`egress.MaxScriptBody`, kept across a redirect); `Response.Truncated` drives the WARN line, and
  what was read is still parsed. The README states the limit.
- **B6: met.** The passive-boundary bullet has the required wording; the canary test runs three
  times (with `--redo jsparse` and `--redo crawl`) and checks every site and the harness canaries.
- **B7: met.** The stage is `Retiring`; a re-crawl that drops a script retires its check and the
  URLs only it found go not current, while one another script also found stays current.
- **B8: met.** The README says existing engagements gain script records only after
  `--redo crawl`, and that a root added later reaches scripts already read only after
  `--redo jsparse`.

Changed while verifying:

- **Escaped absolute URLs (B3).** `"https:\/\/api.example.com\/v1"` (JSON inside a script) was not
  recognised, so neither its URL nor its hostname was recorded. The pattern now also matches an
  absolute URL with escaped slashes and unescapes it. Escaped quoted paths are still left out, as
  the behaviour excludes backslashes there.
- **Absolute URLs with a template placeholder (B3).** These were dropped whole, so their in-scope
  hostname was lost although the behaviour asks for every hostname under an in-scope root, and the
  behaviour applies the placeholder rule only to quoted paths. Such a URL is now cut at its first
  placeholder (`https://api.example.com/v1/${id}` gives `https://api.example.com/v1/`), which is
  what the extractor already records for the same URL written as `"…/v1/" + id`; a placeholder in
  the host still drops it. Both changes alter the pattern, so the parser hash changes and existing
  engagements read their scripts again on the next run (the design's intended effect of a parser
  change). The first two items of `## Known limitations` no longer hold for absolute URLs.
- Tests: the extraction table gains both cases and a placeholder-in-host case;
  `TestJSParse_RecordsURLsAndHostnames` checks the URL and hostname of each. README: one sentence
  in the JavaScript endpoints section.

## Code review

`/code-review high --fix` reported nine findings and applied four. I kept three and undid one by
hand. `make test` passes afterwards.

Kept:

- **`JSParse.MaxScripts` comment (B2).** It said a script already read keeps its place when the
  cap is lowered. Lowering the cap below the number already read retires those past it, in URL
  order, and the comment now says so. Comment only.
- **`Evidencer` on `jsparse` (none of the behaviours).** The check key carries the parser hash,
  so per `CLAUDE.md` the stage now names (`jsparse`, the script URL without the hash) as the
  evidence for a candidate. The stage records only in-scope names, so this matters only if one
  later becomes a candidate; no behaviour changes.
- **Crawl refactor (B1).** `crawler.scan` resolves a reference with one `absolute` closure for
  both links and asset references; no behaviour changes.

Undone by hand:

- **`sensitive-paths` `bodySize` switched to `Response.Truncated`.** It changes how a body of
  exactly 1 MiB is reported (`1048576` instead of `1048576+`), which this spec does not ask for,
  in a stage outside it. Left for a person (see Follow-ups).

Left unfixed:

- **A quoted literal can start at a closing quote followed by `/`** (`a""/x"`), and `"/*"` is
  recorded. `"/*"` fits B3's rule as written; the other case needs JavaScript that is unusual or
  not valid, and fixing it means tracking string state across the whole bundle.
- **A refusal or a non-timeout connection failure completes the check.** A script on a port not in
  `ports` is refused and not read again when the port is added later, until `--redo jsparse`. B1
  names only the timeout as transient, and the README documents this outcome; it is a decision
  for the user (see Follow-ups).
- **The runner's script-only policy refresh** could be folded into the scope signature. The
  Simplify pass chose the separate path so that a new script does not rebuild the scope and
  re-rank candidates.
- **`ScriptAttrs.URL` and `Service` are unread, and `script.go` holds two kinds.** The design names
  both attributes and the file; `script_parsed` exists only to serve `script`.

# Follow-ups

1. Run `jsparse` once against a real single-page application you are authorised to test, to check
   the extraction on a real minified bundle (the tests use hand-written scripts):
   `nyx --authorised --output-dir /tmp/nyx-out <a domain you are authorised for>`, then look for
   `jsparse` in the `found_by` column of `/tmp/nyx-out/<engagement>/urls.csv` and for bogus rows
   (for example `/*` or fragments of regular expressions).
2. Decide whether a refused script (a port not in `ports`) or a connection failure other than a
   timeout should be retried rather than completed. Today it completes with nothing and is read
   only after `--redo jsparse`. The outcome is chosen in `fetchScript` in
   `internal/stages/web/jsparse.go`; returning an error there instead would retry it every run.
3. Decide whether the 500-URL warning should also be given when a script names exactly 500 URLs in
   scope and none are dropped (B4 says "reaching the cap"). It is given only when URLs were left
   out; the test is `more` in `JSParse.Run` in `internal/stages/web/jsparse.go`.
4. Decide whether `sensitive-paths` should use `Response.Truncated` to tell a cut body from one of
   exactly 1 MiB: change `bodySize` in `internal/stages/risk/sensitive.go` to test `r.Truncated`
   (a body of exactly 1 MiB would then be reported as `1048576`, not `1048576+`).
5. Rebuild golangci-lint with the module's Go version (`go install
   github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`), then run
   `golangci-lint run --new-from-rev=main ./...`. It could not run during verification.
