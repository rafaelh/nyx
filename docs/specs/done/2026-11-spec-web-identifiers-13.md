# Spec 13: web identifiers as pivot evidence

## Goal

Tracking IDs, favicon hashes and copyright lines found on in-scope pages are recorded so the user
can pivot to related sites, and with a Shodan key the pivot is done for them.

## Behaviours

1. From pages the probe and crawl fetched, nyx records per web service, as the union over its
   fetched pages: Google Analytics and Tag Manager IDs found in `gtag/js?id=`, `gtag('config',
   …)` or GTM snippet contexts; Facebook pixel IDs found in `fbq('init','<digits>')` or
   `facebook.com/tr?id=`; the first line of the root page's visible text containing `©` or `(c)`
   followed by a year, at most 120 characters, sanitised; and the favicon hash from behaviour 2.
2. The probe fetches one favicon per web service: the same-host `<link rel=icon>` URL if present,
   else `/favicon.ico`; a redirect is followed only to the same host; a 404, HTML or non-image
   response gives no hash; an icon link on another host falls back to `/favicon.ico`. The hash is
   the one Shodan's `http.favicon.hash` uses (signed 32-bit MurmurHash3 of the base64 body with
   line breaks every 76 characters), pinned by a test with a known value. The README adds one
   favicon GET per service to the list of requested paths.
3. `web-services.csv` gains `analytics_ids`, `pixel_ids`, `favicon_hash` and `copyright`.
4. An `identifier-pivot` stage, keyed on `keys.shodan` and available under `--passive`, searches
   Shodan once per distinct analytics ID, pixel ID or favicon hash seen on an in-scope service
   that is not served by a SaaS platform, first result page only, up to
   `identifier_pivot.max_queries` per run (default 50, remainder on later runs). A hostname on a
   returned host is recorded as a hostname when under an in-scope root, otherwise its registrable
   domain is a candidate root whose `sources` entry reads `identifier-pivot:<id>`. Returned
   addresses are classified by the normal scope rules, appear in `ips.csv`, and are never
   contacted when out of scope. A search returning more than 200 hosts records none and produces
   a `--verbose` warning.
5. Favicon hashes on a built-in list of defaults (the empty file and common framework icons,
   listed in the README) are not pivoted. Copyright lines are never pivoted.
6. A key without search access shows the stage failed with one clear warning; exhausted credits
   stop the stage for this run as for other keyed sources. Without a key the identifiers are still
   recorded and the stage is `not-configured (no key)`.
7. Under `--passive` no new identifiers are collected, but the pivot still searches identifiers
   recorded on earlier runs. Existing engagements gain identifiers only after `--redo httpprobe`
   and `--redo crawl`; the README says so.

# Design

**Status:** ready to build (wave 2). Specs 1, 6, 12 and 15 have merged, and the design was
re-checked against them on 2026-11-14: the probe seam is written as Spec 12 built it, the
evidence source now reaches the web identifier family, and a spent Shodan balance stops the
stage. **Depends on:** Spec 1 (`Warnf`, `ErrQuota`, `CleanName`), Spec 6 (`run.Budgeted`),
Spec 15 (candidate evidence), and Spec 12 (the probe's `service()` seam and the `hop` chain).

## Decisions

- **Each identifier is a record**, kind `web_identifier`, keyed `<service>|<type>|<value>` with
  `service`, `host`, `type` (`analytics`, `pixel`, `favicon`, `copyright`) and `value`, shown
  while the host is in scope. One record per identifier makes "the union over fetched pages" the
  store's ordinary behaviour: the probe and the crawl each observe what they saw, and an
  identifier stays current while either still sees it. A single merged attribute would let one
  stage overwrite the other.
- **Extraction is pure**, in `internal/stages/web/identifiers.go`: regular expressions anchored to
  the contexts in behaviour 1, and the copyright line from the root page's visible text. The probe
  calls it on the pages of its redirect chain that came from the service's origin; the crawl on
  each page it scans. Neither check key changes. As built, `service()` in `probe.go` keeps the
  chain as `[]*hop` (`posture.go`): each hop has its `origin` and a lazily parsed `page()`, and
  `chain[0]` is the service's first response. The identifier helper takes that chain, as
  `posture(in.host, chain)` does, and its `web_identifier` observations are appended to the
  `web_service` and `web_posture` ones `service()` returns.
- **Favicon**: the probe makes one extra GET per service through `egress.Link`, which
  enforces same host: against the final page for its `link[rel~=icon]` URL when that page is on
  the service's host, and otherwise (an off-host icon link, or a chain that ended on another host)
  against the service's first response for `/favicon.ico`. "The final page on the service's
  host" is `lastSameOrigin(chain)`, which Spec 12 added. `egress.Link` takes an
  `egress.Response`, and a `hop` does not keep one today, so `hop` gains the response it was
  built from. A redirect is followed once and only to the same host. The hash is computed only
  for a 2xx response whose
  content type is an image type or absent and whose body does not start with `<`.
  `web.FaviconHash` implements MurmurHash3 x86-32 over the base64 body with a newline every 76
  characters (and a trailing newline), returned as a signed 32-bit integer; it is written by hand,
  about thirty lines, to avoid a dependency.
- **`web-services.csv`** gains `analytics_ids`, `pixel_ids`, `favicon_hash`, `copyright`, built by
  grouping current `web_identifier` records by service.
- **`identifier-pivot`** (`internal/stages/shodan/pivot.go`, keyed on `shodan`, third-party
  contact) yields one check per distinct analytics ID, pixel ID or favicon hash on a shown service
  that is not `SaaSServed`, skipping favicon hashes on the built-in default list. Keys:
  `favicon|<hash>` and `html|<id>`. It is `Budgeted` by `identifier_pivot.max_queries` (default
  50, minimum 1): `Budget` returns the setting and each check has `Cost` 1. `Run` requests the
  first result page of `http.favicon.hash:<h>` or `http.html:"<id>"`; a total above 200 records
  nothing and warns. A 401 or 403 (a key without
  search access) and a 429 already abort a keyed stage in `httpsrc.Get`, with one warning. A 402
  (no query credits) does not: `httpsrc.Get` returns it as an ordinary failed check, which
  `shodan` and `shodan-dns` accept. Behaviour 6 asks for the stage to stop, so the pivot calls
  `ThirdParty.Do` for the status, or `httpsrc` gains a variant, and wraps `run.ErrAbortStage` for
  a 402. Otherwise each match's address
  is an `ip` observation, each hostname under an in-scope root a `hostname`, and any other
  hostname's registrable domain a `root`.
- **Evidence**: `Evidencer` returns (`identifier-pivot:<id>`, the identifier), which is what
  puts `identifier-pivot:<id>` in the `sources` column (behaviour 4). As built,
  `candidates.Family` looks a source up by its exact name and the table holds
  `identifier-pivot`, so each `identifier-pivot:<id>` would be a family of its own: two
  identifiers would count as two families and three as `high`. This spec changes `Family` to
  look up the part of a source before its first `:` (no source has one today), so every
  identifier is in the web identifier family. The table entry stays `identifier-pivot`, and the
  README gives the value as `identifier-pivot:<id>`. An analytics ID, a pixel ID and a favicon
  hash hold no `:` or `;`.
- **Under `--passive`** the probe and crawl are gated as today, so nothing new is collected, while
  the pivot (third-party) runs over records kept from earlier runs.

## Changes

- `internal/kinds/webidentifier.go`. `internal/stages/web/identifiers.go`, `favicon.go`; one call
  each in `probe.go` and `crawl.go`; `posture.go`: the response on `hop`.
  `internal/stages/shodan/pivot.go`; registered after `jsparse`.
- `internal/candidates/candidates.go`: `Family` looks up the part before the first `:`.
- `internal/output/output.go`: four columns. `internal/config/config.go`: the setting.
- `README.md`: the favicon GET in the requested-paths list, the default favicon list, columns,
  the unit of the deferred number (searches), and `identifier-pivot:<id>` as a `sources` value
  in place of the reserved `identifier-pivot`.

## Tests

- `internal/stages/web`: extraction contexts (and near-misses that must not match); the copyright
  rule and 120-character cut; `FaviconHash` against a known Shodan value.
- `internal/cli/identifiers_test.go`: union of probe and crawl pages; favicon from the same-host
  link, the `/favicon.ico` fallback, an off-host link, a probe chain that ends on another host, a redirect off host, a 404 and an HTML
  answer; exactly one favicon GET per service.
- Pivot: one search per distinct identifier; SaaS-served services and default favicons are not
  pivoted; copyright never; the per-run cap defers; over 200 hosts records nothing and warns;
  in-scope hostnames and candidate roots with `identifier-pivot:<id>` in `sources`; returned
  addresses appear in `ips.csv` and **(canary)** are never contacted when out of scope; a key
  without search access fails the stage with one warning; a 402 stops the stage and the
  remaining searches run next time; `--passive` pivots stored identifiers and collects none.
- `internal/candidates`: a source with a `:` takes the family of the part before it. A candidate
  root that two identifiers found, and nothing else, has one family: it is `low`, with both
  `identifier-pivot:<id>` values in `sources` and an evidence count of 2.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Family table (Spec 15, follow-up 2).** `identifier-pivot` was reserved in the table for this
  stage. Update the README sentence that lists the reserved names.
- **Budget rules (Spec 6).** The first pending check of a run is always sent, a budget below 1
  counts as 1, and a search that fails still spends its share. The `Deferred to the next run`
  block shows a bare number beside `identifier-pivot`; the README names its unit (searches).
- **Column order (Spec 12).** `web-services.csv` ends with Spec 12's four posture columns. The
  four columns here are appended after them. If Spec 18 has not merged, `tls_error` and
  `tls_self_signed` are still in the file and this spec leaves them alone.
- **SaaS exemption (Spec 12).** Posture judges "served by a SaaS platform" on the service's own
  host (`SaaSServed`). The pivot uses the same test, so the two cannot disagree.
- **The check key does not carry the scope (Specs 2 and 3)**, as for `shodan-dns` and `dnsroot`.
  A hostname under a root the user promotes later was recorded only as that candidate root, so it
  becomes a hostname only after `--redo identifier-pivot`. Putting the scope in the key would
  spend a query credit per identifier on every scope change. The README says so.
- **Hostname cleaning (Spec 1).** `httpsrc.CleanName` strips `*.` before it validates. The
  hostname helpers are merged in one change after Specs 4, 10, 13 and 17.
- **A record that is no longer current has no attributes (Spec 3).** `web_identifier` is keyed
  `<service>|<type>|<value>`, so nothing is lost: the columns are built from current records only.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.
- **Console text (Spec 22).** If Spec 22 has merged, the `--verbose` warning of behaviour 4 is a
  WARN line, shown without a flag.

## Out of scope

Other tracker families; pivoting on copyright text; favicon search on sources other than Shodan.

# Implementation

## Develop

Built as designed, with the deviations below. Every behaviour has a test; the pure rules are unit
tests in `internal/stages/web/identifiers_test.go`, and the rest drive `cli.Execute` in
`internal/cli/identifiers_test.go` with loopback web servers and a fake `api.shodan.io`.

- **Kind and extraction (behaviour 1).** `kinds.WebIdentifier` (`internal/kinds/webidentifier.go`) is
  keyed `<service>|<type>|<value>` and shown while its host is in scope. `web/identifiers.go` holds the
  extraction: regular expressions anchored to the contexts of behaviour 1, and `page.copyright()`,
  which lays the visible text out in lines (script, style, noscript, template, head and title are
  skipped; block elements and `<br>` break a line) and takes the first with `©` or `(c)` followed by a
  year. The probe reads the HTML pages of its redirect chain that the service's own origin served
  and takes the copyright line from the last of them (`lastSameOrigin`); the crawl reads every page it
  scans and takes the copyright line from the root. Neither check key changed. Tests: every context,
  and near-misses that must not match (bare IDs in text, a word for an ID, `gtag('event', …)`,
  `fbq('track', …)`, a lower-case ID); the copyright rule (symbol and year, `(c)`, inline elements as
  one line, `<br>`, nothing from script, style, comment, title or noscript, no year, year before
  the symbol); the 120-character cut, counted in characters, and sanitising; the union of the probe
  and the crawl; identifiers of a page a redirect led to on another host are not taken.
- **Favicon (behaviour 2).** `web/favicon.go`. `hop` keeps the `egress.Response` it was built from.
  `egress.Link` does the same-host check for the icon link and for the one redirect that is followed.
  `FaviconHash` is MurmurHash3 x86-32 written by hand. Tests: the MurmurHash3 published vectors; the
  hashes of three bodies (empty, three bytes, and a hundred bytes whose base64 crosses the 76-character
  line break), computed with Python's `base64.encodebytes` and a separate implementation that matches
  the vectors, not with the code under test; the same-host link (and that `apple-touch-icon` is
  ignored), the `/favicon.ico` fallback, an off-host link, a chain ending on another host, a redirect
  followed once and not twice or off host, a 404, an HTML answer, an HTML body under an image type, a
  non-image type, a server error, no content type (hashed), the empty file (hashed, `0`), and
  exactly one GET per service even across a `--redo crawl`.
- **Columns (behaviour 3).** `output.identifierCells`, appended after the posture columns. Tests: the
  header, and the cells after the probe alone, the probe and the crawl, and a redo.
- **Pivot (behaviours 4 and 5).** `internal/stages/shodan/pivot.go`, registered after `jsparse`,
  `Budgeted` by the new `identifier_pivot.max_queries` setting, with `Evidencer` returning
  (`identifier-pivot:<id>`, `<id>`). `candidates.Family` looks up the part before the first `:`
  when the whole source is not in the table. Tests: one search per distinct identifier, first page
  only; the SaaS-served service's ID and icon, the empty-file icon and copyright text are not
  searched; the per-run cap defers and later runs never repeat a search; over 200 hosts (201) records
  nothing and warns, and exactly 200 is recorded; in-scope hostnames and candidate roots with
  `identifier-pivot:<id>` in `sources`; returned addresses appear in `ips.csv` and **(canary)** are
  never dialled; in `internal/candidates`, a source with a colon takes its part's family and two
  identifiers are one family (low, two sources, count 2); the README lists every default favicon.
- **Keys and credits (behaviour 6).** `httpsrc.GetCredits` is `Get` with a 402 returning `run.ErrQuota`
  (which wraps `run.ErrAbortStage`); the pivot uses it. A key without search access (403) fails the
  stage after the first search with one warning; a 402 stops the stage, the refused search and
  the unsent one run next time and the finished one does not; without a key the stage is
  `not-configured (no key)` and identifiers are still recorded.
- **Passive (behaviour 7).** A passive run of an engagement with stored identifiers searches them and
  sends nothing to the web services; a passive run of a new engagement records none; a plain re-run
  of an engagement whose identifiers were deleted sends nothing, and `--redo httpprobe` then
  `--redo crawl` bring them back.
- **Existing tests changed.** The favicon GET is a new request to every service: tests that counted
  or listed a service's requests now ignore `/favicon.ico` (`site.pageHits`, `site.pageURIs`) or expect
  it; the stage registry and the `web-services.csv` header tests include the additions. The test of
  a crawl that dies mid-body counted requests, and now counts requests for `/`.

Deviations from the design:

- **The icon link comes from the last page on the service's host, not the last on its origin.** The
  design cited `lastSameOrigin`. A service on `http://` that redirects to `https://` on the same host
  would have lost its link to the scheme change; `lastOnHost` keeps the page's own icon link, and
  `egress.Link` still refuses another host. A chain that ends on another host falls back to
  `/favicon.ico` of the service's first response, as designed.
- **A failed icon request is no icon, not a failed service.** The design is silent. An icon request that
  errors (the server cuts the connection) gives no hash and the service is recorded, rather than the
  whole probe check failing and being retried without a record; only the run's being cancelled is an
  error. Tested.
- **A 402 is `run.ErrQuota`, not a bare `run.ErrAbortStage`.** `ErrQuota` wraps it, and reads better in the
  failure text. Same effect.
- **A stage that finishes some searches and then stops is `done` with failed checks**, which is how
  the runner shows any aborted stage; only a stage whose every check failed is `failed`.
- **The default favicon list is four entries**: the empty file (`0`), Spring Boot (`116323821`),
  Jenkins (`81586312`) and Apache Tomcat (`-297069493`). They are the only framework hashes this
  build could be sure of without network access (see Follow-ups).
- **Search ordering.** The searches of one run are sent in parallel (the stage's worker pool), so their
  order on the wire is not the order of the checks; the cap and the budget still use the check order.

The spec has no `## External facts` section, so none turned out different.

Mutation checks, each made by hand, run against the tests, and undone by hand. All were caught:

- **Canary (out-of-scope addresses are never contacted).** `Scope.InScopeIP` made to return true for
  every address: `TestIdentifierPivot_OneSearchPerDistinctIdentifier` fails on its canaries ("an
  out-of-scope address returned by Shodan was contacted"). The first version of the canary could not
  fail, because nothing declared those addresses open, so the probe had no reason to try them; it now
  opens port 80 on each address, as the port sweep would.
- **Pivot.** The SaaS-served exemption removed; the 200-host limit removed; the default favicon list
  ignored; any hostname recorded as a hostname (the in-scope test in `nameObs`); the 402 no longer a
  stop.
- **Family.** The lookup before the first `:` removed (`TestFamily`, `TestScore_TwoIdentifiersAreOneFamily`).
- **Favicon.** Markup accepted; a redirect to another host followed; any content type accepted; an
  absent content type refused; a non-2xx answer accepted.
- **Copyright.** The cut moved from 120 to 121 characters.

## Known limitations

- **Behaviour 2: a negative favicon hash is written with a leading quote in `web-services.csv`.** The
  CSV writer puts `'` in front of every cell that starts with `-` (spreadsheet formula
  protection, pinned by `TestCSVSafety`), so `-1165240594` is `'-1165240594`. The README says the
  quote is not part of the hash. A pure integer cannot be a formula, so the writer could leave it
  alone, but that changes a pinned rule of every file, and was not done.
- **Behaviour 2: SVG icons and `<link rel=icon>` under a `<base href>`.** A body that starts with `<`
  gets no hash (the rule of the spec, which also drops SVG icons), and a relative icon link resolves
  against the page's URL, not a `<base href>`.
- **Behaviour 2: a failed or timed-out icon request is not retried** (the check completes without a
  hash); a later `--redo httpprobe` does.
- **Behaviour 1: "followed by a year" is read as the year coming next after the mark** (`© 2026`,
  `Copyright © 2019-2026`). `© Acme Pty Ltd 2026` and `(c) Acme 2026` record no copyright line.
  Nothing caps how many tracking IDs one page may name; the 1 MiB body cap bounds it.
- **Behaviour 4: the over-200 rule reads the search's `total`**, which counts matching banners, not
  distinct hosts, so a host that matches on several ports counts once for each.
- **Behaviour 4: a hostname that Shodan names and the scope excludes** gives its registrable domain as a
  candidate root, as in `shodan-host` (the open question of that spec, unchanged).
- **Behaviour 4: the search costs one Shodan query credit per search**; the stage has not been run
  against the live API, only against the fake (the filters `http.favicon.hash` and `http.html`
  and the response fields are as Shodan documents them).
- **Behaviour 4: the identifier-pivot check is never retired**, so an identifier that a re-probe no
  longer finds keeps the candidates it found.
- **Behaviour 5: the default favicon list is short** (see Follow-ups).

## Simplify

Fixed:
- The favicon fetch returns the hash as a string, or "" for no icon, and only a cancelled run is an
  error. This replaces a three-value return and a wrapper method of the same name. The markup check
  uses `isMarkup`, which also strips a byte order mark. `iconHref` walks `Descendants()`, and a dead
  nil check is gone.
- `lastOnHost` and `lastSameOrigin` share one `lastWhere` loop.
- `identifierSet` collects into the probe's `obsSet` (the crawl gives it its own) instead of keeping
  a second seen-map.
- The text cleanup and rune cut are shared helpers in `html.go` (`collapse`, `cutRunes`).
- The tracker patterns only scan a page that contains one of their fixed hints (`gtag`,
  `googletagmanager` or `GTM-`, and `fbq` or `facebook.com/tr`).
- `shodan-host` and `identifier-pivot` share the code that sorts Shodan's names into hostnames and
  candidate roots (`nameObs` in `host.go`). The pivot parses addresses with `input.IPLiteral`.
- The pivot builds its query in `Checks`, so the `kind` field, its constants and `query()` are gone.
  It reads `v.Scope()` once.
- The exported `DefaultFavicons` is removed, and the README test reads the list from inside the
  package.
- `httpsrc.get` takes the status that means the allowance is spent (0, 429 or 402) instead of a mode
  enum.
- Tests:
  - The colon-suffix family cases are folded into the `TestFamily` table.
  - `faviconCase` uses `maps.Copy`, and a new `otherSite` helper replaces two duplicated setups.
  - The `pivotKey` alias and a dead branch in `pivotFake.fail` are removed.
  - `pageHits` is written with `count`.

Skipped:
- An http service that redirects to https asks for the same icon as the https service. Avoiding
  that needs either a per-run icon cache shared by concurrent checks, or dropping the http row's
  `favicon_hash`.
- Three changes would go against decisions in this spec's design, so they were left alone:
  - making the icon its own retried check;
  - keeping the candidate family apart from the `identifier-pivot:<id>` label;
  - keeping `hop` without the response.
- Treating a 402 as quota-spent for every keyed source. That changes `shodan`, `shodan-dns` and
  `shodan-host`, which an earlier spec chose to leave as ordinary failed checks.
- Using one "own page" rule for identifiers and the icon link. The two rules differ on purpose (see
  Develop).
- Dropping the sort and dedupe in `extractIdentifiers`. Its unit tests rely on the order.
- Dropping the `Shown` filter in `identifierCells`. Readers apply a kind's showing rules.
- Merging `pivotFake` into `shodanFake`, and reusing one fixture for four tests whose setups differ.

# Verification

## Result

Checked against the code on 2026-11-15. `make test` passes (vet for the four targets, then
`go test -race ./...`). `golangci-lint` could not run: the installed binary was built with Go 1.26
and the module targets Go 1.27.3. The favicon hashes the tests pin were recomputed with Python's
`base64.encodebytes` and a separate pure-Python MurmurHash3 checked against the published vectors;
all three match.

- **Goal: met.** Tracking IDs, favicon hashes and copyright lines of in-scope services are
  `web_identifier` records shown in `web-services.csv`, and with `keys.shodan` the
  `identifier-pivot` stage searches the pivotable ones and records what it finds.
- **B1: met** (after the change below). The probe reads the HTML pages of its chain that the
  service's own origin served, the crawl every page it scans (the crawl never leaves the origin),
  and each identifier is its own record, so the probe and the crawl make the union. The patterns
  are anchored to the named contexts (plus the Tag Manager loader and noscript frame, which are
  GTM snippet contexts). The copyright line comes from the root page (the last same-origin page of
  the probe's chain, the crawl's depth-0 page), skips script, style, noscript, template, head and
  title text, is sanitised and cut to 120 characters.
- **B2: met, with the readings in `## Known limitations`.** One GET per service through
  `egress.Link`: the icon link of the last page on the service's host, else `/favicon.ico` of the
  first response; an off-host link or a chain that ends elsewhere falls back. One redirect is
  followed, only on the same host. A non-2xx, a non-image type, or a body that is markup gives no
  hash. `FaviconHash` is pinned by known values. The README lists the favicon GET among the
  requested paths. A negative hash carries the CSV writer's `'` (Known limitations; follow-up).
- **B3: met.** The four columns follow the posture columns, `;`-joined from current shown records.
- **B4: mostly met.** One budgeted search per distinct analytics ID, pixel ID or non-default
  favicon hash on a shown, non-SaaS service; first page only; `identifier_pivot.max_queries`
  (default 50, at least 1; flag, config, env); in-scope hostnames recorded, other names give a
  candidate root with `identifier-pivot:<id>` in `sources`, one family however many identifiers;
  addresses recorded as `ip` and classified by the scope (canary test). Partly met: the over-200
  rule reads Shodan's `total`, which counts banners, not distinct hosts, so an identifier on fewer
  than 200 hosts that answer on several ports can be refused (Known limitations). The warning is a
  WARN line, as Spec 22 has merged. Not run against the live API.
- **B5: met, with a short list.** The empty file, Spring Boot, Jenkins and Apache Tomcat hashes are
  not pivoted, and the README lists them (a test keeps the two in step). Copyright lines are never
  searched. More framework icons would make the list more useful (follow-up).
- **B6: met.** A 401 or 403 aborts the stage with one warning and shows it failed; a 402 returns
  `run.ErrQuota` and stops the stage for the run, the remaining searches run next time; without a
  key the stage is `not-configured (no key)` and the probe and crawl still record identifiers.
- **B7: met.** The probe and crawl are `Target` stages and do not run under `--passive`; the pivot
  is third-party and searches stored identifiers. The README says existing engagements need
  `--redo httpprobe` and `--redo crawl`.

Changed while verifying:

- **Copyright year after the holder (B1).** The year had to come straight after the mark, so the
  common `© Acme Pty Ltd 2026` and `(c) Acme 2019-2026` recorded nothing, although behaviour 1 asks
  only for a mark followed by a year. The year may now come anywhere later on the same line; a year
  on another line, before the mark, or inside a longer number still does not count. Unit tests
  for both forms and the near-misses; the README's `copyright` row says so. The fourth item of
  `## Known limitations` no longer holds for these forms.
- README: a missing comma in the `web-services.csv` row of the output table.

## Code review

`/code-review high --fix` reported ten findings and applied four, all kept. I added one test.
`make test` passes afterwards.

Kept:

- **Icon link under `<base href>` (B2).** A relative icon link now resolves against the page's
  `<base href>`, as a browser and the crawl do (`withBase` in `html.go`, shared with the crawl).
  Before, `<base href="/static/">` with `href="fav.png"` asked for `/fav.png`, and the 404 lost the
  hash. Pinned by `TestFavicon_LinkUnderBaseHref`, which I added. The `<base href>` half of the
  second item of `## Known limitations` no longer holds.
- **IDs end at a word boundary (B1).** `gtag/js?id=G-ABCDEFGHIJKLMNOP` was recorded as its first 14
  characters, and a 24-digit pixel ID as its first 20 digits: wrong IDs that would each spend a
  search. Such tokens now record nothing. Three near-miss unit cases added.
- **README family wording (B4).** It now says each `identifier-pivot:<id>` source is in the web
  identifier family. Text only.
- **`candidates.Sources` comment.** Notes that a source with a colon is listed by the name before
  it. Comment only.

Left unfixed:

- **The over-200 rule counts banners, not hosts (B4).** Counting distinct hosts needs more result
  pages or Shodan facets, which changes the credit cost of a search and cannot be checked without
  the live API. Already in `## Known limitations`; part of follow-up 3.
- **Only the first icon link is tried (B2).** An SVG or a 404 for the linked icon gives no hash,
  with no retry of `/favicon.ico`. Behaviour 2 asks for exactly one favicon GET per service, so a
  second request would change the behaviour. Follow-up 5.
- **The favicon request is not pinned to the address the probe pinned its root to.** For a name on
  several addresses the icon may come from another of them. Pinning needs an `egress` change the
  spec does not ask for. Follow-up 5.
- **Copyright lines are `;`-joined, and a line may hold a `;`.** Changing the join changes the CSV
  form the design set for every column. The cell is read by people, and usually holds one line.
- **`nameObs` callback, and `copyright()` building every line before matching.** Style and a small
  cost, not worth the churn.

# Follow-ups

1. **Extend the default favicon list** (`defaultFavicons` in `internal/stages/shodan/pivot.go`, and
   the README sentence in `## Web identifiers` that lists them) with the hashes of other common
   framework and product icons (GitLab, Grafana, Confluence, phpMyAdmin, Kibana and the like). Each
   must be verified against a real install or a published list; `TestREADMEListsEveryDefaultFavicon`
   keeps the README in step.
2. **Decide whether a pure integer cell should skip the CSV formula quote**, so that a negative
   `favicon_hash` can be pasted into Shodan as it is. The rule is in `internal/output` and pinned by
   `TestCSVSafety`.
3. **Run `identifier-pivot` once against a real Shodan key** with a paid plan:
   `NYX_KEYS_SHODAN=<key> nyx -e <engagement> --passive --output-dir <dir>` on an existing
   engagement whose `web-services.csv` has identifiers (an `--output-dir` outside the repo). Confirm the query syntax (`http.html:"<id>"` and
   `http.favicon.hash:<hash>`), the 402 and 403 answers, the credit cost of one search, and whether
   `total` counts banners; if it does, decide whether the over-200 rule should count distinct hosts
   (with facets, at whatever credit cost that has).
4. **Run `golangci-lint run ./...`** with a golangci-lint built with Go 1.27.3 or later: the
   installed one was built with Go 1.26 and refuses this module, so the linter did not run on this
   change.
5. **Decide two favicon questions the review raised**: whether to request `/favicon.ico` as well
   when the linked icon is an SVG or a 404 (behaviour 2 now allows one GET per service), and whether
   the icon request should be pinned to the address the probe's root request used (an `egress`
   change, in `fetchFavicon` in `internal/stages/web/favicon.go`).

