# Spec 3 of 4: Hostnames anywhere in a response

## Goal

nyx finds every in-scope hostname mentioned in the part of a target's responses that it reads, not
only the ones written as links, so that names in page text, comments, JSON, scripts, headers and
banners are discovered without changing what is sent to obtain those responses.

Depends on: nothing.

Done when:

- an in-scope hostname that appears only in a page comment, a JSON string in a script, a
  `Content-Security-Policy` header or an SMTP banner is listed as a hostname and resolved.

## Behaviours

- **B1 Where.** Any hostname under an in-scope root that appears in the body or a header of a
  response that `httpprobe`, `crawl`, `jsparse` or `origincheck` received (redirect hops,
  `/robots.txt`, `/sitemap.xml`, pages, scripts and the origin-check answer), or in a TCP banner
  the `ports` procedure read, becomes a hostname and is resolved like any other. A name in a banner
  is taken whichever hostnames its address serves, and when it serves none. A banner only Shodan
  reports is not searched.
- **B2 Sends nothing.** Reading a response or a banner sends nothing. A hostname found this way is
  probed and crawled like any other in-scope hostname.
- **B3 What is read.** Only the part of a response or banner nyx already reads is searched; what
  its size limits cut off is not. A name that runs right up to the point where a size limit cut the
  text (the body cap, or a banner that filled the banner read) is not taken. (amended by D5)
- **B4 How a name is read.** Each of these gives `api.example.com`, and never a name that begins
  with the remains of the escape (`2fapi.example.com`, `u002fapi.example.com`, `x2fapi.example.com`):
  - percent-encoded: `https%3A%2F%2Fapi.example.com`
  - backslash-escaped slashes: `https:\/\/api.example.com`
  - JSON unicode escapes: `https:\u002F\u002Fapi.example.com`
  - hex escapes: `https:\x2F\x2Fapi.example.com`
  - HTML entities: `https:&#x2F;&#x2F;api.example.com`

  `2fa.example.com` written plainly gives `2fa.example.com`. `www.example.com.evil.net` gives
  nothing. `API.Example.COM` gives `api.example.com`. A name with a Latin, Greek or Cyrillic
  non-ASCII letter touching it gives nothing (`bücher.example.com` gives nothing, not
  `cher.example.com`); other non-ASCII text (Chinese, Japanese, emoji) separates names, so a name
  inside such prose is read. `<!--api.example.com-->` gives `api.example.com`: hyphens at the
  ends of a run are trimmed like dots, so `-bad.example.com` gives `bad.example.com`. (amended by
  D6, D9 and D19)
- **B5 Wildcard entries.** `*.cdn.example.com` (as a policy header writes it) gives
  `cdn.example.com`.
- **B6 Left out.** A name under no in-scope root that appears only in text is ignored: it is not a
  candidate and not a third party. Names from links, redirects and certificates give candidates as
  today. The responding host's own name adds nothing. An excluded name is recorded as excluded, as
  any hostname is. The responses to the sensitive-path list and the favicon are not searched.
- **B7 Cap.** At most 1,000 distinct names are taken from the responses of one web service (its
  probe, its crawl and the scripts it serves, together), the names in links included: `crawl` and
  `jsparse` take hostnames only through this reading. Every name read from the service uses a
  place, including one nyx already knew from another source. The cap counts every name taken from
  the service over the engagement, current or not: names once taken are kept, and later responses
  add names only while the service is under the cap. A run that leaves names out prints, when it
  ends, one WARN line for the service with the number of distinct names left out; above 10,000 the
  line says "more than 10,000". An origin-check response and a banner each have the same cap of
  their own. `httpprobe` still takes the names of redirect targets and certificates as today,
  outside the cap; the same name read from a response by `crawl` uses a place. (amended by D1, D2,
  D3, D8 and D20)
- **B8 Passive.** Under `--passive`, or without `--authorised`, these procedures do not run, so
  nothing is read.
- **B9 Documented.** The user guide says that hostnames are taken from anywhere in a response and
  from banners, and gives the cap.

## Out of scope

- Requesting archived URLs (Wayback, Common Crawl) of in-scope hosts to read their responses, as
  bbot does. Declined: it adds a kind of request to the passive boundary.
- Searching the responses to the sensitive-path list, and the favicon. Declined by the user.
- Banners only Shodan reports.
- Candidates or third parties from names that appear only in text.
- A cap per response, and a cap per run on names taken from text. Declined: the cap is per web
  service.
- Names under the registrable domain of a name that is in scope by its address (Spec 4): they stay
  ignored.
- Engagements created before this change. The user will start fresh engagements, so nothing is
  fetched again to read old responses.
- Counting a shared script against the service of the page that referenced it first. Declined
  (D1): the serving origin is used.
- Leaving link names in `crawl` and `jsparse` on their own uncapped path. Declined (D2).
- A WARN line per job, or one with no number. Declined (D3).
- Leaving out a banner name that its address already serves. Declined (D4): banners give every
  name, and may seed name guessing.
- Reading names written with non-ASCII letters (U-labels). Accepted cost of D2 and D6.

# Design

## External facts

- **Go allows indexing and `len` on a type parameter constrained by `~string | ~[]byte`, and a
  function returning `iter.Seq[string]` over it.** *Confirmed live* (2026-11-27): a probe compiled
  and ran with go1.26.4; `go.mod` pins 1.27.3. D10's signature rests on it.
- **`github.com/miekg/dns` gives TXT strings in presentation form: every byte below 0x20 or above
  `~` is written `\DDD` in decimal, and `"` and `\` are written `\"` and `\\`.** *Confirmed from
  source* (2026-11-27): `escapeByte` in the module's `types.go`
  (`go list -m -f '{{.Dir}}' github.com/miekg/dns`); `internal/egress/dns.go` joins the strings
  unchanged. So `ü` in a TXT value reaches the reader as `\195\188`. D10 reads `\DDD` as decimal
  because of it.
- **The escape syntaxes of B4.** *From docs*, not probed (standards, and the reader's tests state
  each form): percent-encoding (RFC 3986 §2.1); JSON `\uXXXX` and `\/` (RFC 8259 §7); ECMAScript
  `\xHH` and `\u{…}`; HTML numeric character references `&#DDD;` and `&#xHH;`, whose semicolon a
  browser does not require and whose digits it reads greedily (WHATWG HTML, "numeric character
  reference state").
- **A `Content-Security-Policy` host source may be written `*.example.com`.** *From docs* (CSP
  Level 3, host-source). B5 is the user's wording of it.
- No external data is embedded.

Facts about this codebase the plan rests on, checked on 2026-11-27:

- `subdomains.txt` lists every in-scope `hostname` record, resolving or not
  (`inScopeHostRows`, `internal/recon/output/output.go`). A misread name is therefore visible, so
  the reader prefers giving nothing to giving a wrong name.
- `egress.MaxTargetBody` is 1 MiB and `MaxScriptBody` 4 MiB; `Response.Truncated` says a body was
  cut. The transport sets `DisableCompression`, so a body is read as sent. A banner is one read
  into a 1,024-byte buffer (`dialAndRead`, `internal/egress/tcp.go`).
- A `script` record's `service` attribute is merged across crawl jobs with the last job key
  winning (`Reader.Records`, `internal/recon/store/store.go`), so it cannot say which page
  referenced a script first. `jsparse.max_scripts` is already per serving origin (`originOf`).
- `Runner.records` caches every record of a kind, current or not; `View.Records` gives the current
  ones.
- `kinds.All()` feeds `nyx recon export --kind`, the export and the root help
  (`TestTree_RootHelpIsTheWholeReference` in `internal/cli/command_tree_test.go` requires every
  kind name in the help, which `exportKinds` builds from `kinds.All()`),
  and `docs/output.md` says kind names are stable.
- The runner flushes the store and gives each procedure a new `View` after any procedure does work
  (`afterWork`, `newProcedureRun`), and runs one procedure's jobs concurrently in a worker pool.
- `run.PerRun` (`internal/recon/run/procedure.go`) shares one value per key across the jobs of a
  run; `Runner.passes` creates that state.

## Decisions

Decided by the user:

- **D1 Shared scripts (B7).** The names read from a script count against the origin that serves
  it (`originOf(scriptURL)`), whichever pages reference it. Why: deterministic, needs no stored
  "first referrer", and matches `jsparse.max_scripts`.
- **D2 One reader, capped (B7).** `crawl` and `jsparse` stop taking hostnames from links on a path
  of their own: the text reader sees the same responses, so a linked name is read from text and
  uses a place. Accepted cost: a link written with non-ASCII letters is no longer taken (today
  `input.ParseDomain` turns it into its `xn--` form). `httpprobe`'s `recordHop` (the redirect
  target's host, in any scope, which is what gives candidates) and `certAttrs` (SANs) are
  untouched and outside the cap.
- **D3 The number left out (B7).** One WARN line per service, printed when the run ends (also when
  it is interrupted), with the number of distinct names left out across its probe, crawl and
  scripts in this run. Exact up to 10,000; past that the line says "more than 10,000" and the job
  that got there stops scanning its responses.
- **D4 Banner names (B1).** Every name in a banner is taken, including one its address already
  serves. Consequence, accepted: a banner that spells a name only `permutations` had found makes
  `ports` a second producer of it, so it becomes a seed for name guessing. It is bounded: the
  banner must spell the name, and guessing has its own per-run cap. A test pins it.
- **D5 A cut name (B3).** A name that reaches the end of text that a size limit cut is not taken.
- **D6 Non-ASCII letters (B4).** A non-ASCII letter or mark of the Latin, Greek or Cyrillic script
  touching a name rejects it whole; any other non-ASCII character separates.
- **D7 A new record kind.** The cap's memory is a new kind, `text_hostname`. It has no output
  file, but `nyx recon export --kind` and the root help list it like every kind, and its name and
  its attribute names (`service`, `name`) become part of the stable interface.
- **D8 What uses a place (B7).** Every name read from a service uses a place: one nyx already
  knew from another source, and one no longer current. The docs say so.
- **D9 A corrected example (B4).** The spec's "JSON unicode escapes" line had lost its escapes
  when it was written; it now reads `https:\u002F\u002Fapi.example.com`.

Decided from the code and the review:

- **D10 The reader.** `dnsname.HostnamesIn` (Spec 2 D14, which handed it here) becomes

  ```go
  func HostnamesIn[T ~string | ~[]byte](text T, cut bool) iter.Seq[string]
  ```

  One pass over the bytes, no regexp, no copy of the text, and lazy, so a caller can stop. It
  yields each name once per occurrence (callers deduplicate). After decoding (below) every
  character is one of:
  - a **name character**: `A-Z a-z 0-9 . -`;
  - a **rejecting character**, which is part of the run and makes it give nothing: `_` (Spec 2's
    rule: `_dmarc.example.com` gives nothing, not `example.com`), a non-ASCII letter or mark in
    `unicode.Latin`, `unicode.Greek` or `unicode.Cyrillic` (D6), a byte of 0x80 or more that is
    not valid UTF-8 (a Latin-1 page), and an escape that gives one byte of 0x80 or more
    (`%C3`, `\xFC`, `\195`);
  - a **separator**: everything else.

  A maximal run of name and rejecting characters is lower-cased, has its leading and trailing dots
  trimmed, and is yielded when it has no rejecting character, is at most 253 bytes, has at least
  two labels and every label is a `ValidLabel`. A longer run is skipped to its end without being
  buffered (the 253 limit is `learn.go`'s `maxNameLen`; a longer name fails `resolve` on every
  run). With `cut`, a run that reaches the end of the text is not yielded (D5).

  Escapes are decoded in line, each to one character that is then classed as above:
  - `%XX` (two hex digits);
  - `\uXXXX`, `\u{X…}` (1 to 6 hex digits) and `\xXX`;
  - `\` and exactly three decimal digits: the byte of that value, in decimal (the DNS
    presentation form; a value over 255 separates). `\` and a digit not followed by two more
    separates (`\0`);
  - `\n`, `\r`, `\t`, `\b`, `\f`, `\v` separate;
  - `\` and any other ASCII letter rejects the run (`\w\.example\.com` in a regular expression
    must not give `w.example.com`);
  - `\` and any other character is that character (`\/` is `/`, `\.` is `.`, `\\` is `\`);
  - `&#DDD;` and `&#xHH;`, the semicolon optional and the digits read greedily; more than seven
    digits separates. `&amp;` is `&`. No other named entity is decoded: its `;` already separates;
  - a decoded `%`, `\` or `&` begins a new escape with the bytes that follow, so `%252F`,
    `\\u002f`, `\\n` and `&amp;#x2F;` are read through. Each step consumes input, so the pass
    stays linear.

  The TXT caller (`recordObservations` in `internal/recon/procedures/dns/records.go`) uses the
  same reader with `cut` false: one reader of hostnames in text. Its `recordHost` rule is
  unchanged, so TXT still drops an excluded name where web text records it (D11); a comment in
  both places says so.

  Inexact readings accepted, each for `docs/todo.md`: a legacy three-digit octal escape in a
  script (`\057`) is read as decimal; `C:\sites\new.example.com` gives `ew.example.com`; a name
  written with non-ASCII letters is not read; a TXT value's literal backslash arrives doubled and
  is read through (`C:\\new.example.com` gives `ew.example.com`, where Spec 2 gave
  `new.example.com`).

- **D11 Which names are taken.** A name the reader yields is taken when it is strictly below an
  input root, exclusions ignored: `r := sc.RootOf(n); r != "" && r != n`, written in line (no
  new `Scope` method). So an excluded name becomes a `hostname` record that the kind's placement
  shows as excluded (B6), a name under no root is dropped (B6), an input root adds nothing, and a
  name in scope only by its address (Spec 4) has no root and stays ignored. Also left out:
  - the job's own host: `in.host` for `httpprobe` and `crawl`, the script's host for `jsparse`,
    the pair's host for `origincheck` (B6; this keeps
    `TestRedirect_PermutationOnlyNameIsNeverSeededByItsOwnService` true). A banner has no own
    host (D4);
  - in `httpprobe`, any name the job has already observed as a `hostname` through `recordHop` or
    `certAttrs`: those are B7's "outside the cap", so they must not also use a place. The text
    is therefore read after `followRedirects` and `certAttrs` have filled the job's `obsSet`.

  The scope snapshot goes in each `Job.Input` (`crawlInput` and `scriptInput` carry `sc` already;
  `probeInput`, the origin-check input and `portCheck` gain it). As `JSParse.Jobs` already says of
  itself, a root added later does not re-read a finished response: that takes `--redo` of the
  procedure, which for `ports` reconnects to every port. The docs say so.

- **D12 What is searched.** Every response the four web procedures receive, whatever its status
  or content type: each header value (names of headers are not read; keys are walked in sorted
  order so the names kept near the cap do not depend on map order), then the body, with
  `cut = Response.Truncated`.
  - `httpprobe`: every hop of the chain `followRedirects` returns, the first response included.
    Not the favicon response (`fetchFavicon`).
  - `crawl`: one hook in `crawler.fetchPage`, on every live response: same-origin redirect hops,
    pages of any type, `/robots.txt`, `/sitemap.xml` and sitemap indexes, non-2xx answers too.
  - `jsparse`: every response `fetchScript` receives, redirect hops, non-2xx and markup answers
    included, so `Run`'s early returns still give the names read.
  - `origincheck`: the one response.
  - `ports`: `egress.Open.Banner` as received, for the plain job and the `|reported` job alike,
    with `cut = len(banner) == egress.MaxBanner` (a new exported constant for the 1,024 in
    `dialAndRead`).
  - Not touched: `sensitive-paths`, the favicon, `takeover`, and Shodan's `reported_port` banners.
  - `parserVersion` in `jsparse.go` is not bumped: Out of scope says old engagements are not read
    again.

- **D13 The cap's accounting.** `maxTextNames = 1000` and `maxLeftOut = 10000` are constants in
  package `web`, not settings (B7 fixes the number).
  - **The kind.** `kinds.TextHostname`, a `defineJoined` kind keyed `<service>|<name>` with
    attributes `service` and `name`, `HostAttr: "name"` (shown only while the name is in scope),
    no category, no change label, no output file. One is written beside each `hostname`
    observation of a name taken from a web service's text. Rejected: counting `hostname`
    observations by job key (probe keys are `host:port` or `port|addr`, crawl keys carry
    settings, jsparse keys the parser hash, and the probe's certificate and redirect names would
    be counted).
  - **The unit** a name counts against: `httpprobe` the service origin it records (`attrs.URL`),
    `crawl` `in.origin`, `jsparse` `originOf(in.url)` (D1).
  - **The seed.** A new `run.View` method returns the whole index, unit to the names of every
    `text_hostname` record, current or not, built once per pass from `Runner.records`. Each of
    the three procedures puts that map in its `Job.Input` and `Run` looks up its own unit: a
    port-detection job (`port|addr`) only learns its scheme, and so its unit, in `Run`.
  - **The collector.** In `Run`, a job-local ordered set gathers the distinct names D11 lets
    through, from all the job's responses, bounded at `maxTextNames + maxLeftOut` distinct names;
    a name past that sets `over` and the job stops scanning. Nothing shared is touched until the
    job has done all its fetching, so a job that fails or is cancelled part-way reserves nothing.
  - **The budget.** At the end of a successful `Run` the job commits to
    `run.PerRun(ctx, budgetKey{unit}, …)`, seeded from the map on first use. Under its mutex,
    `admit(names, over)` keeps a name already taken, keeps a new name while fewer than 1,000 are
    taken, and otherwise adds it to a `left` set bounded at 10,000, with a flag once it would pass
    that or `over` is set. Each kept name becomes a `hostname` and a `text_hostname` observation
    of this job. Why per run and not the seed alone: `jsparse` runs many scripts of one origin
    concurrently. (Across procedures the seed would do, since the runner flushes between them.)
    Which names are kept near the cap therefore depends on the order jobs finish in: tests assert
    counts, not sets.
  - Accepted: a job cancelled after `admit` leaves names in the run's budget that were never
    stored; the next run seeds from the store. Each write of the kind re-derives the findings
    (they read every stored kind), which is harmless.
  - Without a runner context `PerRun` calls its `init` each time, so an isolated test gets a fresh
    budget per job.

- **D14 The WARN at the end.** A new optional interface in package `run`:
  `EndWarner interface{ EndWarning() string }`. `Runner.passes` defers a step that takes every
  value held in the run state, asks those that implement it, and passes each non-empty text to
  `r.warn` in sorted order, on completion and on interrupt, before the summary or the envelope is
  built. The budget implements it: empty when nothing was left out, else
  `<unit>: <n> hostnames in its responses were left out: at most 1,000 are taken from one web
  service` (or `more than 10,000 hostnames`; exact wording is the developer's, the unit, the
  number and "1,000" are required). Rejected: a registration call (`run.AtEnd`) beside `PerRun`,
  two mechanisms for one job; `run.Warnf` per job (D3); a `Noter` (summary lines, and no context
  to reach the run state); storing the count (later runs would warn again).

- **D15 The other two caps (B7).**
  - `origincheck`: the same budget type, under `PerRun` keyed by the job key, with no seed and no
    `text_hostname` records (one response, a cap of its own). Its WARN comes out at the end like
    the others, naming the host and address.
  - `ports`: no cap code. A banner is at most `egress.MaxBanner` bytes and the shortest name
    below a root takes about seven with its separator, so it cannot hold 1,000 names. A comment
    says so and a unit test pins `egress.MaxBanner/7 < 1000`.

- **D16 Nothing else changes.** No new setting or flag, no new `--json` envelope key, no new
  output file, no change to `egress.Policy` or to what is sent. `origincheck` and `ports` become
  producers of `hostname` records; nothing lists the producers of a kind, and neither gains
  `CandidateSources` (they record only names below a root).

- **D17 Docs (B9).**
  - `docs/sources.md`: a new `## Hostnames in responses` section: which responses and banners are
    read and that reading sends nothing; the escapes of B4 in a sentence; what is left out (names
    under no root, the host's own name, sensitive-path and favicon responses, Shodan's banners,
    non-ASCII names, a cut name); the cap of 1,000 per web service, D8's "what uses a place", the
    WARN line and "more than 10,000"; that `crawl` and `jsparse` take hostnames only this way;
    that it needs `--authorised` and is off under `--passive`; that a root added later is read
    only after `--redo` of the procedure, and that `--redo ports` reconnects to every port; that
    the taken names are kept as `text_hostname` records, which `nyx recon export` shows.
  - `docs/passive-boundary.md`, `## Passive boundary`: one sentence that hostnames are read from
    the responses and banners already received, and that this sends nothing.
  - `internal/cli/procedures_topic.go`: the "does" text of `httpprobe`, `crawl`, `origincheck`
    and `ports` mentions the hostnames read (`jsparse`'s already does).
  - `docs/todo.md`: D10's inexact readings; that `crawl` still records `url` rows for hosts the
    cap left out; that `--redo ports` is the only way to read old banners under a new root (the
    banner is stored in `open_port`, so a no-contact reading is possible later).

- **D18 Considered and dropped.**
  - Reading banner names from stored `open_port` records in an analysis, so a new root needs no
    reconnect: an analysis would have to write `hostname`, which other analyses read, and the
    other four procedures have the same `--redo` limit. In `docs/todo.md`.
  - A `Scope` method for D11's predicate: it is one line, and `records.go` already writes it in
    line.

Settled after verification:

- **D19 Hyphens at the ends of a run (B4, D10).** Hyphens at either end of a run are trimmed as
  dots are, so `<!--api.example.com-->` and `--api.example.com` give `api.example.com`. This
  changes an earlier case: `-bad.example.com` now gives `bad.example.com` (the user agreed to
  change that frozen case). A dot and a hyphen side by side still give nothing.
- **D20 Redirect and certificate names the crawl reads (B7, D11).** Accepted: `crawl` reads the same
  redirect responses as `httpprobe` and has no exemption, so such a name uses a place when the
  crawl reads it (D8). The exemption's tests run with `--crawl-pages 0`.
- **D21 Percent-encoded non-ASCII text (B4).** Accepted as D10 writes it: `%E4%B8%AD` rejects a name
  it touches, where literal Chinese text separates. Listed in `docs/todo.md`.

## Files

- `internal/knowledge/dnsname/dnsname.go`, `dnsname_test.go`: D10.
- `internal/recon/procedures/dns/records.go` (and `records_test.go` if a signature shows): the
  call site ranges over the iterator; the comment of D10.
- `internal/recon/kinds/texthostname.go` (new): `TextHostname` and its attributes (D13).
- `internal/recon/run/procedure.go`: `EndWarner`, the `View` method of D13.
  `internal/recon/run/runner.go`: the deferred step in `passes` (D14). A test beside them.
- `internal/egress/tcp.go`: `MaxBanner` (D12).
- `internal/recon/procedures/web/names.go` (new) and `names_test.go`: the collector, the budget,
  the helper that reads one response's header values and body into a collector (D11 to D14).
- `internal/recon/procedures/web/probe.go`: `sc` and the seed in `probeInput`; read the chain
  after `certAttrs`; commit.
- `internal/recon/procedures/web/crawl.go`: the hook in `fetchPage`; remove `crawler.hosts` and
  the `otherHost` branch of `record`; commit in `observations`.
- `internal/recon/procedures/web/jsparse.go`: read in `fetchScript`; remove the `hosts` map;
  every return after a response carries the names; the comment on `Jobs`.
- `internal/recon/procedures/web/origincheck.go`: an input that carries the pair and `sc`.
- `internal/recon/procedures/ports/ports.go`: `sc` in `portCheck`; names beside the `open_port`
  observation; the comment of D15. `ports_test.go` (new) for D15's pin.
- `internal/cli/textnames_test.go` (new): the behaviour tests below.
- `internal/cli/web_crawl_test.go` (near line 93), `jsparse_test.go` (near 210) and
  `web_redirect_test.go` (near 50, 192, 229 and 274) assert exact hostname sets by producer. They
  should pass unchanged; change one only where its fixture's text names another in-scope host, and
  say why in the commit.
- `internal/cli/procedures_topic.go`, `docs/sources.md`, `docs/passive-boundary.md`,
  `docs/todo.md` (D17).

## Tests

Harness: the web world in `internal/cli/web_helpers_test.go` (`newWeb`, `x.host`, `x.plain`,
`x.secure`, `page`, `routes`, `redirectTo`, `posturePage` for headers, `x.observedBy`,
`x.lines(eng, "subdomains.txt")`, `w.warnings()`, the site's `.count()` and `.uris()`); the origin
world in `origin_test.go`; the real ports world in `ports_test.go` (`newPorts`, `p.serve`,
`p.sweep`, `p.canary`). Give a name that a test plants in text no address, or an address of its
own, so that probing it (B2's second sentence) does not change the request counts being asserted.

- **Unit, `dnsname` (B3, B4, B5; mutation check).** A table: each B4 line gives
  `api.example.com` and none gives `2fapi…`, `u002fapi…` or `x2fapi…`; `2fa.example.com` plain;
  `www.example.com.evil.net` is one name; upper case; `*.cdn.example.com` and a leading-dot
  cookie domain; `%252F`, `\\u002f`, `\\n`, `&amp;#x2F;`, `&#x2F` without its semicolon,
  `api&#46;example&#46;com`, `api\.example\.com`; `\n` and `\t` before a name; `\w\.example\.com`
  gives nothing; `\195\188` and `%C3%BC` and a literal `ü` inside a name give nothing; CJK text
  around a name gives the name; a Latin-1 0xFC byte gives nothing; `_` labels; a 254-byte name
  gives nothing and a 253-byte one is given; `cut` drops only the run that reaches the end;
  stopping the iterator early stops the scan; 4 MiB of `a.b.c ` runs and 4 MiB of one unbroken
  run both finish in well under a second (linear, bounded buffer).
- **Unit, `web/names.go` (B7; mutation check).** The collector: order, distinctness, the bound and
  `over`. The budget: the seed counts; a name already taken is kept at the cap; the 1,001st new
  name is left out; 50 goroutines admitting overlapping names never take more than 1,000 and the
  kept and left counts add up; `EndWarning` is empty with nothing left out, exact at 10,000 and
  "more than 10,000" past it or with `over`.
- **Unit, `run` (B7).** A value under `PerRun` that implements `EndWarner` is warned once when
  `passes` returns, on completion and when the context is cancelled mid-run; two values come out
  in sorted order; an empty text prints nothing; the warning is in the `--json` envelope's
  warnings (through the harness).
- **B1, Done-when (behaviour).** One test per place, each asserting the name is in
  `subdomains.txt`, was observed by the named procedure and has a `resolve` job: an HTML comment
  on a crawled page (`crawl`); a JSON string in a script, backslash-escaped (`jsparse`); a
  `Content-Security-Policy` header on the probed root, written `*.cdn.example.com` (`httpprobe`,
  B5); a redirect hop's body (`httpprobe`); a comment in `/robots.txt`, a `<loc>` in
  `/sitemap.xml` and the body of a 404 page (`crawl`); a non-2xx and a markup answer to a script
  URL (`jsparse`); an origin-check body (`origincheck`); an SMTP banner on an address that serves
  a hostname and on one that serves none (the second needs a `--cidr` input, since `eligible`
  sweeps netblocks); a banner on a `|reported` recheck. A service found on a detection port
  (8443) takes names and counts them against its own origin (D13's seed lookup).
- **B1, a banner only Shodan reports.** A `reported_port` banner naming an in-scope host gives no
  hostname.
- **D4.** A name only `permutations` found, spelt in its address's banner, is observed by `ports`
  and becomes a seed; the same name in its own web page does not
  (`TestRedirect_PermutationOnlyNameIsNeverSeededByItsOwnService` stays green).
- **B2 (mutation check).** With names planted in every place above, each site's request count and
  URIs equal those of the same world without the names, and no canary fires. A name found in text
  that resolves to an in-scope service is then probed and crawled.
- **B3.** A page padded past 1 MiB with a name after the cut gives nothing; a name straddling the
  cut gives nothing; the same for a script at 4 MiB; a 1,024-byte banner ending mid-name gives
  nothing for that name.
- **B6 (mutation check).** `api.other.net` in text gives no row in `candidates.csv` or
  `third-parties.csv` and no `hostname` record; the same name as a redirect target still gives a
  candidate, and a certificate SAN still does (existing tests stay green); the host's own name in
  its page adds no `hostname` observation; an input root in text adds none; an excluded name in
  text is listed as excluded and is not probed; a sensitive-path response and a favicon response
  full of names give nothing (`sensitive-paths` and the favicon fetch observe no `hostname`).
- **B7 (mutation check).**
  - A service whose probe, crawl pages and two scripts name 1,500 distinct hosts between them
    takes exactly 1,000 (count of `text_hostname` records for the origin, and of the hostnames),
    with one WARN line naming the origin and 500.
  - Link names count: a page of 1,200 `<a href>` links to distinct in-scope hosts takes 1,000
    (D2). `crawl` and `jsparse` still record the `url` rows.
  - A name already known from crt.sh that the service also names uses a place (D8).
  - A redirect target and a SAN that the page also names do not use a place (D11).
  - A second run with `--redo crawl`, the pages now naming 300 new hosts, adds none and prints the
    WARN again with the new number; a plain second run sends nothing, prints no WARN and lists the
    same names.
  - A script on `cdn.example.com` referenced by `www.example.com` counts against
    `https://cdn.example.com` (D1): `www` at its cap does not stop the script's names.
  - A response with 12,000 distinct names beyond the cap prints "more than 10,000".
  - An origin-check body with 1,200 names gives 1,000 hostnames and its own WARN line; it does
    not use the fronted service's places.
  - D15's pin for banners.
- **B8.** With `--passive`, and without `--authorised`, the five procedures do not run and no
  name from the fixtures above is recorded; no site is contacted.
- **B9.** A doc test (`docsSection`, `## Hostnames in responses`) for: "anywhere", banners,
  "1,000", "more than 10,000", `--redo`, `--passive`; and one that `## Passive boundary` says the
  reading sends nothing.
- **Failures and re-runs.**
  - An external dependency failing: a script fetch that times out fails that job only; the other
    scripts' names are taken, and the next run retries it and takes its names. A crawl whose root
    fetch errors records nothing and reserves nothing in the budget (the next job of the service
    still has all its places). An undecodable or binary body gives no names and no error.
  - One item failing in a batch: covered by the script case above, and by a page that errors
    mid-crawl (skipped, the rest still read).
  - Interrupt part-way: a run cancelled during a slow crawl stores nothing from that job, keeps
    what earlier jobs stored, and still prints the WARN of a service already over its cap. No
    secret is involved in this change (no key, no credential); the existing redaction tests cover
    job keys.
  - Re-run after success: nothing is sent and the files are byte-identical. Re-run after the
    partial failure: the cap still holds across both runs (the seed comes from the store).
- **Unchanged tests.** `TestHostnamesIn` and `TestRecordObservations_TXTHostnames` keep their
  cases (adapted to the iterator); `TestDNSRecords_NamesInTXTValues` stays green; the root-help
  test now requires `text_hostname` in the help.

## Conventions

- `CLAUDE.md`: only `internal/egress` does network I/O, and this change adds none; procedures
  read state only through `run.View` and code outside a procedure never names one (the `View`
  method and `EndWarner` name none); knowledge packages are pure (`dnsname` stays so); a
  `Job.Key` encodes what changes the work (none changes: the keys are as before, by the
  out-of-scope decision on old engagements); `Run` returns negative results as completed jobs.
- Stable interfaces: this adds the kind `text_hostname` and its attributes `service` and `name`
  (D7), and renames nothing. No envelope key is added.
- Testing: `t.Parallel()` first; harness environment only; behaviour tests in `internal/cli`;
  targeted tests without `-race` while iterating, `make test` and `make lint` before finishing.
- Doc tests read `README.md` and `docs/*.md`; a sentence a test names stays in its `## ` section.
- Australian English in docs, comments and messages; commit prefixes `feat:`, `docs:`, `test:`.

## Handed to later specs

- **Spec 4.** Names are taken from text only when `Scope.RootOf` gives a root (D11), so a name in
  scope by its address, and names under its registrable domain, stay ignored as Spec 4 B9 wants,
  as long as Spec 4 does not make `RootOf` answer for such a name. `crawl` and `jsparse` no longer
  take a linked host by `WebHostInScope` (D2), so a link to a name in scope by address gives a
  `url` row and no `hostname` record. TXT text (`recordHost`) drops an excluded name; web text
  records it as excluded.

# Implementation

## Develop

Base commit: 2e555820648adfa2fc479599d5509bf2eaad0d6e

Frozen test files (staged before the code was written; only additions since):
`internal/knowledge/dnsname/dnsname_test.go`, `internal/recon/procedures/web/names_test.go`,
`internal/recon/procedures/ports/ports_test.go`, `internal/cli/endwarning_test.go`,
`internal/cli/textnames_test.go`, `internal/cli/textnames_banner_test.go`,
`internal/cli/textnames_docs_test.go`. All failed on their assertions against stubs, except the
tests that pin existing behaviour (B8 under `--passive` and without `--authorised`, the Shodan
banner, a host's own name making no seed, the sitemap `<loc>` that the crawl already took as a
link, the banner-size pin and the empty end warning).

How it was built:

- **Reader (D10).** `dnsname.HostnamesIn` is one pass over the bytes with a byte-class table, a
  253-byte name buffer and in-line escape decoding (`decodePercent`, `decodeBackslash`,
  `decodeAmpersand`). Where D10 is silent: with `cut`, an escape the text ends inside counts as
  reaching the end; `\u` or `\x` without digits rejects, as `\w` does; a backslash and one or two
  digits separates, taking the digits. `escapes_test.go` (new, not frozen) pins those, and a test
  that no prefix of an escape-heavy text panics or gives an invalid name. The TXT caller ranges
  over it with `cut` false and carries D10's comment.
- **Cap (D13 to D15).** `internal/recon/procedures/web/names.go`: `textNames` (the job-local
  collector and its `read` of sorted header values then the body), `takeable` (D11's rule),
  `textBudget` (`admit`, `EndWarning`), `textUnit` (a service's unit stores `text_hostname`
  records; an origin check's has its own cap and stores none) and `commitText`, called once at the
  end of a successful `Run`. `run.View.TextHostnames` gives the seed, built once per pass from all
  `text_hostname` records. `Runner.passes` defers `endWarnings`, which warns every `EndWarner`
  held in the run state, sorted. The WARN reads `<unit>: <n> hostnames in its responses were left
  out: at most 1,000 are taken from one web service`; for an origin check the unit is
  `origincheck of <host> at <addr>` and the end is "one origin-check response".
- **Procedures.** `httpprobe` reads every hop of the chain after `certAttrs`, skipping any name the
  job already observed as a hostname; `crawl` reads in `fetchPage` and no longer takes link hosts
  (`crawler.hosts` is gone); `jsparse` reads every response `fetchScript` hands to a callback and
  commits before its early returns (its `hosts` map is gone); `origincheck` gets an input with the
  pair and the scope; `ports` reads `egress.Open.Banner` with `cut` at `egress.MaxBanner`, uncapped.
- **Docs (D17).** `docs/sources.md` `## Hostnames in responses`, a sentence in
  `docs/passive-boundary.md`, the four procedure descriptions, and `docs/todo.md`.
- **Other test changes.** `TestHelp_ProceduresTopicTable` (`help_layout_test.go`) pinned the old
  `origincheck` description, which D17 changes; its expected text was updated. The help goldens
  (`help-root`, `help-help`, `help-export`, `help-procedures`) were regenerated: `text_hostname`
  in the kind list, and the new descriptions. The existing exact-set tests in
  `web_crawl_test.go`, `jsparse_test.go` and `web_redirect_test.go` passed unchanged.
- **Failing on the base too** (not this change's; both already in `docs/todo.md`):
  `go test ./internal/cli/ -run 'TestSetup_FailedSaveKeepsTheEdits$' -count=20` fails 20/20 here
  and 20/20 on the base; `go test ./internal/lookup/iplookup/ -run 'TestActive_EndToEnd$'
  -count=20` fails 20/20 here and 20/20 on the base.
- No external fact differed from `## External facts`.
- **After verification (D19).** `TestHostnamesIn_HyphensAtTheEnds` (`escapes_test.go`) was written,
  seen to fail and staged before the reader changed. With the user's agreement, the frozen
  `TestHostnamesIn` case `-bad.example.com` now expects `bad.example.com`.
- **Mutation checks** (each edit made by hand, the tests run, the edit undone by hand), all caught:
  - reader, a Latin letter separating instead of rejecting: `TestHostnamesIn_NonASCII`,
    `TestHostnamesIn_BrokenEscapes`;
  - reader, a `%XX` escape not consuming its digits: `TestHostnamesIn_EscapedLinks` (the
    linear-time test also hung, as the decoded `%` then re-reads the same digits for ever);
  - budget, `<=` for `<` at the cap: five `TestTextBudget_*` tests;
  - B6, names under no root taken: `TestTextNames_NameUnderNoRootIsIgnored`; own name and input
    root taken: `TestTextNames_OwnNameAndInputRootAddNothing`;
  - B7, the probe's redirect and SAN names using a place: `TestTextNames_RedirectTargetAndSANUseNoPlace`;
  - B2, `crawl` sending a second GET of a page that names a host: `TestTextNames_ReadingSendsNothing`.

## Known limitations

- **B4.** Percent-encoded non-ASCII text (`%E4%B8%AD`) rejects a name it touches, where literal
  Chinese text separates (D10's escape rule against B4's wording); an HTML reference without its
  semicolon reads its digits greedily, so `https:&#x2F&#x2Fapi.example.com` gives `pi.example.com`.
  Both are in `docs/todo.md` with D10's other inexact readings.
- **B7.** Not pinned by a test: that header keys are walked in sorted order, the plain-mode WARN
  line on stderr (only the `--json` warnings and events are checked), and that a job past 10,000
  stops scanning (seen only through "more than 10,000").
- **B7.** `crawl` also reads the redirect responses `httpprobe` read, and D11's exemption is
  `httpprobe`'s alone, so with the crawl on a redirect target or SAN that a response names uses a
  place through the crawl (consistent with D8). The tests of the exemption run with
  `--crawl-pages 0`.
- `TestHostnamesIn_Linear`'s one-second limit has about two to three times headroom under `-race`.

## Simplify

Four reviewers (reuse, simplification, efficiency, altitude) read the change against the base
commit.

Fixed:

- `textBudget` holds its `textUnit`; `budgetOf(u)` builds it, so the warning's "per" text has one
  source (`perService`) and `commitText` no longer patches `from` after construction.
  `newTextBudget(service, seed)` stays for the frozen unit tests.
- `takeable` lost its `skip` parameter (one caller): `httpprobe`'s `chainNames` composes its own
  "already observed as a hostname" exception, and drops a redundant `over` check.
- `readText` checks the job's set before calling `keep`, so a repeated name costs no scope lookup;
  its unreachable `return !c.over` is `return true`.
- `EndWarning` sets the number inside each case.
- `withRunState` returns the run state, so `endWarnings` takes it directly (no context lookup and
  no branch that cannot run).
- `View.TextHostnames` is cached on the `Runner` by the `text_hostname` kind version, so
  `httpprobe`, `crawl` and `jsparse` share one build instead of one per procedure run (D13 said
  "once per pass"; it is now once per change of the kind). `crawl.Jobs` reads it and the scope
  once, not once per service.
- `dnsname.HostnamesIn`: one dispatch switch for plain bytes, non-ASCII characters and escapes;
  `highClass` holds the non-ASCII rule written three times before; `nameReader` drops `active`,
  `last` and `labels` (derivable from `buf`).
- `dnsname.MaxNameLen` is exported and `learn.go`'s copy of 253 removed (D10 says they are one
  limit).
- `docs/sources.md`: the JSON escape example had lost its `/` (rendered as `/`), as D9
  describes for the spec; restored.

Skipped:

- Wrapping `egress.TargetHTTP` once per `Run` so every response is read without per-procedure
  hooks: a restructure of four procedures that moves the favicon exclusion and `httpprobe`'s
  exemption point, beyond a cleanup; D12 names the hook points.
- A `Scope` method for "strictly below a root" (`takeable`, `bannerNames`, TXT): D18 dropped it.
- A generic `View.AllRecords` in place of `TextHostnames`: D13 asks for the index method.
- An allocation-free byte-level form of `HostnamesIn` (about 25% faster on minified JS): adds a
  second API for a reader that is not the bottleneck (`ExtractEndpoints` is).
- Embedding `escape` in `decoded`, and having `hexEscape`/`numericReference` return `decoded`:
  longer literals and churn in a heavily tested decoder for little gain.
- Moving `thousands` to `internal/term/layout`: one user so far.
- Building the `text_hostname` index from keys instead of `Attrs`: it would duplicate the kind's
  key format.
- Lazy `seen` map in `bannerNames`, and building the origin-check unit name only when names were
  read: negligible.
- Test duplication and cost in the frozen test files (`wantTaken` twice, `hostnameKeys` against
  `reverseip_test.go`'s method, `withPorts` against `newPorts`, `storedBanner` against
  `kinds.DecodeBanner`, repeated warning filters and number regexes, `tnNames` against hand loops,
  `xmlBody`/`plainText` against `icon`, the 4 MiB `TestTextNames_ScriptBodyCap` run, and the
  1,000-to-13,000-name end-to-end cap tests): the files are frozen (only additions).

# Verification

## Result

Checked against the base `2e55582` (32 files; `docs/specs/2026-11-spec-recursive-discovery-4.md`,
the next spec, is untracked and not part of this change). `go test ./...` passes apart from
`TestSetup_FailedSaveKeepsTheEdits` and `TestActive_EndToEnd`, which fail on the base too and are in
`docs/todo.md`; `make lint` reports 0 issues. The external facts are from the standards' text and
`github.com/miekg/dns`'s source, and none is marked assumed or unconfirmed.

- **Goal.** Met: the four Done-when places (a page comment, an escaped JSON string in a script, a
  `Content-Security-Policy` wildcard and an SMTP banner) each give a listed and resolved hostname,
  and what is sent is unchanged.
- **B1.** Met: every hop of `httpprobe`'s chain, every live response of `crawl.fetchPage` (pages,
  redirect hops, `/robots.txt`, sitemaps, non-2xx), every response `fetchScript` receives, the
  `origincheck` answer and every banner `ports` reads (plain and `|reported`), whichever names its
  address serves. Shodan's `reported_port` banners are not read.
- **B2.** Met: the reading is pure (`dnsname.HostnamesIn` over bytes already received), and the
  request-count tests show no extra request; a found name is probed and crawled.
- **B3.** Met: the body is read with `cut = Response.Truncated`, a banner with
  `cut = len == egress.MaxBanner`; header values are never cut.
- **B4.** Partly met. Every listed form gives `api.example.com` and none gives the escape's
  remains; `2fa.example.com`, `www.example.com.evil.net`, upper case, `bücher.example.com` and CJK
  prose behave as stated. Two gaps from `## Known limitations` stand: percent-encoded non-ASCII
  text (`%E4%B8%AD`) rejects a name it touches, where B4 has Chinese text separate (D10's rule for
  an escape that gives a byte of 0x80 or more), and a reference without its semicolon reads its
  digits greedily (B4's example has its semicolons, so it is met as written). Found and fixed in
  verification: the decomposed form of `bücher.shop.example.com` (`u` and U+0308) gave
  `cher.shop.example.com`, because a combining mark has the Inherited script and so was a
  separator; a combining mark of the Inherited script now rejects a run it touches and separates
  elsewhere (`highClass`, `nameReader.touching` in `dnsname.go`; `TestHostnamesIn_CombiningMarks`
  in `escapes_test.go`). Also seen, and allowed by D10 as written: a run with a leading or trailing
  hyphen gives nothing, so a comment written `<!--api.example.com-->` gives no name (see
  `# Follow-ups`).
- **B5.** Met: `*` separates and the leading dot is trimmed.
- **B6.** Met: `takeable` needs a root strictly above the name and leaves out the job's own host;
  an excluded name is recorded and shown as excluded; the sensitive-path and favicon responses are
  not read. Corrected in verification: `docs/sources.md` said a name is left out when "a label
  starts with `_`"; the reader leaves out a name with an underscore anywhere, and the sentence now
  says so.
- **B7.** Partly met. The cap of 1,000 per web service over the engagement (probe, crawl and the
  scripts an origin serves, links included, known names included, kept names kept), the one WARN
  per service at the end with the exact number or "more than 10,000", the origin check's own cap
  and the banner pin all hold. The gap is the one in `## Known limitations`: `httpprobe` takes a
  redirect target or SAN outside the cap, but `crawl` reads the same responses and pages, so with
  the crawl on such a name uses a place through the crawl; `## Tests` asks that it use none, and
  the test passes only with `--crawl-pages 0`. Put to the user under `# Follow-ups`.
- **B8.** Met: the five procedures are `Target` procedures, gated as before; the canary test passes.
- **B9.** Met: `docs/sources.md` `## Hostnames in responses`, the sentence in
  `docs/passive-boundary.md`, the four procedure descriptions and `docs/todo.md`.

Changed before the code review: the combining-mark fix and its test, and the underscore sentence
in `docs/sources.md`. The `dnsname`, `dns`, `recon` and text-name behaviour tests pass after them.

## Code review

`/code-review high --fix` ran on the changed files. Its written report never reached this session
(the review agent finished without handing one back), so this section rests on the working tree:
the review made one edit.

- **Fixed: the end warning's grammar for one name** (`textBudget.EndWarning`,
  `internal/recon/procedures/web/names.go`). One name left out now reads "1 hostname in its
  responses was left out" instead of "1 hostnames ... were". It touches B7's WARN line, whose
  wording D14 leaves to the developer; the unit, the number and "1,000" are unchanged. Kept.

Nothing was left unfixed, and no test file changed (the frozen files show no diff against the
index). After the review, `make test` (with `-race`) fails only on `TestSetup_FailedSaveKeepsTheEdits`
and `TestActive_EndToEnd`, which fail on the base too and are in `docs/todo.md`; `make lint` reports
0 issues; the text-name, banner, origin-check and end-warning behaviour tests pass 3 times in a row.

# Follow-ups

- **Scripts shared between services (B7):** settled by D1 (the serving origin).
- **Redirect and certificate names the crawl reads (B7):** accepted, D20.
- **Percent-encoded non-ASCII text (B4):** accepted, D21.
- **Hyphens at the ends of a run (B4):** trimmed, D19.
- **Tests that fail on the base too, D10's inexact readings, `crawl`'s `url` rows for hosts the cap
  left out, old banners under a new root:** in `docs/todo.md`.
- **Test gaps in B7:** in `docs/todo.md` under CI improvements/fixes.

**Manual steps:**

1. **A live run** against a domain you are authorised to test, to see what the reading finds and
   how many misread names it lists: `nyx recon --authorised --output-dir /tmp/nyx-live <root>`,
   then compare `subdomains.txt` with `unresolved.txt` and look for the WARN lines of B7.
