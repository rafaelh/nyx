# Spec 14: end-of-life software

## Goal

A web server, framework or network service whose detected version is past the end of security
support for its release cycle is reported as a finding, from versions nyx already captures.

## Behaviours

1. nyx embeds a table of products and the end of security support of each release cycle, as
   endoflife.date records them, for each product endoflife.date tracks that nyx can version
   from Wappalyzer or from SSH, FTP and SMTP banners. The README lists the products, the data
   source and the date the data was taken. A run warns once when the embedded data is older than
   twelve months.
2. A version whose cycle's end date is on or before the run date (UTC) is a medium finding of type
   `eol` in `risk-eol-software.csv`: target (the service URL, or `ip:port` with a hostnames column
   as in `risk-ports.csv`), product, version, end date and where it was seen (`web` or `banner`).
   Each end-of-life product on a service or port is its own finding. A version carrying a
   distribution suffix (`Debian`, `Ubuntu`, `CentOS`, `+deb`, `~bpo` and the like) is one step
   lower (low) with `distribution build` in the detail. A version known only from a Shodan port
   report is one step lower and marked unconfirmed, as in Spec 4.
3. A cycle whose end date is after the run date and within `eol_warn_days` (default 90, flag
   `--eol-warn-days`, minimum 1, 0 disables) is a low finding of type `eol-approaching`.
4. A version that cannot be matched to a cycle in the table produces no finding.
5. SSH, FTP and SMTP banners in `open-ports.csv` gain `product` and `version` columns when the
   banner is recognised (OpenSSH, Dropbear, ProFTPD, vsftpd, Pure-FTPd, Postfix, Exim, Sendmail,
   Microsoft IIS/FTP and Exchange SMTP at least, listed in the README); unrecognised banners leave
   both empty. Values are sanitised like other target text. Existing engagements gain the columns
   on their next run without new contact.
6. Findings are re-derived on every run from the latest probe and banner records and the run
   date, so one may appear with no new contact when the date passes an end date or the table
   changes, and under `--passive` they come from records kept from earlier runs. A finding goes not
   current when `--redo httpprobe` or `--redo ports` no longer shows that version. Only in-scope web
   services and port-eligible addresses are assessed, as for other findings. Both types appear in
   the `--help` severity table and the file in the README output table.

# Design

**Status: review before building (wave 3).** The parts that read Shodan's ports depend on Spec 4,
which is not built yet. Everything else is complete, and was re-checked against the built specs on
2026-11-14 with no correction; after Spec 4 merges, re-read the items marked *Review*. **Depends
on:** Spec 4 (`reported_port`, the `confirmed` column and the "one step lower" rule,
`open-ports.csv`'s merged rows).

## Decisions

- **End-of-life data is embedded data in a pure package**, `internal/eol`: one JSON file per
  product as endoflife.date publishes it, under `internal/eol/data/`, a `products.yaml` that maps
  a detected name (a Wappalyzer technology or a banner product) to a product file and says how a
  version maps to a release cycle (major, or major.minor), and a `DATE` file with the day the data
  was taken. `eol.Lookup(name, version) (cycle, end string, ok bool)` and `eol.DataDate()`.
- **The data is refreshed by a `make eol-data` target that uses `curl`**, not by Go code: no
  first-party package may import a network package or `os/exec`. The target rewrites the JSON
  files and `DATE`; the diff is reviewed and committed.
- **Banner recognition is pure**, in `internal/banner`: `Parse(banner string) (product, version
  string, distro bool)` for the listed SSH, FTP and SMTP servers, where `distro` is true when the
  version carries a distribution suffix. It reads the stored banner, so `open-ports.csv`'s
  `product` and `version` columns are derived on read and existing engagements gain them on their
  next run with no contact.
- **Findings are derived**, in `internal/findings/eol.go` (category `eol-software`, file
  `risk-eol-software.csv`): for each shown web service, each `Name:version` technology; for each
  shown open port, the parsed banner. Past the end date is `eol` (medium); within `eol_warn_days`
  is `eol-approaching` (low); a `distro` version is one step lower with `distribution build` in
  the detail; no cycle match means no finding. The key is `eol-software|<type>|<target>|<product>`
  so each product on a target is its own row. *Review:* a version known only from a
  `reported_port` banner is one step lower with `confirmed: no`, using Spec 4's helper.
- **Columns**: `severity`, `target`, `hostnames`, `type`, `product`, `version`, `end_date`,
  `seen` (`web` or `banner`), `confirmed`.
- **`eol_warn_days`**: default 90, minimum 0, where 0 disables the approaching type; flag
  `--eol-warn-days`.
- **Stale data warning**: at the start of a run, if the run date is more than twelve months after
  `eol.DataDate()`, the runner emits one warning that is not limited to `--verbose`.

## Changes

- `internal/eol/`, `internal/banner/`. `Makefile`: `eol-data`.
- `internal/findings/eol.go`, `table.go`, `records.go`, `findings.go`.
- `internal/output/ports.go`: `product`, `version` (*Review:* the file Spec 4 creates).
- `internal/config/config.go`: `eol_warn_days`. `internal/run/runner.go`: the warning.
- `README.md`: products, data source and date, banners recognised, the file, the severity table.

## Tests

- `internal/eol`: lookups across cycle shapes, an unknown product, an unmatched version; every
  product named in `products.yaml` has a data file.
- `internal/banner`: each listed server, distribution suffixes, unrecognised banners.
- `internal/findings`: past, approaching, future, the date boundary (on the end date is `eol`),
  the distribution step, several products on one service, `eol_warn_days: 0`, an out-of-scope
  service and an ineligible address.
- `internal/cli/eol_test.go`: findings appear with no contact when the clock passes an end date
  and under `--passive` from stored records; `--redo httpprobe` with a new version marks the old
  finding not current; `open-ports.csv` columns on an existing engagement; the stale-data warning;
  `--help` and the README table.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **A finding that is no longer derived keeps only what its key holds (Specs 3 and 12).** The
  store keeps attributes only from current observations. The key
  `eol-software|<type>|<target>|<product>` gives such a row its type, target and product; its
  version, end date and severity are blank, as in every risk file.
- **Version banners are not a source (Spec 12).** `web-services.csv` has a `version_disclosure`
  column read from `Server` and `X-Powered-By`. Versions come only from Wappalyzer technologies
  and port banners here, as `## Out of scope` says; do not read that column.
- **Findings layout (Spec 12).** A category is its own file in `internal/findings`, with its
  rows appended to `table`, one entry in `riskFiles` and one line in `deriver.findings()`.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.
- **Console text (Spec 22).** If Spec 22 has merged, the stale-data warning is a WARN line. It is
  already meant to show without a flag.

## Out of scope

CVE matching; products endoflife.date does not track; versions from sources other than
Wappalyzer and banners.

# Implementation

## Develop

`internal/eol` embeds one JSON file per product as endoflife.date publishes it (`data/<product>.json`),
`products.yaml` (a list of `product`, `cycle` and `names`) and `DATE`. `Lookup(name, version)` finds the
product by name (any case), takes the leading dotted number of the version and returns the cycle named
by its first `parts` numbers, where `cycle: major|minor|patch` in `products.yaml` gives `parts` as 1, 2
or 3. When no cycle has that length it tries fewer, so Jetty (`12.1` and `11`) and PostgreSQL (`9.6`
and `16`) need only their longest. `Names()` lists the names for the README test. `make eol-data` reads
the product list from `products.yaml`, downloads each file with `curl` through `jq -S` and writes
`DATE`; the data in the tree was taken on 2026-11-17 for the 40 products listed in the README.

`internal/banner` has `Parse(text) (product, version, distro)` and `Distro(version)`. Callers decode
the stored banner with `kinds.DecodeBanner` (the inverse of `kinds.EncodeBanner`, falling back to the
raw text); `Parse` tries an ordered list of rules (SSH rules anchored to the line start) and reports `distro` when the text after the product on the same line (or the version
itself, for `Distro`) carries a distribution name or package mark. `findings.eolSoftware`
(`internal/findings/eol.go`) assesses each `Name:version` technology of a shown web service and the
parsed banner of each shown open port; for a port only Shodan reports, or one whose own banner names
no version, it reads the `reported_port` banner and marks `confirmed: no`. The key is
`eol-software|<type>|<target>|<product>` (`Finding.Key`; `ParseKey` drops the product from the target,
and `riskFile` takes it from the key for a row that is not current). The hostnames of a port come from
a `deriver.hostnamesByIP` helper that `ports()` now shares. `Settings.EOLWarnDays` (`--eol-warn-days`,
`eol_warn_days`, default 90, at least 0) follows the five-line settings recipe. `Runner.Run` calls
`warnStaleEOLData`, which warns once per run (through `r.warn`, so it shows without a flag) when the
run date is after `DataDate` plus twelve months. `open-ports.csv` gains `product` and `version`,
read from the banner the row shows. A new finding is announced with `FoundText` ("end-of-life Nginx
1.18.0 on https://…"), so two products on one service are not two identical lines.

Tests: `internal/eol/eol_test.go`, `internal/banner/banner_test.go`, `internal/findings/eol_test.go`,
`internal/config/risk_test.go` (`TestEOLWarnDaysSetting`) and `internal/cli/eol_test.go`.

| Behaviour | Tests |
|---|---|
| 1 (table, README, stale warning) | `TestFind_CycleShapes`, `TestLookup_EmbeddedData`, `TestProducts_EveryEntryHasData`, `TestDataDate_IsADate`, `TestMakefile_DownloadsTheListedProducts`, `TestEOL_StaleDataWarning`, `TestEOL_DocumentedInReadmeAndHelp` |
| 2 (`eol`, distribution, Shodan, columns) | `TestEOL_WebTechnologiesPastTheEnd` (columns, key, several products), `TestEOL_CycleWithNoKnownEndDate`, `TestEOL_DateBoundaryAndWarnWindow` (on the end date), `TestEOL_DistributionBuildIsOneStepLower`, `TestEOL_PortBanners`, `TestEOL_PortBannerDistributionBuild`, `TestEOL_VersionReportedByAThirdParty` (reported only, confirmed, no banner from nyx, closed), `TestEOL_FindingsFromTechnologiesAndBanners` |
| 3 (`eol-approaching`, `eol_warn_days`) | `TestEOL_DateBoundaryAndWarnWindow` (the edge of the window, a narrower one, 0), `TestEOL_WarnDaysFlag`, `TestEOLWarnDaysSetting` |
| 4 (no match, no finding) | `TestFind_CycleShapes`, `TestLookup_EmbeddedData`, `TestEOL_NoFindingWithoutAMatch` |
| 5 (`open-ports.csv`) | `TestParse`, `TestParse_ValuesAreSanitised`, `TestDistro`, `TestEOL_FindingsFromTechnologiesAndBanners`, `TestEOL_PortColumnsOnAnExistingEngagement` (old header rewritten, no contact) |
| 6 (re-derived, `--passive`, not current, scope, help, README) | `TestEOL_ClockMovesFindingsWithNoContact` (clock passes the end date under `--passive`), `TestEOL_RedoProbeWithANewVersion`, `TestEOL_OnlyShownServicesAndEligibleAddresses`, `TestEOL_ExcludedServiceIsNotAssessed`, `TestEOL_KeyAndFile`, `TestEOL_SeverityTable`, `TestSeverityTable` (extended), `TestEOL_DocumentedInReadmeAndHelp` |

Existing tests changed because the behaviour changed: the `open-ports.csv` header in
`TestPortsPlumbing_OpenPortsCSV` and `TestShodanHost_PassiveShowsOpenAndRiskyPorts`, the default file
list in `internal/output`, and the findings files list in `TestFiles`.

Interpretations and deviations:

- **A cycle endoflife.date lists as ended with no date (`"eol": true`, such as jQuery 1.x and Node.js
  1 to 3) is `eol`**, with an empty `end_date` and "endoflife.date gives no date" in the detail. The
  spec speaks only of dates; dropping these would hide the oldest, worst versions. A cycle with
  `"eol": false` (no end announced, such as Apache HTTP Server 2.4) matches nothing.
- **Fewer of the cycle's parts are tried when the product names its cycles by more** (see above); the
  spec says only "major, or major.minor", and a third shape (`patch`) was needed for ProFTPD,
  OpenSSL and Magento.
- **`eol_warn_days` has minimum 0**, as the design says, though behaviour 3 says "minimum 1, 0
  disables"; both mean a 0 turns the type off and a negative is refused.
- **`product` is the name as detected** (Wappalyzer's `Apache HTTP Server`, the banner's `ProFTPD`), and
  `confirmed` is `yes` for a web service, which nyx probed itself.
- **The version is sanitised by construction, not by a `sanitize.Text` call.** Every rule captures
  only digits, letters and dots, so no terminal-acting character can reach `version`; a call to
  `sanitize.Text` after that was dead code (no test could fail without it), so it was left out.
  `TestParse_ValuesAreSanitised` pins the outcome.
- **A web `Name:version` with a distribution suffix is judged by `banner.Distro`** on the version
  string, the same rule as for banners.
- Of the banners behaviour 5 lists, only ProFTPD, Postfix and Exim are products endoflife.date tracks
  that a banner can version. OpenSSH, Dropbear, vsftpd, Pure-FTPd, Sendmail and Microsoft IIS FTP are
  recognised (their columns fill) but have no table entry, and Exchange is recognised as `Microsoft
  Exchange`, whose banner version is a build number no cycle names (endoflife.date names its cycles
  `2016`, `2019`). The README says so.

Mutation checks (each broken by hand, the named tests failed, then undone by hand): the end date
compared with `<` instead of `<=` and the window edge likewise (`TestEOL_DateBoundaryAndWarnWindow`);
the distribution step removed (`TestEOL_DistributionBuildIsOneStepLower`,
`TestEOL_PortBannerDistributionBuild`); the unconfirmed step removed, and Shodan's banner no longer
the fallback when nyx's names no version (`TestEOL_VersionReportedByAThirdParty`); cycle lookup not
falling back to fewer parts, and `"eol": true` not counted as ended (`TestFind_CycleShapes`,
`TestLookup_EmbeddedData`); the product dropped from the key (`TestEOL_WebTechnologiesPastTheEnd`,
`TestEOL_KeyAndFile` and others); `open-ports.csv`'s `product` and `version` left empty
(`TestEOL_FindingsFromTechnologiesAndBanners`, `TestEOL_PortColumnsOnAnExistingEngagement`); the stale
warning one day early (`TestEOL_StaleDataWarning`); the distribution names cut (`TestParse`, `TestDistro`);
the version rule widened to any non-space characters (`TestParse`, `TestParse_ValuesAreSanitised`);
the `eol_warn_days` minimum lowered (`TestEOLWarnDaysSetting`); web services read without the
showing rule, and open ports without it (`TestEOL_OnlyShownServicesAndEligibleAddresses`,
`TestEOL_ExcludedServiceIsNotAssessed`). The first `sanitize.Text` mutation passed, which is why that
call was removed (see above) and the check made on the version rule instead.

External facts that differed: endoflife.date's `/api/<product>.json` lists `eol` as a date string,
`false` or `true`, not only a date (the design assumed dates). `iis`, `openssh`, `vsftpd`, `pure-ftpd`,
`sendmail`, `dropbear` and `lighttpd` are not products it tracks.

## Known limitations

- Behaviour 1: the table is a snapshot, so a cycle that endoflife.date shortens or lengthens after
  2026-11-17 shows only after `make eol-data` and a new build (a run more than twelve months on warns).
- Behaviour 2: a version known only from a Shodan port report keeps Shodan's banner cut to its first
  line and 256 characters, so a banner whose version is on a later line gives no finding.
- Behaviour 2: a Wappalyzer technology whose name is not in `products.yaml` (the table maps exact
  names only) gives no finding, and a name like `Spring` is Wappalyzer's guess at the Spring
  Framework, whose cycles may not match the version it reads.
- Behaviour 5: the Exchange banner rule reads only `Version:` from the `Microsoft ESMTP MAIL Service`
  text, so a modern Exchange that prints no version has the product and an empty version.
- Behaviour 6: `--redo ports` is covered only through the derivation (a finding is derived from
  current records only); there is no test that redoes the real `ports` stage, which the harness
  replaces with a fake.

## Simplify

Fixed:

- `findings.eolSoftware` reads web services through the cached `d.services()` instead of filtering
  them again; the horizon is always computed (a window of 0 makes it today, which the `eol` case
  already takes), so the empty-horizon guard is gone; and `add` takes the port and works out
  `seen` and the hostnames itself, only after `eol.Lookup` matches (so an OpenSSH banner no longer
  builds the hostname index).
- `banner.Parse` takes the banner's text; callers decode the stored form with the new
  `kinds.DecodeBanner`, beside `EncodeBanner`, so the encoding is known in one package. The
  package doc says `Distro` also reads versions that are not from a banner.
- The product part of an end-of-life key is read with `strings.CutLast`. `keyProduct` and
  the `product` fallback that `riskFile` added for every category are gone: each file's `fromKey`
  now also gets the record key, and the end-of-life file's returns the product.
- `FoundText` builds the shared "product version on target" once (the dead `TrimSpace` is gone).
- `products.yaml`'s entry is a named type, used by `load` and by its test.
- Tests: `TestEOL_DateBoundaryAndWarnWindow` runs each case as a subtest (no `wantSetNamed`),
  `TestEOL_KeyAndFile` uses the existing `file`, `cellMap` and `srec` helpers, and the CLI tests
  read `open-ports.csv` rows with `pworld.openRow`.

Skipped:

- Moving the stale-data warning out of the runner into `findings`: one warning does not justify a
  new warnings API, and the design put it in the runner.
- Dropping the `opened` map in `eolSoftware`: it mirrors `ports()`, and relying on the open and
  reported showing rules agreeing is less obvious than the map.
- A `sighting` struct for `eolDetail`'s parameters, a per-category key-suffix field in the risk-file
  table, and indexing each product's cycles by name: more machinery than the one category and
  ~100 cycles per product need.
- Leaving the type out of the end-of-life key (so `eol-approaching` becoming `eol` keeps one row):
  it changes stored keys and the behaviour the tests pin, so it is not a simplification.

# Verification

## Result

The goal is met: a version nyx already captured (a Wappalyzer `Name:version` technology of a shown
web service, or the banner of a shown open or Shodan-reported port) whose cycle has ended is a
medium `eol` finding in `risk-eol-software.csv`, derived on every run with no contact. `make test`
passes (vet for the four targets, then `go test -race ./...`).

- **Behaviour 1: met after a correction.** The table, `products.yaml`, `DATE`, `make eol-data`, the
  README section and the once-per-run stale-data warning (through `r.warn`, no flag needed) are
  as the behaviour asks. The product list was short of the behaviour: of the products
  endoflife.date tracks (its `/api/all.json`) that wappalyzergo v0.3.8 can version from headers,
  cookies, HTML, scripts or meta tags, 24 were missing (Vue.js, React, Ember.js, Next.js, Jenkins,
  Atlassian Bitbucket, Artifactory, Discourse, Concrete CMS, Backdrop, Umbraco, Shopware,
  SonarQube, Gerrit, YouTrack, Apache APISIX, Kong, Neos CMS, Perl, Lua, CouchDB, Subversion,
  Jekyll and Varnish, which endoflife.date now calls `vinyl-cache`). They were added to
  `products.yaml`, downloaded with `make eol-data` (the data is still dated 2026-11-17), listed in
  the README, and `TestLookup_EmbeddedData` covers Jenkins, Varnish and Concrete CMS's mixed cycle
  shapes. Left out on purpose: operating systems (Debian, FreeBSD, SUSE) are not a web server,
  framework or network service; Erlang's fingerprint captures `otp/…` text rather than a number;
  SharePoint's header gives a build number no cycle names; a second `SonarQubes` fingerprint
  duplicates `SonarQube`. Sixteen names in the list (Spring, Ruby on Rails, Laravel, Symfony,
  Node.js, Express, Angular, MySQL, MariaDB, PostgreSQL, Elasticsearch, GitLab, Nextcloud, Moodle,
  RoundCube, Zabbix) are fingerprints wappalyzergo v0.3.8 detects but cannot version, so they give
  no finding today. They are harmless and will work if a later wappalyzergo versions them. The
  known limitation still applies: the table is a snapshot taken when the data was downloaded.
- **Behaviour 2: met after a correction, with one inherited limit.** The type, severity, columns,
  target and hostnames, one row per product, the Shodan-only step and `confirmed: no` all match
  the behaviour, and so does the distribution step for banners. For web services the distribution
  step never applied: Wappalyzer reports `Apache/2.4.41 (Ubuntu)` as `2.4.41` and
  `PHP/7.4.3-4ubuntu2.19` as `7.4.3`, so the version it stores never carries a suffix (the
  existing test fed Wappalyzer a version it would never produce). `eolSoftware` now also reads the
  `Server` and `X-Powered-By` value that carries the version (the web service's `server` and the
  `web_posture` record's `version_disclosure`), only to find the suffix, never the version.
  `TestEOL_DistributionBuildFromTheHeaders` (findings) and `TestEOL_DistributionBuildFromTheProbe`
  (CLI, real probe) pin this, and the README says it. Inherited limit (a known limitation, not
  agreed in `## Out of scope`): a Shodan banner is kept only up to its first line and 256
  characters, so a version on a later line is missed.
- **Behaviour 3: met.** `eol_warn_days` defaults to 90 and is set by `--eol-warn-days`. 0 turns the
  type off and a negative value is refused, which is what "minimum 1, 0 disables" amounts to.
  The edge of the window is covered by tests.
- **Behaviour 4: met.** An unknown product, a version no cycle matches, a cycle with no end
  announced and a technology with no version give no finding.
- **Behaviour 5: met.** All the listed banners are recognised and listed in the README. The
  columns are derived on read, so an existing engagement gains them on its next run with no
  contact (tested). The version is limited to digits, letters and dots, and the product is a
  fixed string. A modern Exchange banner gives the product with no version (a known limitation;
  recognition is still met).
- **Behaviour 6: met, with one gap in the tests.** Findings are re-derived on every run from
  current records and the date, including under `--passive`, and only shown services and eligible
  addresses are assessed. A redo that no longer shows the version marks the finding not current,
  and both types are in the severity table (now in `nyx help findings`, where an earlier spec
  moved it) and the README. `--redo ports` is tested only through the derivation, not with the
  real `ports` stage (a known limitation).

Changed during verification: `internal/eol/products.yaml`, 24 new `internal/eol/data/*.json`,
`internal/eol/eol_test.go`, `internal/findings/eol.go` (`headerDistro`),
`internal/findings/eol_test.go`, `internal/cli/eol_test.go` and `README.md`. The table now has 64
products, not the 40 that `## Develop` names. golangci-lint could not run here (the installed binary
was built with Go 1.26, and `go.mod` targets 1.27.3).

## Code review

`/code-review high --fix` reported seven findings. Four were fixed, each checked against the spec,
and `make test` passes:

- **Cycles longer than declared (behaviours 1 and 4).** Laravel was `cycle: major` but names 5.x
  cycles `5.8` and `5.5`, and Ruby was `cycle: minor` with `2.0.0` and `1.9.3`, so those (the
  oldest, ended) cycles could never match. Laravel is now `minor`, Ruby `patch`, and
  `TestProducts_EveryEntryHasData` fails when a data file names a cycle longer than its entry
  declares; `TestLookup_EmbeddedData` covers Laravel 5.8 and Ruby 1.9.3 and 2.7.8.
- **`make eol-data` could write an empty file (behaviour 1).** Under `sh`, `set -e` saw only
  `jq`'s status in `curl | jq`, so a failed download replaced a data file with an empty one and
  the product silently left the table. curl now writes to a file first, so a failure stops the target.
- **Banner names inside hostnames (behaviour 5).** `220 postfix.example.com ESMTP Exim 4.94.2` was
  read as Postfix with no version. A name or version found anywhere in the line must now end at
  something other than a dot, letter or digit; `TestParse` gained the hostname cases.
- **Multi-word distribution comments (behaviour 2).** `headerDistro`, added during verification,
  read only the first word of `(Red Hat Enterprise Linux)`. It now reads a comment to its closing
  parenthesis; `TestEOL_DistributionBuildFromTheHeaders` gained that case.

Left unfixed:

- **A very large `eol_warn_days`** (millions of days) pushes the horizon past year 9999, where the
  string comparison of dates fails and approaching findings vanish. Fixing it needs an upper
  bound the spec does not give, or a change to how dates are compared; only absurd values trigger it.
- **`open-ports.csv` can lack a version its finding has**: the row's `product` and `version` come
  from the banner the row shows (nyx's own when it has one), while the finding falls back to
  Shodan's banner when nyx's names no version. The README documents the columns this way.
- **Dropping `cycle:` from `products.yaml`** (trying every length from the version's own): a design
  change; the new test guards against the drift it would remove.

# Follow-ups

1. Run golangci-lint with a build made by Go 1.27.3 or later, which this machine lacks:
   `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest && golangci-lint run ./...`.
2. Confirm `--redo ports` against a host you are authorised to test, since no test drives the real
   `ports` stage: run `nyx <root> --authorised --output-dir /tmp/nyx-eol`, change or stop the
   service's banner, run `nyx -e <engagement> --authorised --output-dir /tmp/nyx-eol --redo ports`,
   and check that the old row of `/tmp/nyx-eol/<engagement>/risk-eol-software.csv` is not current.
3. Refresh the end-of-life data before 2027-11-17, when runs start warning: `make eol-data`, review
   `git diff internal/eol`, commit, and rebuild.
4. Decide whether `eol_warn_days` needs an upper bound (very large values make approaching findings
   vanish); the setting is in `internal/config/config.go` (`posInt("eol_warn_days", ...)`).
5. Decide whether `open-ports.csv` should take `product` and `version` from Shodan's banner when
   nyx's banner names no version, as the findings do (`openPortRows` in `internal/output/ports.go`).
6. Decide whether to drop `cycle:` from `internal/eol/products.yaml` and try every length of the
   version, so a refresh that adds a longer cycle name cannot be missed.
