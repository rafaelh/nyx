# Features to add

- Standalone domain enumeration as `domain`. Find and print subdomains and other obtainable records,
  print DMARC with any issues.

- Add the capability to define an internal scope of assets, IPs, domains, etc to identify automatically.
  If a domain has been reconned recently, should it resolve from those files?

- Evaluate the difference in approach that  https://github.com/blacklanternsecurity/bbot uses for scanning.

- Add a lookup of known bulletproof hosting providers - https://github.com/crimsonvector/BPH_Research and compare with the following free threat feeds:

  - ThreatFox, a project between abuse.ch and SpamHaus, provides threat reports for ASNs. See ThreatFox. To search for an ASN, enter the ASN number in the URL: https://threatfox.abuse.ch/asn/[ASN #].

# CI improvements/fixes

- **Two tests fail every time on macOS** (seen on cd8a75e and later, 2026-11-23):
  - `go test ./internal/lookup/iplookup/ -run 'TestActive_EndToEnd$' -count=10`: 10/10 fail with
    "port 21 = no-answer, want closed" (and 3306). A connection to a closed loopback port times
    out instead of being refused, probably because of the local firewall.
  - `go test ./internal/cli/ -run 'TestSetup_FailedSaveKeepsTheEdits$' -count=5`: 5/5 fail. The
    100-column test window cuts the long `/var/folders/...` temporary path short with `…`, so the
    asserted reason and path never appear whole. A wider `h.winW` in the test would fix it.
- **`TestLearnedNames_InterruptKeepsCompletedNames` depends on timing.** It cancels the run once
  three slow (100 ms) learning lookups have been asked and asserts only that some, not all, names
  were kept. Watch it for flakiness on slow CI machines.
- **`TestAbusiveDocs_GiveTheSnapshotDates` fails every time** (20/20 on the base commit a79fd35, so
  not a regression): after `make threat-data`, the docs don't give the date of the built-in Spamhaus
  asndrop list, 2026-11-24. The fix is to update the five dates in `docs/abusive-networks.md`.

# Documentation gaps

- **`docs/console-and-json.md` doesn't exist.** `README.md`, `docs/release-preparation.md` and
  `CLAUDE.md` link to it for the log, the summary, terminal layout and the `--json` envelope. So no page documents the envelope's keys, including the
  ones renamed after procedures and jobs (`failed_jobs`, `meta.jobs_completed`,
  `meta.jobs_cancelled` and the `procedure` key of its rows). The links to its
  `#terminal-layout` and `#the---json-envelope` anchors go nowhere either.

# Refactoring opportunities

Each item is one piece of work. Several output-side items (the showing rule, the "excluded"
counting rule, source names, the provider rule) may change what users see, so check before treating
them as pure refactors.

## Suspected bugs

Confirm each with `/code-review` before fixing.

- **Refresh tool writes `stated: 0`.** When only one ipapi.is page is newer and the kept list is
  an old file with no `stated`, `internal/threatdata/refresh` writes `stated: 0` for it. Every
  built-in list has a `stated` now, so it happens only if an old snapshot is restored; a guard in
  `refresh.go` would close it.


## Design changes

- **Scope build.** Separate the egress Policy from the scope build, and derive `scopeKinds` from a
  table.

- **Procedure-owned behaviour.** Move the procedure-specific `View` queries out to the procedures
  that use them, and make procedure descriptions and the unskippable rule procedure interfaces.

- **Config settings table.** One table driving every setting in `config`: the biggest maintenance
  win, since each integer setting is listed in five places. It's a redesign of `Load`, and because
  flag help order is fixed the table must cover every flag, not just the integers.

- **Egress HTTP.** Give each request kind its own case in `targetHTTP.do`, place API keys once per
  source instead of at every call site, and export `ErrHTTPTimeout`.

- **Crawler script allowlist.** Reconcile the script allowlist with the crawler's anchor
  workaround.

- **Cloud storage in one place.** Bucket URLs are worked out in both `cloudstorage` and the storage
  procedure, and the storage procedure reads CNAMEs the inventory already indexes (needs a new seam in
  `inventory`).

- **Shared redaction.** One redaction walker shared by `config` and `cli/export`, possibly
  reflection-based.

- **Consolidate `dnsname`.** Rename `input.NormaliseHost` to `dnsname.Normalise` (about 30 files),
  and move the SRV/MX writer next to its parser.

- **Provider "fronts a site" rule.** Give the provider data its own rule.

- **Shared helpers.** Shared hash and atomic-write helpers (five copies of the atomic write now,
  `threatdata` included), and one polled-flock helper for `threatdata` and `engagement`; shared
  test fixtures, including a scope builder in `testkit` and the copied test helper that strips
  escapes.

- **Numeric port order.** Sort `OpenPorts` with `AddrPort.Compare`. Changes the order users see
  from text to numeric.

- **Stop `learned-names` enumeration at the cap.** Its `Jobs` yields the whole backlog every pass
  and lets the runner defer what is over `learned_names.max_names`, so on a very large engagement
  (thousands of labels times hundreds of zones) a pass yields millions of jobs and fills
  `procedureRun.all`. Stopping enumeration once the budget is spent needs a runner change: a way
  for `Jobs` to learn the remaining budget, or for the runner to stop pulling jobs while still
  counting the deferred cost the summary reports. The same change would let the cap's rank order
  hold across the passes of a run; today it holds within each pass only.



Too big for a clean-up pass (redesigns):
In the runner and store: caching completed jobs, writing only changed analysis rows, re-reading only changed keys, and not encoding each observation twice.
A Describer interface to generate procedure help from the procedures.
Splitting recon/report into a shared console package.
Applying the "confirmed port supersedes reported port" rule in one place.
One Listed rule shared by the output files and changes.csv.
Moving storage attribution out of findings.
Normalising addresses in one layer.
One atomic file-writer helper for five call sites.
Rendering the summary from one list of blocks.


## Architecture

internal/cli has about 4.2k lines of code and about 40k lines of tests across 93 files. That's intentional (behaviour tests drive cli.Execute), but it means one package does most of the test work and Go can't split it across packages in parallel. If make test gets slow, the option is to move the harness into an exported internal/clitest and split the tests by command (ip, cve, setup, recon). It's not worth doing until the time hurts.

