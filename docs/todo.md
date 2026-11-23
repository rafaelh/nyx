# Features to add

- Standalone domain enumeration as `domain`. Find and print subdomains and other obtainable records,
  print DMARC with any issues.

- Add the capability to define an internal scope of assets, IPs, domains, etc to identify automatically.
  If a domain has been reconned recently, should it resolve from those files?

- Evaluate the difference in approach that  https://github.com/blacklanternsecurity/bbot uses for scanning.

- Add check for known bulletproof hosting providers - https://github.com/crimsonvector/BPH_Research and compare with the following free threat feeds:

  - ThreatFox, a project between abuse.ch and SpamHaus, provides threat reports for ASNs. See ThreatFox. To search for an ASN, enter the ASN number in the URL: https://threatfox.abuse.ch/asn/[ASN #].

# Security fixes

- **Recon dials non-public addresses from public DNS (blind SSRF, medium).** A target can make
  recon send GET/HEAD requests to the operator's own machine, cloud metadata service or internal
  network. The target publishes an in-scope name such as `lo.target.com` with an address such as
  127.0.0.1, 169.254.169.254 or 10.x. It can then redirect from one of its own pages to that name,
  choosing the port (80, 443 or any configured port), path and query.
  - Cause: the resolve stage (`internal/stages/dns/resolve.go`) records every A/AAAA answer, and the
    inventory passes them all into `Policy.Resolutions`. `Policy.vetted`
    (`internal/egress/http.go`), called from `dialAddrs`, drops only addresses the user excluded.
    `dialFirst` tries addresses in order, so a name that answers with `[attacker IP, 127.0.0.1]`
    also reaches loopback once the attacker's address refuses connections. TCP port checks are
    safe, because `PortEligible` refuses an address with no known owner. HTTP doesn't use that
    check.
  - Fix: mirror the `nyx ip --active` rule (`notContacted` in `internal/iplookup/active.go`). In
    `vetted`, or in `dialAddrs` for hostname targets, refuse any address `addrkind` doesn't classify
    as public, with "non-public address from public DNS". Keep allowing addresses inside a netblock
    or literal the user gave as in scope. Apply the same rule to `origincheck` pins and `RootAt`,
    and update `docs/passive-boundary.md`.
  - Test: an `internal/cli` recon test where an in-scope name resolves to 127.0.0.1 and
    169.254.169.254 (through `DialMap`), asserting that no request reaches the canary.
  - Workaround until fixed: exclude the ranges with `-x`, for example `-x 127.0.0.0/8 -x
    169.254.0.0/16 -x 10.0.0.0/8 -x 172.16.0.0/12 -x 192.168.0.0/16 -x ::1/128 -x fe80::/10 -x
    fc00::/7`.

# CI improvements/fixes

- **Two tests fail every time on macOS** (seen on cd8a75e and later, 2026-11-23):
  - `go test ./internal/iplookup/ -run 'TestActive_EndToEnd$' -count=10`: 10/10 fail with
    "port 21 = no-answer, want closed" (and 3306). A connection to a closed loopback port times
    out instead of being refused, probably because of the local firewall.
  - `go test ./internal/cli/ -run 'TestSetup_FailedSaveKeepsTheEdits$' -count=5`: 5/5 fail. The
    100-column test window cuts the long `/var/folders/...` temporary path short with `…`, so the
    asserted reason and path never appear whole. A wider `h.winW` in the test would fix it.

# Refactoring opportunities

Each item is one piece of work. Several output-side items (the showing rule, the "excluded"
counting rule, source names, the provider rule) may change what users see, so check before treating
them as pure refactors.

## Suspected bugs

Confirm each with `/code-review` before fixing.

- **Blank row in `resolutions.csv`.** A DNS claim that is no longer current writes a blank row.

- **Stale records skip the showing rule.** Historical addresses and code mentions that are no
  longer current stay listed after their host or root is excluded.

- **Refresh tool writes `stated: 0`.** When only one ipapi.is page is newer and the kept list is
  an old file with no `stated`, `internal/threatdata/refresh` writes `stated: 0` for it. Every
  built-in list has a `stated` now, so it happens only if an old snapshot is restored; a guard in
  `refresh.go` would close it.

## Missing tests

- **Threat-data TIMEOUT through the command.** `nyx setup --update-threat-data` giving `TIMEOUT` is
  tested only through `threatdata.Update`: the 30 s request timeout can't be shortened through
  `Deps`.
- **Threat data fixed for a whole run.** That every recon pass, not only the final findings, uses
  the threat data loaded when the run started.

## Design changes

- **Scope build.** Separate the egress Policy from the scope build, and derive `scopeKinds` from a
  table.

- **Stage-owned behaviour.** Move the stage-specific `View` queries out to the stages that use
  them, and make stage descriptions and the unskippable rule stage interfaces.

- **Config settings table.** One table driving every setting in `config`: the biggest maintenance
  win, since each integer setting is listed in five places. It's a redesign of `Load`, and because
  flag help order is fixed the table must cover every flag, not just the integers.

- **Egress HTTP.** Give each request kind its own check in `targetHTTP.do`, place API keys once per
  source instead of at every call site, and export `ErrHTTPTimeout`.

- **Crawler script allowlist.** Reconcile the script allowlist with the crawler's anchor
  workaround.

- **Cloud storage in one place.** Bucket URLs are worked out in both `cloudstorage` and the storage
  stage, and the storage stage reads CNAMEs the inventory already indexes (needs a new seam in
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


