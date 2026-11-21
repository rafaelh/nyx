# Features to add

- Standalone domain enumeration as `domain`. Find and print subdomains and other obtainable records,
  print DMARC with any issues.

- Add the capability to define an internal scope of assets, IPs, domains, etc to identify automatically.
  If a domain has been reconned recently, should it resolve from those files?

- Evaluate the difference in approach that  https://github.com/blacklanternsecurity/bbot uses for scanning.


# CI improvements/fixes

None currently.

# Refactoring opportunities

Each item is one piece of work. Several output-side items (the showing rule, the "excluded"
counting rule, source names, the provider rule) may change what users see, so check before treating
them as pure refactors.

## Suspected bugs

Confirm each with `/code-review` before fixing.

- **Blank row in `resolutions.csv`.** A DNS claim that is no longer current writes a blank row.

- **Stale records skip the showing rule.** Historical addresses and code mentions that are no
  longer current stay listed after their host or root is excluded.

## Design changes

- **One showing rule.** Make which entities the files list a single Visibility rule (today
  `changes.go` copies the rules from `output`), and keep the "excluded" counting rule in one place.

- **Candidate rules in `internal/candidates`.** Move the candidate roll-up rules and the ranking
  there. Revisit the `CandidateExempt` plumbing, which serves one stage.

- **No hard-coded stage or source names.** Remove the hard-coded "asn" stage name from finding
  announcements and from `BuildScope`, and take source names from stage data.

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

- **Shared helpers.** Shared hash and atomic-write helpers; shared test fixtures, including a scope
  builder in `testkit` and the copied test helper that strips escapes.

- **Numeric port order.** Sort `OpenPorts` with `AddrPort.Compare`. Changes the order users see
  from text to numeric.

## Performance

- **Skip rewriting unchanged output files.** The biggest win found: up to about 33 fsyncs per pass.
  Comparing with the file on disk would stop the `render-mid-file` crash test reaching its fault
  point, so the runner must keep state between passes instead.

- **Presorted output rows.**

- **Store write path.** Prepared statements, fewer SQL statements per observation, encoding
  observation attributes to JSON only once, and diffing `SaveShown` instead of rewriting every row.

- **Incremental passes.** Cache each stage's completed checks between passes, and refresh changed
  records incrementally.

- **HTTP connection reuse.** Needs rate limiting reworked.

- **Small gains, left alone so far.** Each is minor on its own:
  - cache the inventory's CNAME chains and per-scope results (about 5–10 ms per stage, but touches
    shared infrastructure);
  - cache the per-address hostname lookup that is computed three times per render;
  - let a caller in `scope` or the stages tokenise an organisation name once, not on every match;
  - speed up `indexRegistrants` (runs once per inventory);
  - decode each web service's attributes only once (about 3 ms per 5k services);
  - a non-JSON fast path for encoding finding attributes (risks changing stored values).
