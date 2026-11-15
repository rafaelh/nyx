# Spec 9: third parties from SPF, DMARC and MX, and MTA-STS posture

## Goal

The user sees which outside services an organisation authorises to send its mail, receive its mail
reports or host its mailboxes, in the one third-party inventory, and whether each mail-receiving
root publishes an MTA-STS policy.

## Behaviours

1. For each in-scope input root, every domain the SPF walk follows (`include:` and `redirect=`, as
   far as the email check already goes) plus every domain named by `a:`, `mx:` or `exists:` at any
   level is a row in `third-parties.csv` with mechanism `spf`, the root, and the depth (0 for a
   domain the root's own record names, 1 for one named by a record that record includes, and so on;
   amended 2026-11-14 to count from 0, as the file built by Spec 3 does). Arguments containing
   macros are skipped. A domain equal to or under an in-scope root, or sharing the registrable
   domain of the root it was found on, is not a third party. An include with no SPF record is still
   listed. A SERVFAIL on any include fails the root's email check as today, so that run records no
   third parties for the root.
2. Each DMARC `rua=` and `ruf=` URI (comma-separated, size suffix such as `!10m` removed,
   non-`mailto:` URIs ignored) contributes its mailbox domain with mechanism `dmarc`. The row
   belongs to the root whose policy it is, including when the policy came from the organisational
   domain.
3. Each MX host whose registrable domain is not in scope is a row with mechanism `mx`, using the
   host's registrable domain.
4. Each in-scope hostname whose CNAME chain ends at a provider entry of class SaaS is a row with
   mechanism `cname`. Wildcard-dropped and excluded names are not listed. `provider-hosts.csv` is
   unchanged.
5. One row per root, mechanism and domain. A `provider` column shows the provider name when the
   domain is on a built-in list of mail and SaaS providers named in the README (for example
   `_spf.google.com` shows Google); the domain is never replaced.
6. Third-party domains are not added to `candidates.csv`.
7. Rows follow the standard `current`, `first_seen`, `last_seen` columns. After `--redo email`
   (or `--redo dnsroot`, `--redo resolve` for the mechanisms those stages feed), a third party no
   longer referenced is marked not current.
8. A `+` line is printed per new third party as for other finds, and the summary shows
   `N third parties`. The stage runs under `--passive`.
9. For each in-scope input root with at least one non-null MX record, the email stage also reads
   the TXT records at `_mta-sts.<root>`. `email-posture.csv` gains an `mta_sts` column: `present`
   when exactly one TXT record there begins `v=STSv1`, `absent` otherwise, and empty for roots
   without MX. A subdomain root's value does not fall back to the organisational domain. A
   timeout or SERVFAIL on that lookup fails the root's email check, as for SPF and DMARC. Absence
   is the low finding `mta-sts-missing` in `risk-email.csv`, and the README row for that file
   mentions MTA-STS. The policy file over HTTPS is never fetched. The added lookup is part of the
   email check, so existing engagements re-run their email checks once.

# Design

**Status:** ready to build (wave 2). Specs 3 and 15 have merged, and the design was re-checked
against them on 2026-11-14: the depth now counts from 0, the deriver goes in `derive.go`, and the
rows use the `third_party` kind as built. **Depends on:** Spec 3 (the `third_party` kind, its
showing rule, `third-parties.csv`, `provider.DomainOwner`) and Spec 15 (the runner's
derived-records hook, `newDerivers()`).

## Decisions

- **SPF, DMARC and MX third parties are observations of the email check.** `spfEval` already
  walks the record; it additionally collects `{domain, depth}` for each `include:` and
  `redirect=` it follows and each `a:`, `mx:` and `exists:` argument, skipping macros. The depth
  is 0 in the root's own record and one more in each record followed, which is how the built file
  counts it (`ns` rows are depth 0). DMARC
  `rua` and `ruf` are parsed from the record the check already holds. The check emits
  `third_party` observations beside `email_posture`, so a failed check records none (behaviour 1)
  and `--redo email` retires stale ones (the stage is already `Retiring`).
- **What counts as a third party is decided on read**, not in the stage: the stage drops only a
  domain sharing the registrable domain of the root it was found on; Spec 3's `OutsideAttr` rule
  hides any domain that is, or later becomes, in scope.
- **The domain is kept as written** for `spf` and `dmarc` rows (`_spf.google.com`), and is the
  registrable domain for `mx` rows. `provider` comes from `provider.DomainOwner`, whose
  `domains:` list this spec extends with mail and SaaS providers. `DomainOwner` matches by
  suffix, so `_spf.google.com` matches a `google.com` entry. An `mx` row holds a registrable
  domain, so each new entry is written at the registrable domain (`outlook.com`, not
  `protection.outlook.com`), or it could never match an `mx` or `ns` row. The stage sets
  `provider` when it records the row, as `dnsroot` does.
- **Rows use the kind as built.** The key is `<root>|<mechanism>|<domain>`. The mechanisms `spf`,
  `dmarc`, `mx` and `cname` become constants beside `MechanismNS`. `kinds.ThirdPartyOf` gains them
  in its key fallback (the key's last part is the domain), so a row that is no longer current
  still shows its root, mechanism and domain. Its depth is not in the key and shows 0.
- **`cname` rows are derived, then stored**, so they are printed, counted and dated like the
  others: a `thirdparty-cname` deriver, one entry in `newDerivers()` in `internal/run/derive.go`
  (`reads`: the `hostname`, `resolution` and `wildcard` kinds, and not `third_party`, which it
  writes and stages also write; `writes`: `kinds.ThirdParty`; `derive`: a call to the pure
  `internal/thirdparty`), emits one `third_party` record per
  root and provider suffix for each in-scope, non-wildcard-only hostname whose CNAME chain ends at
  a SaaS-class entry. A row whose hostname stops pointing there loses its observation and goes not
  current, which is what `--redo resolve` produces. `provider-hosts.csv` is not touched. The
  runner leaves every kind a deriver writes out of the findings' signature, so `third_party` will
  be left out of it; no finding reads that kind, and a test pins that none does.
- **MTA-STS is part of the email check**: when the root has a non-null MX, one TXT lookup at
  `_mta-sts.<root>`; `mta_sts` is `present` for exactly one `v=STSv1` record, else `absent`; a
  timeout or SERVFAIL fails the check. The check key, `<root>|dkim=<hash>` as built, gains a
  `|mta-sts` token so existing engagements run it once; the old checks are retired.
- **Finding**: `mta-sts-missing` (low) in the `email` category when `mta_sts` is `absent`.

## Changes

- `internal/stages/risk/email.go`: SPF collection, DMARC URIs, MX domains, MTA-STS, key token.
- `internal/kinds/table.go`: `MTASTS` at the end of `EmailPostureAttrs`.
- `internal/thirdparty/` (pure): the `cname` derivation. `internal/run/derive.go`: one entry in
  `newDerivers()`.
- `internal/kinds/thirdparty.go`: the four mechanism constants and the `ThirdPartyOf` fallback.
- `internal/provider/providers.yaml`: mail and SaaS `domains:` entries.
- `internal/output/evidence.go`: `mta_sts` column. `internal/findings/findings.go`, `table.go`.
- `README.md`: the new mechanisms in the `third-parties.csv` row, the depth of an included
  record, the provider list, `email-posture.csv` and `risk-email.csv` rows.

## Tests

`internal/cli/email_third_parties_test.go`, with `egresstest`:

- Includes two deep give depths 0 and 1; `a:`, `mx:`, `exists:` are listed; macros are skipped; an
  include with no SPF record is listed; a SERVFAIL on an include records nothing for the root.
- `rua`/`ruf`: several URIs, a `!10m` suffix, a non-`mailto:` URI, and a policy inherited from
  the organisational domain (the row belongs to the root).
- MX rows use the registrable domain; an in-scope MX host is not listed.
- A domain under another in-scope root is hidden, including when that root is added later.
- `cname` rows for SaaS chains only; wildcard-only and excluded names are not listed; the row goes
  not current after the CNAME changes and `--redo resolve`, and that row still shows its root,
  mechanism and domain.
- One row per root, mechanism and domain; the `provider` column; nothing in `candidates.csv`;
  the `+` line and the `N third parties` count; the stage runs under `--passive`.
- MTA-STS: `present`, `absent`, empty without MX, no fallback for a subdomain root, SERVFAIL
  fails the check, the finding, and an existing engagement re-running its email checks once. The
  canaries see no HTTPS request for the policy file.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **A record that is no longer current has no attributes (Spec 3, follow-up 1).** The store keeps
  them only from current observations, which is why `ThirdPartyOf` reads the key. If the store is
  changed to keep a record's last attributes, the fallback added here goes with the others.
- **The `domains:` lookup (Spec 3).** `dnsroot` asks `DomainOwner` about a name server's
  registrable domain, so an entry deeper than a registrable domain never matches there. Route 53
  name servers (`awsdns-NN.<tld>`) have no entry for the same reason. Neither changes here.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.
- **Derivers (Spec 15).** A deriver runs after every stage that did work and before every render,
  and is skipped while its `reads`, the inputs and the date are unchanged. It must read nothing
  outside `reads`, the scope and the inventory.
- **Console text (Spec 22).** The `+` line of a new third party is the kind's own `Found` line,
  already built. If Spec 22 has merged it is asserted on stderr; if not, on stdout.

## Out of scope

Fetching the MTA-STS policy; TLS-RPT; resolving third-party domains.

# Implementation

## Develop

Built as designed. The email check (`internal/stages/risk/email.go`) now collects third parties
beside `email_posture`: `spfEval` records each `include:`, followed `redirect=` and `a:`/`mx:`/
`exists:` argument with the nearest depth it was named at (0 in the root's own record, one more per
record followed); DMARC `rua`/`ruf` come from the record the check already holds; MX hosts become
registrable domains. A failed check returns no observations, so it records none. The check key gains
`|mta-sts`, and a root with a non-null MX asks for the TXT records at `_mta-sts.<root>`
(`mta_sts` is `present` for exactly one `v=STSv1` record, else `absent`). The `cname` rows come from
the pure `internal/thirdparty.CNAME`, which reads `Inventory.ProviderHosts` (already wildcard- and
exclusion-aware) for SaaS-class CNAME evidence; it is one `thirdparty-cname` entry in `newDerivers()`.
`kinds` gained the four mechanism constants, `ThirdPartyOf`'s key fallback covers them, `providers.yaml`
gained mail and SaaS `domains:` entries at registrable domains, and `mta-sts-missing` (low) is in the
findings table and `email()`. The README documents the mechanisms, the provider list, the new column
and the finding.

Tests: `internal/cli/email_third_parties_test.go` covers every behaviour (SPF depths and mechanisms,
macros, no-SPF include, include SERVFAIL; DMARC URIs and the inherited policy; MX; later-added roots;
`cname` rows and `--redo resolve`; one row per key and the `provider` column; no candidates; the `+`
line, the count and `--passive`; MTA-STS present, absent, empty, no fallback, SERVFAIL, the one-time
re-run and no HTTPS request). Unit tests: `internal/thirdparty`, `ThirdPartyOf` in `kinds`,
`DomainOwner` for the new entries in `provider`, the severity table and `email()` in `findings`, and
the new column in `output`. `healthy()` in `risk_email_test.go` now publishes an MTA-STS record, and the
subdomain-root test one for its root, so the existing posture tests still expect no new finding.

Deviations and readings of the design:

- The stage drops a domain sharing the root's registrable domain for `dmarc` and `mx` rows as well as
  `spf` (the design's general sentence), so a subdomain root whose MX is in its organisational domain
  lists no `mx` row for it.
- A `redirect=` the record's own `all` makes unreachable is not followed, so it is not listed.
- A `cname` row is made for any SaaS-class entry on the chain, not only the last hop (the same
  evidence `provider-hosts.csv` uses). Its root is the most specific input root that covers the name.
- `ptr:` is not listed (the behaviour names `a:`, `mx:` and `exists:`). An argument that is not a
  valid domain name is skipped like a macro, and a CIDR length (`a:host/24`) is stripped.
- The spec lists no external facts, so none differed.

Mutation checks: `## Tests` marks none, so these are extra, each undone by hand afterwards. Every one
made at least one test fail: the depth of a followed include (`depth+1` to `depth`), the
registrable-domain drop in the email stage, swallowing the `_mta-sts` error instead of failing the
check, running the MTA-STS lookup for roots without MX, and dropping the SaaS-class test in the
`cname` derivation.

## Known limitations

- Behaviour 1: a domain named at several depths shows the nearest; the depth of a not-current row
  shows 0 (the key has no depth), as the design says.
- Behaviour 4: a name whose chain reaches two SaaS suffixes gets a row for each.
- Behaviour 5: the provider list is a hand-curated starter set; an SPF include or MX host of a provider
  not on it has an empty `provider`.
- Behaviour 9: an `_mta-sts` TXT record with a different `id` or a malformed body counts as `present`
  as long as it is the only record that begins `v=STSv1`; the policy itself is never read.

## Simplify

Fixed:

- The SPF walk adds each named domain straight to the check's third-party collector (`spfEval.tp`), so
  the second depth map and the loop that copied one into the other are gone; the collector's map is
  made at construction, not lazily.
- `dnsname.Registrable` (the registrable domain, or the name itself) replaces the inline fallback in
  the email stage's MX rows and the DNS root stage's NS rows; `kinds.ThirdPartyKey` builds the
  `<root>|<mechanism>|<name>` key at all four writers (ns, txt-verification, the email stage, the
  `cname` deriver).
- `ThirdPartyOf` treats every mechanism other than `txt-verification` as naming a domain, so a new
  mechanism needs no edit there.
- The `_mta-sts` lookup runs alongside the DKIM selectors instead of before them, saving a serial
  round trip per root with MX (a failure still fails the check).
- The `cname` deriver is a named function like `rankCandidates`; `reportDomains` uses `CutPrefix`.
- `Scope.RootOf` (the most specific in-scope root of a name, beside `ClassifyHost`) replaces the
  `thirdparty` package's own `rootOf`, so `CNAME` no longer takes a second copy of the roots.
- Tests: the new `(*world).mustPassive` (which shadowed `(*web).mustPassive`) is replaced by
  `runRoot`; `riskTypes` by `col(current(...))`; `domains` is `slices.Sorted(maps.Keys)`; the
  finding-and-column test folds into the absent MTA-STS case; a tautological constants test, a
  one-element loop, a duplicated DNS seed and a redundant suffix loop are gone; the `thirdparty`
  test helper no longer returns an always-nil error.

Skipped:

- Deriving `DomainOwner` from the SaaS fingerprint entries instead of repeating their suffixes under
  `domains:`, and asking `DomainOwner` with the full MX/NS host: both change the provider package and
  how not-current rows are filled in, beyond this change.
- Applying the same-registrable-domain drop to `ns` rows (or deciding it on read): it would change
  the DNS root stage's output.
- A generic check-version token in place of `|mta-sts`, and inlining the constant: the token is the
  designed key change and the tests depend on it.
- Memoising `Inventory.ProviderHosts`, now called by both the takeover findings and the `cname`
  deriver: a change to the inventory outside this diff, for a cost only large engagements notice.

# Verification

## Result

Checked against the code on 2026-11-15. `make test` passes (vet for the four targets, then
`go test -race ./...`). `golangci-lint` could not run: the installed binary was built with Go 1.26
and `go.mod` targets 1.27.3.

- **Goal: met.** SPF, DMARC, MX and SaaS CNAME dependencies land in `third-parties.csv` beside the
  `ns` and `txt-verification` rows, and `email-posture.csv` says whether each root with a mail host
  publishes an MTA-STS record.
- **B1: met, except the depth of a row that is no longer current.** `spfEval.walk` names each
  `include:`, each followed `redirect=` and each `a:`/`mx:`/`exists:` argument (CIDR length
  stripped) at the record's depth, before following, so an include with no SPF record is listed;
  macros and malformed names are skipped. A domain sharing the root's registrable domain is dropped
  in the stage, and one in scope is hidden on read by `OutsideAttr` (also for a root added later,
  and for a not-current row through the key fallback in `thirdPartyRows`). An include SERVFAIL sets
  `tempErr`, the check returns an error and no observations. A not-current row shows depth 0, since
  attributes are kept only from current observations (a known limitation the design accepted; the
  README now says so). A domain named at several depths shows the nearest, which the behaviour
  leaves open.
- **B2: met.** `reportDomains` splits on commas, lower-cases, keeps only `mailto:`, strips `!size`
  and takes the mailbox domain; the rows are keyed to the check's root, including when the policy
  came from the organisational domain.
- **B3: met, with one reading.** Each non-null MX host gives its registrable domain, hidden on read
  when that domain is in scope. The stage also drops an MX domain that shares the root's own
  registrable domain, so a subdomain root (`sub.example.com`) whose MX is `mail.example.com` lists
  no `mx` row though `example.com` itself is not in scope. That follows B1's rule and the goal
  ("outside services"), not B3's literal wording; see Follow-ups.
- **B4: met, with one reading.** The `thirdparty-cname` deriver lists, per root and suffix, each
  in-scope, non-wildcard-only hostname with a SaaS-class CNAME entry anywhere on its chain (the same
  evidence `provider-hosts.csv` uses), not only at its last hop, so a chain `x → *.zendesk.com →
  a CDN` gets a `zendesk.com` row. Excluded and wildcard-only names are skipped by
  `Inventory.ProviderHosts`; `provider-hosts.csv` is untouched. The deriver's `reads` (hostname,
  resolution, wildcard) plus the inputs cover everything the CNAME evidence and the classification
  of names under an input root depend on.
- **B5: met.** One record per `<root>|<mechanism>|<domain>` key; `provider` comes from
  `DomainOwner`, and the README names every provider the new `domains:` entries add.
- **B6: met.** Nothing writes a candidate kind for these domains (`TestEmailThirdParties_OneRowAndProvider`).
- **B7: met.** Standard dated columns; `--redo email` retires an unreferenced row (the stage is
  `Retiring`), `--redo resolve` retires a `cname` row through the deriver, and `--redo dnsroot` is
  unchanged from the built `ns` rows.
- **B8: met.** The kind's `Found` line is printed per new row and counted in the summary as
  `third parties`; the email stage is `ThirdParty` and runs under `--passive`.
- **B9: met.** The `_mta-sts.<root>` TXT lookup runs only with a non-null MX, never at the
  organisational domain; `present` for exactly one `v=STSv1` record, else `absent`, empty without
  MX; a timeout or SERVFAIL fails the check; `mta-sts-missing` (low) is derived from `absent`; the
  README rows for `email-posture.csv` and `risk-email.csv` mention it; no HTTP request is made; the
  `|mta-sts` key token re-runs existing checks once.

Changed while verifying:

- **No test pinned that the findings never read `third_party` (design).** The runner now leaves
  `third_party` out of the findings' signature because a deriver writes it.
  `TestDerivationNeverReadsThirdParties` in `internal/findings` fails if derivation asks for that
  kind.
- **README:** the `third-parties.csv` row says a row that is no longer current shows depth 0.

## Code review

`/code-review high --fix` reported nine issues and fixed four. I kept all four after checking them
against the spec, and fixed one more by hand. `make test` passes afterwards.

Fixed:

- **An MX record naming an address (B3).** The `mx` row is now skipped when the host is an IP
  address instead of being kept as a pseudo-domain. All three mechanisms now check names in one
  place, `thirdParties.add` via `lookupable`, which replaces the inline checks in `spfEval.name`
  and `reportDomains`. `TestEmailThirdParties_MX` now covers an address MX.
- **`mta_sts` had `omitempty` (B9).** The email stage always sets the field, and its empty value
  means "no mail host". Under the rule at the top of `table.go`, a field like that must not be
  omitted, or a field-by-field merge could keep a stale `absent`.
- **The `cname` docs did not match the code (B4).** The `CNAME` doc comment and the README now
  say a SaaS entry at any hop of the chain counts, and that the row goes to the most specific root.
- **The `mta-sts-missing` wording (B9), fixed by hand.** `absent` also covers two or more
  `v=STSv1` records, so the finding's detail, the table description and the README now say "no
  single" or "not exactly one" policy record instead of "no record".

Left unfixed:

- **A failing `_mta-sts` lookup on an existing engagement retires the old email check.** The new
  key's check then fails every run, and the root loses its email posture and findings until the
  lookup succeeds. B9 says the failure fails the check, and the design retires the old checks, so
  changing either is the user's decision.
- **Several SPF domains of one provider print the same `+` line.** For example,
  `_spf.google.com` and its `_netblocks*.google.com` includes each print
  `+ third-party Google via spf on <root>`, and each is counted. B5 and B8 ask for one row and one
  line per domain, so the count is correct. Whether the line should also name the domain is a
  wording decision.
- **The `cname` deriver and the takeover findings both call `Inventory.ProviderHosts`.** Memoising
  it would change the inventory package. Simplify deferred the same change for the same reason.
- **A dead `root == ""` branch in `thirdparty.CNAME`.** It is harmless defensive code.

# Follow-ups

1. Decide whether a `cname` row needs the SaaS entry at the **end** of the chain (B4's wording) or
   at any hop (built, and documented in the README). To narrow it, filter on the last hop in
   `internal/thirdparty/thirdparty.go` (`CNAME`) and update the README `cname` bullet.
2. Decide whether a subdomain root's MX or DMARC domain inside its own organisational domain
   (`sub.example.com` → `mail.example.com`) should be an `mx` or `dmarc` row. Built: it is dropped,
   like B1's same-registrable-domain rule. The behaviour is in `thirdParties.add` in
   `internal/stages/risk/email.go`.
3. Decide whether a timeout or SERVFAIL on `_mta-sts` should keep failing the whole email check.
   Today it does, and on an existing engagement the old check is retired at once, so posture and
   findings vanish until the lookup succeeds. If not, record the error the way DKIM errors are
   recorded, in `Run` in `internal/stages/risk/email.go`.
4. Decide whether the third-party `+` line should name the domain when a provider is known, so
   that `_spf.google.com` and `_netblocks.google.com` print different lines. The line is built in
   `thirdPartyFound` in `internal/kinds/thirdparty.go`, and the README line that describes it must
   change with it.
5. A row that is no longer current shows depth 0, because the store keeps no attributes for it
   (Spec 3, follow-up 1). If the store is changed to keep a record's last attributes, remove the
   key fallback in `kinds.ThirdPartyOf` and the README note.
6. Spot-check the new `domains:` entries in `internal/provider/providers.yaml` against live
   records. For example, run `dig +short TXT _spf.google.com` and `dig +short MX <a real customer
   domain>`, then check that `nyx --passive <domain>` fills `provider` in `third-parties.csv`.
7. Rebuild golangci-lint with Go 1.27 (`go install
   github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`), then run
   `golangci-lint run --new-from-rev=main ./...`. It could not run during verification.
