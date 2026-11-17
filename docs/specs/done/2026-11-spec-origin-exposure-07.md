# Spec 7: historical DNS and origin exposure

## Goal

nyx records the historical addresses of CDN-fronted hostnames, and when such a hostname's
origin server is also reachable directly it reports the exposed origin as a medium finding,
confirmed by one GET to an address nyx is already allowed to contact.

## Behaviours

1. A `dnshistory` stage, keyed on `keys.securitytrails` and available under `--passive`, fetches
   the historical A and AAAA records of each in-scope hostname that currently resolves to a known
   CDN or WAF provider, up to `dnshistory.max_hosts` per run (default 200, in hostname order,
   remainder deferred and reported in the summary). Each historical address is a row in
   `resolutions.csv` with type `A-historical` or `AAAA-historical` and `historical_first_seen` and
   `historical_last_seen` columns from the source. Historical addresses appear in `ips.csv` but
   are never treated as current addresses: they are not probed, port-checked or used for
   wildcard detection by virtue of being historical.
2. An **origin candidate** for a fronted hostname is an address whose owner is known and is not
   provider infrastructure, and which is either a historical address of that hostname, or the
   current address of another in-scope, non-wildcard-only hostname that is not itself behind a
   CDN or WAF and whose certificate names the fronted hostname or whose non-empty page title
   equals the fronted hostname's. At most `origincheck.max_candidates` (default 5) per hostname
   are checked: historical addresses most recent first, then siblings.
3. An `origincheck` stage (target contact, skipped under `--passive` and until authorisation)
   performs one check per (fronted hostname, candidate) pair, but only when the candidate is
   inside an in-scope netblock, or is the current address of an in-scope non-wildcard-only
   hostname with a known, non-shared owner (the port-eligibility rule), and is not excluded. Any
   other candidate is reported as an unconfirmed possible origin and never contacted. No check is
   created until the probe has a 2xx result for the fronted hostname; if that title or
   certificate later changes, the pair is checked again.
4. The check is one HTTPS GET of `/` on port 443 with both the TLS server name and the Host
   header set to the fronted hostname, falling back to one HTTP GET on port 80 only when nothing
   answers on 443 (not on a TLS error). Redirects are not followed and a 3xx confirms nothing. At
   most one GET per scheme per check.
5. The exposure is **confirmed** when the response's non-empty title equals the fronted
   hostname's probe title and that title is not on a built-in list of CDN, WAF and default-server
   titles, or when the response has the same status as the probe and a body length within 10% of
   it and the certificate names the fronted hostname. The probe records body length to support
   this. A certificate match alone, or any other outcome, leaves the pair a possible origin.
6. `risk-origin-exposure.csv` has one row per (hostname, address): the CDN or WAF provider, the
   address, how the candidate was found (`historical`, `sibling-certificate`, `sibling-title`,
   `;`-joined), what confirmed it, and `confirmed` (`yes`/`no`). Confirmed rows are medium
   findings; possible origins are low. The console `+` line reads `medium origin exposure
   <hostname> -> <address> (behind <provider>)`. The README output table and `--help` severity list
   include them.
7. A finding is marked not current when the pair no longer qualifies (the hostname is no longer
   behind a CDN or WAF, the address becomes provider infrastructure, or the sibling no longer
   matches) or when `--redo origincheck` fails to confirm it.
8. Without a SecurityTrails key, `dnshistory` is `not-configured (no key)` and `origincheck` runs
   over sibling-derived candidates only.
9. The README's passive-boundary section says nyx may send one GET of `/` to an address it is
   already allowed to contact, with an in-scope hostname as the server name and Host header, and
   why; `origincheck` joins the list of stages skipped under `--passive`.

# Design

**Status: review before building (wave 3).** Specs 2, 5 and 6 have merged, and the items that
waited on them were settled against the code on 2026-11-14. Spec 18 has not merged: after it
does, re-read the one item still marked *Review*. The point under "Settle before building" needs
an answer first. **Depends on:** Spec 5 (Cloudflare and Fastly ranges, the class passed through
as `Result.Class`, `provider.ClassCDN`), Spec 6 (`run.Budgeted`), Spec 18 (the target TLS
configuration and `Response` TLS accessors), Spec 2 (the `resolutionRows` merge it extends).

## Settle before building

**Akamai addresses in Linode's published list (Spec 5, follow-up 1).** A published range beats
the ASN, and Linode's list holds about 739 /24s in 104.64.0.0/10 that AS20940 (Akamai, class
`cdn`) announces. Those addresses are therefore dedicated. That is wrong twice for this spec. A
hostname whose A record is one of them is not `Fronted` by the address test. And such an address
counts as "not provider infrastructure", so it can be chosen as an origin candidate, be contacted
(it is port-eligible) and confirm an exposure that is not one, because the CDN edge serves the
fronted site's own title. Recommended: in `provider.Classify`, an address whose ASN entry has
class `cdn` stays shared, with that class, even inside a dedicated published range. That amends
behaviour 2 of Spec 5, so it is the user's decision. If the answer is no, this spec needs another
way to keep those addresses out of the origin candidates, and a test either way.

## Decisions

- **"Behind a CDN or WAF" is an inventory question.** `inventory.Fronted(host) (provider string,
  ok bool)` is true when a CNAME on the host's chain matches an entry of class `cdn` or `waf`, or
  one of its addresses classifies as `cdn`. CNAME entries in `providers.yaml` gain those classes
  (CloudFront, Azure Front Door, Cloudflare, Fastly, Akamai, and WAF providers). As built,
  `Result.Class` carries the class of the range rule or ASN entry that classified the address
  (`provider.ClassCDN` for Cloudflare's and Fastly's ranges and for every `cdn` ASN entry), so the
  address test is `Class == provider.ClassCDN`. CNAME entries carry only `class: saas` today and
  no `waf` class exists. This spec adds `provider.ClassWAF` and the `cdn` and `waf` classes on
  CNAME entries. `SaaSServed` compares the class with `saas`, so the new classes change nothing
  for sensitive paths. If an `asn:` entry is ever given `waf`, it must be shared, as `cdn` is.
- **`dnshistory`** (`internal/stages/dnshistory`, keyed on `securitytrails`, third-party) yields one
  check per fronted in-scope hostname in name order, `Budgeted` by `dnshistory.max_hosts` (default
  200): `Budget` returns the setting and each check has `Cost` 1. It records `historical_address`
  (`host`, `addr`, `type`, `first_seen`, `last_seen`) and an `ip` observation for each address.
  Nothing that decides contact reads `historical_address`; the `ip` record makes the address appear
  in `ips.csv` and get an owner lookup, and it stays ineligible for ports and probing unless the
  existing rules already allow it.
- **Candidate selection is pure**, in a new package `internal/origin`:
  `Candidates(fronted, historical, services, inv, scope, max)` returns, per fronted hostname, up
  to `origincheck.max_candidates` (default 5) addresses with how each was found and whether it may
  be contacted (inside an in-scope netblock, or port-eligible; and not excluded). The same function
  feeds the stage's checks and the findings, so they cannot disagree.
- **`origincheck`** (target contact) yields a check per contactable pair once the fronted
  hostname's HTTPS service has a 2xx status, keyed `<host>|<addr>|<hash of the probe's title and
  certificate subject>`; the stage is `Retiring`, so a changed title or certificate re-checks and
  retires the old evidence.
- **The request is a new, narrow egress constructor**, `egress.OriginCheck(host, scheme, addr)`:
  GET `/` on 443 or 80, dialling `addr`, with the server name and Host header `host`. The policy
  enforces what the stage intends: `host` is in scope, and `addr` is not excluded and is inside an
  in-scope netblock or port-eligible. It does not require `addr` to be one of `host`'s resolved
  addresses, which is the one way it differs from `RootAt`. HTTP on 80 is tried only when 443 gave
  `NoService` with a reason other than `tls-failed`. *Review:* Spec 18's TLS configuration applies
  because the request goes through `targetHTTP.do`.
- **Evidence**: `origin_check` (key `host|addr`): `scheme`, `status`, `title`, `body_len`,
  `cert_names_host`. The probe records `body_len` of its first response in `WebServiceAttrs`.
- **Findings** (`internal/findings/origin.go`, category `origin-exposure`, key
  `origin-exposure|<host>|<addr>` so the row is stable when it moves between possible and
  confirmed): `confirmed` (medium) by the rules of behaviour 5 with a built-in list of CDN, WAF
  and default-server titles in `internal/origin`; otherwise `possible` (low), including pairs that
  may not be contacted. The finding carries a `line` attribute that the runner's finding
  announcement prints (findings cannot use `Kind.Found`: `kinds` cannot import `findings`).
- **`resolutions.csv`** shows historical rows as `A-historical`/`AAAA-historical` with the two
  date columns. As built, `resolutionRows` (`internal/output/output.go`) merges `resolution` and
  `dns_claim` records by key into `name`, `type`, `value`, `source`. Historical rows are appended
  from `historical_address`. Their type is their own, so they never share a key with either kind.
  Their `source` is `dnshistory`. The two date columns are the last columns of the file, after
  `source` and after Spec 16's `self_hosted` if that has merged, and are blank on every other row.

## Changes

- `internal/provider/providers.yaml`, `provider.go`; `internal/inventory/inventory.go`: `Fronted`.
- `internal/stages/dnshistory/`, `internal/stages/web/origincheck.go`, `internal/origin/`.
- `internal/egress/http.go`: `OriginCheck` and its policy branch.
- `internal/kinds/origin.go` (`historical_address`, `origin_check`); `body_len` on
  `WebServiceAttrs`. `internal/findings/origin.go`, `table.go`, `records.go`.
- `internal/output/output.go`: resolution rows. `internal/config/config.go`: two settings.
- `internal/cli/cli.go`: `dnshistory` after `reverseip`, `origincheck` before `ports`.
- `README.md`: boundary text, the passive-mode stage list, the file, the severity table.

## Tests

- `internal/egress`: `OriginCheck` is refused for an address outside the netblocks and not
  port-eligible, an excluded address, a candidate or excluded host, and under `--passive`; it
  sends exactly one GET per scheme and never follows a redirect.
- `internal/origin`: candidate selection, ordering and the cap; confirmation rules, including the
  default-title list, the 10% body rule and "certificate alone is not enough".
- `internal/cli/origin_test.go` (loopback fakes, `DialMap`): a historical origin confirmed by
  title; a sibling found by certificate and by title; an uncontactable candidate reported as
  possible and **(canary)** never contacted; no check before the probe's 2xx; a changed title
  re-checks; the HTTP fallback only when 443 does not answer; findings going not current for each
  reason in behaviour 7; no key leaves sibling candidates only; the `dnshistory` cap and its
  deferred count; `--passive` skips `origincheck` and runs `dnshistory`.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Claim sources (Spec 2).** A second claim source that reports the same record would overwrite
  the first one's `source` attribute. It does not arise here: historical addresses are their own
  kind, `historical_address`, not `dns_claim`.
- **Budget rules (Spec 6).** The first pending check of a run is always sent, a budget below 1
  counts as 1, and a check that fails still spends its share. The `Deferred to the next run`
  block shows a bare number beside `dnshistory`; the README names its unit (hostnames).
- **Quota.** `httpsrc.Get` already aborts a keyed stage on a 401, 403 or 429, which is the rule
  for the other keyed sources. `dnshistory` needs no quota code of its own.
- **Linode object storage (Spec 5, follow-up 3).** While editing the `cname:` entries of
  `providers.yaml`, add `{suffix: linodeobjects.com, provider: linode, service: Object Storage}`,
  so a host on Linode object storage is shared, not dedicated.
- **A finding that is no longer derived keeps only what its key holds (Specs 3 and 12).** The
  store keeps attributes only from current observations. The key `origin-exposure|<host>|<addr>`
  gives such a row its hostname and address; its other cells are blank, as in every risk file.
- **New fields go at the end.** `body_len` is appended to `WebServiceAttrs` after the three
  fields Spec 18 adds.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.
- **Console text (Spec 22).** If Spec 22 has merged, the `+` line goes through its log formatter
  and is asserted on stderr. If not, assert it on stdout.

## Out of scope

Origin discovery by scanning netblocks, favicon or certificate search engines; requests other than
GET `/`.

# Implementation

## Develop

Built in layers, tests first. Each layer's tests failed on assertions before its code was written
(stubs only for `inventory.Fronted`, `egress.OriginCheck` and the `internal/origin` functions).

- **Settled first.** The user chose to keep a `cdn`-ASN address shared inside a dedicated published
  range, so `provider.Classify` now returns `Shared`, class `cdn`, evidence `asn` for it (tested for
  Akamai inside Linode's list and Cloudflare's AS inside DigitalOcean's, with a non-CDN owner and
  an unknown owner left dedicated). This amends Spec 5's behaviour 2. The user also chose that
  `--redo origincheck` failing to confirm leaves the same row current as a possible origin (low,
  `confirmed` `no`), not not current (see Deviations).
- **Providers and inventory.** `provider.ClassWAF`; `class: cdn` on the CloudFront, Azure CDN and
  Front Door, Cloudflare, Fastly and Akamai CNAME entries; new `akamaized.net` (cdn), `incapdns.net`
  and `sucuri.net` (waf) and `linodeobjects.com` entries. `Inventory.Fronted` (CNAME class on the
  chain, else an address of class `cdn`). Tests: `provider/origin_test.go`, `inventory/fronted_test.go`.
- **Egress.** `egress.OriginCheck(host, scheme, addr)`: a `target` with `origin` set, port 443 or 80,
  pinned to `addr`. `do` refuses an IP-literal host, applies the normal host rules, then asks
  `scope.PortEligible(addr, policy owner)` in place of the host's own addresses. Tests:
  `egress/origincheck_test.go` (request shape and SNI, redirect not followed, each refusal,
  `--passive` and no acknowledgement, an address that is not the host's, `NoService` reasons).
- **`internal/origin`** is pure. `Candidates` (the spec's selection, order, cap and dedupe),
  `Confirmed`, `DefaultTitle`, `NamesHost`; `records.go` builds `Pair`s from records for the stage
  and the findings, so they cannot disagree. Tests: `origin/origin_test.go`.
- **Kinds and probe.** `historical_address` and `origin_check` (`kinds/origin.go`), `body_len` at the
  end of `WebServiceAttrs`, recorded by the probe.
- **Stages.** `dnshistory` (`stages/dnshistory`, SecurityTrails `/v1/history/<host>/dns/a|aaaa`,
  `Budgeted`, cost 1 per hostname, up to five pages per type) and `origincheck`
  (`stages/web/origincheck.go`, `Retiring`, check key `host|addr|hash(title, cert subject)`).
  `run.View` gained `FrontedHostnames` and `OriginPairs`. Registry: `dnshistory` after `reverseip`,
  `origincheck` after `sensitive-paths` and before `ports`.
- **Findings and output.** `findings/origin.go` (category `origin-exposure`, types `confirmed` and
  `possible`; `Finding.FoundText()` builds the found line's text, in place of the stored `line` attribute the Design describes), `Key`/`ParseKey`
  special-cased so the key is `origin-exposure|<host>|<addr>`, `risk-origin-exposure.csv`, and
  `resolutions.csv` rows of type `A-historical`/`AAAA-historical` with the two date columns after
  `source`. Settings `dnshistory.max_hosts` and `origincheck.max_candidates`, README and `help`.
- **Behaviour tests** are in `cli/origin_test.go` against loopback fakes: confirmation by title
  (historical), by certificate or title or both (sibling), by size; certificate alone and a redirect
  leave a possible origin; an uncontactable and an excluded candidate are reported and never
  contacted (the canary servers); no check before the probe's 2xx; a changed title checks again; HTTP
  fallback only when 443 refuses (not on a TLS error, not when it answers); findings going not
  current for each reason in behaviour 7; the no-key, cap and deferred, `--passive`, console line,
  `body_len`, registry, help and README cases.
- **Existing tests changed** because of this feature: the `resolutions.csv` header, the default file
  list, the findings table and file list, `TestRiskStageRegistry`, and
  `TestSkip_NoPromptWhenEveryTargetStageIsSkipped` (which must also skip `origincheck`).
- **Mutation checks.** `## Tests` marks no behaviour for one, so none were required; four were run
  on the safety-critical guards, each undone by hand. Inverting the `cdn`-ASN guard in
  `provider.Classify` fails the Akamai and published-range tests. Dropping the eligibility refusal in
  `egress.OriginCheck` fails `TestOriginCheck_Refusals`. Dropping the stage's 2xx guard fails
  `TestOrigin_NoCheckBeforeTheProbeHasA2xx`. Dropping the stage's `Contactable` guard first
  *survived*, because egress still refused the request (a failed check, nothing contacted); the
  uncontactable test now also asserts the stage yields no check, and fails under that mutation.

Deviations:

- **Behaviour 7, `--redo origincheck`.** An answer that no longer confirms leaves the row current as
  a possible origin, as the user chose; the row is marked not current only for the other three
  reasons.
- **Sibling title matches ignore default titles.** A sibling matches the fronted host on its title
  only when that title is neither empty nor on the default-title list, which the spec states only
  for confirmation. Without it every host on one default page would be a sibling.
- **A historical address that is excluded or may not be contacted is still reported** as a possible
  origin, as behaviour 3 says; the finding is only derived from addresses whose owner is known and
  that are not shared.
- **Finding target** is `<host> -> <address>` (the key holds the two parts), which the summary lists.
- **External facts.** SecurityTrails' history request and response shapes (`records[].values[].ip`
  or `ipv6`, `first_seen`, `last_seen`, `pages`) are from its documentation and untried against a
  live key, as for `reverseip`. The default-title list is a hand-picked starter set.

## Known limitations

- **Behaviour 1.** A history longer than five pages for one hostname and type is cut with a WARN
  line; the stage does not resume it.
- **Behaviour 2.** A sibling's certificate is judged from the SAN names the probe recorded
  (`tls_sans`), including wildcards of one label; the subject CN alone is not read. A wildcard
  certificate therefore makes every host it covers a sibling of the fronted host, within the cap.
- **Behaviour 3.** The probe's 2xx test reads the HTTPS service on port 443 only; a host that is
  fronted over HTTP only is never checked.
- **Behaviour 5.** `DefaultTitle` matches phrases anywhere in a title, so a legitimate title that
  contains one (for example "Request blocked") cannot confirm an exposure. The probe's `body_len` is
  the part of the body read (capped at 1 MiB), so a larger page compares as the cap.

## Simplify

Four reviewers (reuse, simplification, efficiency, altitude) read the branch. None of the fixes
changes CSV output, `--json` fields or console text, and the full suite passes.

Fixed:

- **`origin.Candidates` does less work.** It indexes the siblings once by certificate name and by
  title, then looks up each fronted host's names (`CertNames` replaces `NamesHost`). It groups
  historical addresses by host, and drops a new address once a host has `max` candidates (an
  address it already kept can still gain a way). The "how found" constants are unexported.
- **`origin.Pairs`.** Web services are filtered with `kinds.Visibility.Shown`, as the findings and
  the output files are. Historical addresses are filtered by the set of fronted hosts, which are in
  scope, instead of calling `ClassifyHost` on every record. `Pair.Probed` is now a method computed
  from the probe's status.
- **`origincheck`.** It passes the `origin.Pair` as the check input and keys the record with
  `Pair.Key()`, so the `host|addr` format is written in one place.
- **The found line is computed, not stored.** `findings.Finding.FoundText()` builds the console
  text from the type, target and provider, and the runner calls it. This replaces the `line`
  attribute the Design describes, so console wording is no longer persisted in the state database.
- **`originTarget`** uses the `originArrow` constant.
- **Egress.** `Policy.portIneligible` is the single refusal for an address that may not be
  port-checked, used by both `targetTCP.Connect` and the origin branch of `targetHTTP.do`. The
  redundant `&& !tg.origin` pin guard is removed.
- **`Inventory.Fronted`** is built on `served`, which now also returns the matching provider. It
  shares one CNAME-then-address walk with `SaaSServed` and `ProviderServed`.
- **`provider.Classify`** builds its ASN result through one helper, `asnResult`, instead of in two
  branches.
- **`historical_address`** stores the DNS type (`A`/`AAAA`) in its `type` attribute and key.
  `resolutionRows` adds `-historical` when it writes the row, so an output label is not frozen in
  the state database.
- **`dnshistory`** uses `cmp.Or` and works out the record type from the address, instead of a
  hand-written helper and a stored field.
- **Tests.**
  - `TestOrigin_StageRegistry` is folded into `TestRiskStageRegistry`, which already pinned the
    order and now also checks the contact.
  - Dead code is removed: `stHistory.status`, the `siblingOwn` option (now `x.set`), `plain443`, the
    initial `cfRanges` value and the lock around setting it, `unusedPortAddr`, and the `hits`
    counter (now the count of requests seen).
  - `wantRow` checks the expected provider instead of skipping the check in the range world.
  - `slices.Equal` and an inline expected list replace the hand-written loops.

Skipped:

- **Folding the origin-exposure key into the takeover rule** (`origin-exposure|host -> addr`). The
  Design and "Carried from built specs" spell out `origin-exposure|<host>|<addr>`, so the
  special-cased `Key`/`ParseKey` stays.
- **Recording the answer's SAN names instead of `cert_names_host`**, so that `origin` alone decides
  confirmation. This changes the stored evidence and the matching rule (`VerifyHostname` against
  `CertNames`), which is a design change, not a cleanup.
- **Replacing `origin.Probe`/`origin.Answer` with the kinds' attribute structs.** The pure package
  keeps its own small input types, which its tests construct directly.
- **Replacing `howRank` with a plain string sort.** The order only happens to be alphabetical; the
  explicit rank documents it.
- **Reusing `world.requests` and `stReverse` for the `stHistory` fake.** This would mean merging two
  SecurityTrails fakes in the test world, beyond this change. The fake's three parallel request
  slices are also left as they are.
- **Computing the fronted set once for both fronts and siblings.** Siblings exclude every fronted
  host, not just the probe hostnames, so the two sets differ.

# Verification

## Result

`make test` (cross-target `go vet`, then `go test -race ./...`) passes.

- **Goal: met.** Historical A/AAAA addresses of fronted hostnames are recorded, candidate origins are
  derived by one pure function shared by the stage and the findings, and a confirmed exposure is a
  medium finding reached by one GET to an address egress would already let nyx handshake.
- **Behaviour 1: met, with one limit.** `dnshistory` is a keyed third-party stage, runs under
  `--passive`, yields the fronted probe hostnames in name order, is `Budgeted` (cost 1, default
  200) and reports the deferred count. Rows are `A-historical`/`AAAA-historical`, source
  `dnshistory`, with the two date columns last before `current`. Historical addresses are `ip`
  records only, so they reach `ips.csv` and the owner lookup, and the scope, inventory and wildcard
  check never read them. Known limitation (not under `## Out of scope`): a history longer than five
  pages per type is cut.
- **Behaviour 2: partly met.** Selection, qualification (owner known, not shared), the sibling rule
  (in scope, not wildcard-only, not fronted, certificate or non-empty title), the order and the cap
  are as specified. Not met, per Known limitations: a sibling certificate is judged from its SANs
  only, so a certificate naming the host only in its subject CN does not match. A wildcard SAN makes
  every host it covers a sibling, which is a literal reading of "names the fronted hostname". The
  implementation also ignores default titles for the sibling title match (a reasonable narrowing
  recorded under Deviations).
- **Behaviour 3: partly met.** Checks are made only for contactable pairs (port-eligibility, not
  excluded); every other candidate is a possible origin with no request, which the canary tests
  confirm. The check key carries a hash of the probe's title and certificate subject, and the stage
  is `Retiring`. Not met, per Known limitations: the 2xx gate reads the HTTPS service on 443 only, so
  a host served over HTTP only is never checked. A renewed certificate with the same subject does
  not trigger a re-check (the Design keys on the subject).
- **Behaviour 4: met.** `egress.OriginCheck` pins the candidate, sets SNI and Host to the hostname,
  never follows a redirect, and the stage falls back to port 80 only for a `NoService` that is not
  `tls-failed`. There is one GET per scheme.
- **Behaviour 5: met, with limits.** `origin.Confirmed` implements both rules; a 3xx and a
  certificate alone confirm nothing; the probe records `body_len`. Known limitations: default titles
  match as substrings, and the probe's body length is capped at 1 MiB.
- **Behaviour 6: met.** `risk-origin-exposure.csv` has the specified columns, one row per
  (hostname, address) via the `origin-exposure|<host>|<addr>` key; confirmed rows are medium,
  possible rows low; the `+` line matches; the README file table and `help findings` list both types.
- **Behaviour 7: partly met.** Each of the three "no longer qualifies" reasons marks the row not
  current (tested). The `--redo origincheck` clause is not met as written: an answer that no longer
  confirms leaves the row current as a low possible origin. The Develop notes record this as the
  user's choice, but the behaviour text and `## Out of scope` were not amended.
- **Behaviour 8: met.** Without a key `dnshistory` is `not-configured (no key)` and sibling
  candidates are still checked.
- **Behaviour 9: met.** The passive-boundary section names the one `GET /`, the server name and Host
  header, the address rule and why; `origincheck` is in the `--passive` list.

Changed during verification:

- **A hostname whose address is in a CloudFront range was not "behind a CDN".** `awsRule` gave
  CloudFront ranges no class, so only a CNAME to `cloudfront.net` counted. An apex aliased to
  CloudFront (A records only) was neither asked about by `dnshistory` nor given candidates, although
  the README says an address belonging to CloudFront counts. `awsRule` now returns class `cdn` for a
  `CLOUDFRONT` range (`internal/provider/provider.go`). The CloudFront case of `TestClassify` now
  expects the class, and `TestFronted` has an aliased host. Nothing else reads the class of a range
  result except `SaaSServed`, which compares it with `saas`.

## Code review

`/code-review high --fix` reported seven issues and fixed four. All four were checked against the
spec and kept, because none changes behaviour. `make test` passes afterwards.

Fixed:

- **One helper splits an origin-exposure target.** `splitOriginTarget` (`internal/findings/origin.go`)
  replaces three hand-written `strings.Cut` calls in `Key`, `ParseKey` and the `riskFiles` row
  builder. Keys and rows are unchanged (behaviour 6).
- **`dnshistory` escapes the hostname in the SecurityTrails URL path** with `url.PathEscape`, as
  the subdomains stage does. Hostnames are already normalised, so no request changes (behaviour 1).
- **README provider list.** The list of providers that make a hostname "behind a CDN or WAF" now
  names Vercel's and Yandex's networks, whose ASN entries have class `cdn` (behaviours 1 and 2,
  documentation only).
- **Registry comment.** The `defaultStages` comment now says `origincheck` follows `dnshistory` and
  the probe, which is where its candidates come from. It no longer says the crawl and sensitive
  paths (no behaviour).

Left unfixed:

- **The candidate cap counts candidates that may not be contacted.** Five uncontactable historical
  addresses can crowd out a contactable sibling, which then is never checked. Behaviour 2 says "at
  most N are checked", which could mean either reading. `TestCandidates_CapKeepsTheFirst` pins the
  current one, so this is the user's decision.
- **AAAA history is asked even after the A history returned 404.** Skipping it assumes something
  about SecurityTrails' API that has not been tried against a live key.
- **`Fronted` is evaluated twice per derivation** (`FrontedHosts` and the sibling filter). This is
  an efficiency point, not a defect. Sharing the set would mean threading it through both callers.

# Follow-ups

1. Try `dnshistory` once with a real SecurityTrails key, against a domain you are authorised to test
   that has a CDN-fronted host: `make build && NYX_KEYS_SECURITYTRAILS=<key> ./nyx --passive
   --output-dir /tmp/nyx-origin <domain>`. Check the `A-historical` rows in
   `/tmp/nyx-origin/<engagement>/resolutions.csv`. The request and response shapes come from its
   documentation. Note the credits one hostname costs (two requests, more for a long history), and
   whether a 404 on the A history makes the AAAA request worth skipping
   (`internal/stages/dnshistory/dnshistory.go`, `Run`).
2. Review the default-title list in `internal/origin/origin.go` (`defaultTitles`) against real CDN,
   WAF and default-server pages, and decide whether matching should be narrower than a substring.
3. Decide whether `origincheck.max_candidates` should count only candidates that may be contacted,
   so that uncontactable historical addresses cannot crowd out a checkable sibling (`Candidates` in
   `internal/origin/origin.go`, pinned by `TestCandidates_CapKeepsTheFirst`).
4. Amend behaviour 7 of this spec (now in `docs/specs/done/`) to match the agreed `--redo
   origincheck` outcome: an answer that no longer confirms leaves the row current as a low possible
   origin. Alternatively, change the code to mark it not current.
5. Decide whether to close the known limitations: the 2xx gate reads only the HTTPS service on 443
   (`origin.Pairs`, `internal/origin/records.go`), and a sibling certificate is judged only from its
   SANs, not its subject CN. A renewed certificate with an unchanged subject does not re-check a pair
   (`Pair.CheckKey`).
6. Run the linter with a golangci-lint v2 built with Go 1.27.3 or later. The one installed here is
   built with Go 1.26 and refuses the module:
   `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest && golangci-lint run --new-from-rev=main ./...`.
7. Spec 5's behaviour 2 changed: a `cdn` ASN keeps an address shared inside a dedicated published
   range. During verification, AWS CloudFront ranges also gained class `cdn`. Amend Spec 5's text
   (`docs/specs/done/2026-11-spec-provider-ranges-05.md`) and the build-order table
   (`docs/plans/2026-11-build-order.md`).
