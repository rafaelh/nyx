# Spec 18: TLS detail and weak protocol findings

## Goal

The TLS version, cipher and trust state of each in-scope HTTPS service are recorded from the
probe's single handshake, and services that offer nothing newer than TLS 1.1, or present a
certificate for the wrong name, are low findings.

## Behaviours

1. Every HTTPS request to an in-scope service (probe, crawl, sensitive paths, takeover
   fingerprinting, origin check) accepts TLS 1.0 and 1.1 and additionally offers CBC-mode and RSA
   key-exchange suites, but not RC4 or 3DES, so a service whose best version is 1.0 or 1.1 is
   recorded with that version instead of failing and is then crawled and checked like any other.
   Requests to third-party sources keep today's minimum version. A service supporting TLS 1.2 or
   later records the same `tls_version` as before; its `tls_cipher` is whatever it picks from the
   wider offer. SSL 3.0-only services still fail. Old versions offered alongside new ones are not
   detected; the README says so.
2. `web-services.csv` gains `tls_version` (`TLS 1.2` style), `tls_cipher` (the IANA suite name)
   and `tls_trust`, which replaces `tls_error` and `tls_self_signed` and holds the first that
   applies of `expired` (including not yet valid), `hostname-mismatch`, `self-signed`,
   `untrusted-chain`, else `trusted`. `tls_issuer` and `tls_sans` are unchanged. Values come from
   the service's own first response, not a redirect target, and are as of the probe; the README
   notes that `untrusted-chain` depends on the running machine's root store.
3. A service negotiating TLS 1.0 or 1.1 is a low finding `legacy-tls` in `risk-certificates.csv`.
   The existing `self-signed` finding is kept. A new low finding `hostname-mismatch` is made for a
   certificate that does not name the probed hostname, except for services addressed by IP literal
   or hosts served by a known provider (CDN or SaaS).
4. A service whose TLS handshake fails is not recorded as an HTTPS service, as today, and produces
   no TLS finding.
5. Findings are marked not current after `--redo httpprobe` negotiates a modern version or a
   matching certificate. Existing engagements have empty `tls_version` and `tls_cipher` until
   `--redo httpprobe`; the README says so, and its `risk-certificates.csv` row mentions legacy
   TLS and hostname mismatch.

# Design

**Status:** ready to build (wave 1). **Depends on:** nothing. Spec 12 merged first, and the
design was re-checked against it on 2026-11-14: the column and probe seams below are as built.
**Used by:** Spec 7 (its origin check goes through the same target client). **Shares with Specs
12 and 13:** `web-services.csv`.

## Decisions

- **One TLS configuration for every target request.** All target HTTP goes through
  `targetHTTP.do`, so the change is there: `MinVersion: tls.VersionTLS10` and an explicit
  `CipherSuites` list built once from `tls.CipherSuites()` plus the CBC and RSA key-exchange
  suites of `tls.InsecureCipherSuites()`, excluding any suite whose name contains `RC4` or `3DES`.
  The third-party client is untouched.
- **Egress reports what was negotiated**: `Response.TLSVersion` (`tls.VersionName`: `TLS 1.2`),
  `Response.TLSCipher` (`tls.CipherSuiteName`), and `Response.CertTrust()`, which replaces
  `CertVerifyErr` and returns the first that applies of `expired`, `hostname-mismatch`,
  `self-signed`, `untrusted-chain`, `trusted`. The self-signed test moves from the probe into
  egress so the order is decided in one place.
- **Attributes**: `tls_version`, `tls_cipher` and `tls_trust` are added to `WebServiceAttrs`.
  `tls_self_signed` is still written (the existing finding reads it); `tls_error` is no longer
  written but stays in the struct so old records decode.
- **Old records get a trust value on read**: `kinds.TLSTrust(attrs)` returns `tls_trust` when set
  and otherwise maps the old `tls_error` text and `tls_self_signed` to the same five values.
  `web-services.csv` shows `tls_version`, `tls_cipher`, `tls_trust` in place of `tls_error` and
  `tls_self_signed`. As built, the columns are `webServiceColumns` and the cells
  `webServiceCells` in `internal/output/output.go`, and the list ends with Spec 12's `hsts`,
  `insecure_cookies`, `directory_listing` and `version_disclosure`. The three new columns take
  the place of the two old ones, before `hsts`, not the end of the list.
- **The probe seam as built.** `service()` in `probe.go` sets `TLSError` from
  `first.CertVerifyErr()` and `TLSSelfSigned` from its own `selfSigned(leaf)`. Both move behind
  `first.CertTrust()`. The values come from `first`, the service's own response, which is also
  `chain[0]` of the `hop` chain Spec 12 added; the posture call beside it is not touched.
- **Findings** extend the `certificates` category: `legacy-tls` (low) when `tls_version` is
  `TLS 1.0` or `TLS 1.1`; `hostname-mismatch` (low) when trust is `hostname-mismatch`, the host is
  not an IP literal and `inv.ProviderServed(host)` is false (a new inventory method: a provider
  CNAME on the chain or a shared-provider address). They join the existing `;`-joined type of the
  one row per service.

## Changes

- `internal/egress/http.go`: TLS config, the three accessors, `CertTrust`.
- `internal/stages/web/probe.go`: attributes from the first response.
- `internal/kinds/table.go`: three fields at the end of `WebServiceAttrs`; `TLSTrust`.
- `internal/inventory/inventory.go`: `ProviderServed`.
- `internal/output/output.go`: columns. `internal/findings/findings.go`, `table.go`: two types.
- `README.md`: columns, the root-store note, what is not detected, the `risk-certificates.csv` row.

## Tests

- `internal/egress` (test TLS servers): a TLS 1.0-only and a 1.1-only server answer and report
  their version; an RSA-CBC-only server answers; an RC4-only or 3DES-only server is `tls-failed`;
  each trust value from a crafted chain against the fixed clock; third-party requests still
  refuse TLS 1.1.
- `internal/findings`: both new types, the IP-literal and provider exceptions, combined types.
- `internal/cli/tls_test.go`: a legacy service is recorded, crawled and checked for sensitive
  paths; columns; old records show a derived `tls_trust` and empty version until
  `--redo httpprobe`; findings go not current after a redo against a fixed service.

## Carried from built specs

Follow-ups and limits of the specs already built that bear on this one.

- **Posture on legacy services (Spec 12).** A service that only speaks TLS 1.0 or 1.1 is now
  recorded as an HTTPS service, so the probe also stores its `web_posture` and it can get the
  HSTS and cookie findings. That follows from behaviour 1 and needs no code.
- **Two provider tests (Spec 12).** Posture findings are skipped for a host `SaaSServed` says a
  SaaS platform serves. The `hostname-mismatch` exception is wider (CDN or SaaS), which is why it
  needs the new `ProviderServed`. Keep both; do not widen `SaaSServed`.
- **Akamai addresses in Linode's list (Spec 5, follow-up 1).** Those addresses classify as
  dedicated, so a host on one, with no Akamai CNAME, is not `ProviderServed` and can get a
  `hostname-mismatch` finding for a CDN certificate. Spec 7's design asks the user to settle
  that classification; nothing is decided here.
- **A finding that is no longer derived keeps only what its key holds (Specs 3 and 12).** A
  not-current `risk-certificates.csv` row has blank cells beyond its key, as today.
- **New fields go at the end.** The three fields are appended to `WebServiceAttrs`, and Spec 7's
  `body_len` follows them.
- **`Kind` is not comparable (Spec 3).** Compare `Name()`.

## Out of scope

Enumerating every version a server offers; SSL 3.0; any extra handshake.

# Implementation

## Develop

**How it was built.** `internal/egress/tls.go` (new) holds the client TLS configuration, the
`Trust*` constants, `Response.CertTrust()`, `Response.SelfSigned()` and the unexported `certTrust`.
`targetHTTP.do` uses `targetTLSConfig(host)`: `MinVersion` TLS 1.0 and a `CipherSuites` list built
once from `tls.CipherSuites()` plus every `tls.InsecureCipherSuites()` entry whose name has neither
`RC4` nor `3DES` (what is left of the insecure list is all CBC or RSA key exchange). The third-party
client is untouched. `do` fills `Response.TLSVersion` and `Response.TLSCipher` from
`resp.TLS`. `CertVerifyErr` and `verifyChain` are gone. The probe sets `TLSVersion`, `TLSCipher` and
`TLSTrust` from `first`, and no longer writes `tls_error`. `kinds.TLSTrust` maps an old record's
`tls_error` text and `tls_self_signed` to the five values. `Inventory.ProviderServed` is a provider
CNAME anywhere on the chain, or an address in shared provider space. `web-services.csv` has the
three columns where the two old ones were, before `hsts`. `internal/findings/findings.go` adds the
two types, joined in alphabetical order; the table has both rows; the README has a new "TLS detail"
section and the changed `risk-certificates.csv` and `web-services.csv` rows.

**Deviations.**
- `Response.TLSVersion` and `TLSCipher` are exported fields, not methods.
- The probe's `tls_self_signed` comes from a new `Response.SelfSigned()`, not from
  `CertTrust() == "self-signed"`. Trust reports the first that applies, so an expired self-signed
  certificate has trust `expired`, and deriving the flag from it would lose today's
  `expired;self-signed` finding. The order of the five values is still decided only in egress.
- The trust values are defined twice: `egress.Trust*` (what `CertTrust` reports) and `kinds.Trust*`
  (the stored vocabulary, used by `kinds.TLSTrust` and `findings`). A `kinds` test pins them equal,
  so the record and findings layers do not import egress.
- `hostname-mismatch` is derived from `kinds.TLSTrust`, not from `tls_trust` alone, so an
  engagement probed by an earlier version gets the finding without `--redo httpprobe` (its
  version and cipher stay empty until the redo, as the spec says). The README says so.
- `certTrust` takes the root pool as an argument (`Response.CertTrust` passes nil, the system's),
  so a test can reach `trusted`, which a fake server cannot produce against the machine's roots.
- The certificate finding's detail ends `, negotiated TLS 1.0` for a legacy service.
- Existing tests that read `tls_error` and `tls_self_signed` were changed to the new columns
  (`web_test.go`, `web_redirect_test.go`, `web_plumbing_test.go`, `egress_test.go`).
- `docs/plans/2026-11-build-order.md` marks Spec 18 built.

**How each behaviour was tested.**
1. `internal/egress/tls_test.go`: TLS 1.0-only and 1.1-only servers answer and report their version
   and cipher; an RSA-key-exchange CBC-only server answers; a TLS 1.3 server and a 1.2-capped one
   report `TLS 1.3` and `TLS 1.2`; RC4-only and 3DES-only servers give `tls-failed`; a TLS 1.1
   source is refused by the third-party client on its protocol version (the error says so, rather
   than naming the certificate). `internal/cli/tls_test.go`: a TLS 1.0 and a TLS 1.1 service are
   recorded, the first is crawled and both are checked for a sensitive path (`/.env` is flagged),
   and a TLS 1.2-capped service records `TLS 1.2` with no `legacy-tls`. SSL 3.0 is not tested end
   to end: Go cannot speak it, so neither the client nor a fake server can.
2. The `web-services.csv` header; one service per trust value (`expired`, `self-signed`,
   `hostname-mismatch`, `untrusted-chain`, and `hostname-mismatch` winning over `self-signed`) and a
   plain HTTP service with blank TLS columns; `TestCertTrustValues` crafts chains against the fixed
   clock for all five values, not-yet-valid, and each pair of the order; a redirecting service keeps
   its own version, cipher and trust, not its target's; `kinds.TLSTrust` on stored and old records.
3. `internal/findings/tls_test.go`: both types, 1.2 and 1.3 and an unrecorded version giving none,
   an IP-literal service and CDN, SaaS, PaaS, shared-address and further-down-the-chain hosts giving
   no `hostname-mismatch`, combined types (`hostname-mismatch;legacy-tls;self-signed`,
   `expired;legacy-tls` at medium), the old-record case, and the severity table.
   `internal/inventory/saas_test.go`: `ProviderServed`.
4. `TestTLS_FailedHandshakeIsNotRecorded`: an RC4-only server is not a service, has no finding and
   sees no request. This already passed before the change, and still does: it pins today's
   behaviour.
5. `TestTLS_ExistingRecordsHaveDerivedTrustAndNoVersionUntilRedo` rewrites the stored attributes to
   the old shape (SQLite `json_set`), checks the columns and that a plain re-run sends nothing, then
   redoes. `TestTLS_FindingsGoNotCurrentAfterRedoAgainstFixedService` flips one server from TLS 1.0
   with a wrong-name certificate to TLS 1.3 with the right name and checks the row is kept and not
   current.

**Assertion failures first.** With stubs for the accessors, `kinds.TLSTrust` and `ProviderServed`,
every new test of behaviours 1, 2, 3 and 5 failed on an assertion (empty values, no findings, a TLS
1.0 server that gave `NoService`). The RC4 test and the other failed-handshake test passed already.

**Mutation checks.** `## Tests` marks no behaviour for one, so these were done by hand on the
behaviours most likely to regress, each undone by hand afterwards. Each made at least one test fail:
offering RC4 and, separately, 3DES (`TestTargetHTTPDoesNotOfferRC4Or3DES`); a TLS 1.2 minimum
(`TestTargetHTTPAcceptsTLS10And11`); dropping the hostname check from `certTrust`
(`TestCertTrustValues`, `TestResponseCertTrustAndSelfSigned`); dropping the provider exception
(`TestHostnameMismatchFinding`); and ignoring TLS 1.1 in `legacy-tls` (`TestLegacyTLSFinding`,
`TestTLSFindingsCombine`).

## Known limitations

- **Behaviour 1.** A service that offers TLS 1.0 or 1.1 alongside TLS 1.2 or later negotiates the
  newer one and is not detected. The spec accepts this and the README says so.
- **Behaviour 2.** `untrusted-chain` and `trusted` depend on the root store of the machine running
  nyx. The CLI tests cannot produce `trusted` (a fake server's chain is never in the system
  roots); it is covered only by `TestCertTrustValues`, with a root pool passed in.
- **Behaviour 3.** An Akamai address in Linode's published list classifies as dedicated, so a host
  on one with no Akamai CNAME can get `hostname-mismatch` for a CDN certificate (Spec 5's
  follow-up, left to Spec 7). `ProviderServed` counts any provider CNAME on the chain, so a host on
  a PaaS such as Heroku has no `hostname-mismatch` finding even though its certificate may be its
  own to fix.
- **Behaviour 5.** The test for an existing engagement makes the old shape by rewriting stored
  attributes, not by running an older binary.

## Simplify

**Fixed.**
- `kinds` and `findings` imported `internal/egress` only for the five trust strings, which pulled
  the network stack into the record layer. The values now also live in `kinds` (`kinds.Trust*`),
  and `TestTrustValuesMatchEgress` pins them to `egress.Trust*`.
- `ProviderServed` and `SaaSServed` were the same walk (IP literal, CNAME chain, addresses) with a
  different test. Both now call one private `served(host, byCNAME, byAddr)`.
- The CLI tests had two fake HTTPS constructors; `secure` now calls `secureConfig`, which records
  SNIs for both. The legacy-version test builds its certificates once, not on every handshake.
  `selfFor(t, host)` replaces four copies of a self-signed certificate naming its host.
  `typeURLs(rows)` replaces the copied bodies of `certTypes` and `postureTypes`.
- The `web-services.csv` header check in `TestTLS_ColumnsAndTrustValues` is dropped: the web
  plumbing test already checks the same header.
- `TestTLSSeverities` is removed: `TestSeverityTable` has both rows and `TestTLSFindingsCombine`
  covers `expired;legacy-tls` at medium.
- In `internal/egress/tls_test.go`, the third-party test uses `thirdPartyEgress`, the plain-HTTP
  case uses `newHTTPFixture`, and the expired date is one `yesterday`.

**Skipped.**
- The self-signed signature is checked twice for a self-named leaf (`SelfSigned` and `CertTrust`).
  It costs one signature check per probed service, next to a network round trip.
- Reporting each certificate check separately (so an expired certificate for the wrong name also
  gets `hostname-mismatch`) would change the "first that applies" behaviour the spec sets.
- A decode-time upgrade hook in `kinds.Of.Attrs`, so readers cannot read `a.TLSTrust` and miss the
  old-record value, is a change to shared record decoding well beyond this spec.
- A shared `LegacyTLS` predicate in place of the `"TLS 1.0"`/`"TLS 1.1"` literals in findings: one
  use, low value.
- Moving the egress test certificate factory and the CLI one into `egresstest`: a cross-package
  restructure of test helpers outside this change.
- Dropping the IP-literal branch of `ProviderServed` (unused by its only production caller): it
  now comes for free from the shared `served` helper and keeps the two methods alike.

# Verification

## Result

All five behaviours and the goal are met, B3 with the caveat below. `make test` passes apart from one run in which
`TestCrawl_DisabledAndSettingsAreInTheCheckKey` (plain HTTP, a file this change does not touch)
probed an extra `http://example.com`; it passed on five reruns and on a rerun of the package.

- **Goal.** Version, cipher and trust come from the probe's one handshake (`targetHTTP.do` fills
  `TLSVersion`/`TLSCipher` from `resp.TLS`; `CertTrust` judges the presented chain afterwards, with
  no extra connection), and the two new low findings are derived from them.
- **B1: met.** `targetTLSConfig` is the only TLS configuration in the target client, and every
  target HTTP request (probe, crawl, sensitive paths, takeover, and Spec 7's origin check when
  built) goes through `targetHTTP.do`. It sets `MinVersion` TLS 1.0 and offers `tls.CipherSuites()`
  plus the insecure suites whose names have neither `RC4` nor `3DES`. The third-party client keeps
  Go's default (TLS 1.2 minimum), which `TestThirdPartyStillRefusesTLS11` pins. TLS 1.0 and 1.1
  services are recorded, crawled and checked for sensitive paths; TLS 1.2 and 1.3 services keep
  their version. SSL 3.0 cannot be negotiated by Go at all. The README says an old version offered
  alongside a new one is not detected.
- **B2: met.** `web-services.csv` has `tls_version`, `tls_cipher` and `tls_trust` where
  `tls_error` and `tls_self_signed` were, before `hsts`. Trust is the first of `expired` (including
  not yet valid), `hostname-mismatch`, `self-signed`, `untrusted-chain`, `trusted`, decided in one
  place (`egress.certTrust`). Values come from `first`, not the redirect target (tested). The
  README notes that `untrusted-chain` depends on the running machine's root store. `trusted` can
  only be reached in a unit test with a supplied root pool, which is a limit of the test, not the
  behaviour.
- **B3: met, with a wider exception than its wording.** `legacy-tls` and `hostname-mismatch` are
  low types in `risk-certificates.csv`,
  joined with the existing types of the service's one row; `self-signed` is kept (still read from
  `tls_self_signed`, so an expired self-signed certificate keeps `expired;self-signed`).
  `hostname-mismatch` is skipped for IP literals and for hosts `Inventory.ProviderServed` reports
  (any provider CNAME on the chain or a shared-provider address). B3 says "a known provider (CDN or
  SaaS)", but the design's rule also exempts PaaS hosts, cloud load balancers (`elb.amazonaws.com`)
  and shared-hosting or fail-closed hyperscaler addresses, whose certificates the target configures
  itself. That is the design's choice and is listed under `## Known limitations`; whether to narrow
  it is left to the user (see Follow-ups). The Akamai-in-Linode case waits on the open Spec 5/7
  decision.
- **B4: met.** A failed handshake is `NoService` and is not recorded, so it has no TLS finding
  (`TestTLS_FailedHandshakeIsNotRecorded`).
- **B5: met.** After `--redo httpprobe` against a fixed service the finding stays on record and
  is not current. An old record has empty `tls_version`/`tls_cipher` and a `tls_trust` derived by
  `kinds.TLSTrust`; the README says so and its `risk-certificates.csv` row names legacy TLS and
  hostname mismatch. The old-shape test rewrites stored attributes rather than running an old
  binary, which is a limit of the test.

Changed during verification: `kinds.TLSTrust` did not map the old `tls_error` text Go gives for a
certificate whose name is only in its Common Name ("certificate relies on legacy Common Name
field"), so such an old record read as `untrusted-chain` (or `self-signed`) while a re-probe gives
`hostname-mismatch`. It now maps to `hostname-mismatch`, with a case in `TestTLSTrust`.

`golangci-lint run ./...` reports five issues, all in files this change does not touch
(`sources_keyed_test.go`, `sanitize_test.go`, `providerranges_test.go`).

The working tree also carries an unrelated one-line correction to
`docs/specs/done/2026-11-spec-log-colours-22.md`, which is committed with this change.

## Code review

`/code-review high --fix` made six findings and applied one fix:

- **Fixed (B3, documentation only).** The `hostname-mismatch` row of the severity table (shown in
  `--help`) and the README bullet said the exception covered "a CDN or SaaS host". They now say a
  host on shared provider infrastructure (any known provider's CNAME on its chain, or an address in
  shared provider space), which is what the code does. No behaviour changed; `make test` passes.

Left unfixed:

- **`ProviderServed` is wider than "CDN or SaaS" (B3).** Narrowing it to CDN and SaaS classes would
  change the rule the design set. A decision for the user.
- **Platform verifier may fetch over the network on macOS (passive boundary, not a spec behaviour).**
  `certTrust` calls `leaf.Verify` with the system roots, which on macOS goes to
  `SecTrustEvaluateWithError`; Go does not turn off Apple's network fetching, so AIA intermediates
  or revocation data named by a target's certificate could be fetched outside the egress `Policy`.
  This predates the change (the old `verifyChain` did the same) and the fix (verify with Go's own
  verifier and an explicit root pool on darwin) is beyond this spec.
- **An expired certificate for the wrong name gives only `expired` (B3).** This is the "first that
  applies" rule of B2 and the design's "`hostname-mismatch` when trust is `hostname-mismatch`".
- **The self-signed signature is checked twice per probed service.** Negligible next to the round
  trip; already skipped in `## Simplify`.
- **Trust strings defined in both `egress` and `kinds`.** A deliberate choice recorded in
  `## Implementation` so the record layer does not import egress; a test pins them equal.

# Follow-ups

1. Decide whether the `hostname-mismatch` exception should cover only CDN and SaaS hosts, as B3
   reads, rather than every provider CNAME and shared address (PaaS, `elb.amazonaws.com`, Azure
   fail-closed addresses). If so, narrow `Inventory.ProviderServed` in
   `internal/inventory/inventory.go` and the wording in `internal/findings/table.go` and the
   README's "TLS detail" section.
2. Settle how Akamai addresses in Linode's list classify (Spec 7's open decision, listed under
   "Decisions still open" in `docs/plans/2026-11-build-order.md`); until then such a host can get a
   `hostname-mismatch` for a CDN certificate.
3. On a Mac, check whether `certTrust`'s `leaf.Verify` against the system roots
   (`internal/egress/tls.go`) makes network requests for AIA or revocation (for example probe a
   test host whose leaf has an AIA URL pointing at a host you watch, with
   `nyx --output-dir /tmp/nyx-out ...`). If it does, verify with an explicit root pool on darwin
   so the passive boundary holds.
4. Run a live probe against a real TLS 1.0/1.1-only service you are authorised to test, and check
   `web-services.csv` and `risk-certificates.csv` (`go run ./cmd/nyx --output-dir /tmp/nyx-out
   <target>`), including an existing engagement before and after `--redo httpprobe`.
5. Fix the five `golangci-lint run ./...` issues in files outside this change
   (`internal/cli/sources_keyed_test.go`, `internal/sanitize/sanitize_test.go`,
   `internal/cli/providerranges_test.go`).
6. Watch `TestCrawl_DisabledAndSettingsAreInTheCheckKey` for flakiness
   (`go test -race ./internal/cli/ -run TestCrawl_DisabledAndSettingsAreInTheCheckKey -count=20`):
   it once probed an extra `http://example.com` in a full `make test` run.
